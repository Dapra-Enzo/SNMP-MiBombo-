#!/usr/bin/env python3
"""
MiBombo Suite - Système d'Authentification Sécurisé v2
=========================================================
- Inscription avec validation admin (tickets)
- 2FA par email
- Mot de passe oublié
- Appareils de confiance (30 jours)
- Serveur SMTP intégré
"""

import os
import re
import json
import hashlib
import secrets
import smtplib
import secrets
import smtplib
import psycopg2
import psycopg2.extras
import uuid
import hmac
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading

# Logger pour événements de sécurité
try:
    from .logger import get_security_logger, log_security_event
    security_logger = get_security_logger()
except ImportError:
    try:
        from core.logger import get_security_logger, log_security_event
        security_logger = get_security_logger()
    except:
        security_logger = None
        def log_security_event(*args, **kwargs): pass

# Fonctions de hachage sécurisées
def hash_password(password: str) -> str:
    """Hache le mot de passe avec PBKDF2 (SHA256) et un sel aléatoire."""
    salt = secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # 100k itérations
    )
    return f"pbkdf2:sha256:{100000}${salt}${hash_bytes.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Vérifie le mot de passe (Supporte PBKDF2 et Legacy SHA256)."""
    try:
        # Format PBKDF2: algo:hash_name:iterations$salt$hash
        if stored_password.startswith("pbkdf2:"):
            parts = stored_password.split('$')
            if len(parts) != 3:
                return False
            
            meta, salt, stored_hash = parts
            _, _, iterations = meta.split(':')
            
            new_hash = hashlib.pbkdf2_hmac(
                'sha256',
                provided_password.encode('utf-8'),
                salt.encode('utf-8'),
                int(iterations)
            )
            return hmac.compare_digest(new_hash.hex(), stored_hash)
            
        # Legacy SHA256 (Non salé - à migrer)
        else:
            legacy_hash = hashlib.sha256(provided_password.encode()).hexdigest()
            return hmac.compare_digest(legacy_hash, stored_password)
    except Exception as e:
        print(f"[!] Erreur vérification mot de passe: {e}")
        return False

# Chemin de la base de données
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "auth.db")
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "mail_config.json")


class TicketStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class UserStatus(Enum):
    PENDING = "pending"      # En attente de validation
    ACTIVE = "active"        # Compte actif
    DISABLED = "disabled"    # Compte désactivé


@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    role: str
    permissions: List[str]
    status: str
    two_fa_enabled: bool
    created_at: str
    last_login: Optional[str] = None
    must_change_password: bool = False


@dataclass
class RegistrationTicket:
    id: str
    username: str
    email: str
    password_hash: str
    status: str
    created_at: str
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    rejection_reason: Optional[str] = None


@dataclass 
class TrustedDevice:
    id: str
    user_id: str
    device_hash: str
    created_at: str
    expires_at: str
    last_used: str


@dataclass
class TwoFACode:
    user_id: str
    code: str
    created_at: str
    expires_at: str
    used: bool = False


class MailConfig:
    """Configuration du serveur SMTP"""
    
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.use_tls = True
        self.username = ""
        self.password = ""  # App password pour Gmail
        self.from_email = ""
        self.from_name = "MiBombo Suite"
        self.enabled = False
        
        self._load_config()
    
    def _load_config(self):
        """Charge la configuration (Priorité: Env Vars > Fichier)"""
        # Charger depuis le fichier d'abord (valeurs par défaut)
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r') as f:
                    data = json.load(f)
                    self.smtp_server = data.get("smtp_server", self.smtp_server)
                    self.smtp_port = data.get("smtp_port", self.smtp_port)
                    self.use_tls = data.get("use_tls", self.use_tls)
                    self.username = data.get("username", "")
                    self.password = data.get("password", "")
                    self.from_email = data.get("from_email", "")
                    self.from_name = data.get("from_name", self.from_name)
                    self.enabled = data.get("enabled", False)
            except:
                pass

        # Surcharger avec les variables d'environnement (Sécurité)
        self.smtp_server = os.getenv("MAIL_SERVER", self.smtp_server)
        self.smtp_port = int(os.getenv("MAIL_PORT", self.smtp_port))
        self.username = os.getenv("MAIL_USERNAME", self.username)
        self.password = os.getenv("MAIL_PASSWORD", self.password)
        self.from_email = os.getenv("MAIL_FROM", self.from_email)
        
        # Si le mot de passe est dans l'env, on active
        if os.getenv("MAIL_PASSWORD"):
            self.enabled = True
    
    def save(self):
        """Sauvegarde la configuration"""
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump({
                "smtp_server": self.smtp_server,
                "smtp_port": self.smtp_port,
                "use_tls": self.use_tls,
                "username": self.username,
                "password": self.password,
                "from_email": self.from_email,
                "from_name": self.from_name,
                "enabled": self.enabled,
            }, f, indent=2)
    
    def test_connection(self) -> Tuple[bool, str]:
        """Teste la connexion SMTP"""
        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            
            server.login(self.username, self.password)
            server.quit()
            return True, "Connexion réussie"
        except Exception as e:
            return False, str(e)


class MailService:
    """Service d'envoi d'emails"""
    
    def __init__(self, config: MailConfig):
        self.config = config
        self._lock = threading.Lock()

    def _get_mail_template(self, title: str, content: str, username: str) -> str:
        """Génère le template HTML Light (Blanc/Gris/Bleu) pour tous les mails."""
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background-color: #f3f4f6; color: #1f2937; margin: 0; padding: 0; }}
                .wrapper {{ width: 100%; background-color: #f3f4f6; padding: 40px 0; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); border: 1px solid #e5e7eb; }}
                .header {{ background-color: #ffffff; padding: 30px; text-align: center; border-bottom: 2px solid #3b82f6; }}
                .brand {{ font-size: 24px; font-weight: 800; color: #111827; letter-spacing: -0.5px; }}
                .brand span {{ color: #3b82f6; }}
                .content {{ padding: 40px; line-height: 1.6; font-size: 16px; color: #4b5563; }}
                .greeting {{ font-size: 18px; color: #111827; margin-bottom: 24px; font-weight: 600; }}
                .title {{ font-size: 20px; font-weight: 700; color: #1f2937; margin-bottom: 24px; text-align: center; }}
                .footer {{ background-color: #f9fafb; padding: 24px; text-align: center; font-size: 12px; color: #9ca3af; border-top: 1px solid #e5e7eb; }}
                .btn {{ display: inline-block; padding: 12px 28px; background-color: #3b82f6; color: white !important; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 24px 0; transition: background-color 0.2s; }}
                .btn:hover {{ background-color: #2563eb; }}
                .highlight-box {{ background-color: #f0f9ff; border-left: 4px solid #3b82f6; padding: 20px; margin: 24px 0; border-radius: 6px; }}
                .contact {{ margin-top: 12px; color: #6b7280; }}
            </style>
        </head>
        <body>
            <div class="wrapper">
                <div class="container">
                    <div class="header">
                        <div class="brand">MiBombo <span>by ensa</span></div>
                    </div>
                    <div class="content">
                        <div class="greeting">Bonjour {username},</div>
                        
                        {content}
                        
                        <p style="margin-top: 32px; border-top: 1px solid #e5e7eb; padding-top: 24px; color: #6b7280; font-size: 14px;">
                            Merci de votre confiance.<br>
                            <strong>L'équipe MiBombo</strong>
                        </p>
                    </div>
                    <div class="footer">
                        &copy; 2026 MiBombo by ensa. Tous droits réservés.
                        <div class="contact">
                            Une question ? support@mibombo.local<br>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''
    
    def send_email(self, to_email: str, subject: str, html_body: str, text_body: str = None) -> Tuple[bool, str]:
        """Envoie un email en mode BULLDOZER (Ignorer totalement les erreurs SSL)"""
        if not self.config.enabled:
            return False, "Service mail désactivé"
        
        import ssl
        import smtplib
        from email.utils import formatdate, make_msgid

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = to_email
            msg['Date'] = formatdate(localtime=True)
            msg['Message-ID'] = make_msgid(domain=self.config.smtp_server)
            
            if text_body:
                msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            print(f"[DEBUG] Connexion à {self.config.smtp_server}:{self.config.smtp_port}...")
            
            # Contexte SSL sécurisé par défaut
            context = ssl.create_default_context()

            with self._lock:
                server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
                # server.set_debuglevel(1) 
                
                server.ehlo()
                if server.has_extn("STARTTLS"):
                    print("[DEBUG] Activation STARTTLS (Sécurisé)...")
                    server.starttls(context=context)
                    server.ehlo()
                
                print("[DEBUG] Tentative de login...")
                server.login(self.config.username, self.config.password)
                
                print("[DEBUG] Envoi du message...")
                server.send_message(msg)
                server.quit()
            
            return True, "Email envoyé avec succès"

        except Exception as e:
            print(f"❌ ERREUR BULLDOZER: {e}")
            return False, str(e)
    
    def send_2fa_code(self, to_email: str, code: str, username: str) -> Tuple[bool, str]:
        """Envoie le code 2FA"""
        subject = "🔐 Code de vérification MiBombo"
        
        content = f"""
            <div class="title">Authentification Sécurisée</div>
            <p style="text-align: center;">Voici votre code de vérification à usage unique :</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #3b82f6; background: #f0f9ff; padding: 15px 30px; border-radius: 8px; border: 1px solid #dbeafe;">{code}</span>
            </div>
            
            <p style="text-align: center; font-size: 14px; color: #6b7280;">
                Ce code expire dans <strong>10 minutes</strong>.<br>
                Si vous n'êtes pas à l'origine de cette demande, veuillez ignorer cet email.
            </p>
        """
        html = self._get_mail_template(subject, content, username)
        
        text = f"Bonjour {username},\n\nVotre code de vérification MiBombo : {code}\n\nCe code expire dans 10 minutes."
        
        return self.send_email(to_email, subject, html, text)
    
    def send_temp_password(self, to_email: str, temp_password: str, username: str) -> Tuple[bool, str]:
        """Envoie le mot de passe temporaire"""
        subject = "🔑 Réinitialisation mot de passe - MiBombo"
        
        content = f"""
            <div class="title">Réinitialisation de mot de passe</div>
            <p>Une demande de réinitialisation a été effectuée pour votre compte.</p>
            
            <div class="highlight-box">
                <strong>Mot de passe temporaire :</strong><br>
                <div style="font-size: 24px; color: #ef4444; font-family: monospace; margin-top: 10px;">{temp_password}</div>
            </div>
            
            <p>⚠️ <strong>Important :</strong> Ce mot de passe est temporaire. Vous serez invité à le changer dès votre prochaine connexion.</p>
        """
        html = self._get_mail_template(subject, content, username)
        
        text = f"Bonjour {username},\n\nVotre mot de passe temporaire MiBombo : {temp_password}\n\nVous devrez le changer à la prochaine connexion.\n\nSi vous n'avez pas demandé cette réinitialisation, contactez l'administrateur."
        
        return self.send_email(to_email, subject, html, text)
    
    def send_registration_pending(self, to_email: str, username: str) -> Tuple[bool, str]:
        """Email de confirmation d'inscription en attente"""
        subject = "MiBombo – Votre inscription est en cours de validation"
        
        content = f"""

            <div class="title">Confirmation de réception</div>
            
            <p>Nous vous informons que votre demande d'inscription à l'espace <strong>MiBombo by ensa</strong> a bien été enregistrée.</p>
            
            <div class="highlight-box" style="background-color: #fffbeb; border-color: #f59e0b;">
                <strong>État de votre dossier :</strong><br>
                <span style="color: #d97706; font-size: 18px; font-weight: 600;">⏳ En attente de validation</span>
            </div>
            
            <p>Notre équipe administrative étudie actuellement votre profil. Cette procédure de sécurité est nécessaire avant toute activation de compte.</p>
            
            <p>Vous serez notifié par email dès que votre accès sera opérationnel.</p>
        """
        html = self._get_mail_template(subject, content, username)
        
        return self.send_email(to_email, subject, html)
    
    def send_registration_approved(self, to_email: str, username: str) -> Tuple[bool, str]:
        """Email de validation d'inscription"""
        subject = "MiBombo – Confirmation d'activation de votre compte"
        
        content = f"""
            <div class="title">Bienvenue sur MiBombo !</div>
            
            <p>Bonjour {username},</p>
            
            <p>Nous avons le plaisir de vous informer que votre inscription sur <strong>MiBombo</strong> a été validée.</p>
            
            <div class="highlight-box" style="border-color: #10b981;">
                <strong>Statut de votre compte :</strong><br>
                <span style="color: #10b981; font-size: 18px;">✅ Activé & Opérationnel</span>
            </div>
            
            <p>Vous pouvez dès à présent accéder à l'ensemble des fonctionnalités de votre espace sécurisé.</p>
            
            <div style="text-align: center;">
                <a href="#" class="btn">Accéder à la Station MiBombo</a>
            </div>
            
            <p>Nous restons à votre disposition pour vous accompagner dans vos premiers pas.</p>
            
            <p>Cordialement,<br>
            <strong>L’équipe MiBombo</strong></p>
        """
        html = self._get_mail_template(subject, content, username)
        
        return self.send_email(to_email, subject, html)
    
    def send_registration_rejected(self, to_email: str, username: str, reason: str = None) -> Tuple[bool, str]:
        """Email de refus d'inscription"""
        subject = "MiBombo – Information concernant votre demande d'inscription"
        
        content = f"""
            <div class="title">Mise à jour de votre demande</div>
            
            <p>Bonjour {username},</p>
            
            <p>Nous avons bien reçu votre demande d'inscription sur <strong>MiBombo</strong>.<br>
            Après examen de votre dossier, nous sommes au regret de vous informer que nous ne pouvons donner une suite favorable à votre demande pour le moment.</p>
            
            <div class="highlight-box" style="border-color: #ef4444;">
                <strong style="color: #ef4444;">Motif du refus :</strong><br>
                {reason if reason else "Critères d'éligibilité non remplis."}
            </div>
            
            <p>Si vous pensez qu'il s'agit d'une erreur ou si vous souhaitez apporter des éléments complémentaires, nous vous invitons à contacter notre support technique.</p>
            
            <p>Cordialement,<br>
            <strong>L’équipe MiBombo</strong></p>
        """
        html = self._get_mail_template(subject, content, username)
        
        return self.send_email(to_email, subject, html)
    
    def send_admin_new_ticket(self, admin_email: str, ticket) -> Tuple[bool, str]:
        """Notifie l'admin d'un nouveau ticket"""
        subject = "🎫 Nouvelle demande d'inscription - MiBombo"
        
        # Gérer le cas où ticket est un dict ou un objet
        if isinstance(ticket, dict):
            username = ticket.get('username', 'N/A')
            email = ticket.get('email', 'N/A')
            created_at = ticket.get('created_at', 'N/A')
        else:
            username = ticket.username
            email = ticket.email
            created_at = ticket.created_at
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; }}
                .container {{ max-width: 500px; margin: 40px auto; background: #161b22; border-radius: 12px; padding: 40px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .logo {{ font-size: 28px; font-weight: bold; color: #f97316; }}
                .ticket-box {{ background: #21262d; border: 2px solid #f97316; border-radius: 8px; padding: 20px; margin: 20px 0; }}
                .field {{ margin: 10px 0; }}
                .label {{ color: #8b949e; font-size: 12px; }}
                .value {{ color: #e6edf3; font-size: 16px; }}
                .info {{ color: #8b949e; font-size: 14px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🛡️ MiBombo Suite</div>
                </div>
                <p>Une nouvelle demande d'inscription a été soumise :</p>
                <div class="ticket-box">
                    <div class="field">
                        <div class="label">Identifiant</div>
                        <div class="value">{username}</div>
                    </div>
                    <div class="field">
                        <div class="label">Email</div>
                        <div class="value">{email}</div>
                    </div>
                    <div class="field">
                        <div class="label">Date</div>
                        <div class="value">{created_at[:16] if len(created_at) > 16 else created_at}</div>
                    </div>
                </div>
                <p class="info">Connectez-vous à MiBombo pour approuver ou refuser cette demande.</p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(admin_email, subject, html)


class AuthDatabase:
    """Gestion de la base de données d'authentification (PostgreSQL)"""
    
    def __init__(self, db_path: str = None):
        # On ignore db_path pour Postgres
        from core.PostgresDB import DataBase
        self.backend = DataBase()
        self._init_db()
    
    def _get_conn(self):
        self.backend.open()
        return self.backend.connection
    
    def _init_db(self):
        """Initialise les tables via PostgresDB"""
        # C'est PostgresDB.initDB() qui fait le travail maintenant
        self.backend.initDB()
        
        # Créer l'admin par défaut si aucun utilisateur
        conn = self._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        try:
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            row = cursor.fetchone()
            if row[0] == 0:
                self._create_default_admin(cursor)
                conn.commit()
        except Exception as e:
            # Table peut ne pas exister si initDB a echoue ou premier run bizarre
            print(f"[AUTH] Erreur verification admin: {e}")
            conn.rollback()
    
    def _create_default_admin(self, cursor):
        """Crée l'admin par défaut"""
        admin_id = str(uuid.uuid4())
        initial_password = secrets.token_urlsafe(12)
        password_hash = hash_password(initial_password)
        
        cursor.execute("""
            INSERT INTO users (id, username, email, password_hash, password_salt, role, permissions, status, two_fa_enabled, must_change_password, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            admin_id,
            "admin",
            "admin@mibombo.local",
            password_hash,
            "embedded",
            "admin",
            json.dumps(["all"]),
            "active",
            False,
            True,
            datetime.now().isoformat()
        ))
        print(f"[SECURITY] Admin par défaut créé.")
        print(f"[SECURITY] Credentials: admin / {initial_password}")
        print(f"[SECURITY] Notez-le bien, il ne sera plus affiché.")


class SecureAuthenticationManager:
    """Gestionnaire d'authentification sécurisé"""
    
    DEVICE_TRUST_DAYS = 30
    CODE_EXPIRY_MINUTES = 10
    SESSION_EXPIRY_HOURS = 24
    
    def __init__(self):
        self.db = AuthDatabase()
        self.mail_config = MailConfig()
        self.mail_service = MailService(self.mail_config)
        
        self.current_user: Optional[Dict] = None
        self.current_session: Optional[str] = None
    
    # ==================== Utilitaires ====================
    
    def _hash_password(self, password: str) -> str:
        """Hash un mot de passe (Utilise hash_password global)"""
        return hash_password(password)
    
    def _generate_code(self, length: int = 6) -> str:
        """Génère un code numérique"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    def _generate_temp_password(self) -> str:
        """Génère un mot de passe temporaire"""
        chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$"
        return ''.join(secrets.choice(chars) for _ in range(12))
    
    def _get_device_hash(self, device_info: str = None) -> str:
        """Génère un hash d'appareil"""
        if not device_info:
            device_info = str(uuid.getnode())  # MAC address
        return hashlib.sha256(device_info.encode()).hexdigest()[:32]
    
    # ==================== Inscription ====================
    
    def _is_valid_email(self, email: str) -> bool:
        """Vérifie le format de l'email avec une regex simple mais robuste."""
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return re.match(pattern, email) is not None

    def register(self, username: str, password: str, email: str) -> Tuple[bool, str]:
        """Soumet une demande d'inscription"""
        if not self._is_valid_email(email):
            print(f"[AUTH] Inscription rejetée: format email invalide ({email})")
            return False, "Format d'email invalide"

        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Vérifier si le username existe déjà (utilisateur ou ticket)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            conn.close()
            return False, "Cet identifiant est déjà utilisé"
        
        cursor.execute("SELECT id FROM registration_tickets WHERE username = %s AND status = 'pending'", (username,))
        if cursor.fetchone():
            conn.close()
            return False, "Une demande est déjà en attente pour cet identifiant"
        
        # Vérifier si l'email existe déjà
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            return False, "Cet email est déjà utilisé"
        
        cursor.execute("SELECT id FROM registration_tickets WHERE email = %s AND status = 'pending'", (email,))
        if cursor.fetchone():
            conn.close()
            return False, "Une demande est déjà en attente pour cet email"
        
        # Créer le ticket
        ticket_id = str(uuid.uuid4())
        password_hash = self._hash_password(password)
        created_at = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO registration_tickets (id, username, email, password_hash, status, created_at)
            VALUES (%s, %s, %s, %s, 'pending', %s)
        """, (ticket_id, username, email, password_hash, created_at))
        
        conn.commit()
        conn.close()
        
        print(f"[+] Nouveau ticket d'inscription: {username} ({email})")
        
        # Envoyer email de confirmation à l'utilisateur
        self.mail_service.send_registration_pending(email, username)
        
        # Notifier les admins
        self._notify_admins_new_ticket({'username': username, 'email': email, 'created_at': created_at})
        
        return True, "Demande soumise avec succès"
    
    def _notify_admins_new_ticket(self, ticket: RegistrationTicket):
        """Notifie tous les admins d'un nouveau ticket"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'active'")
        
        for row in cursor.fetchall():
            self.mail_service.send_admin_new_ticket(row['email'], ticket)
        
        conn.close()
    
    def get_pending_tickets(self) -> List[Dict]:
        """Récupère les tickets en attente"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("""
            SELECT * FROM registration_tickets WHERE status = 'pending' ORDER BY created_at DESC
        """)
        
        tickets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return tickets
    
    def approve_ticket(self, ticket_id: str, admin_id: str, role: str = "user", 
                      permissions: List[str] = None) -> Tuple[bool, str]:
        """Approuve un ticket d'inscription"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer le ticket
        cursor.execute("SELECT * FROM registration_tickets WHERE id = %s AND status = 'pending'", (ticket_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "Ticket non trouvé ou déjà traité"
        
        ticket = dict(row)
        
        # Créer l'utilisateur
        user_id = str(uuid.uuid4())
        perms = json.dumps(permissions or ["read"])
        
        cursor.execute("""
            INSERT INTO users (id, username, email, password_hash, password_salt, role, permissions, status, two_fa_enabled, created_at)
            VALUES (%s, %s, %s, %s, 'embedded', %s, %s, 'active', FALSE, %s)
        """, (
            user_id, ticket['username'], ticket['email'], ticket['password_hash'],
            role, perms, datetime.now().isoformat()
        ))
        
        # Mettre à jour le ticket
        cursor.execute("""
            UPDATE registration_tickets SET status = 'approved', reviewed_at = %s, reviewed_by = %s
            WHERE id = %s
        """, (datetime.now().isoformat(), admin_id, ticket_id))
        
        conn.commit()
        conn.close()
        
        # Envoyer email de confirmation
        self.mail_service.send_registration_approved(ticket['email'], ticket['username'])
        
        print(f"[+] Ticket approuvé: {ticket['username']}")
        return True, f"Compte {ticket['username']} créé et activé"
    
    def reject_ticket(self, ticket_id: str, admin_id: str, reason: str = None) -> Tuple[bool, str]:
        """Rejette un ticket d'inscription"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM registration_tickets WHERE id = %s AND status = 'pending'", (ticket_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "Ticket non trouvé ou déjà traité"
        
        ticket = dict(row)
        
        cursor.execute("""
            UPDATE registration_tickets SET status = 'rejected', reviewed_at = %s, reviewed_by = %s, rejection_reason = %s
            WHERE id = %s
        """, (datetime.now().isoformat(), admin_id, reason, ticket_id))
        
        conn.commit()
        conn.close()
        
        # Envoyer email de refus
        self.mail_service.send_registration_rejected(ticket['email'], ticket['username'], reason)
        
        print(f"[+] Ticket refusé: {ticket['username']}")
        return True, f"Demande de {ticket['username']} refusée"
    
    # ==================== Connexion ====================
    
    def login_step1(self, username: str, password: str) -> Tuple[bool, str, Optional[str]]:
        """
        Première étape de connexion : vérifie username/password
        Retourne: (success, message, user_id si success)
        """
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            log_security_event("AUTH_FAIL", f"Tentative login échouée - utilisateur inconnu: {username}", "WARNING")
            return False, "Identifiant ou mot de passe incorrect", None
        
        user = dict(row)
        
        # Vérifier le statut
        if user.get('status') == 'pending':
            conn.close()
            log_security_event("AUTH_BLOCKED", f"Login bloqué - compte en attente: {username}", "WARNING")
            return False, "Compte en attente de validation", None
        
        if user.get('status') == 'disabled':
            conn.close()
            log_security_event("AUTH_BLOCKED", f"Login bloqué - compte désactivé: {username}", "WARNING")
            return False, "Compte désactivé", None
        
        # Vérifier le mot de passe avec la fonction sécurisée
        if not verify_password(user['password_hash'], password):
            conn.close()
            log_security_event("AUTH_FAIL", f"Mot de passe incorrect pour: {username}", "WARNING")
            return False, "Identifiant ou mot de passe incorrect", None

        # ✅ VÉRIFICATION: Changement de password obligatoire
        if user.get('must_change_password', 0) == 1:
            conn.close()
            log_security_event("AUTH_CHANGE_REQUIRED", f"Changement de mot de passe requis: {username}", "INFO")
            return False, "MUST_CHANGE_PASSWORD", user['id']

        # MIGRATION: Si le mot de passe est valide mais en format legacy, on le met à jour
        if user['password_hash'] and not user['password_hash'].startswith("pbkdf2:"):
            log_security_event("AUTH_MIGRATION", f"Migration mot de passe vers PBKDF2: {username}", "INFO")
            new_hash = hash_password(password)
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user['id']))
            conn.commit()
        
        conn.close()
        log_security_event("AUTH_SUCCESS", f"Connexion réussie: {username} (role: {user.get('role', 'user')})", "INFO")
        return True, "Credentials OK", user['id']
    
    def login_step2_check_2fa(self, user_id: str, device_info: str = None) -> Tuple[bool, str]:
        """
        Vérifie si la 2FA est nécessaire
        Retourne: (need_2fa, message)
        """
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = dict(cursor.fetchone())
        
        if not user['two_fa_enabled']:
            conn.close()
            return False, "2FA désactivée"
        
        # Vérifier appareil de confiance
        device_hash = self._get_device_hash(device_info)
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT * FROM trusted_devices 
            WHERE user_id = %s AND device_hash = %s AND expires_at > %s
        """, (user_id, device_hash, now))
        
        trusted = cursor.fetchone()
        
        if trusted:
            # Mettre à jour last_used
            cursor.execute("""
                UPDATE trusted_devices SET last_used = %s WHERE id = %s
            """, (now, trusted['id']))
            conn.commit()
            conn.close()
            return False, "Appareil de confiance"
        
        conn.close()
        return True, "2FA requise"
    
    def login_step2_send_code(self, user_id: str) -> Tuple[bool, str]:
        """Envoie le code 2FA par email"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = dict(cursor.fetchone())
        
        # Générer le code
        code = self._generate_code()
        now = datetime.now()
        expires = now + timedelta(minutes=self.CODE_EXPIRY_MINUTES)
        
        # Invalider les anciens codes
        cursor.execute("UPDATE twofa_codes SET used = TRUE WHERE user_id = %s AND used = FALSE", (user_id,))
        
        # Sauvegarder le nouveau code
        cursor.execute("""
            INSERT INTO twofa_codes (user_id, code, created_at, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, code, now.isoformat(), expires.isoformat()))
        
        conn.commit()
        conn.close()
        
        # Envoyer par email
        success, msg = self.mail_service.send_2fa_code(user['email'], code, user['username'])
        
        if success:
            return True, "Code envoyé par email"
        return False, f"Erreur envoi email: {msg}"
    
    def login_step2_verify_code(self, user_id: str, code: str, trust_device: bool = False, 
                                device_info: str = None) -> Tuple[bool, str]:
        """Vérifie le code 2FA"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        now = datetime.now().isoformat()
        
        cursor.execute("""
            SELECT * FROM twofa_codes 
            WHERE user_id = %s AND code = %s AND used = FALSE AND expires_at > %s
            ORDER BY created_at DESC LIMIT 1
        """, (user_id, code, now))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "Code invalide ou expiré"
        
        # Marquer le code comme utilisé
        cursor.execute("UPDATE twofa_codes SET used = TRUE WHERE id = %s", (row['id'],))
        
        # Ajouter appareil de confiance si demandé
        if trust_device:
            device_hash = self._get_device_hash(device_info)
            device_id = str(uuid.uuid4())
            now_dt = datetime.now()
            expires = now_dt + timedelta(days=self.DEVICE_TRUST_DAYS)
            
            # Supprimer l'ancien si existe
            cursor.execute("DELETE FROM trusted_devices WHERE user_id = %s AND device_hash = %s", 
                          (user_id, device_hash))
            
            cursor.execute("""
                INSERT INTO trusted_devices (id, user_id, device_hash, created_at, expires_at, last_used)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (device_id, user_id, device_hash, now_dt.isoformat(), expires.isoformat(), now_dt.isoformat()))
        
        conn.commit()
        conn.close()
        
        return True, "Code vérifié"
    
    def complete_login(self, user_id: str) -> Tuple[bool, str, Optional[Dict]]:
        """Finalise la connexion et retourne les infos utilisateur"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False, "Utilisateur non trouvé", None
        
        user = dict(row)
        
        # Mettre à jour last_login
        cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", 
                      (datetime.now().isoformat(), user_id))
        
        # Créer une session
        session_token = secrets.token_urlsafe(32)
        now = datetime.now()
        expires = now + timedelta(hours=self.SESSION_EXPIRY_HOURS)
        
        cursor.execute("""
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (session_token, user_id, now.isoformat(), expires.isoformat()))
        
        conn.commit()
        conn.close()
        
        # Préparer les données utilisateur
        self.current_user = {
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "permissions": json.loads(user['permissions']) if isinstance(user['permissions'], str) else user['permissions'],
            "two_fa_enabled": bool(user['two_fa_enabled']),
            "must_change_password": bool(user['must_change_password']),
        }
        self.current_session = session_token
        
        return True, "Connexion réussie", self.current_user
    
    # ==================== Mot de passe oublié ====================
    
    def forgot_password(self, email: str) -> Tuple[bool, str]:
        """Envoie un mot de passe temporaire par email"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM users WHERE email = %s AND status = 'active'", (email,))
        row = cursor.fetchone()
        
        if not row:
            # Ne pas révéler si l'email existe ou non
            return True, "Si cet email existe, un mot de passe temporaire a été envoyé"
        
        user = dict(row)
        
        # Générer mot de passe temporaire
        temp_password = self._generate_temp_password()
        password_hash = self._hash_password(temp_password)
        
        # Mettre à jour
        cursor.execute("""
            UPDATE users SET password_hash = %s, must_change_password = TRUE WHERE id = %s
        """, (password_hash, user['id']))
        
        conn.commit()
        conn.close()
        
        # Envoyer l'email
        success, msg = self.mail_service.send_temp_password(email, temp_password, user['username'])
        
        if success:
            print(f"[+] Mot de passe temporaire envoyé à {email}")
            return True, "Mot de passe temporaire envoyé par email"
        return False, f"Erreur: {msg}"
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change le mot de passe"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = dict(cursor.fetchone())
        
        # Vérifier l'ancien mot de passe
        if user['password_hash'] != self._hash_password(old_password):
            conn.close()
            return False, "Mot de passe actuel incorrect"
        
        # Mettre à jour
        new_hash = self._hash_password(new_password)
        cursor.execute("""
            UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE id = %s
        """, (new_hash, user_id))
        
        conn.commit()
        conn.close()
        
        return True, "Mot de passe modifié"
    
    def force_change_password(self, user_id: str, new_password: str) -> Tuple[bool, str]:
        """Force le changement de mot de passe (pour mot de passe temporaire)"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        new_hash = self._hash_password(new_password)
        cursor.execute("""
            UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE id = %s
        """, (new_hash, user_id))
        
        conn.commit()
        conn.close()
        
        return True, "Mot de passe modifié"
    
    # ==================== Gestion utilisateurs (Admin) ====================
    
    def get_all_users(self) -> List[Dict]:
        """Récupère tous les utilisateurs"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = []
        for row in cursor.fetchall():
            u = dict(row)
            # PostgreSQL peut retourner déjà une liste/dict pour JSONB
            u['permissions'] = json.loads(u['permissions']) if isinstance(u['permissions'], str) else u['permissions']
            users.append(u)
        conn.close()
        return users
    
    def update_user(self, user_id: str, role: str = None, permissions: List[str] = None,
                   two_fa_enabled: bool = None, status: str = None) -> Tuple[bool, str]:
        """Met à jour un utilisateur"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        updates = []
        params = []
        
        if role is not None:
            updates.append("role = %s")
            params.append(role)
        
        if permissions is not None:
            updates.append("permissions = %s")
            params.append(json.dumps(permissions))
        
        if two_fa_enabled is not None:
            updates.append("two_fa_enabled = %s")
            params.append(two_fa_enabled)
        
        if status is not None:
            updates.append("status = %s")
            params.append(status)
        
        if not updates:
            conn.close()
            return False, "Aucune modification"
        
        params.append(user_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", params)
        
        conn.commit()
        conn.close()
        
        return True, "Utilisateur mis à jour"
    
    def delete_user(self, user_id: str) -> Tuple[bool, str]:
        """Supprime un utilisateur"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Vérifier que ce n'est pas le dernier admin
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'")
        admin_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        
        if row and row['role'] == 'admin' and admin_count <= 1:
            conn.close()
            return False, "Impossible de supprimer le dernier admin"
        
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        cursor.execute("DELETE FROM trusted_devices WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM twofa_codes WHERE user_id = %s", (user_id,))
        
        conn.commit()
        conn.close()
        
        return True, "Utilisateur supprimé"
    
    # ==================== 2FA Settings ====================
    
    def toggle_2fa(self, user_id: str, enabled: bool) -> Tuple[bool, str]:
        """Active/désactive la 2FA pour un utilisateur"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("UPDATE users SET two_fa_enabled = %s WHERE id = %s", 
                      (enabled, user_id))
        
        if not enabled:
            # Supprimer les appareils de confiance
            cursor.execute("DELETE FROM trusted_devices WHERE user_id = %s", (user_id,))
        
        conn.commit()
        conn.close()
        
        return True, "2FA " + ("activée" if enabled else "désactivée")
    
    def get_trusted_devices(self, user_id: str) -> List[Dict]:
        """Liste les appareils de confiance"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("""
            SELECT * FROM trusted_devices WHERE user_id = %s ORDER BY last_used DESC
        """, (user_id,))
        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return devices
    
    def revoke_trusted_device(self, device_id: str) -> Tuple[bool, str]:
        """Révoque un appareil de confiance"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("DELETE FROM trusted_devices WHERE id = %s", (device_id,))
        conn.commit()
        conn.close()
        return True, "Appareil révoqué"
    
    def revoke_all_trusted_devices(self, user_id: str) -> Tuple[bool, str]:
        """Révoque tous les appareils de confiance"""
        conn = self.db._get_conn()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("DELETE FROM trusted_devices WHERE user_id = %s", (user_id,))
        conn.commit()
        conn.close()
        return True, "Tous les appareils révoqués"
    
    # ==================== Déconnexion ====================
    
    def logout(self):
        """Déconnecte l'utilisateur"""
        if self.current_session:
            conn = self.db._get_conn()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute("DELETE FROM sessions WHERE token = %s", (self.current_session,))
            conn.commit()
            conn.close()
        
        self.current_user = None
        self.current_session = None


# Singleton
_auth_manager = None

def get_secure_auth_manager() -> SecureAuthenticationManager:
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = SecureAuthenticationManager()
    return _auth_manager
