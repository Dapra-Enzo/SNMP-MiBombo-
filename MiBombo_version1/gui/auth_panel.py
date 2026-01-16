                                                                #!/usr/bin/env python3
"""
MiBombo  - Interface d'Authentification Sécurisée v2
============================================================
Interface complète avec :
- Inscription avec ticket evnoyer par mail a confirmer par admin sur soft 
- Mot de passe oublié
- Configuration SMTP
"""

import customtkinter as ctk
import tkinter as tk
from PIL import Image
from typing import Optional, Callable, Dict
import threading
import os
import sys

# Ajouter le chemin parent pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import du système d'auth
try:
    from core.secure_authentication import get_secure_auth_manager, SecureAuthenticationManager, MailConfig
    AUTH_AVAILABLE = True
except ImportError:
    try:
        from secure_auth import get_secure_auth_manager, SecureAuthenticationManager, MailConfig
        AUTH_AVAILABLE = True
    except ImportError:
        AUTH_AVAILABLE = False
        print("[!] Secure auth module not available")

# Thème Grafana Dark
# Thème White/Blue (Light Professional)
THEME = {
    "bg": "#FFFFFF",
    "bg_secondary": "#F3F4F6",
    "card": "#F3F4F6",      # Gray Card ("gris devant")
    "card_hover": "#E5E7EB",
    "bg_hover": "#E5E7EB",
    "input": "#FFFFFF",     # White input
    "input_focus": "#FFFFFF",
    "border": "#D1D5DB",
    "text": "#1F2937",      # Dark text
    "text_secondary": "#4B5563",
    "text_muted": "#6B7280",
    "accent": "#3B82F6",    # Blue
    "accent_hover": "#2563EB",
    "accent_blue": "#3B82F6",
    "success": "#10B981",
    "warning": "#F59E0B",
    "error": "#EF4444",
    
    # Special Login Colors
    "login_bg": "#FFFFFF",  # White Background ("blanc tout au fond")
    "login_btn": "#3B82F6", # Blue Button ("boutons bleurs")
    "login_btn_hover": "#2563EB",
}


class SecureLoginWindow:
    """Fenêtre de connexion sécurisée autonome"""
    
    def __init__(self, on_success: Callable[[Dict], None] = None):
        self.auth = get_secure_auth_manager() if AUTH_AVAILABLE else None
        self.on_success = on_success
        
        # État
        self._user_id = None
        self._current_email = None
        self._step = "login"  # login, email_verification, change_password, register, forgot
        
        # Fenêtre principale
        self.root = ctk.CTk()
        self.root.title("Mibombo - Connexion")
        self.root.geometry("450x720") # Plus grand pour tout afficher
        self.root.minsize(400, 600)
        self.root.resizable(True, True) # Permettre le redimensionnement
        # Fond Bleu #2563EB (Tailwind Blue-600 like)
        self.root.configure(fg_color=THEME["login_bg"])
        
        # Centrer
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 420) // 2
        y = (self.root.winfo_screenheight() - 600) // 2
        self.root.geometry(f"+{x}+{y}")
        
        # Construire l'UI
        self._build_ui()
    
    def _build_ui(self):
        """Construit l'interface"""
        # Container principal avec scroll si nécessaire
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=35, pady=30)
        
        # Logo et titre
        self._build_header()
        
        # Contenu (change selon l'étape)
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, pady=(20, 0))
        
        # Afficher le formulaire de login
        self._show_login()
    
    def _build_header(self):
        """En-tête avec logo"""
        # Logo ou Icône
        try:
            # Try to find logo in assets/logo.png relative to this file's parent
            current_dir = os.path.dirname(os.path.abspath(__file__))
            root_dir = os.path.dirname(current_dir)
            logo_path = os.path.join(root_dir, "assets", "logo.png")
            
            if os.path.exists(logo_path):
                pil_image = Image.open(logo_path)
                logo_img = ctk.CTkImage(light_image=pil_image, dark_image=pil_image, size=(80, 80))
                ctk.CTkLabel(
                    self.main_frame,
                    text="",
                    image=logo_img
                ).pack(pady=(0, 10))
            else:
                ctk.CTkLabel(
                    self.main_frame,
                    text="🛡️",
                    font=ctk.CTkFont(size=42)
                ).pack()
        except Exception as e:
            print(f"Error loading logo: {e}")
            ctk.CTkLabel(
                self.main_frame,
                text="🛡️",
                font=ctk.CTkFont(size=42)
            ).pack()
        
        # Titre Noir sur fond blanc
        ctk.CTkLabel(
            self.main_frame,
            text="Login",
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
            text_color=THEME["text"]
        ).pack(pady=(5, 5))
        
        ctk.CTkLabel(
            self.main_frame,
            text="Accédez à votre espace sécurisé",
            font=ctk.CTkFont(size=14),
            text_color=THEME["text_secondary"]
        ).pack(pady=(0, 20))
    
    def _clear_content(self):
        """Efface le contenu actuel"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    # ==================== FORMULAIRE LOGIN ====================
    
    def _show_login(self):
        """Affiche le formulaire de connexion"""
        self._clear_content()
        self._step = "login"
        
        # Sous-titre
        ctk.CTkLabel(
            self.content_frame,
            text="Connexion requise",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_muted"]
        ).pack(pady=(0, 20))
        
        # Card formulaire
        card = ctk.CTkFrame(self.content_frame, fg_color=THEME["card"], corner_radius=12)
        card.pack(fill="x")
        
        # Identifiant (au lieu d'Email)
        ctk.CTkLabel(
            card,
            text="Identifiant",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=20, pady=(20, 5))
        
        self.email_entry = ctk.CTkEntry(
            card,
            height=42,
            fg_color=THEME["input"],
            border_color=THEME["border"],
            border_width=1,
            placeholder_text="votre identifiant",
            font=ctk.CTkFont(size=12)
        )
        self.email_entry.pack(fill="x", padx=20)
        
        # Mot de passe
        ctk.CTkLabel(
            card,
            text="Mot de passe",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=20, pady=(15, 5))
        
        self.password_entry = ctk.CTkEntry(
            card,
            height=42,
            fg_color=THEME["input"],
            border_color=THEME["border"],
            border_width=1,
            placeholder_text="••••••••",
            show="•",
            font=ctk.CTkFont(size=12)
        )
        self.password_entry.pack(fill="x", padx=20)
        
        # Message d'erreur
        self.error_label = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=THEME["error"]
        )
        self.error_label.pack(pady=(10, 5))
        
        # Boutons côte à côte : Se connecter + S'inscrire
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(5, 20))
        
        # Bouton Login (Orange/Coral)
        # Bouton Login (Bleu)
        # Bouton Login (Bleu)
        # Bouton Login (Bleu - Style amélioré)
        self.login_btn = ctk.CTkButton(
            btn_frame,
            text="SE CONNECTER",
            height=50,
            fg_color=THEME["login_btn"],
            hover_color=THEME["login_btn_hover"],
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=8, # Modern rounded rect
            border_width=0,
            command=self._do_login
        )
        self.login_btn.pack(fill="x", pady=(10, 15))
        
        # Séparateur ou texte
        ctk.CTkLabel(btn_frame, text="Pas encore de compte ?", 
                    font=ctk.CTkFont(size=12), text_color=THEME["text_muted"]).pack(pady=(0, 5))

        self.register_btn = ctk.CTkButton(
            btn_frame,
            text="Créer un compte",
            height=40,
            fg_color="transparent",
            text_color=THEME["accent"],
            border_width=2,
            border_color=THEME["accent"],
            hover_color=THEME["bg_hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8,
            command=self._show_register
        )
        self.register_btn.pack(fill="x", pady=(0, 10))
        
        # Bind Enter
        self.password_entry.bind("<Return>", lambda e: self._do_login())
        self.email_entry.bind("<Return>", lambda e: self.password_entry.focus())
        
        # Focus sur identifiant
        self.email_entry.focus()
    
    def _do_login(self):
        """Effectue la connexion"""
        if not self.auth:
            self.error_label.configure(text="Service d'authentification non disponible")
            return
        
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not email or not password:
            self.error_label.configure(text="Remplissez tous les champs")
            return
        
        self.login_btn.configure(state="disabled", text="Connexion...")
        self.error_label.configure(text="")
        
        def do_auth():
            success, msg, user_id = self.auth.login_step1(email, password)
            self.root.after(0, lambda: self._handle_login_result(success, msg, user_id, email))
        
        threading.Thread(target=do_auth, daemon=True).start()
    
    def _handle_login_result(self, success: bool, msg: str, user_id: str, email: str):
        """Gère le résultat du login"""
        self.login_btn.configure(state="normal", text="Connexion")
        
        # Gestion du changement de mot de passe forcé (retourné comme échec avec code spécifique)
        if not success and msg == "MUST_CHANGE_PASSWORD":
            self._user_id = user_id
            self._current_email = email
            self._show_change_password()
            return

        if not success:
            self.error_label.configure(text=msg)
            return
        
        self._user_id = user_id
        self._current_email = email
        
        # Vérifier si vérification email requise
        need_2fa, reason = self.auth.login_step2_check_2fa(user_id)
        
        if need_2fa:
            # Envoyer le code par email
            success, msg = self.auth.login_step2_send_code(user_id)
            if success:
                self._show_email_verification()
            else:
                self.error_label.configure(text=f"Erreur envoi code: {msg}")
        else:
            # Login direct
            self._complete_login()
    
    # ==================== FORMULAIRE VERIFICATION EMAIL ====================
    
    def _show_email_verification(self):
        """Affiche le formulaire de vérification par email"""
        self._clear_content()
        self._step = "email_verification"
        
        # Icône
        ctk.CTkLabel(
            self.content_frame,
            text="�",
            font=ctk.CTkFont(size=36)
        ).pack(pady=(10, 5))
        
        ctk.CTkLabel(
            self.content_frame,
            text="Vérification par email",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=THEME["text"]
        ).pack()
        
        ctk.CTkLabel(
            self.content_frame,
            text=f"Un code de vérification a été envoyé à\n{self._current_email}",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"],
            justify="center"
        ).pack(pady=(5, 20))
        
        # Card
        card = ctk.CTkFrame(self.content_frame, fg_color=THEME["card"], corner_radius=12)
        card.pack(fill="x")
        
        ctk.CTkLabel(
            card,
            text="Code de vérification (6 chiffres)",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=20, pady=(20, 5))
        
        self.code_entry = ctk.CTkEntry(
            card,
            height=50,
            fg_color=THEME["input"],
            border_color=THEME["border"],
            border_width=1,
            placeholder_text="000000",
            font=ctk.CTkFont(size=24, weight="bold"),
            justify="center"
        )
        self.code_entry.pack(fill="x", padx=20)
        
        # Checkbox confiance
        self.trust_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            card,
            text="Mémoriser cet appareil (30 jours)",
            variable=self.trust_var,
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"],
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            checkbox_height=18,
            checkbox_width=18
        ).pack(anchor="w", padx=20, pady=(15, 5))
        
        # Message erreur
        self.error_label = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=THEME["error"]
        )
        self.error_label.pack(pady=(10, 5))
        
        # Boutons
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(5, 20))
        
        ctk.CTkButton(
            btn_frame,
            text="Renvoyer",
            width=100,
            height=38,
            fg_color=THEME["input"],
            hover_color=THEME["card_hover"],
            border_color=THEME["border"],
            border_width=1,
            text_color=THEME["text"],
            command=self._resend_code
        ).pack(side="left")
        
        ctk.CTkButton(
            btn_frame,
            text="Vérifier",
            height=38,
            fg_color=THEME["accent"],
            hover_color=THEME["accent_hover"],
            font=ctk.CTkFont(weight="bold"),
            command=self._verify_code
        ).pack(side="right", fill="x", expand=True, padx=(10, 0))
        
        # Retour
        ctk.CTkButton(
            self.content_frame,
            text="← Retour",
            fg_color="transparent",
            hover_color=THEME["card"],
            text_color=THEME["text_muted"],
            font=ctk.CTkFont(size=11),
            command=self._show_login
        ).pack(pady=(15, 0))
        
        # Bind Enter
        self.code_entry.bind("<Return>", lambda e: self._verify_code())
        self.code_entry.focus()
    
    def _resend_code(self):
        """Renvoie le code"""
        if self._user_id and self.auth:
            success, msg = self.auth.login_step2_send_code(self._user_id)
            if success:
                self.error_label.configure(text="✓ Code renvoyé", text_color=THEME["success"])
            else:
                self.error_label.configure(text=msg, text_color=THEME["error"])
    
    def _verify_code(self):
        """Vérifie le code de vérification email"""
        code = self.code_entry.get().strip()
        
        if not code or len(code) != 6 or not code.isdigit():
            self.error_label.configure(text="Code invalide (6 chiffres)", text_color=THEME["error"])
            return
        
        trust = self.trust_var.get()
        success, msg = self.auth.login_step2_verify_code(self._user_id, code, trust)
        
        if success:
            self._complete_login()
        else:
            self.error_label.configure(text=msg, text_color=THEME["error"])
    
    # ==================== COMPLETE LOGIN ====================
    
    def _complete_login(self, skip_password_check: bool = False):
        """Finalise la connexion"""
        success, msg, user = self.auth.complete_login(self._user_id)
        
        if not success:
            # Créer un label d'erreur si nécessaire
            if not hasattr(self, 'error_label') or self.error_label is None:
                print(f"[!] Erreur login: {msg}")
            else:
                self.error_label.configure(text=msg)
            return
        
        # Changement de mot de passe requis ? (sauf si on vient de le changer)
        if not skip_password_check and user.get("must_change_password"):
            self._show_change_password()
            return
        
        # Succès !
        print(f"[+] Connexion réussie: {user.get('username', 'N/A')}")
        if self.on_success:
            self.on_success(user)
        self.root.quit()
        self.root.destroy()
    
    # ==================== CHANGE PASSWORD ====================
    
    def _show_change_password(self):
        """Formulaire de changement de mot de passe"""
        self._clear_content()
        self._step = "change_password"
        
        ctk.CTkLabel(
            self.content_frame,
            text="🔑",
            font=ctk.CTkFont(size=36)
        ).pack(pady=(10, 5))
        
        ctk.CTkLabel(
            self.content_frame,
            text="Nouveau mot de passe requis",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=THEME["warning"]
        ).pack()
        
        ctk.CTkLabel(
            self.content_frame,
            text="Vous devez définir un nouveau mot de passe",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        ).pack(pady=(5, 20))
        
        # Card
        card = ctk.CTkFrame(self.content_frame, fg_color=THEME["card"], corner_radius=12)
        card.pack(fill="x")
        
        ctk.CTkLabel(card, text="Nouveau mot de passe", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        
        self.new_pass_entry = ctk.CTkEntry(card, height=42, fg_color=THEME["input"],
                                          border_color=THEME["border"], show="•")
        self.new_pass_entry.pack(fill="x", padx=20)
        
        ctk.CTkLabel(card, text="Confirmer", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        
        self.confirm_pass_entry = ctk.CTkEntry(card, height=42, fg_color=THEME["input"],
                                              border_color=THEME["border"], show="•")
        self.confirm_pass_entry.pack(fill="x", padx=20)
        
        # Info
        ctk.CTkLabel(card, text="Minimum 8 caractères", font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(anchor="w", padx=20, pady=(10, 0))
        
        self.error_label = ctk.CTkLabel(card, text="", font=ctk.CTkFont(size=11),
                                       text_color=THEME["error"])
        self.error_label.pack(pady=(10, 5))
        
        ctk.CTkButton(card, text="Enregistrer", height=42, fg_color=THEME["accent"],
                     hover_color=THEME["accent_hover"], font=ctk.CTkFont(weight="bold"),
                     command=self._do_change_password).pack(fill="x", padx=20, pady=(5, 20))
    
    def _do_change_password(self):
        """Change le mot de passe"""
        new_pass = self.new_pass_entry.get()
        confirm = self.confirm_pass_entry.get()
        
        if len(new_pass) < 8:
            self.error_label.configure(text="Minimum 8 caractères")
            return
        
        if new_pass != confirm:
            self.error_label.configure(text="Les mots de passe ne correspondent pas")
            return
        
        success, msg = self.auth.force_change_password(self._user_id, new_pass)
        
        if success:
            # Skip la vérification de must_change_password car on vient de le changer
            self._complete_login(skip_password_check=True)
        else:
            self.error_label.configure(text=msg)
    
    # ==================== FORGOT PASSWORD ====================
    
    def _show_forgot(self):
        """Formulaire mot de passe oublié"""
        self._clear_content()
        self._step = "forgot"
        
        ctk.CTkLabel(
            self.content_frame,
            text="📧",
            font=ctk.CTkFont(size=36)
        ).pack(pady=(10, 5))
        
        ctk.CTkLabel(
            self.content_frame,
            text="Mot de passe oublié",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=THEME["text"]
        ).pack()
        
        ctk.CTkLabel(
            self.content_frame,
            text="Entrez votre email pour recevoir\nun mot de passe temporaire",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"],
            justify="center"
        ).pack(pady=(5, 20))
        
        # Card
        card = ctk.CTkFrame(self.content_frame, fg_color=THEME["card"], corner_radius=12)
        card.pack(fill="x")
        
        ctk.CTkLabel(card, text="Email", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        
        self.forgot_email_entry = ctk.CTkEntry(card, height=42, fg_color=THEME["input"],
                                              border_color=THEME["border"],
                                              placeholder_text="votre@email.com")
        self.forgot_email_entry.pack(fill="x", padx=20)
        
        self.forgot_message = ctk.CTkLabel(card, text="", font=ctk.CTkFont(size=11))
        self.forgot_message.pack(pady=(15, 5))
        
        ctk.CTkButton(card, text="Envoyer", height=42, fg_color=THEME["accent"],
                     hover_color=THEME["accent_hover"], font=ctk.CTkFont(weight="bold"),
                     command=self._do_forgot).pack(fill="x", padx=20, pady=(5, 20))
        
        # Retour
        ctk.CTkButton(
            self.content_frame,
            text="← Retour à la connexion",
            fg_color="transparent",
            hover_color=THEME["card"],
            text_color=THEME["text_muted"],
            font=ctk.CTkFont(size=11),
            command=self._show_login
        ).pack(pady=(15, 0))
    
    def _do_forgot(self):
        """Envoie le mot de passe temporaire"""
        email = self.forgot_email_entry.get().strip()
        
        if not email:
            self.forgot_message.configure(text="Entrez votre email", text_color=THEME["error"])
            return
        
        success, msg = self.auth.forgot_password(email)
        
        if success:
            self.forgot_message.configure(text="✓ Email envoyé si le compte existe", text_color=THEME["success"])
        else:
            self.forgot_message.configure(text=msg, text_color=THEME["error"])
    
    # ==================== REGISTER ====================
    
    def _show_register(self):
        """Formulaire d'inscription"""
        self._clear_content()
        self._step = "register"
        
        # Ajuster la taille de la fenêtre
        self.root.geometry("420x600")
        
        ctk.CTkLabel(
            self.content_frame,
            text="📝 Créer un compte",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=THEME["text"]
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            self.content_frame,
            text="Votre demande sera validée par un administrateur",
            font=ctk.CTkFont(size=10),
            text_color=THEME["warning"]
        ).pack(pady=(0, 15))
        
        # Card
        card = ctk.CTkFrame(self.content_frame, fg_color=THEME["card"], corner_radius=12)
        card.pack(fill="both", expand=True)
        
        # Identifiant
        ctk.CTkLabel(card, text="Identifiant", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        self.reg_username = ctk.CTkEntry(card, height=40, fg_color=THEME["input"],
                                        border_color=THEME["border"], placeholder_text="votre_identifiant")
        self.reg_username.pack(fill="x", padx=20)
        
        # Email
        ctk.CTkLabel(card, text="Email (pour récupération)", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        self.reg_email = ctk.CTkEntry(card, height=40, fg_color=THEME["input"],
                                     border_color=THEME["border"], placeholder_text="votre@email.com")
        self.reg_email.pack(fill="x", padx=20)
        
        # Password
        ctk.CTkLabel(card, text="Mot de passe", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        self.reg_password = ctk.CTkEntry(card, height=40, fg_color=THEME["input"],
                                        border_color=THEME["border"], show="•",
                                        placeholder_text="Minimum 8 caractères")
        self.reg_password.pack(fill="x", padx=20)
        
        # Confirm
        ctk.CTkLabel(card, text="Confirmer le mot de passe", font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        self.reg_confirm = ctk.CTkEntry(card, height=40, fg_color=THEME["input"],
                                       border_color=THEME["border"], show="•")
        self.reg_confirm.pack(fill="x", padx=20)
        
        # Message
        self.reg_message = ctk.CTkLabel(card, text="", font=ctk.CTkFont(size=11), wraplength=300)
        self.reg_message.pack(pady=(15, 5))
        
        # Bouton Soumettre
        ctk.CTkButton(card, text="Soumettre la demande", height=42, fg_color=THEME["accent"],
                     hover_color=THEME["accent_hover"], font=ctk.CTkFont(size=13, weight="bold"),
                     command=self._do_register).pack(fill="x", padx=20, pady=(5, 20))
        
        # Retour
        ctk.CTkButton(
            self.content_frame,
            text="← Retour à la connexion",
            fg_color="transparent",
            hover_color=THEME["card"],
            text_color=THEME["text_muted"],
            font=ctk.CTkFont(size=11),
            command=lambda: [self.root.geometry("420x600"), self._show_login()]
        ).pack(pady=(15, 0))
    
    def _do_register(self):
        """Soumet la demande d'inscription"""
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        
        if not username:
            self.reg_message.configure(text="Identifiant requis", text_color=THEME["error"])
            return
        
        if len(username) < 3:
            self.reg_message.configure(text="Identifiant trop court (min 3 caractères)", text_color=THEME["error"])
            return
        
        if not email or "@" not in email:
            self.reg_message.configure(text="Email invalide", text_color=THEME["error"])
            return
        
        if len(password) < 8:
            self.reg_message.configure(text="Mot de passe trop court (min 8 caractères)", text_color=THEME["error"])
            return
        
        if password != confirm:
            self.reg_message.configure(text="Les mots de passe ne correspondent pas", text_color=THEME["error"])
            return
        
        # Enregistrement
        success, msg = self.auth.register(username, password, email)
        
        if success:
            self.reg_message.configure(text="✓ Demande soumise !\nEn attente de validation par un admin.", text_color=THEME["success"])
            # Vider les champs
            self.reg_username.delete(0, "end")
            self.reg_email.delete(0, "end")
            self.reg_password.delete(0, "end")
            self.reg_confirm.delete(0, "end")
        else:
            self.reg_message.configure(text=msg, text_color=THEME["error"])
    
    def run(self):
        """Lance la fenêtre de login"""
        self.root.mainloop()


def run_secure_login(on_success: Callable[[Dict], None] = None) -> Optional[Dict]:
    """Lance le login sécurisé et retourne les données utilisateur"""
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")
    
    user_data = [None]
    
    def on_login_success(user):
        user_data[0] = user
        # Appeler aussi le callback externe si fourni
        if on_success:
            on_success(user)
    
    login = SecureLoginWindow(on_success=on_login_success)
    login.run()
    
    return user_data[0]


# =============================================================================
# PANNEAU DE GESTION DES TICKETS (pour l'admin)
# =============================================================================

class TicketManagementPanel(ctk.CTkFrame):
    """Panneau de gestion des demandes d'inscription"""
    
    def __init__(self, parent, auth_manager=None, **kwargs):
        super().__init__(parent, fg_color=THEME["card"], corner_radius=12, **kwargs)
        
        self.auth = auth_manager or (get_secure_auth_manager() if AUTH_AVAILABLE else None)
        self._build_ui()
    
    def _build_ui(self):
        """Construit l'interface"""
        # Titre
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 10))
        
        ctk.CTkLabel(
            header,
            text="📋 Demandes d'inscription",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=THEME["text"]
        ).pack(side="left")
        
        ctk.CTkButton(
            header,
            text="🔄 Actualiser",
            width=100,
            height=30,
            fg_color=THEME["input"],
            hover_color=THEME["card_hover"],
            font=ctk.CTkFont(size=11),
            command=self.refresh
        ).pack(side="right")
        
        # Container pour les tickets avec scroll
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            scrollbar_button_color=THEME["border"],
            scrollbar_button_hover_color=THEME["text_muted"]
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Message si vide
        self.empty_label = ctk.CTkLabel(
            self.scroll_frame,
            text="Aucune demande en attente",
            font=ctk.CTkFont(size=12),
            text_color=THEME["text_muted"]
        )
        
        # Charger les tickets
        self.refresh()
    
    def refresh(self):
        """Rafraîchit la liste des tickets"""
        # Vider le contenu
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        
        if not self.auth:
            ctk.CTkLabel(
                self.scroll_frame,
                text="Service d'authentification non disponible",
                text_color=THEME["error"]
            ).pack(pady=20)
            return
        
        # Récupérer les tickets
        tickets = self.auth.get_pending_tickets()
        
        if not tickets:
            self.empty_label = ctk.CTkLabel(
                self.scroll_frame,
                text="✓ Aucune demande en attente",
                font=ctk.CTkFont(size=12),
                text_color=THEME["text_muted"]
            )
            self.empty_label.pack(pady=30)
            return
        
        # Afficher chaque ticket
        for ticket in tickets:
            self._create_ticket_card(ticket)
    
    def _create_ticket_card(self, ticket: Dict):
        """Crée une carte pour un ticket"""
        card = ctk.CTkFrame(self.scroll_frame, fg_color=THEME["input"], corner_radius=8)
        card.pack(fill="x", pady=5, padx=5)
        
        # Info utilisateur
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(fill="x", padx=15, pady=(12, 8))
        
        # Nom complet
        ctk.CTkLabel(
            info_frame,
            text=f"{ticket.get('first_name', '')} {ticket.get('last_name', '')}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=THEME["text"]
        ).pack(anchor="w")
        
        # Username
        ctk.CTkLabel(
            info_frame,
            text=f"@{ticket.get('username', 'N/A')}",
            font=ctk.CTkFont(size=11),
            text_color=THEME["accent"]
        ).pack(anchor="w")
        
        # Email
        email = ticket.get('email', '')
        if email:
            ctk.CTkLabel(
                info_frame,
                text=f"📧 {email}",
                font=ctk.CTkFont(size=10),
                text_color=THEME["text_secondary"]
            ).pack(anchor="w", pady=(3, 0))
        
        # Date
        created = str(ticket.get('created_at', ''))
        if len(created) > 16: created = created[:16].replace('T', ' ')
        ctk.CTkLabel(
            info_frame,
            text=f"📅 {created}",
            font=ctk.CTkFont(size=10),
            text_color=THEME["text_muted"]
        ).pack(anchor="w", pady=(2, 0))
        
        # Boutons d'action
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(5, 12))
        
        # Bouton Approuver
        ctk.CTkButton(
            btn_frame,
            text="✓ Approuver",
            width=100,
            height=32,
            fg_color=THEME["success"],
            hover_color="#2ea043",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda t=ticket: self._approve_ticket(t)
        ).pack(side="left", padx=(0, 8))
        
        # Bouton Refuser
        ctk.CTkButton(
            btn_frame,
            text="✗ Refuser",
            width=100,
            height=32,
            fg_color=THEME["error"],
            hover_color="#da3633",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda t=ticket: self._reject_ticket(t)
        ).pack(side="left")
    
    def _approve_ticket(self, ticket: Dict):
        """Approuve un ticket"""
        if not self.auth:
            return
        
        # Récupérer l'ID admin actuel
        admin_id = None
        if hasattr(self.auth, 'current_user') and self.auth.current_user:
            admin_id = self.auth.current_user.get('id')
        
        success, msg = self.auth.approve_ticket(
            ticket_id=ticket['id'],
            admin_id=admin_id or "admin",
            role="user",
            permissions=["read"]
        )
        
        if success:
            print(f"[+] Ticket approuvé: {ticket.get('username')}")
        else:
            print(f"[!] Erreur approbation: {msg}")
        
        self.refresh()
    
    def _reject_ticket(self, ticket: Dict):
        """Refuse un ticket avec dialogue de raison"""
        if not self.auth:
            return
        
        # Créer une fenêtre de dialogue
        dialog = ctk.CTkToplevel(self)
        dialog.title("Refuser la demande")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.configure(fg_color=THEME["bg"])
        
        # Centrer
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 400) // 2
        y = (dialog.winfo_screenheight() - 250) // 2
        dialog.geometry(f"+{x}+{y}")
        
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        
        # Contenu
        ctk.CTkLabel(
            dialog,
            text=f"Refuser la demande de\n{ticket.get('first_name')} {ticket.get('last_name')} (@{ticket.get('username')})",
            font=ctk.CTkFont(size=12),
            text_color=THEME["text"]
        ).pack(pady=(20, 15))
        
        ctk.CTkLabel(
            dialog,
            text="Raison du refus (optionnel):",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_secondary"]
        ).pack(anchor="w", padx=20)
        
        reason_entry = ctk.CTkTextbox(
            dialog,
            height=60,
            fg_color=THEME["input"],
            border_color=THEME["border"],
            border_width=1
        )
        reason_entry.pack(fill="x", padx=20, pady=(5, 15))
        
        # Boutons
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        def do_reject():
            reason = reason_entry.get("1.0", "end").strip()
            admin_id = None
            if hasattr(self.auth, 'current_user') and self.auth.current_user:
                admin_id = self.auth.current_user.get('id')
            
            success, msg = self.auth.reject_ticket(
                ticket_id=ticket['id'],
                admin_id=admin_id or "admin",
                reason=reason if reason else None
            )
            
            if success:
                print(f"[+] Ticket refusé: {ticket.get('username')}")
            else:
                print(f"[!] Erreur refus: {msg}")
            
            dialog.destroy()
            self.refresh()
        
        ctk.CTkButton(
            btn_frame,
            text="Annuler",
            width=100,
            fg_color=THEME["input"],
            hover_color=THEME["card_hover"],
            command=dialog.destroy
        ).pack(side="left")
        
        ctk.CTkButton(
            btn_frame,
            text="Confirmer le refus",
            width=140,
            fg_color=THEME["error"],
            hover_color="#da3633",
            command=do_reject
        ).pack(side="right")



class UserListPanel(ctk.CTkFrame):
    """Panneau de liste des utilisateurs"""
    
    def __init__(self, parent, auth_manager=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.auth = auth_manager or (get_secure_auth_manager() if AUTH_AVAILABLE else None)
        self._build_ui()
        
    def _build_ui(self):
        """Construit l'interface (Tableau style phpMyAdmin)"""
        # Header (Titre + Refresh)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 10))
        
        ctk.CTkLabel(
            header,
            text="Utilisateurs actifs",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=THEME["text"]
        ).pack(side="left")
        
        ctk.CTkButton(
            header,
            text="Rafraîchir",
            width=80,
            height=25,
            fg_color=THEME["input"],
            hover_color=THEME["card_hover"],
            font=ctk.CTkFont(size=11),
            command=self.refresh
        ).pack(side="right")
        
        # Container avec Scrollbar pour le tableau
        self.users_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent"
        )
        self.users_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Configuration de la grille
        self.users_scroll.grid_columnconfigure(0, weight=2) # Nom (plus large)
        self.users_scroll.grid_columnconfigure(1, weight=1) # Rôle
        self.users_scroll.grid_columnconfigure(2, weight=2) # Nom complet
        self.users_scroll.grid_columnconfigure(3, weight=2) # Last Login
        self.users_scroll.grid_columnconfigure(4, weight=1) # Statut
        self.users_scroll.grid_columnconfigure(5, weight=2) # Actions
        
        self.refresh()
    
    def refresh(self):
        """Rafraîchit la liste des utilisateurs"""
        for widget in self.users_scroll.winfo_children():
            widget.destroy()
        
        # En-têtes (Row 0)
        headers = ["Identifiant", "Rôle", "Nom complet", "Dernière connexion", "Statut", "Actions"]
        for i, h in enumerate(headers):
            # Petit fond pour l'en-tête
            header_bg = ctk.CTkFrame(self.users_scroll, fg_color=THEME["card"], corner_radius=4, height=35)
            header_bg.grid(row=0, column=i, padx=1, pady=1, sticky="nsew")
            
            ctk.CTkLabel(
                header_bg, 
                text=h, 
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=THEME["text_secondary"]
            ).place(relx=0.5, rely=0.5, anchor="center")
            
        if not self.auth:
            return
        
        users = self.auth.get_all_users()
        
        for idx, user in enumerate(users, start=1):
            self._create_user_row(user, idx)
    
    def _create_user_row(self, user: Dict, row_idx: int):
        """Crée une ligne pour un utilisateur (Row Table)"""
        # Couleur alternée pour la lisibilité
        bg_color = THEME["input"] if row_idx % 2 == 0 else "transparent"
        if bg_color == "transparent": bg_color = THEME["bg_secondary"] # Ou un gris très sombre
        
        # Créer un fond unique pour la ligne? Difficile avec grid cell par cell.
        # On met un Frame dans chaque cellule pour "simuler" la ligne ou juste le Label.
        # Pour faire "propre", on met un Frame par cellule qui remplit tout.
        
        # 0. Username
        cell0 = ctk.CTkFrame(self.users_scroll, fg_color=bg_color, corner_radius=0)
        cell0.grid(row=row_idx, column=0, sticky="nsew", padx=1, pady=1)
        ctk.CTkLabel(cell0, text=f"@{user.get('username', 'N/A')}", font=ctk.CTkFont(size=12, weight="bold")).pack(expand=True, pady=8)
        
        # 1. Role
        cell1 = ctk.CTkFrame(self.users_scroll, fg_color=bg_color, corner_radius=0)
        cell1.grid(row=row_idx, column=1, sticky="nsew", padx=1, pady=1)
        role = user.get('role', 'user')
        role_color = THEME["warning"] if role == "admin" else THEME["text"]
        ctk.CTkLabel(cell1, text=role, text_color=role_color, font=ctk.CTkFont(size=11)).pack(expand=True)
        
        # 2. Full Name
        cell2 = ctk.CTkFrame(self.users_scroll, fg_color=bg_color, corner_radius=0)
        cell2.grid(row=row_idx, column=2, sticky="nsew", padx=1, pady=1)
        full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}"
        ctk.CTkLabel(cell2, text=full_name, font=ctk.CTkFont(size=11)).pack(expand=True)
        
        # 3. Last Login
        cell3 = ctk.CTkFrame(self.users_scroll, fg_color=bg_color, corner_radius=0)
        cell3.grid(row=row_idx, column=3, sticky="nsew", padx=1, pady=1)
        # Convertir en string avant de manipuler.
        last_login = str(user.get('last_login') or "Jamais")
        if len(last_login) > 16: last_login = last_login[:16].replace('T', ' ')
        ctk.CTkLabel(cell3, text=last_login, font=ctk.CTkFont(size=11), text_color=THEME["text_muted"]).pack(expand=True)
        
        # 4. Status
        cell4 = ctk.CTkFrame(self.users_scroll, fg_color=bg_color, corner_radius=0)
        cell4.grid(row=row_idx, column=4, sticky="nsew", padx=1, pady=1)
        status = user.get('status', 'active')
        status_text = "Actif" if status == 'active' else "Bloqué"
        status_color = THEME["success"] if status == 'active' else THEME["error"]
        ctk.CTkLabel(cell4, text=status_text, text_color=status_color, font=ctk.CTkFont(size=11, weight="bold")).pack(expand=True)
        
        # 5. Actions
        cell5 = ctk.CTkFrame(self.users_scroll, fg_color=bg_color, corner_radius=0)
        cell5.grid(row=row_idx, column=5, sticky="nsew", padx=1, pady=1)
        
        current_id = None
        if self.auth and self.auth.current_user:
            current_id = self.auth.current_user.get('id')
            
        if user['id'] != current_id:
            # Block/Unblock
            is_active = (status == 'active')
            act_text = "Bloquer" if is_active else "Débloquer"
            act_color = THEME["text_muted"] if is_active else THEME["success"]
            
            ctk.CTkButton(
                cell5, 
                text=act_text,
                width=60, 
                height=22,
                font=ctk.CTkFont(size=10),
                fg_color="transparent",
                border_width=1,
                border_color=act_color,
                text_color=act_color,
                hover_color=THEME.get("bg_hover", "#21262d"),
                command=lambda u=user: self._toggle_status(u)
            ).pack(side="left", padx=5, expand=True)
            
            # Supprimer
            ctk.CTkButton(
                cell5, 
                text="Supprimer",
                width=60, 
                height=22,
                font=ctk.CTkFont(size=10),
                fg_color="transparent",
                border_width=1,
                border_color=THEME["error"],
                text_color=THEME["error"],
                hover_color=THEME.get("bg_hover", "#21262d"),
                command=lambda u=user: self._delete_user(u)
            ).pack(side="left", padx=5, expand=True)
    
    def _toggle_status(self, user: Dict):
        """Active/Désactive un utilisateur"""
        if not self.auth: return
        
        new_status = 'disabled' if user.get('status') == 'active' else 'active'
        success, msg = self.auth.update_user(user['id'], status=new_status)
        
        if success:
            print(f"[+] Status {user['username']} -> {new_status}")
            self.refresh()
        else:
            print(f"[!] Erreur: {msg}")
            
    def _delete_user(self, user: Dict):
        """Supprime un utilisateur avec confirmation"""
        if not self.auth: return
        
        # Petit dialog de confirmation rapide
        dialog = ctk.CTkToplevel(self)
        dialog.title("Confirmation")
        dialog.geometry("300x150")
        dialog.transient(self.winfo_toplevel())
        
        # Center
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 300) // 2
        y = (dialog.winfo_screenheight() - 150) // 2
        dialog.geometry(f"+{x}+{y}")
        
        ctk.CTkLabel(dialog, text=f"Supprimer @{user['username']} ?", 
                    font=ctk.CTkFont(weight="bold")).pack(pady=20)
                    
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=10)
        
        def do_delete():
            success, msg = self.auth.delete_user(user['id'])
            if success:
                print(f"[+] Utilisateur supprimé: {user['username']}")
                self.refresh()
            else:
                print(f"[!] Erreur suppression: {msg}")
            dialog.destroy()
            
        ctk.CTkButton(btn_frame, text="Oui, supprimer", fg_color=THEME["error"], 
                     width=100, command=do_delete).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Annuler", fg_color=THEME["input"], 
                     width=100, command=dialog.destroy).pack(side="right", padx=5)


class SecureUserManagementPanel(ctk.CTkFrame):
    """Panneau combiné : Tickets + Utilisateurs existants"""
    
    def __init__(self, parent, auth_manager=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        
        self.auth = auth_manager or (get_secure_auth_manager() if AUTH_AVAILABLE else None)
        self._build_ui()
    
    def _build_ui(self):
        """Construit l'interface avec tabs"""
        # Tabs
        self.tabview = ctk.CTkTabview(self, fg_color=THEME["card"])
        self.tabview.pack(fill="both", expand=True)
        
        # Tab Tickets
        tickets_tab = self.tabview.add("📋 Demandes")
        self.ticket_panel = TicketManagementPanel(tickets_tab, auth_manager=self.auth)
        self.ticket_panel.pack(fill="both", expand=True)
        
        # Tab Utilisateurs
        users_tab = self.tabview.add("👥 Utilisateurs")
        self.user_panel = UserListPanel(users_tab, auth_manager=self.auth)
        self.user_panel.pack(fill="both", expand=True)
    
    def refresh(self):
        """Rafraîchit tout"""
        if hasattr(self, 'ticket_panel'):
            self.ticket_panel.refresh()
        if hasattr(self, 'user_panel'):
            self.user_panel.refresh()


# Test standalone
if __name__ == "__main__":
    def on_success(user):
        print(f"\n✅ Connexion réussie !")
        print(f"   Utilisateur: {user['full_name']}")
        print(f"   Email: {user['email']}")
        print(f"   Rôle: {user['role']}")
    
    user = run_secure_login(on_success)
    
    if user:
        print("\nUtilisateur connecté:", user)
    else:
        print("\nConnexion annulée")
