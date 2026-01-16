#!/usr/bin/env python3
"""
Gestion des identifiants SNMPv3 (Backend Sécurisé)
Stockage chiffré des utilisateurs et clés pour le déchiffrement.
"""

import os
import json
import logging
from typing import Dict, List, Optional
from cryptography.fernet import Fernet

# Charger les variables d'environnement depuis .env
try:
    from dotenv import load_dotenv
    if os.path.exists('.env'):
        load_dotenv('.env')
    elif os.path.exists('/etc/mibombo/.env'):
        load_dotenv('/etc/mibombo/.env')
except ImportError:
    pass  # dotenv non installé, on utilise les vars système

# Configuration
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
CREDENTIALS_FILE = os.path.join(DATA_DIR, "snmp_users.enc")

class SNMPCredentialManager:
    """Gestionnaire sécurisé des credentials SNMPv3"""
    
    def __init__(self):
        self.key = self._load_key()
        self.cipher = Fernet(self.key) if self.key else None
        self.users = {}
        self._load()

    def _load_key(self) -> Optional[bytes]:
        """Charge la clé de chiffrement. Génère automatiquement si manquante."""
        # On essaie d'abord ENCRYPTION_KEY
        key = os.getenv("ENCRYPTION_KEY") or os.getenv("SNIFFER_KEY")
        
        # Validation basique
        if key:
            try:
                Fernet(key) # Test validité
                return key.encode()
            except Exception:
                logging.warning("⚠️ Clé existante invalide. Regénération...")
        
        # Génération automatique
        logging.info("🔧 Génération d'une nouvelle clé de chiffrement...")
        new_key = Fernet.generate_key().decode()
        
        # Sauvegarde dans .env
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        try:
            # Lecture .env existant
            lines = []
            if os.path.exists(env_path):
                with open(env_path, "r") as f:
                    lines = f.readlines()
            
            # Suppression ancienne clé si présente
            lines = [l for l in lines if not l.startswith("ENCRYPTION_KEY=")]
            
            # Ajout nouvelle clé
            if lines and not lines[-1].endswith("\n"):
                lines.append("\n")
            lines.append(f"ENCRYPTION_KEY={new_key}\n")
            
            # Ecriture
            with open(env_path, "w") as f:
                f.writelines(lines)
                
            logging.info(f"✅ Nouvelle clé sauvegardée dans {env_path}")
            
            # Mise à jour env courant
            os.environ["ENCRYPTION_KEY"] = new_key
            return new_key.encode()
            
        except Exception as e:
            logging.error(f"❌ Impossible de sauvegarder la clé: {e}")
            return None

    def _load(self):
        """Charge et déchiffre les utilisateurs"""
        if not self.cipher:
            logging.warning("[SNMPv3] Chiffrement non disponible, credentials vides.")
            return
            
        if not os.path.exists(CREDENTIALS_FILE):
            logging.info("[SNMPv3] Aucun fichier de credentials trouvé, initialisation vide.")
            self.users = {}
            return

        try:
            with open(CREDENTIALS_FILE, "rb") as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                logging.warning("[SNMPv3] Fichier credentials vide.")
                self.users = {}
                return
                
            decrypted_data = self.cipher.decrypt(encrypted_data)
            self.users = json.loads(decrypted_data.decode())
            logging.info(f"[SNMPv3] ✅ {len(self.users)} utilisateur(s) chargé(s) depuis {CREDENTIALS_FILE}")
        except Exception as e:
            logging.error(f"[SNMPv3] Erreur chargement credentials: {e}")
            self.users = {}

    def _save(self):
        """Chiffre et sauvegarde les utilisateurs"""
        if not self.cipher:
            raise ValueError("Chiffrement non disponible (Clé manquante)")
            
        os.makedirs(DATA_DIR, exist_ok=True)
        
        try:
            data_str = json.dumps(self.users)
            encrypted_data = self.cipher.encrypt(data_str.encode())
            
            with open(CREDENTIALS_FILE, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            logging.error(f"Erreur sauvegarde credentials SNMPv3: {e}")
            raise

    def add_user(self, username: str, 
                 auth_proto: str = "SHA", auth_key: str = None, 
                 priv_proto: str = "AES", priv_key: str = None):
        """Ajoute ou met à jour un utilisateur SNMPv3"""
        is_update = username in self.users
        self.users[username] = {
            "username": username,
            "auth_proto": auth_proto,  # MD5, SHA
            "auth_key": auth_key,
            "priv_proto": priv_proto,  # DES, AES
            "priv_key": priv_key
        }
        self._save()
        action = "modifié" if is_update else "ajouté"
        msg = f"[SNMPv3] ✅ Utilisateur '{username}' {action} (Auth: {auth_proto}, Priv: {priv_proto})"
        print(msg)
        logging.info(msg)

    def get_user(self, username: str) -> Optional[Dict]:
        """Récupère les infos d'un utilisateur (clés en clair)"""
        return self.users.get(username)

    def delete_user(self, username: str):
        """Supprime un utilisateur"""
        if username in self.users:
            del self.users[username]
            self._save()
            msg = f"[SNMPv3] 🗑️ Utilisateur '{username}' supprimé"
            print(msg)
            logging.info(msg)
        else:
            msg = f"[SNMPv3] ⚠️ Utilisateur '{username}' non trouvé (suppression ignorée)"
            print(msg)
            logging.warning(msg)

    def get_all_users(self) -> List[Dict]:
        """Liste tous les utilisateurs"""
        return list(self.users.values())

# Instance globale
snmp_cred_mgr = SNMPCredentialManager()
