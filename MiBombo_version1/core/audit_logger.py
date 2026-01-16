"""
MiBombo - Audit Logger
=======================
Logging détaillé de toutes les requêtes API pour audit de sécurité.
"""

import logging
from datetime import datetime
from flask import g
import os

class AuditLogger:
    """Logger d'audit pour l'API"""
    
    def __init__(self, log_dir="data/logs"):
        self.logger = logging.getLogger("API.Audit")
        self.logger.setLevel(logging.INFO)
        
        # Créer le répertoire si nécessaire
        os.makedirs(log_dir, exist_ok=True)
        
        # Handler fichier
        log_file = os.path.join(log_dir, "api_audit.log")
        handler = logging.FileHandler(log_file)
        handler.setLevel(logging.INFO)
        
        # Format détaillé
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def log_request(self, endpoint, ip, method, status, duration_ms, user_agent=None):
        """Log une requête API"""
        msg = f"{ip} | {method} {endpoint} | {status} | {duration_ms:.2f}ms"
        if user_agent:
            msg += f" | {user_agent}"
        
        if status >= 400:
            self.logger.warning(msg)
        else:
            self.logger.info(msg)
    
    def log_suspicious(self, ip, reason, details=None):
        """Log une activité suspecte"""
        msg = f"[SUSPICIOUS] {ip} | {reason}"
        if details:
            msg += f" | {details}"
        self.logger.warning(msg)
    
    def log_blocked(self, ip, reason):
        """Log un blocage d'IP"""
        self.logger.error(f"[BLOCKED] {ip} | {reason}")
    
    def log_error(self, endpoint, ip, error):
        """Log une erreur serveur"""
        self.logger.error(f"[ERROR] {ip} | {endpoint} | {error}")

# Instance globale
audit_logger = AuditLogger()
