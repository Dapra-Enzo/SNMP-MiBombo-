"""
MiBombo - Rate Limiter
======================
Limite le nombre de requêtes par IP et par endpoint pour prévenir les abus.
"""

from functools import wraps
from collections import defaultdict
from time import time
from flask import request, jsonify

class RateLimiter:
    """Rate limiter basé sur la mémoire avec fenêtre glissante"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked_ips = {}  # IP -> timestamp de déblocage
    
    def is_allowed(self, key, limit=100, window=60):
        """
        Vérifie si une requête est autorisée
        
        Args:
            key: Identifiant unique (IP:endpoint)
            limit: Nombre max de requêtes
            window: Fenêtre de temps en secondes
        
        Returns:
            bool: True si autorisé, False sinon
        """
        now = time()
        
        # Nettoyer les anciennes requêtes
        self.requests[key] = [t for t in self.requests[key] if now - t < window]
        
        # Vérifier la limite
        if len(self.requests[key]) >= limit:
            return False
        
        # Enregistrer la requête
        self.requests[key].append(now)
        return True
    
    def block_ip(self, ip, duration=3600):
        """Bloque une IP pour une durée donnée"""
        self.blocked_ips[ip] = time() + duration
    
    def is_blocked(self, ip):
        """Vérifie si une IP est bloquée"""
        if ip not in self.blocked_ips:
            return False
        
        if time() > self.blocked_ips[ip]:
            del self.blocked_ips[ip]
            return False
        
        return True
    
    def cleanup(self):
        """Nettoie les anciennes entrées (à appeler périodiquement)"""
        now = time()
        
        # Nettoyer les requêtes anciennes
        for key in list(self.requests.keys()):
            self.requests[key] = [t for t in self.requests[key] if now - t < 3600]
            if not self.requests[key]:
                del self.requests[key]
        
        # Nettoyer les IPs débloquées
        for ip in list(self.blocked_ips.keys()):
            if now > self.blocked_ips[ip]:
                del self.blocked_ips[ip]

# Instance globale
limiter = RateLimiter()

def rate_limit(limit=100, window=60):
    """
    Décorateur pour limiter le taux de requêtes
    
    Usage:
        @app.route('/api/endpoint')
        @rate_limit(limit=10, window=60)
        def my_endpoint():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            
            # Vérifier si IP bloquée
            if limiter.is_blocked(ip):
                return jsonify({
                    "error": "IP blocked",
                    "message": "Too many violations. Try again later."
                }), 403
            
            # Vérifier le rate limit
            key = f"{ip}:{f.__name__}"
            if not limiter.is_allowed(key, limit, window):
                return jsonify({
                    "error": "Rate limit exceeded",
                    "message": f"Max {limit} requests per {window}s"
                }), 429
            
            return f(*args, **kwargs)
        return wrapped
    return decorator
