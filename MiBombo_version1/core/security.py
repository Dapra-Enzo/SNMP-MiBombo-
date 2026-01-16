
import time
from functools import wraps
from flask import request, jsonify
import re

# Simple in-memory rate limiter
# IP -> {endpoint -> [timestamps]}
_limiter_storage = {}

def rate_limit(limit=10, window=60):
    """
    Décorateur pour limiter le nombre de requêtes par IP.
    :param limit: Nombre max de requêtes
    :param window: Fenêtre de temps en secondes
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            endpoint = request.endpoint
            
            current_time = time.time()
            
            if ip not in _limiter_storage:
                _limiter_storage[ip] = {}
            if endpoint not in _limiter_storage[ip]:
                _limiter_storage[ip][endpoint] = []
            
            # Nettoyer les anciens timestamps
            _limiter_storage[ip][endpoint] = [t for t in _limiter_storage[ip][endpoint] if current_time - t < window]
            
            if len(_limiter_storage[ip][endpoint]) >= limit:
                return jsonify({
                    "success": False, 
                    "error": "Trop de requêtes. Veuillez patienter."
                }), 429
            
            _limiter_storage[ip][endpoint].append(current_time)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

def validate_input(data, rules):
    """
    Valide les données d'entrée selon des règles.
    rules = {"field": {"type": str, "min": 3, "regex": r"..."}}
    Returns: (is_valid, error_message)
    """
    if not data:
        return False, "Aucune donnée fournie"
        
    for field, rule in rules.items():
        value = data.get(field)
        
        # Check required
        if rule.get("required", True) and not value:
            return False, f"Champ requis manquant : {field}"
            
        if value:
            # Check type
            expected_type = rule.get("type")
            if expected_type and not isinstance(value, expected_type):
                return False, f"Type invalide pour {field}"
            
            # Check min length
            if "min" in rule and len(str(value)) < rule["min"]:
                return False, f"{field} trop court (min {rule['min']})"
            
            # Check max length
            if "max" in rule and len(str(value)) > rule["max"]:
                return False, f"{field} trop long (max {rule['max']})"
                
            # Check regex
            if "regex" in rule and isinstance(value, str):
                if not re.match(rule["regex"], value):
                    return False, f"Format invalide pour {field}"
                    
    return True, None

def sanitize_string(s):
    """Nettoie une chaîne de caractères (base SQL injection prevent, XSS)."""
    if not isinstance(s, str):
        return s
    # Simple whitelist chars logic could be here, but for now allow typical chars
    # Just basic HTML escape maybe? Flask does it in templates. 
    # For logic, we mainly care about SQL (handled by parameterized queries in SQLiteDB/Auth)
    return s.strip()
