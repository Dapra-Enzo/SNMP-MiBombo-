"""
MiBombo - Input Validators
===========================
Validation des inputs pour tous les endpoints de l'API.
"""

from functools import wraps
from flask import request, jsonify
import re
from datetime import datetime

def is_valid_ipv4(ip):
    """Valide une adresse IPv4"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def is_valid_timestamp(ts):
    """Valide un timestamp Unix"""
    try:
        int(ts)
        return True
    except:
        return False

def validate_schema(data, schema):
    """
    Valide les données contre un schéma
    
    Returns:
        list: Liste des erreurs (vide si valide)
    """
    errors = []
    
    for field, rules in schema.items():
        value = data.get(field)
        
        # Champ requis
        if rules.get('required', False) and value is None:
            errors.append(f"Field '{field}' is required")
            continue
        
        # Si optionnel et absent, skip
        if value is None:
            continue
        
        # Validation par type
        field_type = rules.get('type')
        
        if field_type == 'ipv4':
            if not is_valid_ipv4(str(value)):
                errors.append(f"Field '{field}' must be a valid IPv4 address")
        
        elif field_type == 'int':
            try:
                val = int(value)
                if 'min' in rules and val < rules['min']:
                    errors.append(f"Field '{field}' must be >= {rules['min']}")
                if 'max' in rules and val > rules['max']:
                    errors.append(f"Field '{field}' must be <= {rules['max']}")
            except:
                errors.append(f"Field '{field}' must be an integer")
        
        elif field_type == 'timestamp':
            if not is_valid_timestamp(value):
                errors.append(f"Field '{field}' must be a valid Unix timestamp")
        
        elif field_type == 'string':
            if not isinstance(value, str):
                errors.append(f"Field '{field}' must be a string")
            elif 'max_length' in rules and len(value) > rules['max_length']:
                errors.append(f"Field '{field}' must be <= {rules['max_length']} characters")
    
    return errors

# Schémas de validation pour chaque endpoint
SCHEMAS = {
    "device_query": {
        "ip": {"type": "ipv4", "required": False},
        "limit": {"type": "int", "min": 1, "max": 1000, "required": False}
    },
    "stats_query": {
        "start": {"type": "timestamp", "required": False},
        "end": {"type": "timestamp", "required": False},
        "metric": {"type": "string", "max_length": 50, "required": False}
    }
}

def validate_input(schema_name):
    """
    Décorateur pour valider les inputs d'un endpoint
    
    Usage:
        @app.route('/api/devices', methods=['POST'])
        @validate_input('device_query')
        def get_devices():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Récupérer les données (JSON ou query params)
            if request.method == 'POST':
                data = request.get_json() or {}
            else:
                data = request.args.to_dict()
            
            # Valider
            schema = SCHEMAS.get(schema_name, {})
            errors = validate_schema(data, schema)
            
            if errors:
                return jsonify({
                    "error": "Invalid input",
                    "details": errors
                }), 400
            
            return f(*args, **kwargs)
        return wrapped
    return decorator
