"""
SSL Configuration Module for MiBombo
Provides centralized SSL/TLS certificate verification configuration
"""

import os
import certifi
from pathlib import Path

# Chemin vers le certificat Root CA de MiBombo
PROJECT_ROOT = Path(__file__).parent.parent
MIBOMBO_CA_CERT = PROJECT_ROOT / "pki" / "root_ca" / "rootCA.crt"
MIBOMBO_CA_CHAIN = PROJECT_ROOT / "pki" / "sub_ca" / "ca_chain.crt"


def get_ssl_verify_path():
    """
    Retourne le chemin du bundle CA à utiliser pour la vérification SSL.
    
    Priorité:
    1. Variable d'environnement SSL_CERT_FILE
    2. Certificat Root CA MiBombo (si existe)
    3. Chaîne CA MiBombo (si existe)
    4. Bundle système (certifi)
    
    Returns:
        str or bool: Chemin vers le bundle CA, ou True pour utiliser le système
    """
    # 1. Variable d'environnement (permet override manuel)
    env_cert = os.environ.get('SSL_CERT_FILE')
    if env_cert and os.path.exists(env_cert):
        return env_cert
    
    # 2. Root CA MiBombo (pour certificats auto-signés)
    if MIBOMBO_CA_CERT.exists():
        return str(MIBOMBO_CA_CERT)
    
    # 3. Chaîne CA MiBombo (inclut Root + Sub CA)
    if MIBOMBO_CA_CHAIN.exists():
        return str(MIBOMBO_CA_CHAIN)
    
    # 4. Bundle système (certifi)
    # True = utilise le bundle système par défaut
    return certifi.where()


def get_requests_ssl_config():
    """
    Retourne la configuration SSL pour la bibliothèque requests.
    
    Returns:
        dict: Configuration à passer à requests (ex: requests.get(..., **config))
    """
    return {
        'verify': get_ssl_verify_path(),
        'timeout': 10
    }


# Configuration par défaut exportée
SSL_VERIFY = get_ssl_verify_path()

# Pour debug
if __name__ == "__main__":
    print("=== Configuration SSL MiBombo ===")
    print(f"SSL_VERIFY: {SSL_VERIFY}")
    print(f"Type: {type(SSL_VERIFY)}")
    
    if isinstance(SSL_VERIFY, str):
        print(f"Fichier existe: {os.path.exists(SSL_VERIFY)}")
        if os.path.exists(SSL_VERIFY):
            print(f"Taille: {os.path.getsize(SSL_VERIFY)} bytes")
    
    print("\nConfiguration requests:")
    print(get_requests_ssl_config())
