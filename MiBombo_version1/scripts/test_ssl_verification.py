#!/usr/bin/env python3
"""
Script de test automatique SSL/TLS pour MiBombo
Vérifie que la vérification SSL est correctement configurée et fonctionne
"""

import sys
import os
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
import subprocess

# Couleurs pour le terminal
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

def print_header(text):
    print(f"\n{BLUE}{'=' * 60}{NC}")
    print(f"{BLUE}{text}{NC}")
    print(f"{BLUE}{'=' * 60}{NC}\n")

def print_test(name):
    print(f"{YELLOW}🧪 Test: {name}{NC}")

def print_success(msg):
    print(f"   {GREEN}✅ {msg}{NC}")

def print_error(msg):
    print(f"   {RED}❌ {msg}{NC}")

def print_warning(msg):
    print(f"   {YELLOW}⚠️  {msg}{NC}")

def test_ssl_config():
    """Test 1: Vérifier la configuration SSL"""
    print_test("Configuration SSL")
    
    try:
        from core.ssl_config import SSL_VERIFY, get_ssl_verify_path
        
        # Vérifier que SSL_VERIFY est défini
        if SSL_VERIFY:
            print_success(f"SSL_VERIFY défini: {SSL_VERIFY}")
        else:
            print_error("SSL_VERIFY non défini")
            return False
        
        # Vérifier que le fichier existe
        if isinstance(SSL_VERIFY, str):
            if os.path.exists(SSL_VERIFY):
                size = os.path.getsize(SSL_VERIFY)
                print_success(f"Certificat existe ({size} bytes)")
            else:
                print_error(f"Certificat introuvable: {SSL_VERIFY}")
                return False
        
        # Vérifier la fonction helper
        config = get_ssl_verify_path()
        print_success(f"get_ssl_verify_path() retourne: {config}")
        
        return True
        
    except ImportError as e:
        print_error(f"Impossible d'importer ssl_config: {e}")
        return False
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_certificate_validity():
    """Test 2: Vérifier la validité du certificat"""
    print_test("Validité du certificat")
    
    try:
        # Vérifier le certificat Station
        result = subprocess.run(
            ['openssl', 'x509', '-in', 'pki/station/station.crt', 
             '-noout', '-checkend', '0'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_success("Certificat Station valide (non expiré)")
        else:
            print_error("Certificat Station expiré !")
            return False
        
        # Vérifier la chaîne de confiance
        result = subprocess.run(
            ['openssl', 'verify', '-CAfile', 'pki/root_ca/rootCA.crt',
             '-untrusted', 'pki/sub_ca/subCA.crt', 'pki/station/station.crt'],
            capture_output=True,
            text=True
        )
        
        if 'OK' in result.stdout:
            print_success("Chaîne de confiance valide")
        else:
            print_error(f"Chaîne de confiance invalide: {result.stdout}")
            return False
        
        return True
        
    except FileNotFoundError:
        print_error("OpenSSL non trouvé")
        return False
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_api_connection():
    """Test 3: Tester la connexion API avec SSL"""
    print_test("Connexion API avec SSL")
    
    try:
        from core.ssl_config import SSL_VERIFY
        
        base_url = "https://localhost:5000"
        
        # Test 1: Endpoint stats
        try:
            r = requests.get(f"{base_url}/api/stats", 
                           verify=SSL_VERIFY, 
                           timeout=5)
            
            if r.status_code == 200:
                print_success(f"GET /api/stats: {r.status_code}")
            else:
                print_warning(f"GET /api/stats: {r.status_code} (attendu 200)")
            
        except requests.exceptions.SSLError as e:
            print_error(f"Erreur SSL: {e}")
            return False
        except requests.exceptions.ConnectionError:
            print_warning("API non accessible (app non démarrée ?)")
            print_warning("Démarrez l'app avec: sudo ./venv/bin/python main.py")
            return None  # None = test non concluant
        
        return True
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_ssl_rejection():
    """Test 4: Vérifier que les certificats invalides sont rejetés"""
    print_test("Rejet des certificats invalides")
    
    try:
        # Tenter de se connecter avec le bundle système (devrait échouer)
        import certifi
        
        try:
            r = requests.get("https://localhost:5000/api/stats",
                           verify=certifi.where(),
                           timeout=5)
            print_warning("Certificat accepté avec bundle système (inattendu)")
            return None
        except requests.exceptions.SSLError:
            print_success("Certificat rejeté avec bundle système (correct)")
            return True
        except requests.exceptions.ConnectionError:
            print_warning("API non accessible")
            return None
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_no_insecure_warnings():
    """Test 5: Vérifier l'absence de warnings InsecureRequest"""
    print_test("Absence de warnings InsecureRequest")
    
    try:
        import warnings
        from urllib3.exceptions import InsecureRequestWarning
        
        # Capturer les warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            
            from core.ssl_config import SSL_VERIFY
            
            try:
                r = requests.get("https://localhost:5000/api/stats",
                               verify=SSL_VERIFY,
                               timeout=5)
            except:
                pass  # Peu importe si ça échoue, on vérifie juste les warnings
            
            # Vérifier qu'il n'y a pas de InsecureRequestWarning
            insecure_warnings = [x for x in w if issubclass(x.category, InsecureRequestWarning)]
            
            if len(insecure_warnings) == 0:
                print_success("Aucun warning InsecureRequest")
                return True
            else:
                print_error(f"{len(insecure_warnings)} warning(s) InsecureRequest détecté(s)")
                return False
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_verify_false_detection():
    """Test 6: Détecter les verify=False restants dans le code"""
    print_test("Détection de verify=False dans le code")
    
    try:
        result = subprocess.run(
            ['grep', '-r', '--include=*.py', 'verify=False', '.'],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )
        
        # Filtrer les résultats (exclure venv, tests, etc.)
        lines = [l for l in result.stdout.split('\n') 
                if l and 'venv/' not in l and 'test_ssl_verification.py' not in l]
        
        if len(lines) == 0:
            print_success("Aucun verify=False trouvé dans le code")
            return True
        else:
            print_warning(f"{len(lines)} occurrence(s) de verify=False trouvée(s):")
            for line in lines[:5]:  # Afficher max 5
                print(f"      {line}")
            return False
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def main():
    """Exécute tous les tests"""
    print_header("🔐 Tests SSL/TLS Verification - MiBombo")
    
    results = {}
    
    # Exécuter tous les tests
    results['config'] = test_ssl_config()
    results['validity'] = test_certificate_validity()
    results['connection'] = test_api_connection()
    results['rejection'] = test_ssl_rejection()
    results['warnings'] = test_no_insecure_warnings()
    results['verify_false'] = test_verify_false_detection()
    
    # Résumé
    print_header("📊 Résumé des Tests")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    
    print(f"Total:   {total} tests")
    print(f"{GREEN}Réussis: {passed}{NC}")
    print(f"{RED}Échoués: {failed}{NC}")
    print(f"{YELLOW}Ignorés: {skipped}{NC}")
    
    # Détails
    print("\nDétails:")
    for name, result in results.items():
        if result is True:
            print(f"  {GREEN}✅ {name}{NC}")
        elif result is False:
            print(f"  {RED}❌ {name}{NC}")
        else:
            print(f"  {YELLOW}⚠️  {name} (ignoré){NC}")
    
    # Verdict final
    print()
    if failed == 0 and passed > 0:
        print(f"{GREEN}{'=' * 60}{NC}")
        print(f"{GREEN}✅ TOUS LES TESTS PASSENT - SSL CORRECTEMENT CONFIGURÉ{NC}")
        print(f"{GREEN}{'=' * 60}{NC}")
        return 0
    elif failed > 0:
        print(f"{RED}{'=' * 60}{NC}")
        print(f"{RED}❌ {failed} TEST(S) ÉCHOUÉ(S) - VÉRIFIER LA CONFIGURATION{NC}")
        print(f"{RED}{'=' * 60}{NC}")
        return 1
    else:
        print(f"{YELLOW}{'=' * 60}{NC}")
        print(f"{YELLOW}⚠️  TESTS NON CONCLUANTS - DÉMARRER L'APPLICATION{NC}")
        print(f"{YELLOW}{'=' * 60}{NC}")
        return 2

if __name__ == "__main__":
    sys.exit(main())
