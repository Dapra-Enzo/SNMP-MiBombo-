#!/usr/bin/env python3
"""
MiBombo Suite V1 - Point d'Entree Principal
==============================================
Lance automatiquement tous les composants:
- Interface graphique
- Serveur API REST en arriere-plan
- Moteur de detection d'anomalies
- Bot Telegram (alertes et commandes)

Usage:
    sudo python main.py              # Mode complet (GUI + API + Telegram)
    sudo python main.py --cli        # Mode CLI uniquement
    sudo python main.py --cli        # Mode CLI uniquement
    sudo python main.py --api-only   # API seule sans GUI
"""

import argparse
import sys
import os
import threading
import time
import signal

# === AUTO-ACTIVATION DU VENV ===
def ensure_venv():
    """Vérifie qu'on utilise le venv, sinon relance le script avec le bon Python"""
    # Debug info
    print(f"[DEBUG] sys.frozen: {getattr(sys, 'frozen', 'NOT SET')}")
    print(f"[DEBUG] sys.executable: {sys.executable}")
    print(f"[DEBUG] sys.argv: {sys.argv}")

    # Bypass si l'application est "gelée" (PyInstaller)
    if getattr(sys, 'frozen', False):
        print("[DEBUG] Application congelée détectée (sys.frozen). Bypass venv.")
        return
        
    # Fallback: Check if running from built binary path
    if 'mibombo-station' in sys.executable or 'dist/mibombo-station' in sys.argv[0]:
        print("[DEBUG] Application détectée par nom. Bypass venv.")
        return
        
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.prefix != sys.base_prefix)
    
    if not in_venv:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        venv_python = os.path.join(script_dir, 'venv', 'bin', 'python')
        
        if os.path.exists(venv_python):
            print(f"[i] Relancement avec le venv: {venv_python}")
            os.execv(venv_python, [venv_python, '-B'] + sys.argv)
        else:
            print("[!] ERREUR-777: Virtual environment non trouvé!")
            print(f"[!] Créez-le avec: python3 -m venv {os.path.join(script_dir, 'venv')}")
            print(f"[!] Puis installez les dépendances: ./venv/bin/pip install -r requirements.txt")
            sys.exit(1)

def check_requirements():
    """Vérifie que toutes les dépendances sont installées et les installe si nécessaire"""
    missing = []
    required_modules = {
        'scapy': 'scapy',
        'customtkinter': 'customtkinter',
        'flask': 'Flask',
        'influxdb_client': 'influxdb-client',
        'cryptography': 'cryptography',
        'pyotp': 'pyotp'
    }
    
    for module, package in required_modules.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        # Si congelé, on ne peut pas installer avec pip
        if getattr(sys, 'frozen', False):
            print("\n" + "="*60)
            print("[!] CRITICAL: Dépendances manquantes dans l'exécutable!")
            print("="*60)
            for pkg in missing:
                print(f"  - {pkg}")
            print("\n[!] Ceci est une erreur de build. Contactez le développeur.")
            sys.exit(1)

        print("\n" + "="*60)
        print("[!] Dépendances manquantes détectées!")
        print("="*60)
        for pkg in missing:
            print(f"  - {pkg}")
        print("\n[i] Installation automatique en cours...")
        print("="*60)
        
        # Installation automatique via python -m pip (plus fiable)
        import subprocess
        
        try:
            # Utiliser sys.executable pour garantir qu'on utilise le bon Python
            cmd = [sys.executable, '-m', 'pip', 'install', '--quiet'] + missing
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("[✓] Installation réussie!")
                print("[i] Redémarrage de l'application...\n")
                # Relancer le script pour charger les nouveaux modules
                os.execv(sys.executable, [sys.executable, '-B'] + sys.argv)
            else:
                print(f"[!] Erreur lors de l'installation: {result.stderr}")
                print(f"[i] Essayez manuellement: {sys.executable} -m pip install {' '.join(missing)}")
                sys.exit(1)
        except Exception as e:
            print(f"[!] Erreur: {e}")
            print(f"[i] Installation manuelle requise: {sys.executable} -m pip install {' '.join(missing)}")
            sys.exit(1)
    
    return True

def fix_permissions():
    """Corrige les permissions des fichiers de logs et data"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Créer les répertoires si nécessaire
    for directory in ['data', 'data/logs']:
        dir_path = os.path.join(script_dir, directory)
        os.makedirs(dir_path, exist_ok=True)
        
        # Tenter de corriger les permissions (silencieux si échec)
        try:
            import stat
            os.chmod(dir_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)
        except:
            pass

# === INITIALISATION ===
ensure_venv()
fix_permissions()
check_requirements()

# Configuration des chemins - APRÈS vérification venv
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)
os.chdir(ROOT_DIR)

APP_VERSION = "1.1.0"
API_PORT = 5000
API_HOST = "0.0.0.0"

# === INITIALISATION DU LOGGER ===
from core.logger import get_logger, log_security_event
logger = get_logger("Main")

def check_dependencies():
    """Verifie les dependances requises"""
    missing = []
    
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    
    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")
    
    if missing:
        print(f"[!] Dependances manquantes: {', '.join(missing)}")
        print(f"    pip install {' '.join(missing)}")
        return False
    return True


def check_flask():
    """Verifie si Flask est disponible"""
    try:
        import flask
        import flask_cors
        return True
    except ImportError:
        return False





def start_api_server(host=API_HOST, port=API_PORT, quiet=False):
    """Demarre le serveur API en arriere-plan"""
    if not check_flask():
        if not quiet:
            print("[!] Flask non disponible - API desactivee")
            print("    pip install flask flask-cors")
        return None
    
    try:
        from api.api import create_app
        app, socketio = create_app()
        
        # Desactiver les logs Flask en mode quiet
        if quiet:
            import logging
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)
        
        # Check for SSL certs
        ssl_context = None
        if os.path.exists("local_cert.pem") and os.path.exists("local_key.pem"):
            ssl_context = ("local_cert.pem", "local_key.pem")
            
        def run():
            if socketio:
                socketio.run(app, host=host, port=port, debug=False, use_reloader=False, ssl_context=ssl_context)
            else:
                app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False, ssl_context=ssl_context)
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        
        if not quiet:
            proto = "https" if ssl_context else "http"
            print(f"[+] L'API Rest démarre sur l'adresse suivane {proto}://{host}:{port}")

        
        return thread
    except Exception as e:
        if not quiet:
            print(f"[!] Erreur API: {e}")
        return None


def run_gui():
    """Lance l'interface graphique avec authentification obligatoire"""
    if not check_dependencies():
        sys.exit(1)
    
    print("=" * 60)
    print(r"""
  __  __  _  ____                  _          
 |  \/  |(_)|  _ \                | |         
 | \  / | _ | |_) |  ___   _ __   | |__    ___ 
 | |\/| || ||  _ <  / _ \ | '_ \  | '_ \  / _ \ 
 | |  | || || |_) || (_) || | | | | |_) || (_) |
 |_|  |_||_||____/  \___/ |_| |_| |_.__/  \___/ 
    """)
    print(f"                                   v{APP_VERSION}")
    print("=" * 60)
    
    # Demarrer l'API en arriere-plan
    api_thread = start_api_server(quiet=True)
    if api_thread:
        proto = "https" if os.path.exists("local_cert.pem") else "http"
        print(f"[+] L'API Rest démarre sur l'adresse suivane: {proto}://{API_HOST}:{API_PORT}")
    

    
    time.sleep(0.5)  # Laisser l'API demarrer
    
    try:
        # Importer et utiliser la fonction main() de main_gui qui gere l'auth
        from gui.main_gui import main as gui_main
        print("[*] Demarrage de l'interface...")
        print("=" * 60)
        gui_main()
    except Exception as e:
        print(f"[!] Erreur GUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_cli(args):
    """Lance en mode ligne de commande"""
    from threading import Thread
    from queue import Queue
    
    try:
        from core.sniffer import Sniffer
        from core.analyzer import PacketAnalyzer
        from core.PostgresDB import DataBase
        from core.app_config import ConfAPP
        from core.anomaly_detector import get_detector
    except ImportError as e:
        print(f"[!] Erreur import: {e}")
        sys.exit(1)
    
    print("=" * 60)
    print(f"     MiBombo Suite V{APP_VERSION} - Mode CLI")
    print("=" * 60)
    print(f"  Interface: {args.interface}")
    print(f"  Filtre: {args.filter}")
    print(f"  Database: {args.database}")
    print("=" * 60)
    
    # Demarrer l'API si demande
    if args.with_api:
        start_api_server(args.api_host, args.api_port)
    

    
    os.makedirs(args.pcap_dir, exist_ok=True)
    os.makedirs(os.path.dirname(args.config) or "config", exist_ok=True)
    
    q = Queue(maxsize=10000)
    
    db = DataBase(dbFile=args.database)
    db.initDB()
    
    config = ConfAPP(confFile=args.config)
    if config.config is None:
        config.creatConf()
    
    detector = get_detector()
    
    sniffer = Sniffer(iface=args.interface, sfilter=args.filter, queue=q)
    analyser = PacketAnalyzer(queue=q, baseDB=db, config=config.config,
                       pcap_dir=args.pcap_dir, lenPcap=100)
    
    Thread(target=sniffer.start_sniffer, daemon=True).start()
    Thread(target=analyser.start_analyse, daemon=True).start()
    
    print("\n[*] Capture en cours... (Ctrl+C pour arreter)\n")
    
    try:
        while True:
            time.sleep(2)
            stats = detector.get_statistics()
            alerts = stats.get('total_alerts_generated', 0)
            pkts = stats.get('total_packets_analyzed', 0)
            print(f"\r[LIVE] Paquets: {pkts:>6} | Alertes: {alerts:>4}", end="", flush=True)
    except KeyboardInterrupt:
        print("\n\n[!] Arret demande")
        print(f"[i] Total paquets: {detector.get_statistics()['total_packets_analyzed']}")


def run_api_only(args):
    """Lance uniquement le serveur API"""
    if not check_flask():
        print("[!] Flask requis: pip install flask flask-cors")
        sys.exit(1)
    
    print("=" * 60)
    print(f"     MiBombo Suite V{APP_VERSION} - API Server")
    print("=" * 60)
    print(f"  URL: http://{args.api_host}:{args.api_port}")
    print("  Endpoints: /api/status, /api/capture/start, etc.")
    print("=" * 60)
    
    from api.api import create_app
    app, socketio = create_app()
    
    # Check for SSL certs
    ssl_context = None
    if os.path.exists("local_cert.pem") and os.path.exists("local_key.pem"):
        ssl_context = ("local_cert.pem", "local_key.pem")
    
    proto = "https" if ssl_context else "http"
    print(f"  URL: {proto}://{args.api_host}:{args.api_port}")
    if ssl_context:
        print("  [+] L'API Rest démarre sur l'adresse suivane en HTTPS")

    if socketio:
        socketio.run(app, host=args.api_host, port=args.api_port, debug=args.debug, use_reloader=False, ssl_context=ssl_context)
    else:
        app.run(host=args.api_host, port=args.api_port, debug=args.debug, threaded=True, ssl_context=ssl_context)


def main():
    parser = argparse.ArgumentParser(
        description=f"MiBombo Suite V{APP_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  sudo python main.py                    # GUI + API
  sudo python main.py --cli -i eth0      # CLI avec capture
  sudo python main.py --api-only         # API seule
        """
    )
    
    # Modes
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--cli', action='store_true', help='Mode ligne de commande')
    mode.add_argument('--api-only', action='store_true', help='API seule')
    
    # Options API
    parser.add_argument('--api-host', default=API_HOST, help=f'Host API (default: {API_HOST})')
    parser.add_argument('--api-port', type=int, default=API_PORT, help=f'Port API (default: {API_PORT})')
    parser.add_argument('--with-api', action='store_true', help='Active API en mode CLI')
    parser.add_argument('--debug', action='store_true', help='Mode debug Flask')
    

    
    # Options capture
    parser.add_argument('-i', '--interface', default='eth0', help='Interface reseau')
    parser.add_argument('-f', '--filter', default='udp port 161 or udp port 162', help='Filtre BPF')
    parser.add_argument('-d', '--database', default='mibombo.db', help='Fichier SQLite')
    parser.add_argument('-c', '--config', default='config/conf.json', help='Fichier config')
    parser.add_argument('-p', '--pcap-dir', default='captures', help='Dossier PCAP')
    
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {APP_VERSION}')
    
    args = parser.parse_args()
    
    if args.cli:
        run_cli(args)
    elif args.api_only:
        run_api_only(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
