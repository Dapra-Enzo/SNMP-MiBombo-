#!/usr/bin/env python3
"""
MiBombo  - API en Flask + WebSocketIO permettant 
"""

import os
import sys
import json
import time
import argparse
import threading
import socket
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from typing import Dict, List, Optional
from functools import wraps

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

# === LOGGER ===
try:
    from core.logger import get_logger, log_security_event
    logger = get_logger("API")
except ImportError:
    # Fallback si lancé indépendamment
    import logging
    logger = logging.getLogger("API")
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)
    def log_security_event(*args): pass

# Flask
FLASK_AVAILABLE = False
try:
    from flask import Flask, jsonify, request, Response, render_template, g, render_template_string
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    print("[!] Flask requis: pip install flask flask-cors")


# Stats API
API_STATS = {
    "total_requests": 0,
    "total_errors": 0, 
    "latency_sum": 0,
    "latency_count": 0,
    "active_sessions": 0,
    "start_time": time.time()
}

# Sessions actives (token -> user_data)
# Déplacé en global pour permettre le testing
active_sessions = {}
sessions_lock = Lock()

# Template loaded from templates/api_docs.html

# Flask-SocketIO pour WebSocket
SOCKETIO_AVAILABLE = False
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    pass

# Core modules
CORE_AVAILABLE = False
try:
    from core.sniffer import Sniffer
    from core.analyzer import PacketAnalyzer
    from core.PostgresDB import DataBase
    from core.app_config import ConfAPP
    from core.anomaly_detector import get_detector
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"[!] Core: {e}")

# Auth module (Unified with Main App)
AUTH_AVAILABLE = False
try:
    # On essaie d'abord le système sécurisé (prioritaire)
    from core.secure_authentication import get_secure_auth_manager
    # On importe les constantes depuis core.auth (partagées)
    from core.authentication import ROLES, PERMISSIONS
    
    # Adaptateur pour compatibilité API
    def get_auth_manager():
        return get_secure_auth_manager()
        
    AUTH_AVAILABLE = True
except ImportError as e:
    print(f"[!] Secure Auth mismatch: {e}")
    # Fallback sur l'ancien système si nécessaire
    try:
        from core.authentication import AuthenticationManager, get_auth_manager, ROLES, PERMISSIONS
        AUTH_AVAILABLE = True
    except ImportError:
        pass

# Mailer module
try:
    import core.mailer as mailer
except ImportError as e:
    print(f"[!] Mailer: {e}")
    mailer = None

# Security module
try:
    from core.security import rate_limit, validate_input
except ImportError as e:
    print(f"[!] Security: {e}")
    # Fallback dummy decorators if import fails
    def rate_limit(*args, **kwargs):
        return lambda f: f
    def validate_input(*args, **kwargs):
        return True, None

API_VERSION = "2.0.0"
DEFAULT_CONFIG = {
    "interface": "eth0",
    "filter": "udp port 161 or udp port 162",
    "database": "mibombo.db",
    "config_file": "config/conf.json",
    "pcap_dir": "captures"
}


# =============================================================================
# CAPTURE MANAGER
# =============================================================================

class CaptureManager:
    """Gestionnaire de capture SNMP singleton."""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init = False
        return cls._instance
    
    def __init__(self):
        if self._init:
            return
        self._init = True
        self.config = DEFAULT_CONFIG.copy()
        self.db = None
        self.cfg_mgr = None
        self.sniffer = None
        self.analyser = None
        self.detector = None
        self.queue = None
        self.is_capturing = False
        self.is_initialized = False
        self.start_time = None
        self.packets = []
        self.lock = Lock()
        self.stats = {"total": 0, "authorized": 0, "suspect": 0}
        self._packet_callbacks = []
        self._alert_callbacks = []
    
    def add_packet_callback(self, callback):
        """Ajoute un callback appelé à chaque nouveau paquet."""
        self._packet_callbacks.append(callback)

    def remove_packet_callback(self, callback):
        """Supprime un callback de paquet."""
        if callback in self._packet_callbacks:
            self._packet_callbacks.remove(callback)
    
    def add_alert_callback(self, callback):
        """Ajoute un callback appelé à chaque nouvelle alerte."""
        self._alert_callbacks.append(callback)

    def remove_alert_callback(self, callback):
        """Supprime un callback d'alerte."""
        if callback in self._alert_callbacks:
            self._alert_callbacks.remove(callback)
    
    def initialize(self):
        if not CORE_AVAILABLE:
            return {"success": False, "error": "Core not available"}
        try:
            os.makedirs(self.config["pcap_dir"], exist_ok=True)
            os.makedirs(os.path.dirname(self.config["config_file"]) or "config", exist_ok=True)
            self.db = DataBase(dbFile=self.config["database"])
            self.db.initDB()
            self.cfg_mgr = ConfAPP(confFile=self.config["config_file"])
            if self.cfg_mgr.config is None:
                self.cfg_mgr.creatConf()
            self.detector = get_detector()
            self.queue = Queue(maxsize=10000)
            self.is_initialized = True
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def start(self, iface=None, filt=None):
        if not self.is_initialized:
            r = self.initialize()
            if not r["success"]:
                return r
        if self.is_capturing:
            return {"success": False, "error": "Already running"}
        if iface:
            self.config["interface"] = iface
        if filt:
            self.config["filter"] = filt
        try:
            self.sniffer = Sniffer(
                iface=self.config["interface"],
                sfilter=self.config["filter"],
                queue=self.queue
            )
            cfg = self.cfg_mgr.config if self.cfg_mgr else {}
            self.analyser = PacketAnalyzer(
                queue=self.queue,
                baseDB=self.db,
                config=cfg,
                pcap_dir=self.config["pcap_dir"],
                lenPcap=100
            )
            self.is_capturing = True
            Thread(target=self.sniffer.start_sniffer, daemon=True).start()
            Thread(target=self._capture_loop, daemon=True).start()
            self.start_time = time.time()
            return {"success": True, "interface": self.config["interface"]}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _capture_loop(self):
        while self.is_capturing:
            try:
                if self.queue.empty():
                    time.sleep(0.01)
                    continue
                pkt = self.queue.get(timeout=0.5)
                # DECOMMENTING FOR DEBUG
                print(f"[API DEBUG] Dequeued packet, extracting info...")
                try:
                    data = self.analyser.packet_info(pkt)
                except Exception as e:
                    print(f"[API DEBUG] ERROR extracting packet info: {e}")
                    traceback.print_exc()
                    continue

                # print(f"[API DEBUG] Info extracted: {data.get('ip_src')} -> {data.get('ip_dst')}")
                
                try:
                     is_authorized = self.analyser.compare(data)
                except Exception as e:
                     print(f"[API DEBUG] ERROR analyzing packet: {e}")
                     is_authorized = False

                if is_authorized:
                    data["tag"] = 0
                    self.stats["authorized"] += 1
                else:
                    data["tag"] = 1
                    self.stats["suspect"] += 1
                
                # Notifier les callbacks de paquets (GUI)
                raw_bytes = bytes(pkt)
                # print(f"[API DEBUG] Notifying {len(self._packet_callbacks)} callbacks...")
                for callback in self._packet_callbacks:
                    try:
                        callback(data, raw_bytes)
                    except TypeError:
                        # Rétro-compatibilité
                        try:
                            callback(data)
                        except Exception as e:
                            print(f"[API DEBUG] Callback error (legacy): {e}")
                    except Exception as e:
                        print(f"[API DEBUG] Callback error: {e}")
                        traceback.print_exc()
                
                # Analyse comportementale
                if self.detector:
                    alerts = self.detector.analyze_packet(data)
                    if alerts:
                        for callback in self._alert_callbacks:
                            try:
                                callback(alerts)
                            except:
                                pass
                
                # Écriture DB
                db_data = self._prepare_db_data(data)
                ver = str(data.get("snmp_version", "1"))
                
                if ver == "3":
                    self.db.wrData("snmp_v3", db_data)
                elif ver == "0":
                    self.db.wrData("snmp_v1", db_data)
                else:
                    self.db.wrData("snmp_v2", db_data)
                
                # PCAP
                try:
                    self.analyser.pcap_writer.write(pkt)
                    self.analyser.nb_pkt += 1
                    if self.analyser.nb_pkt >= self.analyser.lenPcap:
                        self.analyser.open_new_pcap()
                except:
                    pass
                
                # Stockage mémoire
                with self.lock:
                    self.packets.append(data)
                    if len(self.packets) > 10000:
                        self.packets = self.packets[-5000:]
                
                self.stats["total"] += 1
                
                # Notifier les callbacks de paquets
                raw_bytes = bytes(pkt)
                for callback in self._packet_callbacks:
                    try:
                        callback(data, raw_bytes)
                    except TypeError:
                        # Backwards compatibility for callbacks asking only for data
                        try:
                            callback(data)
                        except:
                            pass
                    except:
                        pass
                
                self.queue.task_done()
            except:
                pass
    
    def _prepare_db_data(self, d):
        r = {
            "time_stamp": d.get("time_stamp"),
            "mac_src": d.get("mac_src"),
            "mac_dst": d.get("mac_dst"),
            "ip_src": d.get("ip_src"),
            "ip_dst": d.get("ip_dst"),
            "port_src": d.get("port_src"),
            "port_dst": d.get("port_dst"),
            "snmp_community": d.get("snmp_community"),
            "snmp_pdu_type": d.get("snmp_pdu_type"),
            "snmp_oidsValues": json.dumps({"oidsValues": d.get("snmp_oidsValues", [])}),
            "tag": d.get("tag", 0)
        }
        ver = str(d.get("snmp_version", "1"))
        if ver == "0":
            r.update({
                "snmp_enterprise": d.get("snmp_enterprise"),
                "snmp_agent_addr": d.get("snmp_agent_addr"),
                "snmp_generic_trap": d.get("snmp_generic_trap"),
                "snmp_specific_trap": d.get("snmp_specific_trap"),
                "snmp_request_id": d.get("snmp_request_id"),
                "snmp_error_status": d.get("snmp_error_status"),
                "snmp_error_index": d.get("snmp_error_index")
            })
        elif ver == "3":
            r.update({
                "snmp_msg_id": d.get("snmp_msg_id"),
                "snmp_msg_max_size": d.get("snmp_msg_max_size"),
                "snmp_msg_flags": d.get("snmp_msg_flags"),
                "snmp_msg_security_model": d.get("snmp_msg_security_model"),
                "snmp_usm_engine_id": d.get("snmp_usm_engine_id"),
                "snmp_usm_engine_boots": d.get("snmp_usm_engine_boots"),
                "snmp_usm_engine_time": d.get("snmp_usm_engine_time"),
                "snmp_usm_user_name": d.get("snmp_usm_user_name"),
                "snmp_usm_auth_protocol": d.get("snmp_usm_auth_protocol"),
                "snmp_usm_priv_protocol": d.get("snmp_usm_priv_protocol"),
                "snmp_usm_auth_params": d.get("snmp_usm_auth_params"),
                "snmp_usm_priv_params": d.get("snmp_usm_priv_params"),
                "snmp_context_engine_id": d.get("snmp_context_engine_id"),
                "snmp_context_name": d.get("snmp_context_name"),
                "snmp_request_id": d.get("snmp_request_id"),
                "snmp_error_status": d.get("snmp_error_status"),
                "snmp_error_index": d.get("snmp_error_index"),
                "snmp_non_repeaters": d.get("snmp_non_repeaters"),
                "snmp_max_repetitions": d.get("snmp_max_repetitions"),
                "security_level": d.get("security_level"),
                "is_encrypted": d.get("is_encrypted"),
                "is_authenticated": d.get("is_authenticated"),
                "decryption_status": d.get("decryption_status")
            })
        else:
            r.update({
                "snmp_request_id": d.get("snmp_request_id"),
                "snmp_error_status": d.get("snmp_error_status"),
                "snmp_error_index": d.get("snmp_error_index"),
                "snmp_non_repeaters": d.get("snmp_non_repeaters"),
                "snmp_max_repetitions": d.get("snmp_max_repetitions")
            })
        return {k: v for k, v in r.items() if v is not None}
    
    def stop(self):
        if not self.is_capturing:
            return {"success": False, "error": "Not running"}
        self.is_capturing = False
        if self.analyser and hasattr(self.analyser, 'pcap_writer'):
            try:
                self.analyser.pcap_writer.close()
            except:
                pass
        dur = time.time() - self.start_time if self.start_time else 0
        return {"success": True, "duration": round(dur, 2), "packets": self.stats["total"]}
    
    def get_status(self):
        return {
            "version": API_VERSION,
            "core": CORE_AVAILABLE,
            "auth": AUTH_AVAILABLE,
            "capturing": self.is_capturing,
            "interface": self.config.get("interface"),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_stats(self):
        dur = time.time() - self.start_time if self.start_time and self.is_capturing else 0
        r = {
            **self.stats,
            "duration": round(dur, 2),
            "in_memory": len(self.packets)
        }
        if self.detector:
            r["anomalies"] = self.detector.get_statistics()
        return r
    
    def get_packets(self, limit=100, offset=0, tag=None):
        with self.lock:
            f = self.packets.copy()
        
        # Inverser pour avoir les plus récents en premier
        f.reverse()
        
        if tag is not None:
            f = [p for p in f if p.get("tag") == tag]
        return {"total": len(f), "packets": f[offset:offset+limit]}
    
    def get_alerts(self, limit=100):
        if not self.detector:
            return {"alerts": []}
        return {
            "alerts": self.detector.get_alerts(limit=limit),
            "stats": self.detector.get_statistics()
        }
    
    def get_devices(self):
        """Récupère la liste des appareils découverts."""
        if not self.detector:
            return {"devices": []}
        try:
            from core.anomaly_detector import get_device_manager
            dm = get_device_manager()
            if dm:
                devices = []
                for ip, device in dm.devices.items():
                    devices.append({
                        "ip": ip,
                        "mac": device.mac_address,
                        "hostname": device.hostname,
                        "device_type": device.device_type,
                        "vendor": device.vendor,
                        "role": device.role,
                        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
                        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                        "packet_count": device.packet_count,
                        "is_whitelisted": device.is_whitelisted,
                        "is_blacklisted": device.is_blacklisted
                    })
                return {"devices": devices, "total": len(devices)}
        except:
            pass
        return {"devices": [], "total": 0}
    
    def get_baseline(self):
        """Récupère les données de baseline."""
        if not self.detector:
            return {"baseline": {}}
        try:
            stats = self.detector.get_statistics()
            return {
                "baseline": {
                    "packets_analyzed": stats.get("total_packets_analyzed", 0),
                    "alerts_generated": stats.get("total_alerts_generated", 0),
                    "unique_sources": stats.get("unique_sources", 0),
                    "unique_destinations": stats.get("unique_destinations", 0)
                }
            }
        except:
            return {"baseline": {}}
    
    def clear_data(self):
        """Efface les données en mémoire."""
        with self.lock:
            self.packets.clear()
        self.stats = {"total": 0, "authorized": 0, "suspect": 0}
        if self.detector:
            self.detector.reset()
        return {"success": True}


# =============================================================================
# FLASK APP
# =============================================================================

def create_app(enable_auth=True):
    """Crée l'application Flask avec tous les endpoints."""
    if not FLASK_AVAILABLE:
        print("Flask requis!")
        sys.exit(1)
    
    # Charger les variables d'environnement
    try:
        from dotenv import load_dotenv
        # 1. Priorité au .env local (dev/custom)
        if os.path.exists('.env'):
            load_dotenv('.env')
            print("[+] Variables d'environnement chargées depuis .env local")
        # 2. Repli sur la config globale (si installé via .deb)
        elif os.path.exists('/etc/mibombo/.env'):
            load_dotenv('/etc/mibombo/.env')
            print("[+] Variables d'environnement chargées depuis /etc/mibombo/.env")
        else:
            print("[!] Aucun fichier .env trouvé (local ou /etc/mibombo/)")
    except ImportError:
        print("[!] python-dotenv non installé, utilisation des valeurs par défaut")
    
    app = Flask(__name__)
    
    # SECRET_KEY depuis .env avec fallback pour compatibilité
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
    if SECRET_KEY:
        app.config['SECRET_KEY'] = SECRET_KEY
        print("[+] SECRET_KEY chargée depuis .env")
    else:
        app.config['SECRET_KEY'] = 'mibombo-secret-key-change-in-production'
        print("[!] AVERTISSEMENT: SECRET_KEY par défaut utilisée - Définir FLASK_SECRET_KEY dans .env")
    
    # CORS simple
    CORS(app)
    
    # WebSocket
    socketio = None
    if SOCKETIO_AVAILABLE:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    mgr = CaptureManager()
    auth = get_auth_manager() if AUTH_AVAILABLE else None
    
    mgr = CaptureManager()
    auth = get_auth_manager() if AUTH_AVAILABLE else None
    
    def require_permission(permission):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not enable_auth:
                    return f(*args, **kwargs)
                
                user = getattr(request, 'current_user', None)
                if not user:
                    return jsonify({"error": "Non authentifié"}), 401
                
                perms = user.get("permissions", [])
                if "all" in perms or permission in perms:
                    return f(*args, **kwargs)
                
                return jsonify({"error": "Permission insuffisante"}), 403
            return decorated
        return decorator
    
    def require_auth(f):
        """Décorateur pour exiger une authentification sans permission spécifique"""
        @wraps(f)
        def decorated(*args, **kwargs):
            if not enable_auth:
                return f(*args, **kwargs)
            
            user = getattr(request, 'current_user', None)
            if not user:
                return jsonify({"error": "Non authentifié"}), 401
            
            return f(*args, **kwargs)
        return decorated
    
    def require_auth(f):
        """Décorateur pour exiger une authentification sans permission spécifique"""
        @wraps(f)
        def decorated(*args, **kwargs):
            if not enable_auth:
                return f(*args, **kwargs)
            
            user = getattr(request, 'current_user', None)
            if not user:
                return jsonify({"error": "Non authentifié"}), 401
            
            return f(*args, **kwargs)
        return decorated
    
    # Request Hooks for Stats
    @app.before_request
    def before_request():
        g.start = time.time()
        API_STATS["total_requests"] += 1
        
        # Gestion de l'authentification globale
        if enable_auth:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            with sessions_lock:
                if token and token in active_sessions:
                    # On attache l'utilisateur à la requête pour les décorateurs
                    setattr(request, 'current_user', active_sessions[token])

    @app.after_request
    def after_request(response):
        diff = time.time() - g.start
        API_STATS["latency_sum"] += diff
        API_STATS["latency_count"] += 1
        if response.status_code >= 400:
            API_STATS["total_errors"] += 1
        
        # ============================================
        # SECURITY HEADERS
        # ============================================
        
        # 1. Empêche le MIME type sniffing
        # Protège contre: Exécution de code déguisé en image/texte
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # 2. Empêche le clickjacking
        # Protège contre: Affichage dans iframe malveillant
        response.headers['X-Frame-Options'] = 'DENY'
        
        # 3. Active la protection XSS du navigateur
        # Protège contre: Cross-Site Scripting
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # 4. Force HTTPS pendant 1 an
        # Protège contre: SSL stripping, MITM attacks
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        # 5. Politique de sécurité du contenu
        # Protège contre: XSS, injection de code, data exfiltration
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self' https://cdnjs.cloudflare.com"
        )
        
        # 6. Contrôle du referer
        # Protège contre: Fuite d'URLs sensibles vers sites externes
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # 7. Désactive les fonctionnalités sensibles du navigateur
        # Protège contre: Abus de géolocalisation, webcam, micro
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # 8. Empêche le téléchargement automatique
        # Protège contre: Drive-by downloads
        response.headers['X-Download-Options'] = 'noopen'
        
        # 9. Désactive le DNS prefetching pour la confidentialité
        response.headers['X-DNS-Prefetch-Control'] = 'off'
        
        return response

    # WebSocket callbacks
    if socketio:
        def on_new_packet(packet):
            socketio.emit('new_packet', packet, namespace='/live')
        
        def on_new_alert(alerts):
            for alert in alerts if isinstance(alerts, list) else [alerts]:
                socketio.emit('new_alert', alert, namespace='/live')
        
        mgr.add_packet_callback(on_new_packet)
        mgr.add_alert_callback(on_new_alert)
        
        @socketio.on('connect', namespace='/live')
        def handle_connect():
            with sessions_lock:
               API_STATS["active_sessions"] += 1
            print(f"[WS] Client connecté")
        
        @socketio.on('disconnect', namespace='/live')
        def handle_disconnect():
            with sessions_lock:
               API_STATS["active_sessions"] = max(0, API_STATS["active_sessions"] - 1)
            print(f"[WS] Client déconnecté")
    
    
    
    # === ENDPOINTS ===
    
    @app.route("/")
    def index():
        return jsonify({
            "name": "MiBombo Station API",
            "version": API_VERSION,
            "auth_enabled": enable_auth and AUTH_AVAILABLE,
            "websocket": SOCKETIO_AVAILABLE
        })
    
    @app.route("/api/status")
    def status():
        return jsonify(mgr.get_status())
    
    @app.route("/api/ping")
    def ping():
        return jsonify({"pong": True, "timestamp": datetime.now().isoformat()})
    
    @app.route("/api/auth/login", methods=["POST"])
    @rate_limit(limit=5, window=60)
    def login():
        if not AUTH_AVAILABLE:
            return jsonify({"error": "Auth non disponible"}), 500
        
        data = request.get_json() or {}
        
        # Validation
        valid, err = validate_input(data, {
            "username": {"type": str, "min": 1, "max": 50},
            "password": {"type": str, "min": 1}
        })
        if not valid:
            return jsonify({"success": False, "error": err}), 400
        
        username = data.get("username", "")
        password = data.get("password", "")
        
        if not username or not password:
            return jsonify({"success": False, "error": "Identifiants requis"}), 400
        
        if hasattr(auth, 'login_step1'):
            # Secure Auth Logic
            success, msg, result = auth.login_step1(username, password)
            if success:
                user_id = result
                # Check 2FA
                need_2fa, msg = auth.login_step2_check_2fa(user_id)
                if need_2fa:
                     # Pour l'API, on ne gère pas la 2FA interactivement facilement ici
                     # On pourrait renvoyer un code spécifique, mais pour l'instant on bloque sans 2FA
                     return jsonify({"success": False, "error": "2FA requis mais non supporté via cette route API simple"}), 403
                
                # Finaliser
                success_final, msg_final, user_data = auth.complete_login(user_id)
                
                if success_final:
                    user = user_data
                    # Le token est dans l'instance auth après complete_login
                    if hasattr(auth, 'current_session'):
                         token = auth.current_session
                    else:
                         token = "unknown_token"
                         
                    user["session_token"] = token
                    
                    with sessions_lock:
                         active_sessions[token] = user
                    
                    return jsonify({
                        "success": True,
                        "token": token,
                        "user": {
                            "id": user.get("id"),
                            "username": user.get("username"),
                            "role": user.get("role"),
                            "permissions": user.get("permissions", [])
                        }
                    })
                else:
                     return jsonify({"success": False, "error": msg_final}), 401
            else:
                return jsonify({"success": False, "error": msg}), 401
        else:
            # Legacy Auth Logic
            success, msg, user = auth.login(username, password)
            
            if success:
                token = user.get("session_token")
                with sessions_lock:
                    active_sessions[token] = user
                return jsonify({
                    "success": True,
                    "token": token,
                    "user": {
                        "id": user.get("id"),
                        "username": user.get("username"),
                        "role": user.get("role"),
                        "permissions": user.get("permissions", [])
                    }
                })
            else:
                return jsonify({"success": False, "error": msg}), 401
    
    @app.route("/api/auth/register", methods=["POST"])
    @rate_limit(limit=3, window=300)
    def register():
        if not AUTH_AVAILABLE:
            return jsonify({"error": "Auth non disponible"}), 500
        
        data = request.get_json() or {}
        
        # Validation
        valid, err = validate_input(data, {
            "username": {"type": str, "min": 3, "max": 20, "regex": r"^[a-zA-Z0-9_]+$"},
            "password": {"type": str, "min": 6},
            "email": {"type": str, "min": 5, "regex": r"^[^@]+@[^@]+\.[^@]+$"},
            "full_name": {"type": str, "min": 2, "max": 100, "required": False}
        })
        if not valid:
             return jsonify({"success": False, "error": err}), 400

        username = data.get("username", "")
        password = data.get("password", "")
        email = data.get("email", "")
        full_name = data.get("full_name", "")
        
        if not username or not password or not email:
            return jsonify({"success": False, "error": "Champs requis manquants"}), 400
        
        # Enregistrement
        if hasattr(auth, 'register') and callable(getattr(auth, 'register')):
            # Secure Auth
            try:
                # La signature peut varier, on essaie l'appel standard (username, password, email)
                success, msg, ticket_id = auth.register(username, password, email)
                if success:
                    # Notifications email gérées par SecureAuthenticationManager, pas besoin de le faire ici
                    return jsonify({"success": True, "message": "Inscription réussie (en attente de validation admin)", "ticket_id": ticket_id}), 201
                else:
                     return jsonify({"success": False, "error": msg}), 400
            except Exception as e:
                return jsonify({"success": False, "error": f"Erreur interne auth: {e}"}), 500
        else:
            # Legacy Auth
            success, msg = auth.register_user(username, password, email, full_name)
            
            if success:
                # Notifications email manuelles pour legacy
                if mailer:
                    mailer.notify_admin_new_user(username, email)
                    mailer.notify_user_pending(email, username)
                
                return jsonify({"success": True, "message": msg})
            else:
                 return jsonify({"success": False, "error": msg}), 400
    
    @app.route("/api/auth/logout", methods=["POST"])
    @require_auth
    def logout():
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        with sessions_lock:
            if token in active_sessions:
                del active_sessions[token]
        if auth:
            auth.logout()
        return jsonify({"success": True})
    
    @app.route("/api/auth/verify", methods=["GET"])
    @require_auth
    def verify():
        user = getattr(request, 'current_user', None)
        if user:
            return jsonify({
                "valid": True,
                "user": {
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "role": user.get("role"),
                    "permissions": user.get("permissions", [])
                }
            })
        return jsonify({"valid": False}), 401
    
    @app.route("/api/auth/users", methods=["GET"])
    @require_auth
    @require_permission("manage_users")
    def get_users():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        users = auth.get_all_users()
        return jsonify({"users": users})
    
    @app.route("/api/auth/users", methods=["POST"])
    @require_auth
    @require_permission("manage_users")
    def create_user():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        data = request.get_json() or {}
        success, msg = auth.create_user(
            username=data.get("username"),
            password=data.get("password"),
            role=data.get("role", "viewer"),
            email=data.get("email"),
            full_name=data.get("full_name")
        )
        if success:
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "error": msg}), 400
    
    @app.route("/api/auth/tickets", methods=["GET"])
    @require_auth
    @require_permission("manage_users")
    def get_tickets():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        tickets = auth.get_tickets()
        return jsonify({"tickets": tickets})
    
    @app.route("/api/auth/tickets", methods=["POST"])
    def create_ticket():
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        data = request.get_json() or {}
        success, msg, ticket_id = auth.create_ticket(
            username=data.get("username"),
            ticket_type=data.get("ticket_type", "other"),
            subject=data.get("subject", ""),
            message=data.get("message", "")
        )
        if success:
            return jsonify({"success": True, "ticket_id": ticket_id})
        return jsonify({"success": False, "error": msg}), 400
    
    @app.route("/api/capture/start", methods=["POST"])
    @require_auth
    @require_permission("start_capture")
    def start_capture():
        data = request.get_json() or {}
        return jsonify(mgr.start(
            iface=data.get("interface"),
            filt=data.get("filter")
        ))
    
    @app.route("/api/capture/stop", methods=["POST"])
    @require_auth
    @require_permission("stop_capture")
    def stop_capture():
        return jsonify(mgr.stop())
    
    @app.route("/api/capture/clear", methods=["POST"])
    @require_auth
    def clear_capture():
        return jsonify(mgr.clear_data())
    
    @app.route("/api/packets")
    @require_auth
    @require_permission("view_packets")
    def get_packets():
        return jsonify(mgr.get_packets(
            limit=request.args.get("limit", 100, type=int),
            offset=request.args.get("offset", 0, type=int),
            tag=request.args.get("tag", type=int)
        ))
    
    @app.route("/api/stats")
    @require_auth
    @require_permission("view_stats")
    def get_stats():
        stats = mgr.get_stats()
        
        # Enrichir avec InfluxDB
        try:
            from core.influx_wrapper import InfluxWrapper
            influx = InfluxWrapper.get_instance()
            influx_data = influx.get_stats_last_hour()
            stats["influx"] = influx_data
            stats["influx_connected"] = influx._connected
        except ImportError:
            pass
            
        # Enrichir avec API Stats
        stats["api_usage"] = {
            "requests": API_STATS["total_requests"],
            "errors": API_STATS["total_errors"], 
            "avg_latency_ms": round((API_STATS["latency_sum"] / API_STATS["latency_count"] * 1000), 2) if API_STATS["latency_count"] > 0 else 0,
            "uptime_sec": round(time.time() - API_STATS["start_time"], 0)
        }
            
        return jsonify(stats)
    
    @app.route("/api/alerts")
    @require_auth
    @require_permission("view_behavior")
    def get_alerts():
        return jsonify(mgr.get_alerts(
            limit=request.args.get("limit", 100, type=int)
        ))
    
    @app.route("/api/devices")
    @require_auth
    @require_permission("view_devices")
    def get_devices():
        return jsonify(mgr.get_devices())
    
    @app.route("/api/baseline")
    @require_auth
    @require_permission("view_behavior")
    def get_baseline():
        return jsonify(mgr.get_baseline())
    
    @app.route("/api/config", methods=["GET"])
    @require_auth
    @require_permission("manage_config")
    def get_config():
        if mgr.cfg_mgr and mgr.cfg_mgr.config:
            return jsonify({"config": mgr.cfg_mgr.config})
        return jsonify({"config": {}})
    
    @app.route("/api/config", methods=["PUT"])
    @require_auth
    @require_permission("manage_config")
    def update_config():
        """Met à jour la configuration"""
        if not mgr.cfg_mgr:
            return jsonify({"error": "Config manager non disponible"}), 500
        data = request.get_json() or {}
        try:
            mgr.cfg_mgr.config.update(data)
            mgr.cfg_mgr.saveConf()
            return jsonify({"success": True, "message": "Configuration mise à jour"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
    
    # =========================================================================
    # CRUD USERS (PUT/DELETE)
    # =========================================================================
    
    @app.route("/api/auth/users/<user_id>", methods=["GET"])
    @require_auth
    @require_permission("manage_users")
    def get_user(user_id):
        """Récupère un utilisateur par ID"""
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        user = auth.get_user_by_id(user_id) if hasattr(auth, 'get_user_by_id') else None
        if user:
            return jsonify({"user": user})
        return jsonify({"error": "Utilisateur non trouvé"}), 404
    
    @app.route("/api/auth/users/<user_id>", methods=["PUT"])
    @require_auth
    @require_permission("manage_users")
    def update_user(user_id):
        """Met à jour un utilisateur"""
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        data = request.get_json() or {}
        if hasattr(auth, 'update_user'):
            success, msg = auth.update_user(user_id, **data)
            if success:
                return jsonify({"success": True, "message": msg})
            return jsonify({"success": False, "error": msg}), 400
        return jsonify({"error": "Méthode non supportée"}), 501
    
    @app.route("/api/auth/users/<user_id>", methods=["DELETE"])
    @require_auth
    @require_permission("manage_users")
    def delete_user(user_id):
        """Supprime un utilisateur"""
        if not auth:
            return jsonify({"error": "Auth non disponible"}), 500
        if hasattr(auth, 'delete_user'):
            success, msg = auth.delete_user(user_id)
            if success:
                return jsonify({"success": True, "message": msg})
            return jsonify({"success": False, "error": msg}), 400
        return jsonify({"error": "Méthode non supportée"}), 501
    
    # =========================================================================
    # CRUD SNMPv3 USERS
    # =========================================================================
    
    @app.route("/api/snmpv3/users", methods=["GET"])
    @require_auth
    @require_permission("manage_snmp")
    def get_snmpv3_users():
        """Liste tous les utilisateurs SNMPv3"""
        try:
            from core.snmp_credentials import snmp_cred_mgr
            users = snmp_cred_mgr.get_all_users()
            # Masquer les clés sensibles
            safe_users = []
            for u in users:
                safe_users.append({
                    "username": u["username"],
                    "auth_proto": u.get("auth_proto", "SHA"),
                    "priv_proto": u.get("priv_proto", "AES"),
                    "has_auth_key": bool(u.get("auth_key")),
                    "has_priv_key": bool(u.get("priv_key"))
                })
            return jsonify({"users": safe_users, "total": len(safe_users)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route("/api/snmpv3/users", methods=["POST"])
    @require_auth
    @require_permission("manage_snmp")
    def create_snmpv3_user():
        """Crée un utilisateur SNMPv3"""
        try:
            from core.snmp_credentials import snmp_cred_mgr
            data = request.get_json() or {}
            
            username = data.get("username")
            if not username:
                return jsonify({"success": False, "error": "Username requis"}), 400
            
            snmp_cred_mgr.add_user(
                username=username,
                auth_proto=data.get("auth_proto", "SHA"),
                auth_key=data.get("auth_key"),
                priv_proto=data.get("priv_proto", "AES"),
                priv_key=data.get("priv_key")
            )
            return jsonify({"success": True, "message": f"Utilisateur {username} créé"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
    
    @app.route("/api/snmpv3/users/<username>", methods=["DELETE"])
    @require_auth
    @require_permission("manage_snmp")
    def delete_snmpv3_user(username):
        """Supprime un utilisateur SNMPv3"""
        try:
            from core.snmp_credentials import snmp_cred_mgr
            snmp_cred_mgr.delete_user(username)
            return jsonify({"success": True, "message": f"Utilisateur {username} supprimé"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
    
    # =========================================================================
    # CRUD DEVICES (Whitelist/Blacklist)
    # =========================================================================
    
    @app.route("/api/devices/<ip>", methods=["PUT"])
    @require_auth
    @require_permission("manage_devices")
    def update_device(ip):
        """Met à jour un appareil (whitelist/blacklist)"""
        data = request.get_json() or {}
        try:
            from core.anomaly_detector import get_device_manager
            dm = get_device_manager()
            if not dm:
                return jsonify({"error": "Device manager non disponible"}), 500
            
            if ip not in dm.devices:
                return jsonify({"error": "Appareil non trouvé"}), 404
            
            device = dm.devices[ip]
            if "is_whitelisted" in data:
                device.is_whitelisted = data["is_whitelisted"]
            if "is_blacklisted" in data:
                device.is_blacklisted = data["is_blacklisted"]
            if "hostname" in data:
                device.hostname = data["hostname"]
            
            return jsonify({"success": True, "message": f"Appareil {ip} mis à jour"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
    
    @app.route("/api/devices/<ip>", methods=["DELETE"])
    @require_auth
    @require_permission("manage_devices")
    def delete_device(ip):
        """Supprime un appareil de la liste"""
        try:
            from core.anomaly_detector import get_device_manager
            dm = get_device_manager()
            if dm and ip in dm.devices:
                del dm.devices[ip]
                return jsonify({"success": True, "message": f"Appareil {ip} supprimé"})
            return jsonify({"error": "Appareil non trouvé"}), 404
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
    
    # =========================================================================
    # CRUD ALERTS
    # =========================================================================
    
    @app.route("/api/alerts/<alert_id>", methods=["DELETE"])
    @require_auth
    @require_permission("manage_alerts")
    def delete_alert(alert_id):
        """Supprime/acquitte une alerte"""
        if mgr.detector and hasattr(mgr.detector, 'acknowledge_alert'):
            mgr.detector.acknowledge_alert(alert_id)
            return jsonify({"success": True, "message": "Alerte acquittée"})
        return jsonify({"error": "Non supporté"}), 501
    
    @app.route("/api/alerts", methods=["DELETE"])
    @require_auth
    @require_permission("manage_alerts")
    def clear_alerts():
        """Efface toutes les alertes"""
        if mgr.detector and hasattr(mgr.detector, 'reset'):
            mgr.detector.reset()
            return jsonify({"success": True, "message": "Alertes effacées"})
        return jsonify({"error": "Non supporté"}), 501
    
    @app.route("/api/docs")
    def docs():
        endpoints = [
            # Status & Health
            {"method": "GET", "url": "/api/status", "desc": "État général des services"},
            {"method": "GET", "url": "/api/ping", "desc": "Health check"},
            {"method": "GET", "url": "/api/stats", "desc": "Statistiques complètes (SNMP, API, InfluxDB)"},
            
            # Authentication
            {"method": "POST", "url": "/api/auth/login", "desc": "Authentification (Retourne token)"},
            {"method": "POST", "url": "/api/auth/register", "desc": "Inscription (Crée ticket)"},
            {"method": "POST", "url": "/api/auth/logout", "desc": "Déconnexion"},
            {"method": "GET", "url": "/api/auth/verify", "desc": "Vérifie token"},
            
            # Users CRUD
            {"method": "GET", "url": "/api/auth/users", "desc": "Liste tous les utilisateurs"},
            {"method": "POST", "url": "/api/auth/users", "desc": "Créer un utilisateur"},
            {"method": "GET", "url": "/api/auth/users/{id}", "desc": "Récupérer un utilisateur"},
            {"method": "PUT", "url": "/api/auth/users/{id}", "desc": "Modifier un utilisateur"},
            {"method": "DELETE", "url": "/api/auth/users/{id}", "desc": "Supprimer un utilisateur"},
            
            # SNMPv3 Users CRUD
            {"method": "GET", "url": "/api/snmpv3/users", "desc": "Liste utilisateurs SNMPv3"},
            {"method": "POST", "url": "/api/snmpv3/users", "desc": "Créer utilisateur SNMPv3"},
            {"method": "DELETE", "url": "/api/snmpv3/users/{username}", "desc": "Supprimer utilisateur SNMPv3"},
            
            # Capture
            {"method": "POST", "url": "/api/capture/start", "desc": "Démarrer la capture"},
            {"method": "POST", "url": "/api/capture/stop", "desc": "Arrêter la capture"},
            {"method": "POST", "url": "/api/capture/clear", "desc": "Effacer les données"},
            
            # Packets
            {"method": "GET", "url": "/api/packets", "desc": "Liste des paquets capturés"},
            
            # Alerts CRUD
            {"method": "GET", "url": "/api/alerts", "desc": "Alertes de sécurité"},
            {"method": "DELETE", "url": "/api/alerts", "desc": "Effacer toutes les alertes"},
            {"method": "DELETE", "url": "/api/alerts/{id}", "desc": "Acquitter une alerte"},
            
            # Devices CRUD
            {"method": "GET", "url": "/api/devices", "desc": "Appareils découverts"},
            {"method": "PUT", "url": "/api/devices/{ip}", "desc": "Modifier appareil (whitelist/blacklist)"},
            {"method": "DELETE", "url": "/api/devices/{ip}", "desc": "Supprimer un appareil"},
            
            # Config
            {"method": "GET", "url": "/api/config", "desc": "Récupérer la configuration"},
            {"method": "PUT", "url": "/api/config", "desc": "Modifier la configuration"},
            
            # Baseline
            {"method": "GET", "url": "/api/baseline", "desc": "Données de baseline"},
        ]
        
        # Détecter l'IP réelle
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"
            
        server_host = f"{local_ip}:5000"
        server_url = f"https://{server_host}"
        
        # Try to use template file, fallback to string if needs strict path setup but for now let's assume root
        # Or even better: read the file content manually since we are not sure about Flask template folder location relative to execution
        try:
             template_path = os.path.join(ROOT_DIR, "templates", "api_docs.html")
             with open(template_path, "r", encoding="utf-8") as f:
                 template_content = f.read()
             return render_template_string(template_content, version=API_VERSION, endpoints=endpoints, 
                                     server_url=server_url, server_host=server_host)
        except Exception as e:
             return jsonify({"error": f"Template missing: {e}"}), 500
    
    if socketio:
        return app, socketio
    return app, None


def main():
    if not FLASK_AVAILABLE:
        print("pip install flask flask-cors")
        sys.exit(1)
    
    p = argparse.ArgumentParser(description="MiBombo Station API")
    p.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    p.add_argument("--debug", action="store_true", help="Mode debug")
    p.add_argument("--no-auth", action="store_true", help="Désactiver l'auth")
    args = p.parse_args()
    
    print("=" * 50)
    print(f"  MiBombo Station API v{API_VERSION}")
    print("=" * 50)
    print(f"  URL: http://{args.host}:{args.port}")
    print(f"  Auth: {'Desactivee' if args.no_auth else 'Activee'}")
    print(f"  WebSocket: {'Disponible' if SOCKETIO_AVAILABLE else 'Non disponible'}")
    print("=" * 50)
    
    app, socketio = create_app(enable_auth=not args.no_auth)
    
    if socketio:
        socketio.run(app, host=args.host, port=args.port, debug=args.debug)
    else:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)




if __name__ == "__main__":
    print("🚀 Démarrage de l'API en mode LOCAL SÉCURISÉ (HTTPS)...")

    # 1. On crée l'application (Indispensable !)
    app, socketio = create_app(enable_auth=True) 

    # 2. Tes nouveaux certificats locaux
    mes_certificats = ('local_cert.pem', 'local_key.pem')

    # 3. Lancement
    if socketio:
        print("[+] Mode SocketIO activé")
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, ssl_context=mes_certificats)
    else:
        print("[+] Mode Flask standard activé")
        app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=mes_certificats)
    main()
