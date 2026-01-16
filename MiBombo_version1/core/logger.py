"""
MiBombo Logging System
======================
Système de logging professionnel avec :
- Logs persistants dans data/logs/
- Rotation quotidienne automatique
- Niveaux: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Format structuré avec timestamps

Usage:
    from core.logger import get_logger
    logger = get_logger("MonModule")
    logger.info("Message d'information")
    logger.warning("Attention!")
    logger.error("Erreur critique", exc_info=True)
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from datetime import datetime
from pathlib import Path

# === CONFIGURATION ===
ROOT_DIR = Path(__file__).parent.parent
LOG_DIR = ROOT_DIR / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Taille max par fichier (5 MB)
MAX_BYTES = 5 * 1024 * 1024
# Nombre de fichiers de backup
BACKUP_COUNT = 10

# Format des logs
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Couleurs pour la console (ANSI)
COLORS = {
    'DEBUG': '\033[36m',     # Cyan
    'INFO': '\033[32m',      # Vert
    'WARNING': '\033[33m',   # Jaune
    'ERROR': '\033[31m',     # Rouge
    'CRITICAL': '\033[35m',  # Magenta
    'RESET': '\033[0m'
}


class ColoredFormatter(logging.Formatter):
    """Formatter avec couleurs pour la console"""
    
    def format(self, record):
        # Ajouter la couleur
        color = COLORS.get(record.levelname, COLORS['RESET'])
        reset = COLORS['RESET']
        
        # Format personnalisé
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


class MiBomboLogger:
    """Gestionnaire centralisé des logs MiBombo"""
    
    _instance = None
    _loggers = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._setup_root_logger()
        self._setup_file_handlers()
        
        # Log de démarrage
        self.get_logger("System").info("=" * 60)
        self.get_logger("System").info("MiBombo Logging System initialisé")
        self.get_logger("System").info(f"Logs directory: {LOG_DIR}")
        self.get_logger("System").info("=" * 60)
    
    def _setup_root_logger(self):
        """Configure le logger racine"""
        root = logging.getLogger("MiBombo")
        root.setLevel(logging.DEBUG)
        
        # Handler console avec couleurs
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console.setFormatter(ColoredFormatter(LOG_FORMAT, DATE_FORMAT))
        root.addHandler(console)
    
    def _setup_file_handlers(self):
        """Configure les handlers de fichiers"""
        root = logging.getLogger("MiBombo")
        
        # === 1. Fichier principal (rotation par taille) ===
        main_log = LOG_DIR / "mibombo.log"
        main_handler = RotatingFileHandler(
            main_log,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding='utf-8'
        )
        main_handler.setLevel(logging.DEBUG)
        main_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        root.addHandler(main_handler)
        
        # === 2. Fichier quotidien (rotation par jour) ===
        daily_log = LOG_DIR / "mibombo_daily.log"
        daily_handler = TimedRotatingFileHandler(
            daily_log,
            when='midnight',
            interval=1,
            backupCount=30,  # Garder 30 jours
            encoding='utf-8'
        )
        daily_handler.setLevel(logging.INFO)
        daily_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        daily_handler.suffix = "%Y-%m-%d"
        root.addHandler(daily_handler)
        
        # === 3. Fichier erreurs uniquement ===
        error_log = LOG_DIR / "errors.log"
        error_handler = RotatingFileHandler(
            error_log,
            maxBytes=MAX_BYTES,
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(filename)s:%(lineno)d | %(message)s",
            DATE_FORMAT
        ))
        root.addHandler(error_handler)
        
        # === 4. Fichier sécurité (alertes, auth, anomalies) ===
        security_log = LOG_DIR / "security.log"
        self._security_handler = RotatingFileHandler(
            security_log,
            maxBytes=MAX_BYTES,
            backupCount=10,
            encoding='utf-8'
        )
        self._security_handler.setLevel(logging.INFO)
        self._security_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            DATE_FORMAT
        ))
        
        # === 5. Fichier capture SNMP ===
        capture_log = LOG_DIR / "capture.log"
        self._capture_handler = RotatingFileHandler(
            capture_log,
            maxBytes=MAX_BYTES * 2,  # 10 MB pour les captures
            backupCount=5,
            encoding='utf-8'
        )
        self._capture_handler.setLevel(logging.DEBUG)
        self._capture_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(message)s",
            DATE_FORMAT
        ))
    
    def get_logger(self, name: str) -> logging.Logger:
        """Récupère ou crée un logger pour un module"""
        full_name = f"MiBombo.{name}"
        
        if full_name not in self._loggers:
            logger = logging.getLogger(full_name)
            self._loggers[full_name] = logger
        
        return self._loggers[full_name]
    
    def get_security_logger(self) -> logging.Logger:
        """Logger spécialisé pour les événements de sécurité"""
        logger = self.get_logger("Security")
        if self._security_handler not in logger.handlers:
            logger.addHandler(self._security_handler)
        return logger
    
    def get_capture_logger(self) -> logging.Logger:
        """Logger spécialisé pour les captures SNMP"""
        logger = self.get_logger("Capture")
        if self._capture_handler not in logger.handlers:
            logger.addHandler(self._capture_handler)
        return logger


# === API PUBLIQUE ===

_manager = None

def _get_manager() -> MiBomboLogger:
    """Récupère le singleton du gestionnaire de logs"""
    global _manager
    if _manager is None:
        _manager = MiBomboLogger()
    return _manager


def get_logger(name: str = "App") -> logging.Logger:
    """
    Récupère un logger pour un module.
    
    Args:
        name: Nom du module (ex: "API", "PacketAnalyzer", "GUI")
    
    Returns:
        Logger configuré
    
    Example:
        logger = get_logger("MonModule")
        logger.info("Application démarrée")
        logger.debug("Variable x = %s", x)
        logger.warning("Connexion lente")
        logger.error("Erreur de parsing", exc_info=True)
    """
    return _get_manager().get_logger(name)


def get_security_logger() -> logging.Logger:
    """
    Logger pour événements de sécurité (alertes, auth, anomalies).
    Écrit dans security.log
    """
    return _get_manager().get_security_logger()


def get_capture_logger() -> logging.Logger:
    """
    Logger pour la capture SNMP.
    Écrit dans capture.log
    """
    return _get_manager().get_capture_logger()


def log_security_event(event_type: str, details: str, severity: str = "INFO"):
    """
    Log un événement de sécurité formaté.
    
    Args:
        event_type: Type d'événement (AUTH, ALERT, ANOMALY, BLOCKED, etc.)
        details: Description détaillée
        severity: INFO, WARNING, ERROR, CRITICAL
    """
    logger = get_security_logger()
    level = getattr(logging, severity.upper(), logging.INFO)
    logger.log(level, f"[{event_type}] {details}")


def log_packet_capture(ip_src: str, ip_dst: str, pdu_type: str, version: str, status: str = "OK"):
    """
    Log une capture de paquet SNMP.
    
    Args:
        ip_src: IP source
        ip_dst: IP destination
        pdu_type: Type de PDU
        version: Version SNMP
        status: OK, SUSPECT, ERROR
    """
    logger = get_capture_logger()
    msg = f"{ip_src} → {ip_dst} | SNMPv{version} | {pdu_type} | {status}"
    
    if status == "OK":
        logger.info(msg)
    elif status == "SUSPECT":
        logger.warning(msg)
    else:
        logger.error(msg)


# === INITIALISATION AUTO ===
# Créer le dossier logs au chargement du module
LOG_DIR.mkdir(parents=True, exist_ok=True)
