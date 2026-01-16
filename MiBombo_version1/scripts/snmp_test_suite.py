#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🧪 MiBombo - SNMP Test Suite Complet                      ║
║                                                                              ║
║  Script de test professionnel pour valider toutes les fonctionnalités       ║
║  de capture et d'analyse SNMP de MiBombo Station.                           ║
║                                                                              ║
║  Supporte: v1, v2c, v3 | GET, SET, GETNEXT, GETBULK, TRAP, TRAPv2, INFORM  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import argparse
import importlib
import importlib.util
import types

# ═══════════════════════════════════════════════════════════════════════════════
# PATCH PYTHON 3.12+ (module 'imp' supprimé)
# ═══════════════════════════════════════════════════════════════════════════════
try:
    import imp
except ImportError:
    imp = types.ModuleType('imp')
    sys.modules['imp'] = imp
    imp.PY_SOURCE = 1
    imp.PKG_DIRECTORY = 5
    imp.C_EXTENSION = 3
    imp.get_magic = lambda: b'\x00\x00\x00\x00'
    def find_module(name, path=None): return None, None, None
    def load_module(name, file, filename, details): return importlib.import_module(name)
    imp.find_module = find_module
    imp.load_module = load_module
    imp.reload = importlib.reload

# Patch importlib.machinery si nécessaire
if not hasattr(importlib, 'machinery'):
    import importlib.machinery

# ═══════════════════════════════════════════════════════════════════════════════
# IMPORTS PYSNMP
# ═══════════════════════════════════════════════════════════════════════════════
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, setCmd, nextCmd, bulkCmd,
    usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
    usmAesCfb128Protocol, usmDESPrivProtocol
)
from pysnmp.hlapi import sendNotification, NotificationType

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION PAR DÉFAUT
# ═══════════════════════════════════════════════════════════════════════════════
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_PORT = 161
DEFAULT_TRAP_PORT = 162
DEFAULT_COMMUNITY = "public"
DEFAULT_V3_USER = "admin"
DEFAULT_V3_AUTH = "12345678"
DEFAULT_V3_PRIV = "87654321"

# OIDs de test standards
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
}

# ═══════════════════════════════════════════════════════════════════════════════
# COULEURS TERMINAL
# ═══════════════════════════════════════════════════════════════════════════════
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                    🧪 MiBombo - SNMP Test Suite Complet                      ║
╚══════════════════════════════════════════════════════════════════════════════╝{C.END}
""")

def section(title):
    print(f"\n{C.BLUE}{'─'*60}{C.END}")
    print(f"{C.BOLD}{C.BLUE}  {title}{C.END}")
    print(f"{C.BLUE}{'─'*60}{C.END}")

def success(msg):
    print(f"  {C.GREEN}✅ {msg}{C.END}")

def warning(msg):
    print(f"  {C.YELLOW}⚠️  {msg}{C.END}")

def error(msg):
    print(f"  {C.RED}❌ {msg}{C.END}")

def info(msg):
    print(f"  {C.CYAN}ℹ️  {msg}{C.END}")

# ═══════════════════════════════════════════════════════════════════════════════
# FONCTIONS DE TEST SNMP
# ═══════════════════════════════════════════════════════════════════════════════

def get_auth_data(version, community, user, auth_key, priv_key, auth_proto, priv_proto):
    """Retourne l'objet d'authentification selon la version"""
    if version in ("v1", "1"):
        return CommunityData(community, mpModel=0)
    elif version in ("v2c", "2"):
        return CommunityData(community, mpModel=1)
    else:  # v3
        auth_p = usmHMACSHAAuthProtocol if auth_proto.upper() == "SHA" else usmHMACMD5AuthProtocol
        priv_p = usmAesCfb128Protocol if priv_proto.upper() == "AES" else usmDESPrivProtocol
        return UsmUserData(user, auth_key, priv_key, authProtocol=auth_p, privProtocol=priv_p)


def test_get(target, port, auth_data, oid_name="sysDescr"):
    """Test SNMP GET"""
    oid = OIDS.get(oid_name, oid_name)
    info(f"GET {oid_name} ({oid})")
    
    iterator = getCmd(
        SnmpEngine(),
        auth_data,
        UdpTransportTarget((target, port), timeout=2, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    
    if errorIndication:
        warning(f"Indication: {errorIndication}")
    elif errorStatus:
        error(f"Erreur: {errorStatus.prettyPrint()}")
    else:
        for vb in varBinds:
            success(f"{vb[0].prettyPrint()} = {vb[1].prettyPrint()}")


def test_getnext(target, port, auth_data, oid_name="sysDescr"):
    """Test SNMP GETNEXT"""
    oid = OIDS.get(oid_name, oid_name)
    info(f"GETNEXT {oid_name} ({oid})")
    
    iterator = nextCmd(
        SnmpEngine(),
        auth_data,
        UdpTransportTarget((target, port), timeout=2, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    
    if errorIndication:
        warning(f"Indication: {errorIndication}")
    elif errorStatus:
        error(f"Erreur: {errorStatus.prettyPrint()}")
    else:
        for vb in varBinds:
            success(f"Next: {vb[0].prettyPrint()} = {vb[1].prettyPrint()}")


def test_getbulk(target, port, auth_data, oid_name="sysDescr", max_reps=5):
    """Test SNMP GETBULK (v2c/v3 only)"""
    oid = OIDS.get(oid_name, oid_name)
    info(f"GETBULK {oid_name} (max-repetitions={max_reps})")
    
    iterator = bulkCmd(
        SnmpEngine(),
        auth_data,
        UdpTransportTarget((target, port), timeout=2, retries=0),
        ContextData(),
        0, max_reps,  # non-repeaters, max-repetitions
        ObjectType(ObjectIdentity(oid))
    )
    
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    
    if errorIndication:
        warning(f"Indication: {errorIndication}")
    elif errorStatus:
        error(f"Erreur: {errorStatus.prettyPrint()}")
    else:
        for vb in varBinds:
            success(f"{vb[0].prettyPrint()} = {vb[1].prettyPrint()}")


def test_set(target, port, auth_data, oid_name="sysContact", value="test@mibombo.local"):
    """Test SNMP SET"""
    from pysnmp.proto.rfc1902 import OctetString
    oid = OIDS.get(oid_name, oid_name)
    info(f"SET {oid_name} = '{value}'")
    
    iterator = setCmd(
        SnmpEngine(),
        auth_data,
        UdpTransportTarget((target, port), timeout=2, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid), OctetString(value))
    )
    
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    
    if errorIndication:
        warning(f"Indication: {errorIndication}")
    elif errorStatus:
        error(f"Erreur: {errorStatus.prettyPrint()}")
    else:
        success(f"SET effectué")


def test_trap(target, port, auth_data, version):
    """Test SNMP TRAP / TRAPv2"""
    info(f"Envoi TRAP vers {target}:{port}")
    
    try:
        # Utilisation de sendNotification pour les TRAPs
        from pysnmp.hlapi import sendNotification, NotificationType
        
        iterator = sendNotification(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((target, port)),
            ContextData(),
            'trap',
            NotificationType(
                ObjectIdentity('1.3.6.1.6.3.1.1.5.1')  # coldStart
            )
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        if errorIndication:
            warning(f"Indication: {errorIndication}")
        else:
            success(f"TRAP envoyé!")
            
    except Exception as e:
        warning(f"Erreur TRAP: {e}")


def test_inform(target, port, auth_data):
    """Test SNMP INFORM (v2c/v3)"""
    info(f"Envoi INFORM vers {target}:{port}")
    
    try:
        iterator = sendNotification(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((target, port), timeout=2, retries=0),
            ContextData(),
            'inform',
            NotificationType(
                ObjectIdentity('1.3.6.1.6.3.1.1.5.1')
            )
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        if errorIndication:
            warning(f"Indication: {errorIndication}")
        else:
            success(f"INFORM envoyé!")
            
    except Exception as e:
        warning(f"Erreur INFORM: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# SCÉNARIOS DE TEST
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_all_pdu(target, port, auth_data, version):
    """Test tous les types de PDU"""
    section("🔄 Test de tous les types de PDU")
    
    test_get(target, port, auth_data)
    time.sleep(0.3)
    
    test_getnext(target, port, auth_data)
    time.sleep(0.3)
    
    if version not in ("v1", "1"):
        test_getbulk(target, port, auth_data)
        time.sleep(0.3)
    
    test_set(target, port, auth_data)
    time.sleep(0.3)


def scenario_all_versions(target, port, community, user, auth_key, priv_key):
    """Test toutes les versions SNMP"""
    section("📊 Test de toutes les versions SNMP")
    
    # v1
    info("Version: SNMPv1")
    auth_v1 = get_auth_data("v1", community, None, None, None, None, None)
    test_get(target, port, auth_v1)
    time.sleep(0.5)
    
    # v2c
    info("Version: SNMPv2c")
    auth_v2 = get_auth_data("v2c", community, None, None, None, None, None)
    test_get(target, port, auth_v2)
    time.sleep(0.5)
    
    # v3
    info("Version: SNMPv3 (authPriv)")
    auth_v3 = get_auth_data("v3", None, user, auth_key, priv_key, "SHA", "AES")
    test_get(target, port, auth_v3)


def scenario_stress(target, port, auth_data, count=10):
    """Test de charge"""
    section(f"⚡ Test de charge ({count} requêtes)")
    
    start = time.time()
    for i in range(count):
        test_get(target, port, auth_data, "sysUpTime")
    elapsed = time.time() - start
    
    info(f"Temps total: {elapsed:.2f}s ({count/elapsed:.1f} req/s)")


# ═══════════════════════════════════════════════════════════════════════════════
# MENU INTERACTIF
# ═══════════════════════════════════════════════════════════════════════════════

def interactive_menu(args):
    """Menu interactif pour choisir les tests"""
    banner()
    
    print(f"{C.BOLD}Configuration actuelle:{C.END}")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Version: {args.version}")
    if args.version in ("v1", "v2c", "1", "2"):
        print(f"  Community: {args.community}")
    else:
        print(f"  User: {args.user} | Auth: {args.auth_proto}/{args.auth_key[:4]}*** | Priv: {args.priv_proto}/{args.priv_key[:4]}***")
    
    print(f"""
{C.BOLD}╔═══════════════════════════════════════════╗
║          Choisissez un test:              ║
╠═══════════════════════════════════════════╣
║  1. GET         - Requête simple          ║
║  2. GETNEXT     - Requête suivante        ║
║  3. GETBULK     - Requête bulk (v2c/v3)   ║
║  4. SET         - Modification            ║
║  5. TRAP        - Notification            ║
║  6. INFORM      - Notification confirmée  ║
╠═══════════════════════════════════════════╣
║  A. Tous les PDU (scénario complet)       ║
║  V. Toutes les versions (v1, v2c, v3)     ║
║  S. Test de stress (10 requêtes)          ║
╠═══════════════════════════════════════════╣
║  Q. Quitter                               ║
╚═══════════════════════════════════════════╝{C.END}
""")
    
    auth_data = get_auth_data(
        args.version, args.community, args.user,
        args.auth_key, args.priv_key, args.auth_proto, args.priv_proto
    )
    
    while True:
        try:
            choice = input(f"{C.CYAN}Votre choix > {C.END}").strip().upper()
            
            if choice == "1":
                test_get(args.target, args.port, auth_data)
            elif choice == "2":
                test_getnext(args.target, args.port, auth_data)
            elif choice == "3":
                if args.version in ("v1", "1"):
                    warning("GETBULK n'est pas disponible en SNMPv1")
                else:
                    test_getbulk(args.target, args.port, auth_data)
            elif choice == "4":
                test_set(args.target, args.port, auth_data)
            elif choice == "5":
                test_trap(args.target, args.trap_port, auth_data, args.version)
            elif choice == "6":
                if args.version in ("v1", "1"):
                    warning("INFORM n'est pas disponible en SNMPv1")
                else:
                    test_inform(args.target, args.trap_port, auth_data)
            elif choice == "A":
                scenario_all_pdu(args.target, args.port, auth_data, args.version)
            elif choice == "V":
                scenario_all_versions(args.target, args.port, args.community, 
                                     args.user, args.auth_key, args.priv_key)
            elif choice == "S":
                scenario_stress(args.target, args.port, auth_data)
            elif choice == "Q":
                print(f"\n{C.GREEN}👋 À bientôt!{C.END}\n")
                break
            else:
                warning("Choix invalide")
                
        except KeyboardInterrupt:
            print(f"\n{C.GREEN}👋 Interruption...{C.END}\n")
            break


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🧪 MiBombo SNMP Test Suite - Test complet de toutes les fonctionnalités SNMP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s                              # Mode interactif (défaut)
  %(prog)s --version v2c --test get     # Test GET en v2c
  %(prog)s --version v3 --test all      # Tous les tests en v3
  %(prog)s --target 192.168.1.1 --test stress  # Test de charge
        """
    )
    
    # Cible
    parser.add_argument("-t", "--target", default=DEFAULT_TARGET, help="Adresse IP cible")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port SNMP (défaut: 161)")
    parser.add_argument("--trap-port", type=int, default=DEFAULT_TRAP_PORT, help="Port TRAP (défaut: 162)")
    
    # Version
    parser.add_argument("-v", "--version", choices=["v1", "v2c", "v3", "1", "2", "3"], 
                       default="v3", help="Version SNMP (défaut: v3)")
    
    # Auth v1/v2c
    parser.add_argument("-c", "--community", default=DEFAULT_COMMUNITY, help="Community string (v1/v2c)")
    
    # Auth v3
    parser.add_argument("-u", "--user", default=DEFAULT_V3_USER, help="Utilisateur USM (v3)")
    parser.add_argument("--auth-key", default=DEFAULT_V3_AUTH, help="Clé d'authentification (v3)")
    parser.add_argument("--priv-key", default=DEFAULT_V3_PRIV, help="Clé de chiffrement (v3)")
    parser.add_argument("--auth-proto", choices=["SHA", "MD5"], default="SHA", help="Protocole auth")
    parser.add_argument("--priv-proto", choices=["AES", "DES"], default="AES", help="Protocole priv")
    
    # Test à exécuter
    parser.add_argument("--test", choices=["get", "getnext", "getbulk", "set", "trap", "inform", 
                                           "all", "versions", "stress", "interactive"],
                       default="interactive", help="Test à exécuter (défaut: interactive)")
    
    # Options
    parser.add_argument("--count", type=int, default=10, help="Nombre de requêtes pour stress test")
    parser.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux")
    
    args = parser.parse_args()
    
    # Normaliser version
    if args.version == "1": args.version = "v1"
    if args.version == "2": args.version = "v2c"
    if args.version == "3": args.version = "v3"
    
    # Exécuter
    if args.test == "interactive":
        interactive_menu(args)
    else:
        banner()
        auth_data = get_auth_data(
            args.version, args.community, args.user,
            args.auth_key, args.priv_key, args.auth_proto, args.priv_proto
        )
        
        if args.test == "get":
            test_get(args.target, args.port, auth_data)
        elif args.test == "getnext":
            test_getnext(args.target, args.port, auth_data)
        elif args.test == "getbulk":
            test_getbulk(args.target, args.port, auth_data)
        elif args.test == "set":
            test_set(args.target, args.port, auth_data)
        elif args.test == "trap":
            test_trap(args.target, args.trap_port, auth_data, args.version)
        elif args.test == "inform":
            test_inform(args.target, args.trap_port, auth_data)
        elif args.test == "all":
            scenario_all_pdu(args.target, args.port, auth_data, args.version)
        elif args.test == "versions":
            scenario_all_versions(args.target, args.port, args.community,
                                 args.user, args.auth_key, args.priv_key)
        elif args.test == "stress":
            scenario_stress(args.target, args.port, auth_data, args.count)


if __name__ == "__main__":
    main()
