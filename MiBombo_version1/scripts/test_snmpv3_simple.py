#!/usr/bin/env python3
import asyncio
import sys
import importlib
import importlib.util
import types

# --- PATCH FOR PYTHON 3.12+ SUPPORT (implib/imp) ---
# Fix 1: Ensure importlib.util is available
if not hasattr(importlib, 'util'):
    import importlib.util

# Fix 2: Emulate 'imp' module if missing (removed in Py3.12)
try:
    import imp
except ImportError:
    imp = types.ModuleType('imp')
    sys.modules['imp'] = imp
    
    # Minimal implementation for PySNMP
    imp.PY_SOURCE = 1
    imp.PKG_DIRECTORY = 5
    imp.C_EXTENSION = 3
    
    def find_module(name, path=None):
        return None, None, None
        
    def load_module(name, file, filename, details):
        return importlib.import_module(name)
        
    imp.find_module = find_module
    imp.load_module = load_module
    imp.reload = importlib.reload

from pysnmp.hlapi import *

def run():
    print("🚀 Envoi d'un paquet SNMPv3 (authPriv) vers 127.0.0.1:161...")
    
    # Configuration correspondant à votre utilisateur 'admin'
    
    snmp_engine = SnmpEngine()
    
    # Données utilisateur USM
    user_data = UsmUserData(
        'admin', 
        '12345678', 
        '87654321',
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmAesCfb128Protocol
    )
    
    # Cible (Target)
    target = UdpTransportTarget(('127.0.0.1', 161), timeout=1.0, retries=0)
    
    # OID à demander (sysDescr)
    var_bind = ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
    
    print(f"📦 Contenu chiffré: GET OID 1.3.6.1.2.1.1.1.0")
    
    try:
        # Version Synchrone pour pysnmp 4.x
        iterator = getCmd(
            snmp_engine,
            user_data,
            target,
            ContextData(),
            var_bind
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            print(f"⏱️  Résultat (côté émetteur): {errorIndication}")
            print("(C'est normal si 'No SNMP response received' car vous n'avez pas d'agent SNMP qui écoute,")
            print(" l'important est que MiBombo ait capturé le paquet !)")
        elif errorStatus:
            print(f"❌ Erreur SNMP: {errorStatus.prettyPrint()}")
        else:
            for varBind in varBinds:
                print(f"✅ Réponse reçue: {varBind}")
                
    except Exception as e:
        print(f"⚠️ Erreur d'exécution: {e}")

    print("\n👉 Vérifiez maintenant dans MiBombo (Interface 'lo') si le paquet est apparu et DÉCHIFFRÉ (cadenas vert/ouvert) !")

if __name__ == "__main__":
    run()
