#!/usr/bin/env python3
"""
=============================================================================
verify_snmpv3_complete.py
Environnement de test professionnel SNMPv3 complet.

Ce script:
1. Démarre un agent SNMPv3 embarqué avec les credentials de test
2. Envoie des requêtes GET chiffrées (authPriv)
3. Affiche le trafic capturé pour vérification

Auteur: MiBombo Team
=============================================================================
"""

import sys
import os
import time
import threading
import importlib
import importlib.util
import types

# --- PATCH PYTHON 3.12+ (imp module removed) ---
try:
    import imp
except ImportError:
    imp = types.ModuleType('imp')
    sys.modules['imp'] = imp
    imp.PY_SOURCE = 1
    imp.PKG_DIRECTORY = 5
    imp.C_EXTENSION = 3
    def find_module(name, path=None): return None, None, None
    def load_module(name, file, filename, details): return importlib.import_module(name)
    imp.find_module = find_module
    imp.load_module = load_module
    imp.reload = importlib.reload

# --- IMPORTS PYSNMP ---
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.hlapi import (
    SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol
)
from pysnmp.smi import builder, view, rfc1902
from pysnmp.proto.api import v2c

# --- CONFIGURATION ---
AGENT_PORT = 10161  # Port non-privilégié pour l'agent de test
USM_USER = 'admin'
AUTH_KEY = '12345678'
PRIV_KEY = '87654321'
OID_SYSDESCR = '1.3.6.1.2.1.1.1.0'

class SNMPv3Agent(threading.Thread):
    """Agent SNMPv3 embarqué avec support authPriv"""
    
    def __init__(self, port=AGENT_PORT):
        super().__init__(daemon=True)
        self.port = port
        self.running = False
        self._engine = None
        
    def run(self):
        print(f"[AGENT] Démarrage agent SNMPv3 sur 127.0.0.1:{self.port}...")
        
        # 1. Créer le moteur SNMP
        self._engine = engine.SnmpEngine()
        
        # 2. Configurer le transport UDP
        config.addTransport(
            self._engine,
            udp.domainName,
            udp.UdpTransport().openServerMode(('127.0.0.1', self.port))
        )
        
        # 3. Configurer l'utilisateur USM (SNMPv3)
        config.addV3User(
            self._engine,
            USM_USER,
            config.usmHMACSHAAuthProtocol,
            AUTH_KEY,
            config.usmAesCfb128Protocol,
            PRIV_KEY
        )
        
        # 4. Autoriser l'accès en lecture
        config.addVacmUser(
            self._engine, 3, USM_USER, 'authPriv',
            (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1)
        )
        
        # 5. Créer le contexte SNMP
        snmpContext = context.SnmpContext(self._engine)
        
        # 6. Enregistrer les handlers de commandes
        cmdrsp.GetCommandResponder(self._engine, snmpContext)
        cmdrsp.NextCommandResponder(self._engine, snmpContext)
        
        print(f"[AGENT] ✅ Agent prêt! User: {USM_USER}, Auth: SHA, Priv: AES")
        self.running = True
        
        # 7. Boucle principale
        try:
            self._engine.transportDispatcher.jobStarted(1)
            self._engine.transportDispatcher.runDispatcher()
        except:
            pass
        finally:
            self._engine.transportDispatcher.closeDispatcher()
            
    def stop(self):
        if self._engine:
            self._engine.transportDispatcher.jobFinished(1)
        self.running = False


def send_snmpv3_request():
    """Envoie une requête SNMPv3 authPriv réelle"""
    print(f"\n[CLIENT] Envoi requête GET vers 127.0.0.1:{AGENT_PORT}...")
    print(f"[CLIENT] OID: {OID_SYSDESCR}")
    print(f"[CLIENT] User: {USM_USER}, Auth: SHA/{AUTH_KEY}, Priv: AES/{PRIV_KEY}")
    
    snmp_engine = SnmpEngine()
    
    user_data = UsmUserData(
        USM_USER,
        AUTH_KEY,
        PRIV_KEY,
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmAesCfb128Protocol
    )
    
    target = UdpTransportTarget(('127.0.0.1', AGENT_PORT), timeout=2, retries=1)
    
    iterator = getCmd(
        snmp_engine,
        user_data,
        target,
        ContextData(),
        ObjectType(ObjectIdentity(OID_SYSDESCR))
    )
    
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    
    if errorIndication:
        print(f"[CLIENT] ⚠️ Indication: {errorIndication}")
    elif errorStatus:
        print(f"[CLIENT] ❌ Erreur: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds:
            print(f"[CLIENT] ✅ Réponse: {varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}")


def main():
    print("=" * 70)
    print("   VERIFICATION SNMPv3 COMPLETE - MiBombo Station")
    print("=" * 70)
    print()
    print("Ce script démarre un agent SNMPv3 local et envoie des requêtes")
    print("chiffrées pour générer du vrai trafic authPriv.")
    print()
    
    # 1. Démarrer l'agent
    agent = SNMPv3Agent(port=AGENT_PORT)
    agent.start()
    
    # Attendre que l'agent soit prêt
    timeout = 5
    while not agent.running and timeout > 0:
        time.sleep(0.5)
        timeout -= 0.5
    
    if not agent.running:
        print("[!] ERREUR: L'agent n'a pas démarré!")
        return
    
    print()
    print("-" * 70)
    print("IMPORTANT: Assurez-vous que MiBombo écoute sur 'lo' avec le filtre:")
    print(f"   udp port {AGENT_PORT} or udp port 161 or udp port 162")
    print("-" * 70)
    print()
    input("Appuyez sur ENTER quand MiBombo est prêt...")
    
    # 2. Envoyer des requêtes
    for i in range(3):
        print(f"\n--- Requête {i+1}/3 ---")
        send_snmpv3_request()
        time.sleep(1)
    
    # 3. Arrêter
    print()
    print("=" * 70)
    print("✅ Test terminé! Vérifiez dans MiBombo:")
    print("   - Les paquets doivent être VERSION: SNMPv3")
    print("   - Security Level: authPriv")
    print("   - Decrypt Status: SUCCESS (si les credentials sont configurés)")
    print("=" * 70)
    
    agent.stop()


if __name__ == "__main__":
    main()
