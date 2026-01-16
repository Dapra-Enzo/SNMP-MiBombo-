#!/usr/bin/env python3
"""
MiBombo Station - Oral Defense Demo Script
Simplified SNMP Simulator for live demonstration.
"""

import sys
import os
import time
import random

try:
    from scapy.all import *
    from scapy.layers.snmp import SNMP, SNMPget, SNMPnext, SNMPset, SNMPresponse, SNMPvarbind
    # SNMPv3 is handled by PySNMP, no need to import Scapy v3 layers here which might fail
except ImportError:
    print("Erreur: Scapy n'est pas installé sur ce Python.")
    print("Essayez: sudo apt install python3-scapy")
    sys.exit(1)

if os.geteuid() != 0:
    print("Erreur: Ce script doit être lancé avec sudo.")
    sys.exit(1)

# CONFIGURATION
TARGET_IP = "127.0.0.1"
COMMUNITY = "public"
V3_USER = "admin"
V3_AUTH_PROTO = "SHA"
V3_AUTH_KEY = "12345678"
V3_PRIV_PROTO = "AES"
V3_PRIV_KEY = "87654321"

OIDS = [
    "1.3.6.1.2.1.1.1.0", # sysDescr
    "1.3.6.1.2.1.1.5.0", # sysName
    "1.3.6.1.2.1.2.2.1.10.1", # ifInOctets
]

def send_v2(pkt_type="get", count=1):
    print(f"[*] Envoi de {count} paquets SNMPv2 ({pkt_type})...")
    for _ in range(count):
        oid = random.choice(OIDS)
        ip = IP(dst=TARGET_IP)
        udp = UDP(sport=random.randint(40000, 60000), dport=161)
        
        if pkt_type == "get":
            pdu = SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))])
        elif pkt_type == "set":
            pdu = SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_INTEGER(1))])
        elif pkt_type == "response":
            pdu = SNMPresponse(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_STRING("MiBombo-Device"))])
        elif pkt_type == "walk":
            pdu = SNMPnext(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))])
            
        pkt = ip / udp / SNMP(version=1, community=COMMUNITY, PDU=pdu)
        send(pkt, verbose=0)
        time.sleep(0.5)

# --- PYBMBO SNMV3 ENGINE (PySNMP) ---
import asyncio
import importlib.util
import types

# Emulate 'imp' module for PySNMP if missing (Python 3.12+)
try:
    import imp
except ImportError:
    imp = types.ModuleType('imp')
    sys.modules['imp'] = imp
    imp.PY_SOURCE, imp.PKG_DIRECTORY, imp.C_EXTENSION = 1, 5, 3
    def find_module(name, path=None): return None, None, None
    def load_module(name, file, filename, details): return importlib.import_module(name)
    imp.find_module, imp.load_module, imp.reload = find_module, load_module, importlib.reload

from pysnmp.hlapi import *

def send_v3(pkt_type="get", count=1):
    print(f"[*] Envoi de {count} paquets SNMPv3 ({pkt_type})...")
    print(f"    [SEC] User: {V3_USER}, Auth: {V3_AUTH_PROTO}, Priv: {V3_PRIV_PROTO}")
    
    snmp_engine = SnmpEngine()
    user_data = UsmUserData(
        V3_USER, V3_AUTH_KEY, V3_PRIV_KEY,
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmAesCfb128Protocol
    )
    target = UdpTransportTarget((TARGET_IP, 161), timeout=1.0, retries=0)
    
    for _ in range(count):
        if pkt_type == "get":
            # Requête GET classique (chiffrée)
            print(f"    -> Sending encrypted GET (sysDescr)")
            iterator = getCmd(snmp_engine, user_data, target, ContextData(),
                              ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
            next(iterator)
        else:
            # Simulation de RÉPONSE
            print(f"    -> Sending encrypted RESPONSE simulation with content")
            user_content = 'MiBombo-Station-V3-Secure-Response-OK'
            iterator = sendNotification(
                snmp_engine, user_data, target, ContextData(), 'trap',
                NotificationType(ObjectIdentity('1.3.6.1.2.1.1.1.0')).addVarBinds(
                    ('1.3.6.1.2.1.1.1.0', OctetString(user_content))
                )
            )
            next(iterator)
            print(f"       [CONTENT] {user_content}")
        
        time.sleep(0.5)

def attack_flood(count=100):
    print(f"[!] LANCEMENT ATTACK FLOOD ({count} paquets)...")
    src_ip = "10.0.0." + str(random.randint(2, 254))
    for i in range(count):
        pkt = IP(src=src_ip, dst=TARGET_IP)/UDP(dport=161)/SNMP(community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid="1.3.6.1.2.1.1.1.0")]))
        send(pkt, verbose=0)
        if i % 10 == 0: print(f"Sent {i}/{count}...")
    print("[+] Flood terminé.")

def attack_bruteforce(count=20):
    print(f"[!] LANCEMENT BRUTEFORCE COMMUNAUTÉS ({count} tentatives)...")
    bad_coms = ["admin", "root", "cisco", "password", "1234", "secret", "private"]
    for i in range(count):
        com = random.choice(bad_coms)
        pkt = IP(dst=TARGET_IP)/UDP(dport=161)/SNMP(community=com, PDU=SNMPget(varbindlist=[SNMPvarbind(oid="1.3.6.1.2.1.1.1.0")]))
        send(pkt, verbose=0)
        print(f"Try community: {com}")
        time.sleep(0.2)

def main():
    global TARGET_IP
    print("\n--- MIBOMBO ORAL SIMULATOR ---")
    TARGET_IP = input(f"IP Cible [{TARGET_IP}] : ") or TARGET_IP
    
    while True:
        print("\n--- MENU DEMO ---")
        print("1. SNMPv2 : Get (Trame Normale)")
        print("2. SNMPv2 : Set (Modification)")
        print("3. SNMPv2 : Walk (Exploration)")
        print("4. SNMPv3 : Get (Sécurisé)")
        print("5. SNMPv3 : Response (Sécurisé)")
        print("6. ATTAQUE : Flood (Déni de service)")
        print("7. ATTAQUE : Bruteforce (Dictionnaire)")
        print("Q. Quitter")
        
        choice = input("\nChoix : ").upper()
        
        if choice == "1": send_v2("get", 5)
        elif choice == "2": send_v2("set", 2)
        elif choice == "3": send_v2("walk", 5)
        elif choice == "4": send_v3("get", 5)
        elif choice == "5": send_v3("response", 5)
        elif choice == "6": attack_flood(100)
        elif choice == "7": attack_bruteforce(15)
        elif choice == "Q": break
        else: print("Choix invalide.")

if __name__ == "__main__":
    main()
