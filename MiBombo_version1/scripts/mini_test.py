#!/usr/bin/env python3
import time
import sys
# Patch pysnmp import issues
import importlib.util, importlib.machinery, types
if not hasattr(importlib, 'util'): import importlib.util
if not hasattr(importlib, 'machinery'): import importlib.machinery
try: import imp
except ImportError:
    imp = types.ModuleType('imp')
    sys.modules['imp'] = imp
    imp.PY_SOURCE=1; imp.PKG_DIRECTORY=5; imp.C_EXTENSION=3
    imp.find_module = lambda name, path=None: (None, None, None)
    imp.load_module = lambda name, file, filename, details: importlib.import_module(name)
    imp.reload = importlib.reload
    imp.get_magic = lambda: importlib.util.MAGIC_NUMBER

from pysnmp.hlapi import *
from pysnmp.proto.rfc1902 import Integer, OctetString

TARGET = '192.168.1.254'
PORT = 161
COMMUNITY = 'public'

def send_get(oid):
    print(f"🔹 GET {oid}...")
    iterator = getCmd(SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, PORT)), ContextData(),
                      ObjectType(ObjectIdentity(oid)))
    next(iterator)

def send_set(oid, val):
    print(f"🔸 SET {oid} = {val}...")
    iterator = setCmd(SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, PORT)), ContextData(),
                      ObjectType(ObjectIdentity(oid), OctetString(val)))
    next(iterator)

def send_trap(oid, val):
    print(f"⚡ TRAP {oid} = {val}...")
    iterator = sendNotification(SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, 162)), ContextData(),
                         'trap', NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.3')).addVarBinds(
                             (oid, OctetString(val))))
    next(iterator)

if __name__ == "__main__":
    print("--- 3 GET REQUESTS ---")
    send_get('1.3.6.1.2.1.1.1.0') # sysDescr
    time.sleep(0.5)
    send_get('1.3.6.1.2.1.1.5.0') # sysName
    time.sleep(0.5)
    send_get('1.3.6.1.2.1.1.3.0') # sysUpTime
    
    print("\n--- 3 SET REQUESTS ---")
    send_set('1.3.6.1.2.1.1.6.0', 'Lab 1')  # sysLocation
    time.sleep(0.5)
    send_set('1.3.6.1.2.1.1.4.0', 'admin@mibombo.com') # sysContact
    time.sleep(0.5)
    send_set('1.3.6.1.2.1.1.6.0', 'DataCenter A') # sysLocation again
    
    print("\n--- 3 TRAPS ---")
    send_trap('1.3.6.1.2.1.1.9.1.3.1', 'Alert 1: High CPU')
    time.sleep(0.5)
    send_trap('1.3.6.1.2.1.1.9.1.3.2', 'Alert 2: Low Memory')
    time.sleep(0.5)
    send_trap('1.3.6.1.2.1.1.9.1.3.3', 'Alert 3: Fan Failure')
    
    print("\n✅ Fini ! 9 paquets envoyés.")
