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

TARGET = '127.0.0.1'
PORT = 161
USER = 'admin'
AUTH_KEY = '12345678'
PRIV_KEY = '87654321'

# V3 Setup
snmp_engine = SnmpEngine()
user_data = UsmUserData(USER, AUTH_KEY, PRIV_KEY,
                        authProtocol=usmHMACSHAAuthProtocol,
                        privProtocol=usmAesCfb128Protocol)
target = UdpTransportTarget((TARGET, PORT))
context = ContextData()

def print_break(title):
    print(f"\n{'='*20} {title} {'='*20}")

def demo_get():
    print_break("1. SNMPv3 GET (sysDescr)")
    iterator = getCmd(snmp_engine, user_data, target, context,
                      ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication: print(f"Error: {errorIndication}")
    elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds: print(f"OK: {varBind}")

def demo_set():
    print_break("2. SNMPv3 SET (sysLocation)")
    iterator = setCmd(snmp_engine, user_data, target, context,
                      ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'), OctetString('Secure Lab V3')))
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication: print(f"Error: {errorIndication}")
    elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}")
    else:
        print("SET Success!")
        for varBind in varBinds: print(f"New Value: {varBind}")

def demo_getnext_walk():
    print_break("3. SNMPv3 WALK (GetNext) - System Branch")
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            snmp_engine, user_data, target, context,
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1')), lexicographicMode=False):
        
        if errorIndication: print(f"Error: {errorIndication}"); break
        elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}"); break
        else:
            for varBind in varBinds: print(f"Walk: {varBind}")

def demo_bulk():
    print_break("4. SNMPv3 BULK (UDP Table)")
    # Bulk on 1.3.6.1.2.1.7 (UDP)
    for (errorIndication, errorStatus, errorIndex, varBinds) in bulkCmd(
            snmp_engine, user_data, target, context,
            0, 10,
            ObjectType(ObjectIdentity('1.3.6.1.2.1.7')), lexicographicMode=False):
        
        if errorIndication: print(f"Error: {errorIndication}"); break
        elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}"); break
        else:
            for varBind in varBinds: print(f"Bulk: {varBind}")

def demo_trap():
    print_break("5. SNMPv3 INFORM/TRAP")
    # Using Generic INFORM instead of TRAP for V3 usually, but let's try Notification
    # Inform requires an engineID discovery usually or configuration
    # Simple V3 Trap
    errorIndication, errorStatus, errorIndex, varBinds = next(
        sendNotification(snmp_engine, user_data, UdpTransportTarget(('127.0.0.1', 162)), context,
                         'trap', NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.4')).addVarBinds(
                             ('1.3.6.1.2.1.1.3.0', TimeTicks(99999))))
    )
    if errorIndication: print(f"Error: {errorIndication}")
    else: print("TRAP/INFORM Sent successfully")

if __name__ == "__main__":
    try:
        demo_get()
        time.sleep(0.5)
        demo_set()
        time.sleep(0.5)
        demo_getnext_walk()
        time.sleep(0.5)
        demo_bulk()
        time.sleep(0.5)
        demo_trap()
        print("\n[FIN] Tous les tests V3 sont terminés.")
    except Exception as e:
        print(f"Exception: {e}")
