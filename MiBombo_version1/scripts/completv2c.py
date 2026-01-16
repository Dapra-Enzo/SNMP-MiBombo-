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
COMMUNITY = 'private' # RW community needed for SET

def print_break(title):
    print(f"\n{'='*20} {title} {'='*20}")

def demo_get():
    print_break("1. SNMP GET (sysDescr)")
    iterator = getCmd(SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, PORT)), ContextData(),
                      ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication: print(f"Error: {errorIndication}")
    elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds: print(f"OK: {varBind}")

def demo_set():
    print_break("2. SNMP SET (sysLocation)")
    # Tenter de changer sysLocation
    iterator = setCmd(SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, PORT)), ContextData(),
                      ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'), OctetString('MiBombo Lab')))
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication: print(f"Error: {errorIndication}")
    elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}")
    else:
        print("SET Success!")
        for varBind in varBinds: print(f"New Value: {varBind}")

def demo_getnext_walk():
    print_break("3. SNMP WALK (GetNext) - System Branch")
    # Walk on 1.3.6.1.2.1.1 (System)
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, PORT)), ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1')), lexicographicMode=False):
        
        if errorIndication: print(f"Error: {errorIndication}"); break
        elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}"); break
        else:
            for varBind in varBinds: print(f"Walk: {varBind}")

def demo_bulk():
    print_break("4. SNMP BULK (TCP Table)")
    # Bulk on 1.3.6.1.2.1.6 (TCP)
    for (errorIndication, errorStatus, errorIndex, varBinds) in bulkCmd(
            SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget((TARGET, PORT)), ContextData(),
            0, 20, # Non-repeaters, Max-repetitions
            ObjectType(ObjectIdentity('1.3.6.1.2.1.6')), lexicographicMode=False):
        
        if errorIndication: print(f"Error: {errorIndication}"); break
        elif errorStatus: print(f"SNMP Error: {errorStatus.prettyPrint()}"); break
        else:
            for varBind in varBinds: print(f"Bulk: {varBind}")

def demo_trap():
    print_break("5. SNMP TRAP (V2c Notification)")
    # Sending trap to port 162 (standard trap port)
    # Note: MiBombo sniffer usually listens on 161/162.
    errorIndication, errorStatus, errorIndex, varBinds = next(
        sendNotification(SnmpEngine(), CommunityData(COMMUNITY), UdpTransportTarget(('127.0.0.1', 162)), ContextData(),
                         'trap', NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.3')).addVarBinds(
                             ('1.3.6.1.2.1.1.3.0', TimeTicks(12345))))
    )
    if errorIndication: print(f"Error: {errorIndication}")
    else: print("TRAP Sent successfully (check sniffer on port 162)")

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
        print("\n[FIN] Tous les tests V2c sont terminés.")
    except Exception as e:
        print(f"Exception: {e}")
