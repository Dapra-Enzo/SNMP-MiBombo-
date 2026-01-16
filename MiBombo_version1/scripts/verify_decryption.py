
import os
import sys
import threading
import time
import subprocess
from queue import Queue
from unittest.mock import MagicMock

# Environment & Keys
from cryptography.fernet import Fernet
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
from dotenv import load_dotenv
load_dotenv()

from core.analyzer import PacketAnalyzer
from core.snmp_credentials import snmp_cred_mgr

# Scapy
from scapy.all import sniff, UDP

# PySNMP Agent imports
try:
    from pysnmp.entity import engine, config
    from pysnmp.entity.rfc3413 import cmdrsp, context
    from pysnmp.carrier.asyncore.dgram import udp
    from pysnmp.proto.api import v2c
except ImportError:
    print("PySNMP missing for Agent setup")
    sys.exit(1)

def run_agent():
    print("[Agent] Starting SNMPv3 Agent on 127.0.0.1:16161...")
    snmpEngine = engine.SnmpEngine()
    
    # Transport
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('127.0.0.1', 16161))
    )
    
    # User: admin, SHA, 12345678, AES, 87654321
    config.addV3User(
        snmpEngine, 'admin',
        config.usmHMACSHAAuthProtocol, '12345678',
        config.usmAesCfb128Protocol, '87654321'
    )
    
    # Context
    snmpContext = context.SnmpContext(snmpEngine)
    
    # Allow access
    config.addVacmUser(snmpEngine, 3, 'admin', 'authPriv', (1,3,6), (1,3,6)) 
    
    # Apps
    cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
    
    # Run
    try:
        snmpEngine.transportDispatcher.jobStarted(1)
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        pass

def run_sender():
    time.sleep(3)
    print("[Sender] Sending Encrypted Packet...")
    subprocess.run([
        "./venv/bin/python", "scripts/mIbombo.py",
        "--scenario", "snmpv3",
        "--target", "127.0.0.1",
        "--port", "16161",
        "--v3-user", "admin",
        "--v3-level", "authPriv",
        "--v3-authproto", "sha", "--v3-authkey", "12345678",
        "--v3-privproto", "aes", "--v3-privkey", "87654321",
        "--duration", "2",
        "--delay", "0.5"
    ])

if __name__ == "__main__":
    # 1. Add User to Cred Manager (for PacketAnalyzer)
    snmp_cred_mgr.add_user("admin", "SHA", "12345678", "AES", "87654321")
    print("[+] User 'admin' added to store.")
    
    # 2. Start Agent Thread
    t_agent = threading.Thread(target=run_agent, daemon=True)
    t_agent.start()
    
    # 3. Start Sender Thread
    t_sender = threading.Thread(target=run_sender, daemon=True)
    t_sender.start()
    
    # 4. Sniff
    print("[*] Sniffing on loopback port 16161...")
    pkts = sniff(iface="lo", filter="udp port 16161", count=15, timeout=12)
    
    if pkts:
        print(f"[+] Captured {len(pkts)} packet(s). Analyzing...")
        analyser = PacketAnalyzer(Queue(), MagicMock())
        analyser.baseDB = MagicMock()
        
        found_encrypted = False
        encrypted_count = 0
        
        for i, pkt in enumerate(pkts):
            res = {
                "time_stamp": str(time.time()),
                "ip_src": "127.0.0.1", "ip_dst": "127.0.0.1", "protocol": "SNMPv3",
                "len": 100, "info": "", "is_encrypted": False, "is_authenticated": False,
                "snmp_usm_user_name": None
            }
            try:
                # Basic check if it's UDP payload (Scapy sometimes captures CookedLinux)
                if UDP in pkt:
                    res = analyser._parse_snmpv3(pkt, res)
                    
                    if res.get("is_encrypted"):
                        encrypted_count += 1
                        found_encrypted = True
                        print(f"Packet {i+1}: ENCRYPTED | User: {res.get('snmp_usm_user_name')} | Status: {res.get('decryption_status')}")
                        if res.get("decryption_status") == "SUCCESS":
                             print("   -> VARBINDS LOCATED: ", res.get("snmp_oidsValues"))
                             print("\n✅ VERIFICATION SUCCESSFUL: Full Decryption Verified!")
                             sys.exit(0)
            except Exception as e:
                pass

        if found_encrypted:
             print("\n❌ VERIFICATION FAILED: Encrypted packet found but not decrypted.")
             sys.exit(1)
        else:
             print("\n❌ VERIFICATION FAILED: No encrypted packet found (Handshake failed?).")
             sys.exit(1)
            
    else:
        print("❌ No packets captured.")
        sys.exit(1)
