from scapy.all import *

bind_layers(UDP, SNMP, sport=161)
bind_layers(UDP, SNMP, dport=161)

def pkt_callback(pkt):
    print("PACKET CAPTURED:")
    
    # Method 1: Original attribute
    if hasattr(pkt, 'original') and pkt.original:
        print(f"HAS ORIGINAL: {len(pkt.original)} bytes")
        print(f"HEX: {pkt.original.hex()}")
        # Check for V3 signature in whole packet
        if b"\x02\x01\x03" in pkt.original:
            print("FOUND V3 SIGNATURE IN ORIGINAL!")
        else:
            print("NO V3 SIGNATURE IN ORIGINAL.")
    else:
        print("NO PKT.ORIGINAL")

    # Method 2: UDP payload via bytes()
    if UDP in pkt:
        payload = bytes(pkt[UDP].payload)
        print(f"UDP PAYLOAD BYTES: {payload.hex()}")
        if b"\x02\x01\x03" in payload:
             print("FOUND V3 SIGNATURE IN UDP PAYLOAD REBUILD")
        else:
             print("NO V3 SIGNATURE IN UDP PAYLOAD REBUILD")

    if SNMP in pkt:
        print(f"SCAPY VERSION: {pkt[SNMP].version}")

print("Sniffing on lo...")
sniff(iface="lo", filter="udp port 161", count=1, prn=pkt_callback)
