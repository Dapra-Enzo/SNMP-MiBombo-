from scapy.all import *

def send_snmp_response():
    print("[*] Génération d'une réponse SNMP simulée...")
    
    # Configuration
    target = "127.0.0.1"
    port = 162  # Port Trap/Response souvent écouté, ou 161
    
    # Construction du paquet SNMP Response
    # On simule une réponse à un GET
    pkt = (
        IP(src="127.0.0.1", dst=target) /
        UDP(sport=161, dport=161) /
        SNMP(
            version="v2c",
            community="public",
            PDU=SNMPresponse(
                id=123456,
                error=0,
                error_index=0,
                varbindlist=[
                    # 1. String: sysDescr.0
                    SNMPvarbind(
                        oid=ASN1_OID("1.3.6.1.2.1.1.1.0"),
                        value=ASN1_STRING("MiBombo Test Success - Value Display Works!")
                    ),
                    # 2. Integer: hrProcessorLoad
                    SNMPvarbind(
                        oid=ASN1_OID("1.3.6.1.2.1.25.3.3.1.2"),
                        value=ASN1_INTEGER(85)
                    ),
                    # 3. String: sysName.0
                    SNMPvarbind(
                        oid=ASN1_OID("1.3.6.1.2.1.1.5.0"),
                        value=ASN1_STRING("Test-Agent-VM")
                    )
                ]
            )
        )
    )
    
    # Envoi
    send(pkt, iface="lo", verbose=True)
    print(f"[*] Paquet envoyé vers {target}:161")

if __name__ == "__main__":
    send_snmp_response()
