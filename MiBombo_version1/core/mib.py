"""
Module de traduction OID -> Nom (MIB)
Contient les définitions pour SNMPv2-MIB et autres standards courants.
"""

MIB_MAP = {
    # === SYSTEM ===
    "1.3.6.1.2.1.1.1.0": "sysDescr.0",
    "1.3.6.1.2.1.1.2.0": "sysObjectID.0",
    "1.3.6.1.2.1.1.3.0": "sysUpTime.0",
    "1.3.6.1.2.1.1.4.0": "sysContact.0",
    "1.3.6.1.2.1.1.5.0": "sysName.0",
    "1.3.6.1.2.1.1.6.0": "sysLocation.0",
    "1.3.6.1.2.1.1.7.0": "sysServices.0",

    # === INTERFACES ===
    "1.3.6.1.2.1.2.1.0": "ifNumber.0",
    
    # === IP ===
    "1.3.6.1.2.1.4.1.0": "ipForwarding.0",
    "1.3.6.1.2.1.4.2.0": "ipDefaultTTL.0",

    # === HOST-RESOURCES ===
    "1.3.6.1.2.1.25.3.3.1.2": "hrProcessorLoad",

    # === TRAPS ===
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID.0",
    "1.3.6.1.6.3.1.1.4.3.0": "snmpTrapEnterprise.0",
}

# Prefixes pour les tables (si match exact échoue)
MIB_PREFIXES = {
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.4": "ifMtu",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.2.2.1.9": "ifLastChange",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.11": "ifInUcastPkts",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.17": "ifOutUcastPkts",
}

def translate_oid(oid: str) -> str:
    """Traduit un OID en nom lisible."""
    if not oid:
        return "N/A"
        
    oid = str(oid).strip()
    
    # 1. Match Exact
    if oid in MIB_MAP:
        return MIB_MAP[oid]
    
    # 2. Match Prefix (pour les tables)
    # On cherche le préfixe le plus long
    best_match = None
    best_len = 0
    
    for prefix, name in MIB_PREFIXES.items():
        if oid.startswith(prefix) and len(prefix) > best_len:
            # Vérifier que le reste est un index (points)
            remainder = oid[len(prefix):]
            if remainder.startswith("."):
                best_match = f"{name}{remainder}"
                best_len = len(prefix)
    
    if best_match:
        return best_match
        
    # 3. Fallback
    return oid
