from queue import Queue
from scapy.all import *
from scapy.layers.snmp import SNMP
# SNMPv3 classes not available in this scapy version, using raw parsing fallbacks or will define if needed
SNMPv3 = None
SNMPv3USMData = None
SNMPv3ScopedPDU = None
from datetime import datetime
import os
import json
import hashlib
import binascii

# Import relatif pour utilisation en module
try:
    from . import PostgresDB
    from .snmp_credentials import snmp_cred_mgr
    from .logger import get_logger, log_packet_capture, log_security_event
except ImportError:
    import core.PostgresDB as PostgresDB
    from core.snmp_credentials import snmp_cred_mgr
    from core.logger import get_logger, log_packet_capture, log_security_event

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# PySNMP imports for key localization (if avl) or manual implementation
import hmac

# Logger pour ce module
logger = get_logger("PacketAnalyzer")


# =============================================================================
# CONSTANTES SNMPv3
# =============================================================================

# Protocoles d'authentification
AUTH_PROTOCOLS = {
    "1.3.6.1.6.3.10.1.1.1": "noAuth",
    "1.3.6.1.6.3.10.1.1.2": "HMAC-MD5-96",
    "1.3.6.1.6.3.10.1.1.3": "HMAC-SHA-96",
    "1.3.6.1.6.3.10.1.1.4": "HMAC-SHA-224",
    "1.3.6.1.6.3.10.1.1.5": "HMAC-SHA-256",
    "1.3.6.1.6.3.10.1.1.6": "HMAC-SHA-384",
    "1.3.6.1.6.3.10.1.1.7": "HMAC-SHA-512",
}

# Protocoles de chiffrement (Privacy)
PRIV_PROTOCOLS = {
    "1.3.6.1.6.3.10.1.2.1": "noPriv",
    "1.3.6.1.6.3.10.1.2.2": "DES",
    "1.3.6.1.6.3.10.1.2.3": "3DES-EDE",
    "1.3.6.1.6.3.10.1.2.4": "AES-128-CFB",
    "1.3.6.1.6.3.10.1.2.5": "AES-192-CFB",
    "1.3.6.1.6.3.10.1.2.6": "AES-256-CFB",
}

# Security Levels
SECURITY_LEVELS = {
    0: "noAuthNoPriv",
    1: "authNoPriv", 
    3: "authPriv"
}


class PacketAnalyzer(object):
    """
    Analyse les trames stockées dans la FILE puis envoie les résultats sur une base de donnée
    Applique les filtres définis dans la configuration fournie.
    Supporte SNMPv1, SNMPv2c et SNMPv3.
    """
    def __init__(self, queue:Queue, baseDB, config:dict=None, pcap_dir="captures", lenPcap:int=100):
        self.queue = queue
        self.baseDB = baseDB
        self.config = config if config else {}
        self.pcap_dir = pcap_dir
        self.lenPcap = lenPcap
        self.nb_pkt = 0
        self.file_index = 0
        self.pcap_writer = None

        # Init InfluxDB Wrapper via import dynamique pour eviter cycle
        try:
            from core.influx_wrapper import InfluxWrapper
            self.influx = InfluxWrapper.get_instance()
        except ImportError:
            pass

        # Initialisation des tables en base de données (V1, V2, V3)
        self.baseDB.initDB()

        os.makedirs(pcap_dir, exist_ok=True)
        self.open_new_pcap()

    def open_new_pcap(self):
        if self.pcap_writer:
            self.pcap_writer.close()
        filename = os.path.join(self.pcap_dir, f"capture_{self.file_index:04d}.pcap")
        self.pcap_writer = PcapWriter(filename, append=False, sync=False)
        self.file_index += 1
        self.nb_pkt = 0

    def convert_asn1(self, obj):
        if obj is None: return ""
        # print(f"[DEBUG ASN1] Type: {type(obj)} Repr: {repr(obj)}")
        
        # 1. Gestion spécifique ASN1_NULL (Scapy)
        if "ASN1_NULL" in str(type(obj)):
            return ""
            
        # 2. Gestion ASN1_STRING / bytes qui sont souvent des poubelles si non-ascii
        if hasattr(obj, "val"):
            if obj.val is None: return ""
            
            # Si c'est des bytes, on check si c'est printable
            if isinstance(obj.val, bytes):
                try:
                    return obj.val.decode('utf-8')
                except:
                    # Si binaire pur -> Hex ou string vide
                    return f"<BINARY: {len(obj.val)} bytes>"
            
            return str(obj.val)
            
        # 3. Fallback
        if hasattr(obj, "pretty"): return obj.pretty()
        
        # 4. Check final si le cast str donne "Null"
        s = str(obj)
        return "" if "Null" in s or "None" in s else s

    def bytes_to_hex(self, data):
        """Convertit des bytes en string hexadécimal"""
        if isinstance(data, bytes):
            return binascii.hexlify(data).decode('utf-8')
        return str(data)
    
    # ... (skipping some lines)

    def _extract_varbinds(self, pdu):
        """Extrait les varbinds d'un PDU"""
        varbinds = []
        if hasattr(pdu, "varbindlist"):
            for elt in pdu.varbindlist:
                # print(f"[DEBUG VARBIND] OID={elt.oid} Val={elt.value} TypeVal={type(elt.value)}")
                # Utiliser convert_asn1 aussi pour la valeur pour uniformiser
                val = self.convert_asn1(elt.value)
                varbinds.append({
                    "oid": self.convert_asn1(elt.oid),
                    "value": val
                })
        return varbinds
    
    def parse_snmpv3_flags(self, flags_byte):
        """Parse les flags SNMPv3 msgFlags"""
        if isinstance(flags_byte, bytes):
            flags = flags_byte[0] if len(flags_byte) > 0 else 0
        else:
            flags = int(flags_byte) if flags_byte else 0
        
        auth = bool(flags & 0x01)
        priv = bool(flags & 0x02)
        reportable = bool(flags & 0x04)
        
        if auth and priv:
            level = "authPriv"
        elif auth:
            level = "authNoPriv"
        else:
            level = "noAuthNoPriv"
        
        return {
            "auth": auth,
            "priv": priv,
            "reportable": reportable,
            "security_level": level,
            "raw": flags
        }

    def packet_info(self, pkt):
        # --- 1. Timestamp & Couches Réseau ---
        time_stamp = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")

        mac_src = pkt[Ether].src if Ether in pkt else None
        mac_dst = pkt[Ether].dst if Ether in pkt else None
        ip_src = pkt[IP].src if IP in pkt else None
        ip_dst = pkt[IP].dst if IP in pkt else None
        port_src = pkt[UDP].sport if UDP in pkt else None
        port_dst = pkt[UDP].dport if UDP in pkt else None

        # --- 2. Initialisation des champs SNMP (Tous à None par défaut) ---
        res = {
            "time_stamp": time_stamp,
            "mac_src": mac_src, "mac_dst": mac_dst,
            "ip_src": ip_src, "ip_dst": ip_dst,
            "port_src": port_src, "port_dst": port_dst,
            "packet_len": len(pkt) if hasattr(pkt, "__len__") else 0,
            "snmp_oidsValues": [],
            "snmp_version": None, "snmp_community": None, "snmp_pdu_type": None,
            # Champs communs / V2
            "snmp_request_id": None, "snmp_error_status": None, "snmp_error_index": None,
            # Champs V1 Trap
            "snmp_enterprise": None, "snmp_agent_addr": None, 
            "snmp_generic_trap": None, "snmp_specific_trap": None,
            # Champs V2 Bulk
            "snmp_non_repeaters": None, "snmp_max_repetitions": None,
            # === Champs SNMPv3 ===
            "snmp_msg_id": None,
            "snmp_msg_max_size": None,
            "snmp_msg_flags": None,
            "snmp_msg_security_model": None,
            # USM
            "snmp_usm_engine_id": None,
            "snmp_usm_engine_boots": None,
            "snmp_usm_engine_time": None,
            "snmp_usm_user_name": None,
            "snmp_usm_auth_protocol": None,
            "snmp_usm_priv_protocol": None,
            "snmp_usm_auth_params": None,
            "snmp_usm_priv_params": None,
            # ScopedPDU
            "snmp_context_engine_id": None,
            "snmp_context_name": None,
            # Sécurité
            "security_level": None,
            "is_encrypted": False,
            "is_authenticated": False,
            "decryption_status": None
        }
        # =====================================================================
        # PHASE 1: DETECTION SNMPv3 INDEPENDANTE (Scapy peut rater les V3!)
        # =====================================================================
        raw_data = bytes(pkt[UDP].payload) if UDP in pkt else b""
        
        # Détection SNMPv3 (Soit par Scapy, soit par signature brute \x02\x01\x03)
        is_v3 = (SNMPv3 is not None and SNMPv3 in pkt) or (b"\x02\x01\x03" in raw_data[:32])
        
        if is_v3:
            res["snmp_version"] = 3
            res = self._parse_snmpv3(pkt, res)
            return res  # Sortie directe pour le V3

        # =====================================================================
        # PHASE 2: STANDARD V1/V2c (Scapy detected SNMP layer)
        # =====================================================================
        if SNMP in pkt:
            snmp = pkt[SNMP]
            version_raw = self.convert_asn1(snmp.version)
            try:
                res["snmp_version"] = int(version_raw)
            except:
                res["snmp_version"] = version_raw

            # Backup check for V3 via Scapy (rare but possible)
            if str(res["snmp_version"]) == "3":
                res["snmp_version"] = 3
                res = self._parse_snmpv3(pkt, res)
            else:
                # V1/V2c Logic
                res["snmp_community"] = self.convert_asn1(snmp.community)

                if hasattr(snmp, "PDU") and snmp.PDU:
                    pdu = snmp.PDU
                    res["snmp_pdu_type"] = pdu.__class__.__name__

                    # TRAP v1 (structure spéciale)
                    if res["snmp_pdu_type"] == "SNMPtrap":
                        res["snmp_enterprise"] = self.convert_asn1(pdu.enterprise)
                        res["snmp_agent_addr"] = self.convert_asn1(pdu.agent_addr)
                        res["snmp_generic_trap"] = int(pdu.generic_trap)
                        res["snmp_specific_trap"] = int(pdu.specific_trap)

                    # GETBULK (v2c/v3)
                    elif res["snmp_pdu_type"] == "SNMPbulk":
                        res["snmp_request_id"] = self.convert_asn1(pdu.id)
                        res["snmp_non_repeaters"] = self.convert_asn1(pdu.non_repeaters)
                        res["snmp_max_repetitions"] = self.convert_asn1(pdu.max_repetitions)

                    # TRAPv2 / INFORM / REPORT (structure standard avec request_id)
                    elif res["snmp_pdu_type"] in ("SNMPv2_trap", "SNMPtrapV2", "SNMPinform", "SNMPreport"):
                        if hasattr(pdu, "id"):
                            res["snmp_request_id"] = self.convert_asn1(pdu.id)
                        # Ces PDUs n'ont pas d'error_status/index significatifs
                        # mais les extraire quand même si présents
                        if hasattr(pdu, "error_status"):
                            res["snmp_error_status"] = self.convert_asn1(pdu.error_status)
                        if hasattr(pdu, "error_index"):
                            res["snmp_error_index"] = self.convert_asn1(pdu.error_index)

                    # STANDARD (Get, GetNext, Set, Response)
                    else:
                        if hasattr(pdu, "id"):
                            res["snmp_request_id"] = self.convert_asn1(pdu.id)
                        if hasattr(pdu, "error_status"):
                            res["snmp_error_status"] = self.convert_asn1(pdu.error_status)
                        if hasattr(pdu, "error_index"):
                            res["snmp_error_index"] = self.convert_asn1(pdu.error_index)

                    res["snmp_oidsValues"] = self._extract_varbinds(pdu)
                    
        return res
    
    # --- CRYPTO HELPERS (RFC 3414) ---
    def _localize_key(self, auth_proto, password, engine_id):
        """Derives localized key from password and engine_id (RFC3414)"""
        if not password: return None
        
        # 1. Password to Key (1M iterations logic - simplified here for standard SNMP)
        # Standard: Pass -> Ku -> Kul
        # Implementing the "Password to Key" algorithm (RFC3414 A.2.1)
        h = hashlib.sha1 if auth_proto.upper() == "SHA" else hashlib.md5
        digest_len = 20 if auth_proto.upper() == "SHA" else 16
        
        # Expand password to fill buffer
        count = 0
        p = password.encode()
        buf = b""
        while count < 1048576:
            cp = p * (64 // len(p) + 1)
            buf += cp[:64]
            count += 64
        
        ku = h(buf).digest()
        
        # 2. Key Localization (Ku -> Kul)
        # Kul = H(Ku . engineID . Ku)
        try:
             # EngineID is usually hex string in res, convert to bytes
            eid = binascii.unhexlify(engine_id) if isinstance(engine_id, str) else engine_id
        except:
             return None # Invalid engine ID
             
        return h(ku + eid + ku).digest()

    def _decrypt_aes(self, encrypted_data, key, engine_boots, engine_time, salt):
        """Decrypt AES-CFB-128 (RFC3826)"""
        if len(key) < 16: return None
        aes_key = key[:16]
        
        # IV = engineBoots (4) + engineTime (4) + salt (8)
        try:
            iv = (int(engine_boots).to_bytes(4, 'big') + 
                  int(engine_time).to_bytes(4, 'big') + 
                  salt)
        except:
            return None
            
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

    def _decrypt_des(self, encrypted_data, key, salt):
        """Decrypt DES-CBC (RFC3414)"""
        if len(key) < 16: return None # Need 16 bytes for localized key (use first 8 for DES)
        des_key = key[:8]
        
        # Pre-IV = key[8:16] XOR salt
        try:
            pre_iv = bytes(a ^ b for a, b in zip(key[8:16], salt))
            cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(pre_iv)) # Using 3DES with single key = DES compat
            # Warning: Logic might vary slightly for strict DES, but simple DES is deprecated.
            # Using basic DES if available or 3DES fallback
            # Let's simplify: PyCrypto / cryptography handling of DES
            cipher = Cipher(algorithms.DES(des_key), modes.CBC(pre_iv))
        except:
            return None
            
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

    def _parse_snmpv3(self, pkt, res):
        """Parse un paquet SNMPv3 avec support Scapy natif et fallback brut"""
        try:
            snmpv3_layer = None
            if SNMPv3 in pkt:
                snmpv3_layer = pkt[SNMPv3]
            elif SNMP in pkt and hasattr(pkt[SNMP], "PDU") and pkt[SNMP].PDU.__class__.__name__ == "SNMPv3":
                snmpv3_layer = pkt[SNMP].PDU
            else:
                # Tentative de forcer le parse Scapy si non détecté automatiquement
                raw_data = bytes(pkt[UDP].payload) if UDP in pkt else b""
                if raw_data:
                    try:
                        temp_v3 = SNMPv3(raw_data)
                        if temp_v3: snmpv3_layer = temp_v3
                    except: pass

            if snmpv3_layer:
                # --- Utilisation des champs Scapy (Plus robuste) ---
                res["snmp_msg_id"] = self.convert_asn1(getattr(snmpv3_layer, "msgID", None))
                res["snmp_msg_max_size"] = self.convert_asn1(getattr(snmpv3_layer, "msgMaxSize", None))
                
                flags_raw = getattr(snmpv3_layer, "msgFlags", 0)
                flags_info = self.parse_snmpv3_flags(flags_raw)
                res["snmp_msg_flags"] = flags_info["raw"]
                res["security_level"] = flags_info["security_level"]
                res["is_authenticated"] = flags_info["auth"]
                res["is_encrypted"] = flags_info["priv"]
                res["snmp_msg_security_model"] = self.convert_asn1(getattr(snmpv3_layer, "msgSecurityModel", None))
                
                # USM Security Parameters
                if hasattr(snmpv3_layer, "security"):
                    usm = snmpv3_layer.security
                    res["snmp_usm_user_name"] = self.convert_asn1(getattr(usm, "msgUserName", None))
                    res["snmp_usm_engine_id"] = self.bytes_to_hex(getattr(usm, "msgAuthoritativeEngineID", None))
                    res["snmp_usm_engine_boots"] = self.convert_asn1(getattr(usm, "msgAuthoritativeEngineBoots", None))
                    res["snmp_usm_engine_time"] = self.convert_asn1(getattr(usm, "msgAuthoritativeEngineTime", None))
                    res["snmp_usm_auth_params"] = self.bytes_to_hex(getattr(usm, "msgAuthenticationParameters", None))
                    res["snmp_usm_priv_params"] = self.bytes_to_hex(getattr(usm, "msgPrivacyParameters", None))
                    self._cached_salt = getattr(usm, "msgPrivacyParameters", None)

                # ScopedPDU (Data)
                if hasattr(snmpv3_layer, "data"):
                    scoped = snmpv3_layer.data
                    res["snmp_context_engine_id"] = self.bytes_to_hex(getattr(scoped, "contextEngineID", None))
                    res["snmp_context_name"] = self.convert_asn1(getattr(scoped, "contextName", None))
                    
                    if hasattr(scoped, "data") and scoped.data:
                        pdu = scoped.data
                        if hasattr(pdu, "__class__") and pdu.__class__.__name__ != "ASN1_STRING":
                            res["snmp_pdu_type"] = pdu.__class__.__name__
                            if hasattr(pdu, "id"): res["snmp_request_id"] = self.convert_asn1(pdu.id)
                            res["snmp_oidsValues"] = self._extract_varbinds(pdu)
                        else:
                            # It's likely encrypted data
                            self._cached_encrypted_pdu = bytes(pdu)
                
            else:
                # --- Fallback sur le parser manuel si Scapy échoue ---
                raw_data = bytes(pkt[UDP].payload)
                res = self._parse_snmpv3_raw(raw_data, res)

            # 2. Check encryption
            if res.get("is_encrypted") and res.get("snmp_usm_user_name"):
                username = res["snmp_usm_user_name"]
                print(f"[DEBUG_V3] Packet Encrypted. User: {username}")
                user_creds = snmp_cred_mgr.get_user(username) if snmp_cred_mgr else None
                
                if user_creds and user_creds.get("priv_key"):
                    print(f"[DEBUG_V3] Credentials found for {username}")
                    try:
                        auth_proto = user_creds.get("auth_proto", "SHA")
                        auth_pass = user_creds.get("auth_key")
                        priv_proto = user_creds.get("priv_proto", "AES")
                        priv_pass = user_creds.get("priv_key")
                        engine_id = res["snmp_usm_engine_id"]
                        
                        local_priv_key = self._localize_key(auth_proto, priv_pass, engine_id)
                        if local_priv_key:
                            encrypted_pdu = getattr(self, '_cached_encrypted_pdu', None)
                            salt = getattr(self, '_cached_salt', None)
                            decrypted_data = None
                            
                            if priv_proto == "AES" and salt:
                                decrypted_data = self._decrypt_aes(
                                    encrypted_pdu, local_priv_key, 
                                    res["snmp_usm_engine_boots"], res["snmp_usm_engine_time"], salt
                                )
                            elif priv_proto == "DES" and salt:
                                decrypted_data = self._decrypt_des(encrypted_pdu, local_priv_key, salt)
                                
                            if decrypted_data:
                                print(f"[DEBUG_V3] DECRYPTION SUCCESS!")
                                res["decryption_status"] = "SUCCESS"
                                self._parse_scoped_pdu(decrypted_data, res)
                            else:
                                res["decryption_status"] = "Failed: No Decrypted Data"
                        else:
                            res["decryption_status"] = "Failed: Key Derivation Error"
                    except Exception as e:
                        print(f"[DEBUG_V3] DECRYPTION ERROR: {e}")
                        res["decryption_status"] = f"Decryption Error: {e}"
                else:
                    res["decryption_status"] = "No Key Found (Check Creds)"
            else:
                res["decryption_status"] = "Not Encrypted"

            # SANITIZATION: Ensure numeric fields are None if empty string (for Postgres strict typing)
            NUMERIC_FIELDS = [
                "snmp_msg_id", "snmp_msg_max_size", "snmp_msg_flags", "snmp_msg_security_model",
                "snmp_usm_engine_boots", "snmp_usm_engine_time",
                "snmp_request_id", "snmp_error_status", "snmp_error_index",
                "snmp_non_repeaters", "snmp_max_repetitions"
            ]
            for field in NUMERIC_FIELDS:
                if res.get(field) == "":
                    res[field] = None

            return res
        except Exception as e:
            print(f"[!] Critical error in _parse_snmpv3: {e}")
            return res
    def _parse_varbinds_raw(self, vbl_bytes):
        """Parse raw ASN.1 VarBindList"""
        results = []
        try:
            idx = 0
            # Sequence Header
            if vbl_bytes[idx] != 0x30: return []
            idx += 1
            # Length
            if vbl_bytes[idx] & 0x80: 
                l_len = vbl_bytes[idx] & 0x7f
                length = int.from_bytes(vbl_bytes[idx+1:idx+1+l_len], 'big')
                idx += 1 + l_len
            else:
                length = vbl_bytes[idx]
                idx += 1
            
            end = idx + length
            
            while idx < min(len(vbl_bytes), end):
                # VarBind Sequence
                if vbl_bytes[idx] != 0x30: break
                idx += 1
                if vbl_bytes[idx] & 0x80: i = (vbl_bytes[idx]&0x7f)+1; idx+=i
                else: idx+=1
                
                # OID (0x06)
                if vbl_bytes[idx] == 0x06:
                    idx += 1
                    l = vbl_bytes[idx]
                    idx += 1
                    oid_bytes = vbl_bytes[idx:idx+l]
                    # Decode OID
                    oid_str = self._decode_oid(oid_bytes)
                    idx += l
                else:
                    break
                    
                # Value (Any Type)
                tag = vbl_bytes[idx]
                idx += 1
                if vbl_bytes[idx] & 0x80: 
                    l_len = vbl_bytes[idx] & 0x7f
                    l = int.from_bytes(vbl_bytes[idx+1:idx+1+l_len], 'big')
                    idx += 1 + l_len
                else:
                    l = vbl_bytes[idx]
                    idx += 1
                
                val_bytes = vbl_bytes[idx:idx+l]
                idx += l
                
                # Decode Value based on Tag
                if tag == 0x02: val = int.from_bytes(val_bytes, 'big') # Integer
                elif tag == 0x04: # String
                    try: val = val_bytes.decode('utf-8')
                    except: val = val_bytes.hex()
                elif tag == 0x05: val = "NULL"
                elif tag == 0x06: val = self._decode_oid(val_bytes) # OID
                else: val = f"Raw({val_bytes.hex()})"
                
                results.append({"oid": oid_str, "value": str(val)})
                
        except Exception as e:
            results.append({"oid": "ParseError", "value": str(e)})
            
        return results

    def _decode_oid(self, oid_bytes):
        """Decode OID bytes to string"""
        res = []
        try:
            val = 0
            for byte in oid_bytes:
                if byte < 128:
                    val = val * 128 + byte
                    res.append(val)
                    val = 0
                else:
                    val = val * 128 + (byte - 128)
            
            # First byte is 40*x + y
            if len(res) > 0:
                first = res.pop(0)
                res.insert(0, first % 40)
                res.insert(0, first // 40)
            
            return "1.3." + ".".join(map(str, res[2:])) # Hacky standard OID start
        except:
            return ".".join(map(str, oid_bytes))

    def _parse_scoped_pdu(self, data, res):
        """Parse les données d'une ScopedPDU (ASN.1 manual)"""
        try:
            idx = 0
            if data[idx] == 0x30: # Sequence
                idx += 1
                if data[idx] & 0x80: idx += (data[idx] & 0x7f) + 1
                else: idx += 1
                
                # contextEngineID
                if idx < len(data) and data[idx] == 0x04:
                    idx += 1
                    l = data[idx]
                    if l & 0x80: ids = (l & 0x7f); l = int.from_bytes(data[idx+1:idx+1+ids], 'big'); idx += 1 + ids
                    else: idx += 1
                    res["snmp_context_engine_id"] = self.bytes_to_hex(data[idx:idx+l])
                    idx += l
                
                # contextName
                if idx < len(data) and data[idx] == 0x04:
                    idx += 1
                    l = data[idx]
                    if l & 0x80: ids = (l & 0x7f); l = int.from_bytes(data[idx+1:idx+1+ids], 'big'); idx += 1 + ids
                    else: idx += 1
                    res["snmp_context_name"] = data[idx:idx+l].decode('utf-8', 'ignore')
                    idx += l
                    
                # PDU Data
                if idx < len(data):
                    pdu_tag = data[idx]
                    TAG_MAP = {
                        0xA0: "SNMPget", 0xA1: "SNMPgetnext", 0xA2: "SNMPresponse",
                        0xA3: "SNMPset", 0xA4: "SNMPtrap", 0xA5: "SNMPbulk",
                        0xA6: "SNMPinform", 0xA7: "SNMPtrapV2", 0xA8: "SNMPreport"
                    }
                    res["snmp_pdu_type"] = TAG_MAP.get(pdu_tag, f"Unknown ({hex(pdu_tag)})")
                    idx += 1
                    if data[idx] & 0x80: idx += (data[idx] & 0x7f) + 1
                    else: idx += 1
                    
                    # Request ID
                    if idx < len(data) and data[idx] == 0x02:
                        idx += 1
                        l = data[idx]; idx += 1
                        res["snmp_request_id"] = int.from_bytes(data[idx:idx+l], 'big')
                        idx += l
                    
                    # On cherche la séquence de varbinds (0x30)
                    while idx < len(data) - 2:
                        if data[idx] == 0x30:
                            res["snmp_oidsValues"] = self._parse_varbinds_raw(data[idx:])
                            break
                        idx += 1
        except Exception as e:
            print(f"[!] Error _parse_scoped_pdu: {e}")

    def _parse_varbinds_raw(self, vbl_bytes):
        """Parse une séquence de varbinds brute"""
        results = []
        try:
            idx = 0
            if vbl_bytes[idx] != 0x30: return results
            idx += 1
            if vbl_bytes[idx] & 0x80: idx += (vbl_bytes[idx] & 0x7f) + 1
            else: idx += 1
            
            while idx < len(vbl_bytes):
                if vbl_bytes[idx] != 0x30: break # Chaque varbind est une séquence
                idx += 1
                if vbl_bytes[idx] & 0x80: idx += (vbl_bytes[idx] & 0x7f) + 1
                else: idx += 1
                
                # OID (0x06)
                if vbl_bytes[idx] != 0x06: break
                idx += 1
                l = vbl_bytes[idx]; idx += 1
                oid_bytes = vbl_bytes[idx:idx+l]
                oid_str = self._decode_oid(oid_bytes)
                idx += l
                
                # Value
                tag = vbl_bytes[idx]; idx += 1
                l = vbl_bytes[idx]
                if l & 0x80: ids = (l & 0x7f); l = int.from_bytes(vbl_bytes[idx+1:idx+1+ids], 'big'); idx += 1 + ids
                else: idx += 1
                val_bytes = vbl_bytes[idx:idx+l]
                idx += l
                
                if tag == 0x02: val = int.from_bytes(val_bytes, 'big')
                elif tag == 0x04: val = val_bytes.decode('utf-8', 'ignore')
                elif tag == 0x06: val = self._decode_oid(val_bytes)
                else: val = f"Raw({val_bytes.hex()})"
                
                results.append({"oid": oid_str, "value": str(val)})
            return results
        except: return results

    def _decode_oid(self, oid_bytes):
        """Decode OID bytes to string"""
        res = []
        try:
            val = 0
            for byte in oid_bytes:
                if byte < 128:
                    val = val * 128 + byte
                    res.append(val)
                    val = 0
                else: val = val * 128 + (byte - 128)
            if len(res) > 0:
                first = res.pop(0)
                res.insert(0, first % 40)
                res.insert(0, first // 40)
            return "1.3." + ".".join(map(str, res[2:]))
        except: return ".".join(map(str, oid_bytes))

    def _parse_snmpv3_raw(self, raw_data, res):
        """Parse les données brutes SNMPv3"""
        try:
            idx = 0
            if raw_data[idx] == 0x30:
                idx += 1
                if raw_data[idx] & 0x80:
                    len_bytes = raw_data[idx] & 0x7f
                    idx += 1 + len_bytes # On saute la longueur globale
                else:
                    idx += 1
                
                # Version (INTEGER)
                if idx < len(raw_data) and raw_data[idx] == 0x02:
                    idx += 1
                    ver_len = raw_data[idx]
                    idx += 1 + ver_len
                
                # msgGlobalData (SEQUENCE)
                if idx < len(raw_data) and raw_data[idx] == 0x30:
                    idx += 1
                    if raw_data[idx] & 0x80:
                        l_len = raw_data[idx] & 0x7f
                        g_data_len = int.from_bytes(raw_data[idx+1:idx+1+l_len], 'big')
                        idx += 1 + l_len
                    else:
                        g_data_len = raw_data[idx]
                        idx += 1
                    
                    g_end = idx + g_data_len
                    
                    # msgID
                    if idx < g_end and raw_data[idx] == 0x02:
                        idx += 1; l = raw_data[idx]; idx += 1
                        res["snmp_msg_id"] = int.from_bytes(raw_data[idx:idx+l], 'big')
                        idx += l
                    
                    # msgMaxSize
                    if idx < g_end and raw_data[idx] == 0x02:
                        idx += 1; l = raw_data[idx]; idx += 1
                        res["snmp_msg_max_size"] = int.from_bytes(raw_data[idx:idx+l], 'big')
                        idx += l
                    
                    # msgFlags
                    if idx < g_end and raw_data[idx] == 0x04:
                        idx += 1; l = raw_data[idx]; idx += 1
                        flags_raw = raw_data[idx]
                        res.update(self.parse_snmpv3_flags(flags_raw))
                        idx += l
                    
                    # msgSecurityModel
                    if idx < g_end and raw_data[idx] == 0x02:
                        idx += 1; l = raw_data[idx]; idx += 1
                        res["snmp_msg_security_model"] = int.from_bytes(raw_data[idx:idx+l], 'big')
                        idx += l
                        
                # msgSecurityParameters
                if idx < len(raw_data) and raw_data[idx] == 0x04:
                    idx += 1
                    if raw_data[idx] & 0x80:
                        l_len = raw_data[idx] & 0x7f
                        usm_len = int.from_bytes(raw_data[idx+1:idx+1+l_len], 'big')
                        idx += 1 + l_len
                    else:
                        usm_len = raw_data[idx]
                        idx += 1
                    usm_data = raw_data[idx:idx+usm_len]
                    res = self._parse_usm(usm_data, res)
                    idx += usm_len
                
                # ScopedPDU
                if idx < len(raw_data):
                    tag = raw_data[idx]
                    if tag == 0x30:
                        res["is_encrypted"] = False
                        self._parse_scoped_pdu(raw_data[idx:], res)
                    elif tag == 0x04:
                        res["is_encrypted"] = True
                        idx += 1
                        if raw_data[idx] & 0x80:
                            l_len = raw_data[idx] & 0x7f
                            pdu_len = int.from_bytes(raw_data[idx+1:idx+1+l_len], 'big')
                            idx += 1 + l_len
                        else:
                            pdu_len = raw_data[idx]
                            idx += 1
                        self._cached_encrypted_pdu = raw_data[idx:idx+pdu_len]
            
            # Protocols summary
            res["snmp_usm_auth_protocol"] = "HMAC-MD5/SHA" if res.get("is_authenticated") else "noAuth"
            res["snmp_usm_priv_protocol"] = "DES/AES" if res.get("is_encrypted") else "noPriv"
            res["decryption_status"] = "encrypted" if res.get("is_encrypted") else "not_encrypted"
            
        except Exception as e:
            res["decryption_status"] = f"Raw parse error: {str(e)}"
        return res
    
    def _parse_usm(self, usm_data, res):
        """Parse les paramètres USM (User-based Security Model)"""
        try:
            idx = 0
            
            # USM est une SEQUENCE
            if usm_data[idx] == 0x30:
                idx += 1
                if usm_data[idx] & 0x80:
                    len_bytes = usm_data[idx] & 0x7f
                    idx += 1 + len_bytes
                else:
                    idx += 1
            
            # msgAuthoritativeEngineID (OCTET STRING)
            if idx < len(usm_data) and usm_data[idx] == 0x04:
                idx += 1
                engine_id_len = usm_data[idx]
                idx += 1
                res["snmp_usm_engine_id"] = self.bytes_to_hex(usm_data[idx:idx+engine_id_len])
                idx += engine_id_len
            
            # msgAuthoritativeEngineBoots (INTEGER)
            if idx < len(usm_data) and usm_data[idx] == 0x02:
                idx += 1
                boots_len = usm_data[idx]
                idx += 1
                res["snmp_usm_engine_boots"] = int.from_bytes(usm_data[idx:idx+boots_len], 'big')
                idx += boots_len
            
            # msgAuthoritativeEngineTime (INTEGER)
            if idx < len(usm_data) and usm_data[idx] == 0x02:
                idx += 1
                time_len = usm_data[idx]
                idx += 1
                res["snmp_usm_engine_time"] = int.from_bytes(usm_data[idx:idx+time_len], 'big')
                idx += time_len
            
            # msgUserName (OCTET STRING)
            if idx < len(usm_data) and usm_data[idx] == 0x04:
                idx += 1
                user_len = usm_data[idx]
                idx += 1
                try:
                    res["snmp_usm_user_name"] = usm_data[idx:idx+user_len].decode('utf-8')
                except:
                    res["snmp_usm_user_name"] = self.bytes_to_hex(usm_data[idx:idx+user_len])
                idx += user_len
            
            # msgAuthenticationParameters (OCTET STRING)
            if idx < len(usm_data) and usm_data[idx] == 0x04:
                idx += 1
                auth_len = usm_data[idx]
                idx += 1
                res["snmp_usm_auth_params"] = self.bytes_to_hex(usm_data[idx:idx+auth_len]) if auth_len > 0 else None
                idx += auth_len
            
            # msgPrivacyParameters (OCTET STRING)
            if idx < len(usm_data) and usm_data[idx] == 0x04:
                idx += 1
                priv_len = usm_data[idx]
                idx += 1
                res["snmp_usm_priv_params"] = self.bytes_to_hex(usm_data[idx:idx+priv_len]) if priv_len > 0 else None
                # Store SALT for AES/DES
                self._cached_salt = usm_data[idx:idx+priv_len]
                idx += priv_len
                
        except Exception as e:
            pass
        
        return res
    
    def _extract_varbinds(self, pdu):
        """Extrait les varbinds d'un PDU"""
        varbinds = []
        if hasattr(pdu, "varbindlist"):
            for elt in pdu.varbindlist:
                val = elt.value
                if hasattr(val, "prettyPrint"): 
                    val = val.prettyPrint()
                else: 
                    val = str(val)
                varbinds.append({
                    "oid": self.convert_asn1(elt.oid),
                    "value": val
                })
        return varbinds

    # --- Logique de filtrage ---

    def in_whitelist(self, key, value):
        whitelist = self.config.get("whiteList", {})
        values = whitelist.get(key, [])
        return value in values

    def in_filtre(self, pkt_data:dict):
        filtres = self.config.get("filtres", {})
        rule_elts = ["mac_src","mac_dst","ip_src","ip_dst","port_src","port_dst"]
        
        for rule_name, rule in filtres.items():
            match = True
            if not isinstance(rule, dict): continue
            
            for key, val in rule.items():
                if not val: continue
                if key in rule_elts:
                    if str(val) != str(pkt_data.get(key)):
                        match = False
                        break
            
            # Vérification spéciale pour OIDs (contient partiel)
            if match and "snmp_oidsValues" in rule and rule["snmp_oidsValues"]:
                target = rule["snmp_oidsValues"]
                found = False
                for oid_entry in pkt_data.get("snmp_oidsValues", []):
                    if target in oid_entry["oid"]:
                        found = True
                        break
                if not found: match = False

            if match:
                return True, rule_name

        return False, None

    def _analyze_behavior(self, ip_src, data):
        """
        Analyse le comportement de l'IP source
        Retourne un indicateur de menace (0-100)
        """
        threat_score = 0
        try:
            is_allowed = self.compare(data)
            if not is_allowed:
                threat_score += 20
            
            # Score final
            threat_score = min(100, threat_score)
            
            # Envoi vers InfluxDB
            if hasattr(self, 'influx') and self.influx:
                self.influx.write_threat(threat_score, ip_src)

            if threat_score >= 50:
                print(f"[!] ALERTE MENACE: {ip_src} (Score: {threat_score})")

            return threat_score
        except Exception as e:
            # print(f"Error checking behavior: {e}")
            return 0

    def compare(self, data:dict):
        """
        Retourne True si le paquet est autorisé.
        Logique STRICTE (AND) pour la Whitelist.
        """
        if not self.config: return False

        # 1. Whitelist (Logique AND : Src ET Dst doivent être autorisés)
        # MACs
        if data.get("mac_src") and data.get("mac_dst"):
            if self.in_whitelist("MACs", data.get("mac_src")) and self.in_whitelist("MACs", data.get("mac_dst")):
                return True
        
        # IPs
        if data.get("ip_src") and data.get("ip_dst"):
            if self.in_whitelist("IPs", data.get("ip_src")) and self.in_whitelist("IPs", data.get("ip_dst")):
                return True
        
        # Ports
        if data.get("port_src") and data.get("port_dst"):
            if self.in_whitelist("PORTs", str(data.get("port_src"))) and self.in_whitelist("PORTs", str(data.get("port_dst"))):
                return True
        
        # OIDs (Si l'un des OIDs du paquet est dans la liste, on accepte)
        for oid_entry in data.get("snmp_oidsValues", []):
            if self.in_whitelist("OIDs", oid_entry["oid"]):
                return True
        
        # SNMPv3 Users
        if data.get("snmp_usm_user_name"):
            if self.in_whitelist("USM_Users", data.get("snmp_usm_user_name")):
                return True

        # 2. Filtres
        is_match, rule_name = self.in_filtre(data)
        if is_match:
            print(f"[OK] Règle correspondante : {rule_name}")
            return True

        return False

    # ---------------------------

    def _analyze_snmp(self, pkt):
        # 1. Extraction complète
        full_data = self.packet_info(pkt)
        
        # 2. Comparaison et définition du TAG
        full_data["tag"] = None 

        if self.compare(full_data):
            print(f"[+] Paquet autorisé ({full_data['time_stamp']})")
            full_data["tag"] = 0
            # Analyse comportementale (même si autorisé, on check)
            self._analyze_behavior(full_data.get("ip_src"), full_data)
        else:
            print(f"[!] Paquet suspect/interdit ({full_data['time_stamp']})")
            full_data["tag"] = 1
            # Analyse comportementale
            self._analyze_behavior(full_data.get("ip_src"), full_data)
                
        # 3. Préparation DB - Aiguillage selon version
        version = str(full_data.get("snmp_version"))
        
        if version == "3":
            table_cible = "snmp_v3"
            db_data = {
                "time_stamp": full_data["time_stamp"],
                "mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
                "ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
                "port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
                # SNMPv3 Header
                "snmp_msg_id": full_data["snmp_msg_id"],
                "snmp_msg_max_size": full_data["snmp_msg_max_size"],
                "snmp_msg_flags": full_data["snmp_msg_flags"],
                "snmp_msg_security_model": full_data["snmp_msg_security_model"],
                # USM
                "snmp_usm_engine_id": full_data["snmp_usm_engine_id"],
                "snmp_usm_engine_boots": full_data["snmp_usm_engine_boots"],
                "snmp_usm_engine_time": full_data["snmp_usm_engine_time"],
                "snmp_usm_user_name": full_data["snmp_usm_user_name"],
                "snmp_usm_auth_protocol": full_data["snmp_usm_auth_protocol"],
                "snmp_usm_priv_protocol": full_data["snmp_usm_priv_protocol"],
                "snmp_usm_auth_params": full_data["snmp_usm_auth_params"],
                "snmp_usm_priv_params": full_data["snmp_usm_priv_params"],
                # PDU
                "snmp_context_engine_id": full_data["snmp_context_engine_id"],
                "snmp_context_name": full_data["snmp_context_name"],
                "snmp_pdu_type": full_data["snmp_pdu_type"],
                "snmp_request_id": full_data["snmp_request_id"],
                "snmp_error_status": full_data["snmp_error_status"],
                "snmp_error_index": full_data["snmp_error_index"],
                "snmp_non_repeaters": full_data["snmp_non_repeaters"],
                "snmp_max_repetitions": full_data["snmp_max_repetitions"],
                "snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
                # Sécurité
                "security_level": full_data["security_level"],
                "is_encrypted": full_data["is_encrypted"],
                "is_authenticated": full_data["is_authenticated"],
                "decryption_status": full_data["decryption_status"],
                "tag": full_data["tag"]
            }
        elif version == "0":
            table_cible = "snmp_v1"
            db_data = {
                "time_stamp": full_data["time_stamp"],
                "mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
                "ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
                "port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
                "snmp_community": full_data["snmp_community"],
                "snmp_pdu_type": full_data["snmp_pdu_type"],
                "snmp_enterprise": full_data["snmp_enterprise"],
                "snmp_agent_addr": full_data["snmp_agent_addr"],
                "snmp_generic_trap": full_data["snmp_generic_trap"],
                "snmp_specific_trap": full_data["snmp_specific_trap"],
                "snmp_request_id": full_data["snmp_request_id"],
                "snmp_error_status": full_data["snmp_error_status"],
                "snmp_error_index": full_data["snmp_error_index"],
                "snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
                "tag": full_data["tag"]
            }
        else:
            table_cible = "snmp_v2"
            db_data = {
                "time_stamp": full_data["time_stamp"],
                "mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
                "ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
                "port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
                "snmp_community": full_data["snmp_community"],
                "snmp_pdu_type": full_data["snmp_pdu_type"],
                "snmp_request_id": full_data["snmp_request_id"],
                "snmp_error_status": full_data["snmp_error_status"],
                "snmp_error_index": full_data["snmp_error_index"],
                "snmp_non_repeaters": full_data["snmp_non_repeaters"],
                "snmp_max_repetitions": full_data["snmp_max_repetitions"],
                "snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
                "tag": full_data["tag"]
            }

        # Nettoyage des valeurs None pour laisser SQLite gérer les NULL
        db_data = {k: v for k, v in db_data.items() if v is not None}

        if version == "3":
            db_data["snmp_context_engine_id"] = full_data.get("snmp_context_engine_id")
            db_data["snmp_context_name"] = full_data.get("snmp_context_name")
            db_data["snmp_msg_id"] = full_data.get("snmp_msg_id")
            db_data["snmp_msg_max_size"] = full_data.get("snmp_msg_max_size")
            db_data["snmp_msg_flags"] = full_data.get("snmp_msg_flags")
            db_data["snmp_msg_security_model"] = full_data.get("snmp_msg_security_model")
            db_data["snmp_usm_engine_id"] = full_data.get("snmp_usm_engine_id")
            db_data["snmp_usm_engine_boots"] = full_data.get("snmp_usm_engine_boots")
            db_data["snmp_usm_engine_time"] = full_data.get("snmp_usm_engine_time")
            db_data["snmp_usm_user_name"] = full_data.get("snmp_usm_user_name")
            db_data["security_level"] = full_data.get("security_level")
            db_data["is_encrypted"] = full_data.get("is_encrypted")
            db_data["is_authenticated"] = full_data.get("is_authenticated")
            db_data["decryption_status"] = full_data.get("decryption_status")
            
        # Ecriture en Base de Données
        self.baseDB.wrData(table_cible, db_data)
            
        # 5. Enregistrement PCAP
        self.pcap_writer.write(pkt)
        self.nb_pkt += 1
            
        if self.nb_pkt >= self.lenPcap:
            self.open_new_pcap()

    def export_packet_bytes(self, raw_bytes: bytes, filename: str):
        """Exporte les octets bruts d'un paquet vers un fichier PCAP"""
        try:
            # On tente de reconstruire le paquet (Ethernet par défaut)
            pkt = Ether(raw_bytes)
            wrpcap(filename, pkt)
            return True
        except Exception as e:
            print(f"Erreur export PCAP: {e}")
            return False

    def process_packet(self):
        """
        Récupère un paquet depuis la file et l'analyse.
        Retourne True si un paquet a été traité, False sinon.
        """
        if not self.queue.empty():
            packet = self.queue.get()
            
            # Statistiques temps réel vers InfluxDB
            if hasattr(self, 'influx'):
                if IP in packet:
                    src_ip = packet[IP].src
                    pkt_len = len(packet)
                    proto = "UDP" if UDP in packet else "OTHER"
                    self.influx.write_packet_stat(pkt_len, proto, src_ip)

            if SNMP in packet:
                self.nb_pkt += 1
                self._analyze_snmp(packet)
            
            return True
        return False

    def start_analyse(self):
        print(list(self.queue.queue))
        try:
            while True:
                pkt = self.queue.get()
                self._analyze_snmp(pkt)
                self.queue.task_done()
        except KeyboardInterrupt:
            print("\n[!] Interruption.")
        finally:
            print("[!] Fermeture ressources...")
            if self.pcap_writer: self.pcap_writer.close()
            if hasattr(self.baseDB, 'close'): self.baseDB.close()


if __name__ == "__main__":
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, UDP
    
    # Mock DB pour test
    class MockDB:
        def wrData(self, table, data):
            print(f"   [DB -> {table}] INSERT: {data.get('ip_src')} -> {data.get('ip_dst')}")
        def initDB(self): 
            print("   [DB] Init v1, v2 & v3 tables")
        def close(self): pass

    print("\n--- [TEST] PacketAnalyzer avec support SNMPv3 ---")

    fake_config = {
        "filtres": {},
        "whiteList": {
            "IPs": ["10.0.0.1", "8.8.8.8"],
            "MACs": [], "PORTs": [], "OIDs": [],
            "USM_Users": ["admin", "monitoring"]
        }
    }

    analyser = PacketAnalyzer(Queue(), MockDB(), config=fake_config, pcap_dir="test_cap")
    print("[+] PacketAnalyzer initialisé avec support SNMPv1/v2c/v3")