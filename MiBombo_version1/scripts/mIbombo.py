#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import random
import sys
import time
from dataclasses import dataclass
from typing import Optional

# -----------------------------
# Scapy imports (compat)
# -----------------------------
try:
    from scapy.all import IP, UDP, send, RandInt
    import scapy.layers.snmp as snmp_layer

    # Classes SNMP selon versions Scapy :
    SNMP = snmp_layer.SNMP
    SNMPget = snmp_layer.SNMPget
    SNMPset = snmp_layer.SNMPset
    SNMPbulk = getattr(snmp_layer, "SNMPbulk", None)  # peut ne pas exister selon build
    SNMPvarbind = snmp_layer.SNMPvarbind

    # GETNEXT : selon version => SNMPnext (courant) ou SNMPgetnext (rare)
    SNMPgetnext = getattr(snmp_layer, "SNMPgetnext", None)
    SNMPnext = getattr(snmp_layer, "SNMPnext", None)

    if SNMPgetnext is None and SNMPnext is None:
        raise ImportError("Aucune classe GETNEXT trouvée (SNMPnext/SNMPgetnext) dans Scapy.")

except Exception as e:
    print("[!] Scapy manquant ou import impossible. Installe: sudo apt install python3-scapy OU pip install scapy")
    raise

try:
    # PySNMP pour SNMPv3 réel
    from pysnmp.hlapi import (
        SnmpEngine,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        nextCmd,
        setCmd,
        sendNotification,
        NotificationType,
        Integer,
        usmNoAuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmNoPrivProtocol,
        usmDESPrivProtocol,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
    )
except Exception:
    print("[!] PySNMP manquant. Installe: pip install pysnmp")
    raise

# -----------------------------
# Constantes
# -----------------------------
COMMON_OIDS = [
    "1.3.6.1.2.1.1.1.0",   # sysDescr
    "1.3.6.1.2.1.1.3.0",   # sysUpTime
    "1.3.6.1.2.1.1.5.0",   # sysName
    "1.3.6.1.2.1.2.2.1.2.1",  # ifDescr.1
    "1.3.6.1.2.1.2.2.1.10.1", # ifInOctets.1
    "1.3.6.1.2.1.2.2.1.16.1", # ifOutOctets.1
]

COMMUNITIES_OK = ["public", "private", "monitor"]
COMMUNITIES_BAD = ["admin", "root", "cisco", "password", "123456", "snmp", "netadmin"]

DEFAULT_PORT = 161
DEFAULT_TRAP_PORT = 162


def pick_oid() -> str:
    return random.choice(COMMON_OIDS)


def pick_ip_like(source_ip: Optional[str]) -> str:
    if source_ip:
        return source_ip
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# -----------------------------
# SNMP v1/v2c (Scapy)
# -----------------------------
class ScapySNMPv1v2c:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def build_packet(self, src_ip: str, dst_ip: str, community: str, version: int, pdu: str, oid: str, dst_port: int):
        sport = random.randint(1024, 65535)
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=sport, dport=dst_port)

        if pdu == "get":
            pdu_layer = SNMPget(id=RandInt(), varbindlist=[SNMPvarbind(oid=oid)])

        elif pdu == "getnext":
            # compat : SNMPnext préféré sur Debian/Scapy 2.6.1
            cls = SNMPnext if SNMPnext is not None else SNMPgetnext
            pdu_layer = cls(id=RandInt(), varbindlist=[SNMPvarbind(oid=oid)])

        elif pdu == "getbulk":
            if SNMPbulk is None:
                # fallback: si bulk absent, on fait getnext
                cls = SNMPnext if SNMPnext is not None else SNMPgetnext
                pdu_layer = cls(id=RandInt(), varbindlist=[SNMPvarbind(oid=oid)])
            else:
                pdu_layer = SNMPbulk(
                    id=RandInt(),
                    non_repeaters=0,
                    max_repetitions=10,
                    varbindlist=[SNMPvarbind(oid=oid)],
                )

        elif pdu == "set":
            # Exemple simple: SET integer 42 (beaucoup d'agents refuseront => mais trafic OK)
            pdu_layer = SNMPset(id=RandInt(), varbindlist=[SNMPvarbind(oid=oid, value=42)])

        else:
            raise ValueError(f"PDU inconnu: {pdu}")

        # version ASN.1 : v1=0, v2c=1
        if version not in (0, 1):
            raise ValueError("version doit être 0 (v1) ou 1 (v2c)")

        snmp = SNMP(version=version, community=community, PDU=pdu_layer)
        return ip / udp / snmp

    def send(self, pkt, count: int = 1):
        send(pkt, count=count, verbose=self.verbose)


# -----------------------------
# SNMPv3 (PySNMP)
# -----------------------------
AUTH_PROTOCOLS = {
    "none": usmNoAuthProtocol,
    "md5": usmHMACMD5AuthProtocol,
    "sha": usmHMACSHAAuthProtocol,
    "sha256": usmHMAC192SHA256AuthProtocol,
}

PRIV_PROTOCOLS = {
    "none": usmNoPrivProtocol,
    "des": usmDESPrivProtocol,
    "aes": usmAesCfb128Protocol,
    "aes128": usmAesCfb128Protocol,
    "aes192": usmAesCfb192Protocol,
    "aes256": usmAesCfb256Protocol,
}


@dataclass
class V3Profile:
    user: str
    level: str  # noAuthNoPriv | authNoPriv | authPriv
    auth_proto: str = "sha"
    auth_key: str = ""
    priv_proto: str = "aes"
    priv_key: str = ""


class PySnmpV3:
    def __init__(self, profile: V3Profile, timeout: float = 1.0, retries: int = 0, verbose: bool = False):
        self.profile = profile
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self.engine = SnmpEngine()

        lvl = profile.level.lower()
        if lvl == "noauthnopriv":
            self.user_data = UsmUserData(profile.user)
        elif lvl == "authnopriv":
            ap = AUTH_PROTOCOLS.get(profile.auth_proto.lower(), None)
            if not ap or ap == usmNoAuthProtocol:
                raise ValueError("authNoPriv exige --v3-authproto != none")
            if not profile.auth_key:
                raise ValueError("authNoPriv exige --v3-authkey")
            self.user_data = UsmUserData(profile.user, profile.auth_key, authProtocol=ap)
        elif lvl == "authpriv":
            ap = AUTH_PROTOCOLS.get(profile.auth_proto.lower(), None)
            pp = PRIV_PROTOCOLS.get(profile.priv_proto.lower(), None)
            if not ap or ap == usmNoAuthProtocol:
                raise ValueError("authPriv exige --v3-authproto != none")
            if not pp or pp == usmNoPrivProtocol:
                raise ValueError("authPriv exige --v3-privproto != none")
            if not profile.auth_key:
                raise ValueError("authPriv exige --v3-authkey")
            if not profile.priv_key:
                raise ValueError("authPriv exige --v3-privkey")
            self.user_data = UsmUserData(profile.user, profile.auth_key, profile.priv_key, authProtocol=ap, privProtocol=pp)
        else:
            raise ValueError("level invalide: noAuthNoPriv | authNoPriv | authPriv")

    def _target(self, host: str, port: int):
        return UdpTransportTarget((host, port), timeout=self.timeout, retries=self.retries)

    def get(self, host: str, oid: str, port: int):
        it = getCmd(self.engine, self.user_data, self._target(host, port), ContextData(), ObjectType(ObjectIdentity(oid)))
        errInd, errStat, errIdx, varBinds = next(it)
        if self.verbose:
            print("[v3][GET]", oid, "->", errInd or errStat or varBinds)
        return errInd, errStat, errIdx, varBinds


# -----------------------------
# Scénarios
# -----------------------------
def scenario_normal(args):
    gen = ScapySNMPv1v2c(verbose=args.verbose)
    end = time.time() + args.duration
    while time.time() < end:
        pkt = gen.build_packet(
            src_ip=pick_ip_like(args.source),
            dst_ip=args.target,
            community=random.choice(COMMUNITIES_OK),
            version=1,
            pdu=random.choice(["get", "getnext", "getbulk"]),
            oid=pick_oid(),
            dst_port=args.port,
        )
        gen.send(pkt)
        time.sleep(args.delay)


def scenario_suspect(args):
    gen = ScapySNMPv1v2c(verbose=args.verbose)
    end = time.time() + args.duration
    while time.time() < end:
        pkt = gen.build_packet(
            src_ip=pick_ip_like(args.source),
            dst_ip=args.target,
            community=random.choice(COMMUNITIES_BAD),
            version=1,
            pdu=random.choice(["get", "getnext", "set"]),
            oid=pick_oid(),
            dst_port=args.port,
        )
        gen.send(pkt)
        time.sleep(args.delay)


def scenario_snmpv3(args):
    profile = V3Profile(
        user=args.v3_user,
        level=args.v3_level,
        auth_proto=args.v3_authproto,
        auth_key=args.v3_authkey or "",
        priv_proto=args.v3_privproto,
        priv_key=args.v3_privkey or "",
    )
    v3 = PySnmpV3(profile, timeout=args.v3_timeout, retries=args.v3_retries, verbose=args.verbose)

    end = time.time() + args.duration
    while time.time() < end:
        v3.get(args.target, pick_oid(), port=args.port)
        time.sleep(args.delay)


SCENARIOS = {
    "normal": scenario_normal,
    "suspect": scenario_suspect,
    "snmpv3": scenario_snmpv3,
}


def build_parser():
    p = argparse.ArgumentParser(description="SNMP Traffic Simulator (v1/v2c + v3)")
    p.add_argument("--scenario", choices=SCENARIOS.keys(), required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--source", default=None)
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--delay", type=float, default=2.0)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("-v", "--verbose", action="store_true")

    # v3
    p.add_argument("--v3-user", default="snmpuser")
    p.add_argument("--v3-level", default="noAuthNoPriv", help="noAuthNoPriv | authNoPriv | authPriv")
    p.add_argument("--v3-authproto", default="sha", help="none|md5|sha|sha256")
    p.add_argument("--v3-authkey", default="")
    p.add_argument("--v3-privproto", default="aes", help="none|des|aes|aes128|aes192|aes256")
    p.add_argument("--v3-privkey", default="")
    p.add_argument("--v3-timeout", type=float, default=1.0)
    p.add_argument("--v3-retries", type=int, default=0)
    return p


def main():
    args = build_parser().parse_args()
    SCENARIOS[args.scenario](args)


if __name__ == "__main__":
    main()
