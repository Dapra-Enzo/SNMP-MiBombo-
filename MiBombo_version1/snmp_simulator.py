#!/usr/bin/env python3
"""
===============================================================================
MiBombo - SNMP Traffic Simulator
===============================================================================
Script de simulation complet pour tester tous les scénarios SNMP.

Usage:
    sudo python snmp_simulator.py                    # Menu interactif
    sudo python snmp_simulator.py --scenario all    # Tous les scénarios
    sudo python snmp_simulator.py --scenario flood  # Scénario spécifique
    sudo python snmp_simulator.py --list            # Liste des scénarios

Scénarios disponibles:
    1. normal      - Trafic SNMP normal (communautés autorisées)
    2. suspect     - Trafic suspect (communautés non autorisées)
    3. flood       - Attaque flood (beaucoup de paquets rapidement)
    4. scan        - Scan réseau (une IP vers plusieurs destinations)
    5. trapstorm   - Tempête de traps (beaucoup de traps)
    6. mixed       - Trafic mixte réaliste
    7. discovery   - Découverte d'appareils (nouveaux équipements)
    8. snmpv3      - Trafic SNMPv3 (authentifié/chiffré)
    9. malformed   - Paquets malformés (tests de robustesse)
    10. all        - Tous les scénarios enchaînés

Auteur: MiBombo Suite
===============================================================================
"""

import argparse
import random
import time
import sys
import os
import threading
from datetime import datetime
from typing import List, Tuple, Optional

# Vérification Scapy
try:
    from scapy.all import *
    from scapy.layers.snmp import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("=" * 60)
    print("[!] ERREUR: Scapy n'est pas installé")
    print("    Installation: pip install scapy")
    print("=" * 60)


# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Configuration du simulateur."""
    
    # Interface réseau (sera détectée automatiquement si None)
    INTERFACE: Optional[str] = None
    
    # Adresses IP
    LOCAL_IP = "10.204.0.88"          # IP source par défaut
    TARGET_IP = "10.204.0.1"           # IP destination par défaut
    NETWORK = "10.204.0.1/16"          # Réseau pour le scan
    
    # Ports SNMP
    SNMP_PORT = 161
    TRAP_PORT = 162
    
    # Communautés
    VALID_COMMUNITIES = ["public", "private", "monitoring"]
    SUSPECT_COMMUNITIES = ["admin", "root", "test", "cisco", "secret", 
                          "password", "snmp", "network", "default"]
    
    # OIDs communs
    COMMON_OIDS = [
        "1.3.6.1.2.1.1.1.0",      # sysDescr
        "1.3.6.1.2.1.1.3.0",      # sysUpTime
        "1.3.6.1.2.1.1.4.0",      # sysContact
        "1.3.6.1.2.1.1.5.0",      # sysName
        "1.3.6.1.2.1.1.6.0",      # sysLocation
        "1.3.6.1.2.1.2.1.0",      # ifNumber
        "1.3.6.1.2.1.2.2.1.1",    # ifIndex
        "1.3.6.1.2.1.2.2.1.2",    # ifDescr
        "1.3.6.1.2.1.2.2.1.10",   # ifInOctets
        "1.3.6.1.2.1.2.2.1.16",   # ifOutOctets
        "1.3.6.1.2.1.4.1.0",      # ipForwarding
        "1.3.6.1.2.1.4.3.0",      # ipInReceives
        "1.3.6.1.2.1.25.1.1.0",   # hrSystemUptime
        "1.3.6.1.2.1.25.2.2.0",   # hrMemorySize
        "1.3.6.1.2.1.25.3.3.1.2", # hrProcessorLoad
    ]
    
    # Types de PDU
    PDU_TYPES = {
        "get": SNMPget,
        "getnext": SNMPnext,
        "getbulk": SNMPbulk,
        "set": SNMPset,
    }
    
    # Trap OIDs
    TRAP_OIDS = [
        "1.3.6.1.6.3.1.1.5.1",    # coldStart
        "1.3.6.1.6.3.1.1.5.2",    # warmStart
        "1.3.6.1.6.3.1.1.5.3",    # linkDown
        "1.3.6.1.6.3.1.1.5.4",    # linkUp
        "1.3.6.1.6.3.1.1.5.5",    # authenticationFailure
    ]
    
    # Types d'appareils simulés
    DEVICE_TYPES = [
        ("Router", "Cisco IOS Software, C2900"),
        ("Switch", "HP ProCurve Switch 2920"),
        ("Firewall", "Fortinet FortiGate-60E"),
        ("Server", "Linux server 5.4.0"),
        ("Printer", "HP LaserJet Pro MFP"),
        ("AP", "Ubiquiti UniFi AP-AC-Pro"),
        ("NAS", "Synology DiskStation DS920+"),
        ("Camera", "Hikvision DS-2CD2143G0-I"),
        ("UPS", "APC Smart-UPS 1500"),
        ("PLC", "Siemens SIMATIC S7-1200"),
    ]


# =============================================================================
# UTILITAIRES
# =============================================================================

class Colors:
    """Couleurs pour le terminal."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


def log(msg: str, level: str = "info"):
    """Affiche un message coloré."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "info": Colors.CYAN,
        "success": Colors.GREEN,
        "warning": Colors.WARNING,
        "error": Colors.FAIL,
        "header": Colors.HEADER,
    }
    color = colors.get(level, Colors.END)
    print(f"{color}[{timestamp}] {msg}{Colors.END}")


def banner():
    """Affiche la bannière."""
    print(Colors.HEADER + """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███╗   ███╗██╗██████╗ ██╗   ██╗██████╗ ███╗   ██╗           ║
║   ████╗ ████║██║██╔══██╗██║   ██║██╔══██╗████╗  ██║           ║
║   ██╔████╔██║██║██████╔╝██║   ██║██████╔╝██╔██╗ ██║           ║
║   ██║╚██╔╝██║██║██╔══██╗██║   ██║██╔══██╗██║╚██╗██║           ║
║   ██║ ╚═╝ ██║██║██████╔╝╚██████╔╝██║  ██║██║ ╚████║           ║
║   ╚═╝     ╚═╝╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝           ║
║                                                               ║
║              🔬 SNMP Traffic Simulator 🔬                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
""" + Colors.END)


def get_default_interface() -> str:
    """Détecte l'interface réseau par défaut."""
    try:
        return conf.iface
    except:
        return "eth0"


def random_ip(network: str = "192.168.1.0/24") -> str:
    """Génère une IP aléatoire dans le réseau."""
    base = network.split('/')[0]
    parts = base.split('.')
    parts[3] = str(random.randint(1, 254))
    return '.'.join(parts)


def random_mac() -> str:
    """Génère une adresse MAC aléatoire."""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])


# =============================================================================
# GÉNÉRATEURS DE PAQUETS SNMP
# =============================================================================

class SNMPPacketGenerator:
    """Générateur de paquets SNMP."""
    
    def __init__(self, interface: str = None):
        self.interface = interface or get_default_interface()
        self.packet_count = 0
    
    def create_snmp_packet(self, src_ip: str, dst_ip: str, community: str,
                           pdu_type: str = "get", oid: str = None,
                           src_port: int = None, dst_port: int = 161,
                           version: int = 1) -> Packet:
        """Crée un paquet SNMP."""
        
        if src_port is None:
            src_port = random.randint(1024, 65535)
        
        if oid is None:
            oid = random.choice(Config.COMMON_OIDS)
        
        # Couches réseau
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=src_port, dport=dst_port)
        
        # PDU SNMP
        pdu_class = Config.PDU_TYPES.get(pdu_type, SNMPget)
        
        if pdu_type == "getbulk":
            pdu = pdu_class(
                id=RandInt(),
                max_repetitions=10,
                varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]
            )
        elif pdu_type == "set":
            pdu = pdu_class(
                id=RandInt(),
                varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_INTEGER(42))]
            )
        else:
            pdu = pdu_class(
                id=RandInt(),
                varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]
            )
        
        # Paquet SNMP
        snmp = SNMP(version=version, community=community, PDU=pdu)
        
        return ip / udp / snmp
    
    def create_trap_packet(self, src_ip: str, dst_ip: str, community: str,
                           trap_oid: str = None, version: int = 1) -> Packet:
        """Crée un paquet SNMP Trap."""
        
        if trap_oid is None:
            trap_oid = random.choice(Config.TRAP_OIDS)
        
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=random.randint(1024, 65535), dport=162)
        
        if version == 1:
            # SNMPv1 Trap
            pdu = SNMPtrapv1(
                enterprise=ASN1_OID("1.3.6.1.4.1.9"),
                agent_addr=src_ip,
                generic_trap=random.randint(0, 6),
                specific_trap=random.randint(0, 100),
                time_stamp=int(time.time()),
                varbindlist=[SNMPvarbind(oid=ASN1_OID(trap_oid))]
            )
        else:
            # SNMPv2c Trap
            pdu = SNMPtrapv2(
                id=RandInt(),
                varbindlist=[
                    SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.3.0"), value=ASN1_INTEGER(int(time.time()))),
                    SNMPvarbind(oid=ASN1_OID("1.3.6.1.6.3.1.1.4.1.0"), value=ASN1_OID(trap_oid)),
                ]
            )
        
        snmp = SNMP(version=version, community=community, PDU=pdu)
        
        return ip / udp / snmp
    
    def create_response_packet(self, src_ip: str, dst_ip: str, community: str,
                               request_id: int, oid: str, value: str) -> Packet:
        """Crée un paquet SNMP Response."""
        
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=161, dport=random.randint(1024, 65535))
        
        pdu = SNMPresponse(
            id=request_id,
            error=0,
            error_index=0,
            varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_STRING(value))]
        )
        
        snmp = SNMP(version=1, community=community, PDU=pdu)
        
        return ip / udp / snmp
    
    def send_packet(self, packet: Packet, verbose: bool = False):
        """Envoie un paquet."""
        try:
            send(packet, iface=self.interface, verbose=0)
            self.packet_count += 1
            if verbose:
                log(f"Paquet envoyé: {packet[IP].src} -> {packet[IP].dst}", "success")
        except Exception as e:
            log(f"Erreur envoi: {e}", "error")
    
    def send_packets(self, packets: List[Packet], delay: float = 0.1, verbose: bool = False):
        """Envoie une liste de paquets."""
        for pkt in packets:
            self.send_packet(pkt, verbose)
            time.sleep(delay)


# =============================================================================
# SCÉNARIOS DE TEST
# =============================================================================

class Scenarios:
    """Collection de scénarios de test."""
    
    def __init__(self, generator: SNMPPacketGenerator):
        self.gen = generator
        self.running = False
    
    def stop(self):
        """Arrête le scénario en cours."""
        self.running = False
    
    # -------------------------------------------------------------------------
    # 1. TRAFIC NORMAL
    # -------------------------------------------------------------------------
    
    def normal_traffic(self, duration: int = 30, rate: float = 2.0):
        """
        Génère du trafic SNMP normal.
        - Communautés autorisées
        - Requêtes GET/GETNEXT classiques
        - Taux modéré
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Trafic SNMP Normal", "header")
        log(f"Durée: {duration}s | Taux: {rate} pkt/s", "info")
        log("=" * 50, "header")
        
        self.running = True
        start = time.time()
        count = 0
        
        sources = [random_ip() for _ in range(5)]
        
        while self.running and (time.time() - start) < duration:
            src = random.choice(sources)
            dst = Config.TARGET_IP
            community = random.choice(Config.VALID_COMMUNITIES)
            pdu_type = random.choice(["get", "getnext"])
            oid = random.choice(Config.COMMON_OIDS)
            
            pkt = self.gen.create_snmp_packet(src, dst, community, pdu_type, oid)
            self.gen.send_packet(pkt)
            count += 1
            
            if count % 10 == 0:
                log(f"Envoyé: {count} paquets normaux", "info")
            
            time.sleep(1.0 / rate)
        
        log(f"✅ Terminé: {count} paquets normaux envoyés", "success")
        return count
    
    # -------------------------------------------------------------------------
    # 2. TRAFIC SUSPECT
    # -------------------------------------------------------------------------
    
    def suspect_traffic(self, duration: int = 30, rate: float = 1.0):
        """
        Génère du trafic SNMP suspect.
        - Communautés non autorisées (admin, root, etc.)
        - Tentatives de bruteforce
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Trafic Suspect (Communities)", "header")
        log(f"Durée: {duration}s | Communities suspectes", "warning")
        log("=" * 50, "header")
        
        self.running = True
        start = time.time()
        count = 0
        
        attacker_ip = random_ip()
        log(f"Attaquant: {attacker_ip}", "warning")
        
        while self.running and (time.time() - start) < duration:
            community = random.choice(Config.SUSPECT_COMMUNITIES)
            oid = random.choice(Config.COMMON_OIDS)
            
            pkt = self.gen.create_snmp_packet(
                attacker_ip, Config.TARGET_IP, community, "get", oid
            )
            self.gen.send_packet(pkt)
            count += 1
            
            log(f"[SUSPECT] Community: '{community}'", "warning")
            
            time.sleep(1.0 / rate)
        
        log(f"⚠️ Terminé: {count} tentatives suspectes", "warning")
        return count
    
    # -------------------------------------------------------------------------
    # 3. ATTAQUE FLOOD
    # -------------------------------------------------------------------------
    
    def flood_attack(self, duration: int = 10, packets_per_second: int = 200):
        """
        Simule une attaque flood SNMP.
        - Beaucoup de paquets très rapidement
        - Même source IP
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Attaque Flood SNMP", "header")
        log(f"Durée: {duration}s | Taux: {packets_per_second} pkt/s", "error")
        log("=" * 50, "header")
        
        self.running = True
        start = time.time()
        count = 0
        
        attacker_ip = random_ip()
        log(f"🌊 Attaquant: {attacker_ip}", "error")
        
        delay = 1.0 / packets_per_second
        
        while self.running and (time.time() - start) < duration:
            pkt = self.gen.create_snmp_packet(
                attacker_ip, Config.TARGET_IP,
                random.choice(Config.VALID_COMMUNITIES),
                "get", random.choice(Config.COMMON_OIDS)
            )
            self.gen.send_packet(pkt)
            count += 1
            
            if count % 100 == 0:
                elapsed = time.time() - start
                rate = count / elapsed if elapsed > 0 else 0
                log(f"🌊 Flood: {count} paquets ({rate:.0f}/s)", "error")
            
            time.sleep(delay)
        
        log(f"🌊 Terminé: {count} paquets flood", "error")
        return count
    
    # -------------------------------------------------------------------------
    # 4. SCAN RÉSEAU
    # -------------------------------------------------------------------------
    
    def network_scan(self, start_ip: int = 1, end_ip: int = 50, delay: float = 0.1):
        """
        Simule un scan réseau SNMP.
        - Une source scanne plusieurs destinations
        - Détection communautés
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Scan Réseau SNMP", "header")
        log(f"Plage: .{start_ip} à .{end_ip}", "warning")
        log("=" * 50, "header")
        
        self.running = True
        count = 0
        
        scanner_ip = random_ip()
        log(f"🔍 Scanner: {scanner_ip}", "warning")
        
        base = Config.NETWORK.split('.')[:-1]
        
        for i in range(start_ip, end_ip + 1):
            if not self.running:
                break
            
            target = '.'.join(base) + f".{i}"
            
            # Essayer plusieurs communautés
            for community in ["public", "private", "admin"]:
                if not self.running:
                    break
                
                pkt = self.gen.create_snmp_packet(
                    scanner_ip, target, community, "get",
                    "1.3.6.1.2.1.1.1.0"  # sysDescr
                )
                self.gen.send_packet(pkt)
                count += 1
                time.sleep(delay)
            
            log(f"🔍 Scanné: {target}", "info")
        
        log(f"🔍 Terminé: {count} requêtes de scan", "warning")
        return count
    
    # -------------------------------------------------------------------------
    # 5. TEMPÊTE DE TRAPS
    # -------------------------------------------------------------------------
    
    def trap_storm(self, duration: int = 10, rate: float = 50.0):
        """
        Simule une tempête de traps SNMP.
        - Beaucoup de traps envoyés rapidement
        - Différents types (linkDown, linkUp, etc.)
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Tempête de Traps", "header")
        log(f"Durée: {duration}s | Taux: {rate} traps/s", "error")
        log("=" * 50, "header")
        
        self.running = True
        start = time.time()
        count = 0
        
        sources = [random_ip() for _ in range(10)]
        
        while self.running and (time.time() - start) < duration:
            src = random.choice(sources)
            trap_oid = random.choice(Config.TRAP_OIDS)
            version = random.choice([1, 2])
            
            pkt = self.gen.create_trap_packet(
                src, Config.TARGET_IP,
                random.choice(Config.VALID_COMMUNITIES),
                trap_oid, version
            )
            self.gen.send_packet(pkt)
            count += 1
            
            if count % 50 == 0:
                log(f"⛈️ Traps: {count}", "error")
            
            time.sleep(1.0 / rate)
        
        log(f"⛈️ Terminé: {count} traps", "error")
        return count
    
    # -------------------------------------------------------------------------
    # 6. TRAFIC MIXTE RÉALISTE
    # -------------------------------------------------------------------------
    
    def mixed_realistic(self, duration: int = 60):
        """
        Génère un trafic mixte réaliste.
        - Majorité de trafic normal
        - Quelques événements suspects
        - Quelques traps
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Trafic Mixte Réaliste", "header")
        log(f"Durée: {duration}s", "info")
        log("=" * 50, "header")
        
        self.running = True
        start = time.time()
        stats = {"normal": 0, "suspect": 0, "trap": 0}
        
        # Appareils simulés
        devices = [(random_ip(), random.choice(Config.DEVICE_TYPES)) for _ in range(8)]
        log(f"📡 {len(devices)} appareils simulés", "info")
        
        while self.running and (time.time() - start) < duration:
            rand = random.random()
            
            if rand < 0.80:
                # 80% - Trafic normal
                device_ip, (dtype, _) = random.choice(devices)
                pkt = self.gen.create_snmp_packet(
                    device_ip, Config.TARGET_IP,
                    random.choice(Config.VALID_COMMUNITIES),
                    random.choice(["get", "getnext"]),
                    random.choice(Config.COMMON_OIDS)
                )
                self.gen.send_packet(pkt)
                stats["normal"] += 1
                
            elif rand < 0.90:
                # 10% - Trap
                device_ip, _ = random.choice(devices)
                pkt = self.gen.create_trap_packet(
                    device_ip, Config.TARGET_IP,
                    random.choice(Config.VALID_COMMUNITIES),
                    random.choice(Config.TRAP_OIDS)
                )
                self.gen.send_packet(pkt)
                stats["trap"] += 1
                log(f"📨 Trap de {device_ip}", "info")
                
            else:
                # 10% - Suspect
                pkt = self.gen.create_snmp_packet(
                    random_ip(), Config.TARGET_IP,
                    random.choice(Config.SUSPECT_COMMUNITIES),
                    "get", random.choice(Config.COMMON_OIDS)
                )
                self.gen.send_packet(pkt)
                stats["suspect"] += 1
                log(f"⚠️ Requête suspecte", "warning")
            
            time.sleep(random.uniform(0.1, 0.5))
        
        total = sum(stats.values())
        log(f"📊 Résumé: {stats['normal']} normaux, {stats['trap']} traps, {stats['suspect']} suspects", "success")
        return total
    
    # -------------------------------------------------------------------------
    # 7. DÉCOUVERTE D'APPAREILS
    # -------------------------------------------------------------------------
    
    def device_discovery(self, num_devices: int = 10, interval: float = 2.0):
        """
        Simule la découverte de nouveaux appareils.
        - Nouveaux appareils apparaissent progressivement
        - Différents types (routeur, switch, serveur, etc.)
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Découverte d'Appareils", "header")
        log(f"Appareils: {num_devices} | Intervalle: {interval}s", "info")
        log("=" * 50, "header")
        
        self.running = True
        devices_added = []
        
        for i in range(num_devices):
            if not self.running:
                break
            
            device_ip = random_ip()
            device_type, sys_descr = random.choice(Config.DEVICE_TYPES)
            
            devices_added.append((device_ip, device_type))
            
            # Envoyer plusieurs paquets pour simuler l'activité
            for _ in range(random.randint(3, 8)):
                pkt = self.gen.create_snmp_packet(
                    device_ip, Config.TARGET_IP,
                    random.choice(Config.VALID_COMMUNITIES),
                    "get", random.choice(Config.COMMON_OIDS)
                )
                self.gen.send_packet(pkt)
                time.sleep(0.1)
            
            log(f"📡 Nouvel appareil: {device_ip} ({device_type})", "success")
            time.sleep(interval)
        
        log(f"✅ {len(devices_added)} appareils découverts", "success")
        return len(devices_added)
    
    # -------------------------------------------------------------------------
    # 8. TRAFIC SNMPv3
    # -------------------------------------------------------------------------
    
    def snmpv3_traffic(self, duration: int = 20, rate: float = 1.0):
        """
        Simule du trafic SNMPv3.
        Note: Scapy a un support limité pour SNMPv3, 
        on simule les en-têtes de base.
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Trafic SNMPv3", "header")
        log(f"Durée: {duration}s", "info")
        log("=" * 50, "header")
        
        self.running = True
        start = time.time()
        count = 0
        
        sources = [random_ip() for _ in range(3)]
        
        while self.running and (time.time() - start) < duration:
            src = random.choice(sources)
            
            # SNMPv3 utilise version=3
            pkt = self.gen.create_snmp_packet(
                src, Config.TARGET_IP,
                "",  # Pas de community en SNMPv3
                "get", random.choice(Config.COMMON_OIDS),
                version=3
            )
            self.gen.send_packet(pkt)
            count += 1
            
            log(f"🔐 SNMPv3 de {src}", "info")
            time.sleep(1.0 / rate)
        
        log(f"🔐 Terminé: {count} paquets SNMPv3", "success")
        return count
    
    # -------------------------------------------------------------------------
    # 9. PAQUETS MALFORMÉS
    # -------------------------------------------------------------------------
    
    def malformed_packets(self, count: int = 20, delay: float = 0.5):
        """
        Envoie des paquets SNMP malformés.
        - OIDs invalides
        - Versions incorrectes
        - Données corrompues
        """
        log("=" * 50, "header")
        log("SCÉNARIO: Paquets Malformés", "header")
        log(f"Paquets: {count}", "warning")
        log("=" * 50, "header")
        
        self.running = True
        sent = 0
        
        attacker_ip = random_ip()
        
        malformed_types = [
            "empty_community",
            "long_community",
            "invalid_oid",
            "wrong_version",
            "truncated",
        ]
        
        for i in range(count):
            if not self.running:
                break
            
            mal_type = random.choice(malformed_types)
            
            try:
                if mal_type == "empty_community":
                    pkt = self.gen.create_snmp_packet(
                        attacker_ip, Config.TARGET_IP, "", "get"
                    )
                elif mal_type == "long_community":
                    long_comm = "A" * 500
                    pkt = self.gen.create_snmp_packet(
                        attacker_ip, Config.TARGET_IP, long_comm, "get"
                    )
                elif mal_type == "invalid_oid":
                    pkt = self.gen.create_snmp_packet(
                        attacker_ip, Config.TARGET_IP, "public", "get",
                        "999.999.999.999.999"
                    )
                elif mal_type == "wrong_version":
                    pkt = self.gen.create_snmp_packet(
                        attacker_ip, Config.TARGET_IP, "public", "get",
                        version=99
                    )
                else:
                    # Paquet tronqué - on envoie juste IP/UDP
                    pkt = IP(src=attacker_ip, dst=Config.TARGET_IP) / UDP(sport=12345, dport=161) / Raw(b"\x30\x00")
                
                self.gen.send_packet(pkt)
                sent += 1
                log(f"💥 Malformé [{mal_type}]", "warning")
                
            except Exception as e:
                log(f"Erreur création paquet: {e}", "error")
            
            time.sleep(delay)
        
        log(f"💥 Terminé: {sent} paquets malformés", "warning")
        return sent
    
    # -------------------------------------------------------------------------
    # 10. TOUS LES SCÉNARIOS
    # -------------------------------------------------------------------------
    
    def run_all(self):
        """Exécute tous les scénarios."""
        log("=" * 60, "header")
        log("EXÉCUTION DE TOUS LES SCÉNARIOS", "header")
        log("=" * 60, "header")
        
        scenarios = [
            ("Trafic Normal", lambda: self.normal_traffic(20, 2)),
            ("Trafic Suspect", lambda: self.suspect_traffic(15, 1)),
            ("Flood Attack", lambda: self.flood_attack(5, 100)),
            ("Scan Réseau", lambda: self.network_scan(1, 20, 0.05)),
            ("Trap Storm", lambda: self.trap_storm(5, 30)),
            ("Trafic Mixte", lambda: self.mixed_realistic(30)),
            ("Découverte", lambda: self.device_discovery(5, 1)),
            ("SNMPv3", lambda: self.snmpv3_traffic(10, 1)),
            ("Malformés", lambda: self.malformed_packets(10, 0.3)),
        ]
        
        results = {}
        
        for name, func in scenarios:
            log(f"\n{'─' * 40}", "info")
            log(f"▶ Démarrage: {name}", "header")
            log(f"{'─' * 40}", "info")
            
            try:
                count = func()
                results[name] = count
                log(f"✅ {name}: {count} paquets", "success")
            except Exception as e:
                log(f"❌ {name}: {e}", "error")
                results[name] = 0
            
            time.sleep(2)  # Pause entre scénarios
        
        # Résumé
        log("\n" + "=" * 60, "header")
        log("RÉSUMÉ FINAL", "header")
        log("=" * 60, "header")
        
        total = 0
        for name, count in results.items():
            log(f"  {name}: {count} paquets", "info")
            total += count
        
        log(f"\n📊 TOTAL: {total} paquets envoyés", "success")
        return total


# =============================================================================
# MENU INTERACTIF
# =============================================================================

def interactive_menu(scenarios: Scenarios):
    """Menu interactif pour choisir les scénarios."""
    
    while True:
        print(Colors.CYAN + """
┌─────────────────────────────────────────────────────────────┐
│                    MENU PRINCIPAL                           │
├─────────────────────────────────────────────────────────────┤
│  1. Trafic Normal          │  6. Trafic Mixte Réaliste     │
│  2. Trafic Suspect         │  7. Découverte d'Appareils    │
│  3. Attaque Flood          │  8. Trafic SNMPv3             │
│  4. Scan Réseau            │  9. Paquets Malformés         │
│  5. Tempête de Traps       │ 10. Tous les Scénarios        │
├─────────────────────────────────────────────────────────────┤
│  0. Quitter                │  C. Configuration             │
└─────────────────────────────────────────────────────────────┘
""" + Colors.END)
        
        choice = input(Colors.GREEN + "Choix > " + Colors.END).strip().lower()
        
        if choice == "0" or choice == "q":
            log("Au revoir!", "info")
            break
        
        elif choice == "c":
            print(f"""
Configuration actuelle:
  Interface: {scenarios.gen.interface}
  IP Source: {Config.LOCAL_IP}
  IP Cible:  {Config.TARGET_IP}
  Réseau:    {Config.NETWORK}
""")
            new_target = input("Nouvelle IP cible (Enter = garder): ").strip()
            if new_target:
                Config.TARGET_IP = new_target
                log(f"IP cible: {Config.TARGET_IP}", "success")
        
        elif choice == "1":
            dur = input("Durée en secondes [30]: ").strip() or "30"
            rate = input("Paquets/seconde [2]: ").strip() or "2"
            scenarios.normal_traffic(int(dur), float(rate))
        
        elif choice == "2":
            dur = input("Durée en secondes [30]: ").strip() or "30"
            scenarios.suspect_traffic(int(dur))
        
        elif choice == "3":
            dur = input("Durée en secondes [10]: ").strip() or "10"
            rate = input("Paquets/seconde [200]: ").strip() or "200"
            scenarios.flood_attack(int(dur), int(rate))
        
        elif choice == "4":
            start = input("IP début (.X) [1]: ").strip() or "1"
            end = input("IP fin (.X) [50]: ").strip() or "50"
            scenarios.network_scan(int(start), int(end))
        
        elif choice == "5":
            dur = input("Durée en secondes [10]: ").strip() or "10"
            rate = input("Traps/seconde [50]: ").strip() or "50"
            scenarios.trap_storm(int(dur), float(rate))
        
        elif choice == "6":
            dur = input("Durée en secondes [60]: ").strip() or "60"
            scenarios.mixed_realistic(int(dur))
        
        elif choice == "7":
            num = input("Nombre d'appareils [10]: ").strip() or "10"
            scenarios.device_discovery(int(num))
        
        elif choice == "8":
            dur = input("Durée en secondes [20]: ").strip() or "20"
            scenarios.snmpv3_traffic(int(dur))
        
        elif choice == "9":
            num = input("Nombre de paquets [20]: ").strip() or "20"
            scenarios.malformed_packets(int(num))
        
        elif choice == "10":
            confirm = input("Exécuter TOUS les scénarios? [o/N]: ").strip().lower()
            if confirm == "o":
                scenarios.run_all()
        
        else:
            log("Choix invalide", "error")
        
        input("\n[Appuyez sur Entrée pour continuer...]")


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

def main():
    """Point d'entrée principal."""
    
    parser = argparse.ArgumentParser(
        description="MiBombo SNMP Traffic Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  sudo python snmp_simulator.py                     # Menu interactif
  sudo python snmp_simulator.py --scenario normal   # Trafic normal
  sudo python snmp_simulator.py --scenario flood --duration 30
  sudo python snmp_simulator.py --scenario all      # Tous les scénarios
  sudo python snmp_simulator.py --list              # Liste des scénarios
        """
    )
    
    parser.add_argument('-s', '--scenario', type=str,
                       help='Scénario à exécuter (normal, suspect, flood, scan, trapstorm, mixed, discovery, snmpv3, malformed, all)')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Durée en secondes (défaut: 30)')
    parser.add_argument('-r', '--rate', type=float, default=10,
                       help='Taux de paquets/seconde (défaut: 10)')
    parser.add_argument('-t', '--target', type=str, default=Config.TARGET_IP,
                       help=f'IP cible (défaut: {Config.TARGET_IP})')
    parser.add_argument('-i', '--interface', type=str,
                       help='Interface réseau')
    parser.add_argument('-l', '--list', action='store_true',
                       help='Liste les scénarios disponibles')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Mode silencieux')
    
    args = parser.parse_args()
    
    # Liste des scénarios
    if args.list:
        print("""
Scénarios disponibles:
  normal     - Trafic SNMP normal (communautés autorisées)
  suspect    - Trafic suspect (communautés non autorisées)
  flood      - Attaque flood (beaucoup de paquets)
  scan       - Scan réseau (vers plusieurs destinations)
  trapstorm  - Tempête de traps
  mixed      - Trafic mixte réaliste
  discovery  - Découverte d'appareils
  snmpv3     - Trafic SNMPv3
  malformed  - Paquets malformés
  all        - Tous les scénarios
        """)
        return
    
    # Vérification Scapy
    if not SCAPY_AVAILABLE:
        sys.exit(1)
    
    # Vérification root
    if os.geteuid() != 0:
        log("⚠️ Ce script nécessite les droits root (sudo)", "error")
        sys.exit(1)
    
    # Banner
    if not args.quiet:
        banner()
    
    # Configuration
    Config.TARGET_IP = args.target
    interface = args.interface or get_default_interface()
    
    log(f"Interface: {interface}", "info")
    log(f"Cible: {Config.TARGET_IP}", "info")
    
    # Initialisation
    generator = SNMPPacketGenerator(interface)
    scenarios = Scenarios(generator)
    
    # Exécution
    if args.scenario:
        scenario_map = {
            "normal": lambda: scenarios.normal_traffic(args.duration, args.rate),
            "suspect": lambda: scenarios.suspect_traffic(args.duration),
            "flood": lambda: scenarios.flood_attack(args.duration, int(args.rate)),
            "scan": lambda: scenarios.network_scan(),
            "trapstorm": lambda: scenarios.trap_storm(args.duration, args.rate),
            "mixed": lambda: scenarios.mixed_realistic(args.duration),
            "discovery": lambda: scenarios.device_discovery(),
            "snmpv3": lambda: scenarios.snmpv3_traffic(args.duration),
            "malformed": lambda: scenarios.malformed_packets(),
            "all": lambda: scenarios.run_all(),
        }
        
        func = scenario_map.get(args.scenario.lower())
        if func:
            try:
                func()
            except KeyboardInterrupt:
                log("\n⛔ Arrêt demandé", "warning")
                scenarios.stop()
        else:
            log(f"Scénario inconnu: {args.scenario}", "error")
            log("Utilisez --list pour voir les scénarios", "info")
    else:
        # Menu interactif
        try:
            interactive_menu(scenarios)
        except KeyboardInterrupt:
            log("\n👋 Au revoir!", "info")


if __name__ == "__main__":
    main()
