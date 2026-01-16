import unittest
from unittest.mock import MagicMock, patch
from queue import Queue
from scapy.all import IP, UDP, SNMP
import core.analyzer
import core.influx_wrapper
from core.analyzer import PacketAnalyzer

class TestAnalyser(unittest.TestCase):
    def setUp(self):
        self.mock_queue = Queue()
        self.mock_db = MagicMock()
        
        # Patch InfluxWrapper instance
        self.patcher = patch('core.influx_wrapper.InfluxWrapper.get_instance')
        self.mock_influx_cls = self.patcher.start()
        self.mock_influx = self.mock_influx_cls.return_value
        
        self.analyser = PacketAnalyzer(self.mock_queue, self.mock_db, pcap_dir="tests/tmp_pcap")

    def tearDown(self):
        self.patcher.stop()

    def test_process_packet_ip_udp(self):
        """Test processing of standard IP/UDP packet for Influx stats"""
        pkt = IP(src="192.168.1.50", dst="192.168.1.1") / UDP(sport=161, dport=162) / "Payload"
        self.mock_queue.put(pkt)
        
        processed = self.analyser.process_packet()
        
        self.assertTrue(processed)
        # Verify Influx write
        self.mock_influx.write_packet_stat.assert_called_with(len(pkt), "UDP", "192.168.1.50")

    def test_process_packet_snmp(self):
        """Test processing of SNMP packet triggers DB analysis"""
        pkt = IP(src="192.168.1.50") / UDP(sport=161, dport=162) / SNMP(version=0, community="public", PDU=MagicMock())
        self.mock_queue.put(pkt)
        
        # Mock internal analysis method to avoid complexity of full parser here
        self.analyser._analyze_snmp = MagicMock()
        
        processed = self.analyser.process_packet()
        
        self.assertTrue(processed)
        self.assertEqual(self.analyser.nb_pkt, 1)
        self.analyser._analyze_snmp.assert_called_once()

    def test_analyze_behavior_threat(self):
        """Test threat detection logic and Influx write"""
        # Data packet (simulated)
        data = {
            "ip_src": "10.0.0.666", 
            "ip_dst": "192.168.1.1",
            "mac_src": "AA:BB:CC:DD:EE:FF",
            "mac_dst": "00:00:00:00:00:00"
        }
        
        # Should detect as suspect because not in whitelist (default)
        score = self.analyser._analyze_behavior("10.0.0.666", data)
        
        # Expect score > 0 (e.g. 20 for suspect)
        self.assertGreater(score, 0)
        
        # Verify Influx write
        self.mock_influx.write_threat.assert_called_with(score, "10.0.0.666")

    def test_whitelist_logic(self):
        """Test whitelisting mechanism"""
        # Configure Valid Whitelist
        self.analyser.config = {
            "whiteList": {
                "IPs": ["192.168.1.100"]
            }
        }
        
        # Case 1: Allowed IP
        data_ok = {"ip_src": "192.168.1.100", "ip_dst": "192.168.1.100"}
        self.assertTrue(self.analyser.compare(data_ok))
        
        # Case 2: Blocked IP
        data_bad = {"ip_src": "1.2.3.4", "ip_dst": "192.168.1.100"}
        self.assertFalse(self.analyser.compare(data_bad))

if __name__ == '__main__':
    unittest.main()
