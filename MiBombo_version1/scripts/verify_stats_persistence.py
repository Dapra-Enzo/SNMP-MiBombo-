
import sys
import os
import time

# Add root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.anomaly_detector import AnomalyDetector, AnomalyType, Severity

def test_persistence():
    print("[*] Testing Stats Persistence...")
    
    # Clean previous stats
    if os.path.exists("data/stats.json"):
        os.remove("data/stats.json")
    
    # 1. First run
    detector = AnomalyDetector()
    print(f"Initial stats: {detector.stats['total_packets_analyzed']}")
    
    # Simulate activity
    detector.stats["total_packets_analyzed"] += 42
    detector.stats["total_alerts_generated"] += 5
    print(f"Modified stats: {detector.stats['total_packets_analyzed']}")
    
    # Save
    detector.save_stats()
    print("[*] Stats saved.")
    
    # 2. Second run (simulation restart)
    print("[*] Reinstantiating Detector...")
    detector2 = AnomalyDetector()
    
    # Verify
    restored_packets = detector2.stats["total_packets_analyzed"]
    restored_alerts = detector2.stats["total_alerts_generated"]
    
    print(f"Restored stats: {restored_packets} packets, {restored_alerts} alerts")
    
    if restored_packets == 42 and restored_alerts == 5:
        print("[SUCCESS] Persistence works correctly!")
        return True
    else:
        print(f"[FAILURE] Expected 42/5, got {restored_packets}/{restored_alerts}")
        return False

if __name__ == "__main__":
    test_persistence()
