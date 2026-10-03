#!/usr/bin/env python3
"""Example: Full threat analysis with YARA + IP + Sigma-Lite"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import ConfigManager, ImplantLogger
from detection import IPAnalyzer, YARADetector, SigmaLiteDetector, ThreatCorrelator
from detection.ip_analysis import IPProfile


def main():
    """Run full analysis example"""
    print("[*] Full Threat Analysis Example")
    print("=" * 50)
    
    # Initialize
    config_manager = ConfigManager()
    logger = ImplantLogger(stealth_mode=False).get_logger()
    
    print("[+] Initializing threat detection stack...")
    ip_analyzer = IPAnalyzer()
    yara_detector = YARADetector()
    sigma_detector = SigmaLiteDetector()
    correlator = ThreatCorrelator()
    
    # Simulate network events
    print("\n[*] Simulating suspicious network activity...")
    sample_events = [
        {
            "timestamp": time.time(),
            "ip": "192.168.1.100",
            "direction": "outbound",
            "dport": 4444,  # Suspicious port
            "protocol": "TCP",
            "comm": "suspicious_process",
            "bytes_sent": 1024 * 1024,  # 1MB
        },
        {
            "timestamp": time.time() + 1,
            "ip": "192.168.1.100",
            "direction": "outbound",
            "dport": 5555,  # Another suspicious port
            "protocol": "TCP",
            "comm": "suspicious_process",
            "bytes_sent": 512 * 1024,
        },
        {
            "timestamp": time.time() + 2,
            "ip": "192.168.1.100",
            "direction": "outbound",
            "dport": 53,
            "is_dns": True,
            "comm": "curl",
            "bytes_sent": 50000,  # DNS tunneling indicator
        },
    ]
    
    # Process through detection layers
    print("\n[*] Running threat detection layers...")
    
    for event in sample_events:
        print(f"\n  [Event] {event['comm']} -> {event['ip']}:{event['dport']}")
        
        # Layer 1: IP Analysis
        print("    [Layer 1: IP Analysis]")
        # Would normally process through IP analyzer
        
        # Layer 2: YARA Detection
        print("    [Layer 2: YARA Detection]")
        # Would normally run YARA patterns
        
        # Layer 3: Sigma-Lite (behavioral)
        print("    [Layer 3: Sigma-Lite Behavioral]")
        sigma_detector.add_event(event)
    
    # Get Sigma-Lite detections
    sigma_matches = sigma_detector.detect_patterns()
    print(f"\n[+] Sigma-Lite detected {len(sigma_matches)} behavioral patterns")
    for match in sigma_matches:
        print(f"  - {match.chain_name}: {match.description}")
    
    # Correlate all results
    print("\n[*] Correlating threat detection results...")
    verdict = correlator.correlate(
        ip="192.168.1.100",
        ip_profile={"threat_score": 45.0},
        yara_matches=[],  # No YARA matches in this example
        sigma_chains=[{
            "chain_name": "DNS Exfiltration",
            "severity": "HIGH",
            "confidence": 0.85,
            "mitre_techniques": ["T1041"],
        }]
    )
    
    print(f"\n[+] THREAT VERDICT")
    print(f"  IP: {verdict.ip}")
    print(f"  Level: {verdict.threat_level.value}")
    print(f"  Confidence: {verdict.confidence:.2f}")
    print(f"  Agreement: {verdict.agreement_level}")
    print(f"  MITRE Techniques: {', '.join(verdict.mitre_techniques)}")
    print(f"  Description: {verdict.sigma_threat_description}")


if __name__ == "__main__":
    main()
