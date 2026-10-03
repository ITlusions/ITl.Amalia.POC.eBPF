#!/usr/bin/env python3
"""
Textual Demo: eBPF Implant 24/7 Operations
Shows event collection, threat detection, and exporting in real-time
"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from core import ConfigManager, ImplantLogger
from collection import TelemetryCollection
from detection import IPAnalyzer, YARADetector, SigmaLiteDetector, ThreatCorrelator


def print_header(title):
    """Print formatted header"""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def print_event(timestamp, event_type, details):
    """Print event in real-time style"""
    time_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
    print(f"[{time_str}] [{event_type:^12}] {details}")


def demo_1_configuration():
    """Demo 1: Configuration Loading"""
    print_header("DEMO 1: Configuration Loading")
    
    print("Loading implant configuration...\n")
    config_manager = ConfigManager()
    settings = config_manager.settings
    
    print(f"Implant ID:              {settings.implant_id}")
    print(f"Collection Interval:     {settings.collection_interval}s")
    print(f"Enable IP Analysis:      {settings.enable_ip_analysis}")
    print(f"Enable YARA Detection:   {settings.enable_yara_detection}")
    print(f"Enable Sigma-Lite:       {settings.enable_sigma_detection}")
    print(f"Enable Stealth:          {settings.enable_stealth}")
    print(f"BrainCell Streaming:     {settings.enable_braincell_streaming}")
    print(f"Amalia Export:           {settings.enable_amalia_export}")
    print(f"C2 Enabled:              {settings.c2_enabled}")
    
    input("\n[Press Enter to continue...]")


def demo_2_event_collection():
    """Demo 2: Event Collection"""
    print_header("DEMO 2: Event Collection (Simulated)")
    
    logger = ImplantLogger(stealth_mode=False).get_logger()
    print("Starting event collection...\n")
    
    base_time = time.time()
    events = [
        (0.0, "PROCESS", "bash (PID 1234) started by UID 1000"),
        (1.2, "PROCESS", "curl (PID 1235) spawned from bash"),
        (2.5, "NETWORK", "curl -> 192.168.1.100:443 (HTTPS)"),
        (3.8, "NETWORK", "curl -> 192.168.1.100:53 (DNS query for C2)"),
        (5.1, "NETWORK", "curl -> 10.0.0.50:4444 (Suspicious port!)"),
        (6.3, "FILE", "curl accessed /etc/resolv.conf"),
        (7.9, "NETWORK", "curl -> 10.0.0.50:5555 (Another C2 port!)"),
        (9.2, "FILE", "bash accessed /root/.ssh/id_rsa"),
        (10.5, "PROCESS", "ssh (PID 1236) started"),
        (12.0, "NETWORK", "ssh -> 192.168.2.50:22 (Lateral movement)"),
    ]
    
    for offset, event_type, details in events:
        timestamp = base_time + offset
        print_event(timestamp, event_type, details)
        time.sleep(0.3)
    
    print(f"\n[SUMMARY] Collected 10 events in 12 seconds")
    input("\n[Press Enter to continue...]")


def demo_3_threat_detection():
    """Demo 3: Threat Detection Layers"""
    print_header("DEMO 3: Threat Detection Analysis")
    
    print("Running detection layers...\n")
    
    # Layer 1: IP Analysis
    print("[Layer 1] IP Behavioral Analysis")
    print("-" * 70)
    print("Target IP: 10.0.0.50\n")
    print("  [Analysis] Suspicious port combinations detected:")
    print("    - Port 4444 (Metasploit default) - HIGH RISK")
    print("    - Port 5555 (RemoteExec default) - HIGH RISK")
    print("    - Port 3389 (RDP) after unusual hours - MEDIUM RISK")
    print("  [Analysis] High outbound volume: 1.2 MB in 12 seconds")
    print("  [Analysis] Multiple connection failures: 3 timeouts")
    print("  [Verdict] IP Threat Score: 72/100 (SUSPICIOUS)\n")
    time.sleep(1)
    
    # Layer 2: YARA Detection
    print("[Layer 2] YARA Signature Matching")
    print("-" * 70)
    print("Scanning network profiles against 25 YARA rules...\n")
    print("  [MATCH] c2_beacon - Known C2 beacon pattern")
    print("    Rule: Port diversity (4444, 5555) + high volume")
    print("    Confidence: 0.85 (HIGH)")
    print("    Category: C2 Communication\n")
    print("  [MATCH] lateral_movement - Remote access attempt")
    print("    Rule: SSH connection to internal network + root access")
    print("    Confidence: 0.78 (HIGH)")
    print("    Category: Lateral Movement\n")
    time.sleep(1)
    
    # Layer 3: Sigma-Lite Behavioral
    print("[Layer 3] Sigma-Lite Behavioral Detection")
    print("-" * 70)
    print("Correlating events within 60-second time window...\n")
    print("  [CHAIN] DNS Exfiltration Attack")
    print("    Events: DNS query -> High data transfer -> SSH connection")
    print("    MITRE Techniques: T1041 (Exfiltration Over C2), T1570 (Lateral Movement)")
    print("    Confidence: 0.82 (HIGH)")
    print("    Severity: HIGH\n")
    print("  [CHAIN] Reconnaissance & Exploitation")
    print("    Events: Port scanning (4444, 5555) -> SSH attempt -> File access")
    print("    MITRE Techniques: T1046 (Network Service Scanning), T1021 (Remote Services)")
    print("    Confidence: 0.89 (VERY HIGH)")
    print("    Severity: CRITICAL\n")
    time.sleep(1)
    
    input("\n[Press Enter to continue...]")


def demo_4_threat_correlation():
    """Demo 4: Unified Threat Verdict"""
    print_header("DEMO 4: Threat Correlation & Unified Verdict")
    
    print("Combining all detection methods...\n")
    print("Detection Method        Score/Match        Confidence")
    print("-" * 70)
    print("IP Analysis             72/100             0.72")
    print("YARA (c2_beacon)        MATCH              0.85")
    print("YARA (lateral_movement) MATCH              0.78")
    print("Sigma-Lite (DNS Exfil)  MATCH              0.82")
    print("Sigma-Lite (Recon+Expl) MATCH              0.89")
    print("-" * 70)
    
    print("\nCorrelation Logic:")
    print("  All 3 detection methods: AGREE")
    print("  Agreement Level: UNANIMOUS (5/5 verdicts align)")
    print("  Confidence Score: (0.72 + 0.85 + 0.88) / 3 = 0.82 (82%)")
    
    print("\n" + "=" * 70)
    print("FINAL THREAT VERDICT")
    print("=" * 70)
    print(f"Target IP:               10.0.0.50")
    print(f"Threat Level:            *** CRITICAL ***")
    print(f"Confidence:              0.82 (82%)")
    print(f"Agreement:               UNANIMOUS (all methods agree)")
    print(f"Attack Categories:       C2 Communication, Lateral Movement, Exfiltration")
    print(f"MITRE Techniques:        T1041, T1570, T1046, T1021")
    print(f"\nRecommended Action:      IMMEDIATE INCIDENT RESPONSE")
    print(f"  1. Isolate affected host")
    print(f"  2. Block IP 10.0.0.50 at firewall")
    print(f"  3. Forensic analysis of /etc/passwd access")
    print(f"  4. Review SSH logs for unauthorized access")
    print(f"  5. Check for lateral movement to other hosts")
    print("=" * 70)
    
    input("\n[Press Enter to continue...]")


def demo_5_streaming():
    """Demo 5: Real-Time Streaming to BrainCell"""
    print_header("DEMO 5: Real-Time Streaming to BrainCell")
    
    print("Streaming telemetry in batches...\n")
    
    batches = [
        ("2026-10-01 14:23:15", 50, "process_events + network_events"),
        ("2026-10-01 14:23:25", 47, "network_events + file_events"),
        ("2026-10-01 14:23:35", 52, "all event types"),
    ]
    
    for timestamp, count, types in batches:
        print(f"[{timestamp}] Streaming batch: {count} events ({types})")
        print(f"  -> POST to BrainCell /api/ingest")
        print(f"  -> Status: 200 OK")
        print(f"  -> Batch ID: batch_20261001_142315_a1b2c3")
        print(f"  -> Events tagged: tcp, udp, inbound, outbound, suspicious-port\n")
        time.sleep(0.5)
    
    input("\n[Press Enter to continue...]")


def demo_6_c2_communication():
    """Demo 6: C2 Communication"""
    print_header("DEMO 6: C2 Command & Control")
    
    print("Attempting C2 communication...\n")
    
    print("[C2] Primary Channel: HTTPS")
    print("  Endpoint: http://c2.attacker.com:8000/api/implants")
    print("  Certificate SHA-256: 3a2f5b8c9e1d4a6b7c8d9e0f1a2b3c4d5e6f7a8b")
    print("  Payload: TelemetryBatch (encrypted with Fernet)")
    print("  Status: CONNECTION TIMEOUT (firewall blocked)")
    print("  Fallback: Switching to DNS channel...\n")
    time.sleep(1)
    
    print("[C2] Fallback Channel: DNS TXT Records")
    print("  Encoding: Base64 of encrypted telemetry")
    print("  Query: c2.attacker.com TXT")
    print("  Response: v=telemetry; batch=<encoded_payload>; ack=received")
    print("  Status: SUCCESS (200 OK)")
    print("  Rate Limiter: 1 request every 5±1.5 seconds (adaptive jitter)\n")
    
    print("[C2] Server Commands Received:")
    print("  1. adjust_sampling_rate(0.05) - Only collect 5% of events (lower overhead)")
    print("  2. enable_feature(sigma_lite) - Activate behavioral detection")
    print("  3. exfiltrate_now() - Send all pending events immediately\n")
    
    print("[C2] Commands Applied:")
    print("  ✓ Sampling rate changed: 100% -> 5%")
    print("  ✓ Sigma-Lite enabled")
    print("  ✓ Batch exfiltrated: 245 events (1.2 MB)\n")
    
    input("\n[Press Enter to continue...]")


def demo_7_amalia_export():
    """Demo 7: Amalia Platform Export"""
    print_header("DEMO 7: Threat Verdict Export to Amalia")
    
    print("Exporting verdicts to Amalia red team platform...\n")
    
    print("[Amalia] Endpoint: http://amalia.local:8000/api/verdicts")
    print("[Amalia] Payload:")
    print("""
    {
      "timestamp": "2026-10-01T14:23:45Z",
      "implant_id": "ebpf-sensor-pod-01",
      "threat_verdict": {
        "ip": "10.0.0.50",
        "threat_level": "CRITICAL",
        "confidence": 0.82,
        "agreement_level": "UNANIMOUS",
        "detection_methods": [
          "ip_analysis",
          "yara_detection",
          "sigma_lite"
        ],
        "yara_matches": 2,
        "sigma_chains": 2,
        "mitre_techniques": [
          "T1041 - Exfiltration Over C2",
          "T1570 - Lateral Tool Transfer",
          "T1046 - Network Service Scanning",
          "T1021 - Remote Services"
        ],
        "attack_categories": [
          "C2 Communication",
          "Lateral Movement",
          "Exfiltration"
        ],
        "summary": "Suspicious host shows signs of C2 communication via ports 4444/5555, \
lateral movement via SSH, and DNS exfiltration. Behavioral chains detected."
      }
    }
    """)
    print("[Amalia] Status: 201 CREATED")
    print("[Amalia] Verdict ID: verdict_20261001_142345_x9y8z7w6")
    print("[Amalia] Alert Status: ROUTED TO INCIDENT RESPONSE TEAM\n")
    
    input("\n[Press Enter to continue...]")


def demo_8_file_export():
    """Demo 8: File Export"""
    print_header("DEMO 8: Telemetry File Export")
    
    print("Exporting full telemetry to JSON file...\n")
    print("File: /opt/ebpf-implant/telemetry/telemetry-2026-10-01-142345.json")
    print("Size: 1.2 MB")
    print("Events: 347 total")
    print("  - Process events: 23")
    print("  - Network events: 156")
    print("  - File events: 168")
    print("\nSample export structure:")
    print("""
    {
      "implant_id": "ebpf-sensor-pod-01",
      "exported_at": "2026-10-01T14:23:45.123456Z",
      "collection_window": {
        "start": 1696164225.1,
        "end": 1696164345.5,
        "duration_sec": 120.4
      },
      "events": {
        "process": [
          {
            "type": "process",
            "timestamp": 1696164225.123,
            "pid": 1234,
            "ppid": 1200,
            "uid": 1000,
            "comm": "bash",
            "filename": "/bin/bash",
            "argv": "/bin/bash"
          },
          ...
        ],
        "network": [
          {
            "type": "network",
            "timestamp": 1696164227.456,
            "pid": 1235,
            "protocol": "TCP",
            "sport": 54821,
            "dport": 4444,
            "saddr": "192.168.1.100",
            "daddr": "10.0.0.50",
            "direction": "outbound",
            "bytes": 2048
          },
          ...
        ],
        "file": [...]
      },
      "summary": {
        "process_events": 23,
        "network_events": 156,
        "file_events": 168,
        "total_events": 347
      }
    }
    """)
    
    input("\n[Press Enter to continue...]")


def demo_9_24_7_monitoring():
    """Demo 9: 24/7 Monitoring Status"""
    print_header("DEMO 9: 24/7 Continuous Operation Status")
    
    print("systemctl status ebpf-implant\n")
    print("""
    ebpf-implant.service - eBPF Implant - 24/7 Kernel Telemetry Collector
       Loaded: loaded (/etc/systemd/system/ebpf-implant.service; enabled; preset: disabled)
       Active: active (running) since Wed 2026-10-01 06:00:15 UTC; 8h 23m ago
      Process: 1234 ExecStart=/usr/bin/python3 -m application.implant_agent --stealth (code=exited, status=0/SUCCESS)
     Main PID: 1235 (python3)
       Status: "Running collection for 3600 seconds"
       Memory: 42.3M
         CPU: 2.1%
    """)
    
    print("\nOperational Metrics (Last 8 hours):")
    print("  Events Collected:      12,847")
    print("  Average Rate:          0.42 events/second")
    print("  Peak Rate:             2.1 events/second")
    print("  Threats Detected:      47")
    print("  CRITICAL Verdicts:     8")
    print("  HIGH Verdicts:         12")
    print("  MEDIUM Verdicts:       27")
    print("  Service Restarts:      0")
    print("  Uptime:                8h 23m (99.97%)")
    print("  Memory Usage:          42.3M (8.3% of limit)")
    print("  Disk Usage:            287.4M (in last 8 hours)")
    print("  BrainCell Exports:     156 batches (0 failures)")
    print("  C2 Communications:     287 (240 HTTPS, 47 DNS fallback)")
    
    print("\nRecent Activity:")
    print("  14:23:45 [CRITICAL] IP 10.0.0.50 - C2 + Lateral Movement")
    print("  14:18:32 [HIGH] IP 192.168.2.15 - Port Scanning Activity")
    print("  14:12:01 [MEDIUM] IP 172.16.0.5 - Unusual DNS Queries")
    print("  14:05:22 [MEDIUM] IP 10.1.1.1 - Connection Spike")
    
    input("\n[Press Enter to continue...]")


def main():
    """Run complete textual demo"""
    print("\n")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                                                                    ║")
    print("║            eBPF IMPLANT - TEXTUAL DEMONSTRATION                    ║")
    print("║                                                                    ║")
    print("║          Domain-Driven Design Architecture in Action              ║")
    print("║                                                                    ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print("\nThis demo shows:")
    print("  1. Configuration loading")
    print("  2. Event collection (simulated)")
    print("  3. Threat detection analysis (all 3 layers)")
    print("  4. Threat verdict correlation")
    print("  5. Real-time streaming to BrainCell")
    print("  6. C2 command & control communication")
    print("  7. Threat export to Amalia platform")
    print("  8. JSON telemetry file export")
    print("  9. 24/7 continuous operation status")
    
    input("\n[Press Enter to START DEMO...]\n")
    
    try:
        demo_1_configuration()
        demo_2_event_collection()
        demo_3_threat_detection()
        demo_4_threat_correlation()
        demo_5_streaming()
        demo_6_c2_communication()
        demo_7_amalia_export()
        demo_8_file_export()
        demo_9_24_7_monitoring()
        
        print_header("DEMO COMPLETE")
        print("Key Takeaways:")
        print("  ✓ 4-layer threat detection (IP + YARA + Sigma-Lite + Correlation)")
        print("  ✓ Real-time streaming to BrainCell and Amalia platforms")
        print("  ✓ Dual C2 channels (HTTPS + DNS fallback)")
        print("  ✓ Unified threat verdicts with 82% confidence")
        print("  ✓ 24/7 continuous operation with auto-restart")
        print("  ✓ Low resource overhead (<50MB memory, <3% CPU)")
        print("\n  The implant is now running on all production systems.")
        print("  Monitor alerts at: http://amalia.local:8000/dashboard\n")
        
    except KeyboardInterrupt:
        print("\n\n[Demo interrupted by user]")
        sys.exit(0)
    except Exception as e:
        print(f"\n[Error during demo]: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
