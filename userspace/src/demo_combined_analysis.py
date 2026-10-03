#!/usr/bin/env python3
"""
Combined Behavioral + Signature-Based Threat Detection Demo

Shows IP analysis (behavioral scoring) and YARA detection (signature matching)
working together to identify threats from multiple angles.
"""

import sys
import json
from datetime import datetime

sys.path.insert(0, '/home/user/ITl.Amalia.POC.eBPF/userspace/src')

from ip_analysis import IPAnalyzer, IPThreatIntelligence
from yara_detection import YARADetector
import time
from datetime import datetime, timedelta


def generate_demo_events():
    """Generate realistic network events for demonstration"""
    base_time = time.time()
    events = []

    # Scenario 1: Normal web traffic
    for i in range(5):
        events.append({
            "timestamp": base_time + (i * 2),
            "timestamp_iso": datetime.fromtimestamp(base_time + (i * 2)).isoformat(),
            "pid": 2341,
            "uid": 1000,
            "comm": "firefox",
            "protocol": "TCP",
            "family": "IPv4",
            "sport": 54000 + i,
            "dport": 443,
            "saddr": "192.168.1.100",
            "daddr": "8.8.8.8",
            "direction": "outbound",
            "tcp_state": "ESTABLISHED",
            "bytes_sent": 2048,
            "bytes_received": 8192,
            "retransmits": 0,
            "is_dns": False
        })

    # Scenario 2: DNS queries
    for i in range(3):
        events.append({
            "timestamp": base_time + 10 + (i * 1),
            "timestamp_iso": datetime.fromtimestamp(base_time + 10 + (i * 1)).isoformat(),
            "pid": 2341,
            "uid": 1000,
            "comm": "firefox",
            "protocol": "UDP",
            "family": "IPv4",
            "sport": 53000 + i,
            "dport": 53,
            "saddr": "192.168.1.100",
            "daddr": "1.1.1.1",
            "direction": "outbound",
            "tcp_state": None,
            "bytes_sent": 64,
            "bytes_received": 128,
            "retransmits": 0,
            "is_dns": True
        })

    # Scenario 3: C2 pattern - suspicious ports
    suspicious_ports = [4444, 8888]
    for port in suspicious_ports:
        for j in range(12):
            events.append({
                "timestamp": base_time + 20 + (j * 1.5),
                "timestamp_iso": datetime.fromtimestamp(base_time + 20 + (j * 1.5)).isoformat(),
                "pid": 1234,
                "uid": 1000,
                "comm": "curl",
                "protocol": "TCP",
                "family": "IPv4",
                "sport": 55000 + j,
                "dport": port,
                "saddr": "192.168.1.100",
                "daddr": "93.184.216.34",
                "direction": "outbound",
                "tcp_state": "SYN_SENT",
                "bytes_sent": 512,
                "bytes_received": 256,
                "retransmits": 2,
                "is_dns": False
            })

    # Scenario 4: DNS tunneling
    for i in range(150):
        events.append({
            "timestamp": base_time + 50 + (i * 0.2),
            "timestamp_iso": datetime.fromtimestamp(base_time + 50 + (i * 0.2)).isoformat(),
            "pid": 5678,
            "uid": 1000,
            "comm": "malware",
            "protocol": "UDP",
            "family": "IPv4",
            "sport": 53500 + (i % 100),
            "dport": 53,
            "saddr": "192.168.1.105",
            "daddr": "10.0.0.5",
            "direction": "outbound",
            "tcp_state": None,
            "bytes_sent": 15000,
            "bytes_received": 8000,
            "retransmits": 0,
            "is_dns": True
        })

    # Scenario 5: Data exfiltration
    events.append({
        "timestamp": base_time + 100,
        "timestamp_iso": datetime.fromtimestamp(base_time + 100).isoformat(),
        "pid": 9876,
        "uid": 0,
        "comm": "scp",
        "protocol": "TCP",
        "family": "IPv4",
        "sport": 52000,
        "dport": 22,
        "saddr": "192.168.1.200",
        "daddr": "185.220.101.1",
        "direction": "outbound",
        "tcp_state": "ESTABLISHED",
        "bytes_sent": 2500000,
        "bytes_received": 50000,
        "retransmits": 0,
        "is_dns": False
    })

    # Scenario 6: Internal traffic
    for i in range(8):
        events.append({
            "timestamp": base_time + 110 + (i * 1),
            "timestamp_iso": datetime.fromtimestamp(base_time + 110 + (i * 1)).isoformat(),
            "pid": 3456,
            "uid": 1000,
            "comm": "sshpass",
            "protocol": "TCP",
            "family": "IPv4",
            "sport": 54500 + i,
            "dport": 22,
            "saddr": "192.168.1.50",
            "daddr": "10.0.0.10",
            "direction": "outbound",
            "tcp_state": "ESTABLISHED",
            "bytes_sent": 1024,
            "bytes_received": 2048,
            "retransmits": 0,
            "is_dns": False
        })

    return events


def print_header(title):
    """Print formatted section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def demo_combined_analysis():
    """Run combined behavioral and signature-based threat detection demo"""

    print_header("🔍 COMBINED THREAT ANALYSIS DEMO")
    print("Behavioral IP Analysis + YARA Signature-Based Detection\n")

    # Generate demo events
    print("[*] Generating simulated network events...")
    events = generate_demo_events()
    print(f"[+] Generated {len(events)} network events\n")

    # Initialize analyzers
    print("[*] Initializing analyzers...")
    ip_analyzer = IPAnalyzer()
    yara_detector = YARADetector()

    # Process events through IP analyzer
    print("[*] Processing events through IP analyzer...")
    for i, event in enumerate(events):
        ip_analyzer.process_event(event)
        if (i + 1) % 50 == 0:
            print(f"    [{i + 1}/{len(events)}] events processed")

    print(f"[+] IP analysis complete\n")

    # Scan IP profiles with YARA rules
    print("[*] Scanning IP profiles with YARA signature rules...")
    for ip, profile in ip_analyzer.ip_profiles.items():
        matches = yara_detector.scan_profile(ip, profile)
        if matches:
            print(f"[+] {ip}: Found {len(matches)} YARA matches")

    print(f"[+] YARA scanning complete\n")

    # Generate combined threat report
    print_header("📊 COMBINED THREAT ANALYSIS RESULTS")

    # Get unique IPs
    unique_ips = ip_analyzer.get_unique_ips()
    print(f"Total Unique IPs Analyzed: {len(unique_ips)}")
    print(f"External IPs: {len(ip_analyzer.get_external_ips())}")
    print(f"Internal IPs: {len(ip_analyzer.get_internal_ips())}\n")

    # Suspicious IPs from behavioral analysis
    print_header("BEHAVIORAL ANALYSIS: Suspicious IPs (Threat Score >= 20)")
    suspicious_behavioral = ip_analyzer.get_suspicious_ips(min_threat_score=20.0)

    for ip in suspicious_behavioral:
        profile = ip_analyzer.ip_profiles[ip['ip']]
        threat_score = ip['threat_score']

        print(f"\n🚨 {ip['ip']} | Behavioral Threat Score: {threat_score:.1f}/100")
        print(f"   Connections: {ip['total_connections']}")
        print(f"   Protocols: {', '.join(f'{k}({v})' for k, v in ip['protocols_used'].items())}")
        print(f"   Data Transfer: ↑{ip['bytes_sent']/1024:.0f}KB ↓{ip['bytes_received']/1024:.0f}KB")

        # Show threat patterns detected
        c2 = IPThreatIntelligence.check_c2_indicators(profile)
        dns_tunnel = IPThreatIntelligence.check_dns_tunneling(profile)
        exfil = IPThreatIntelligence.check_data_exfiltration(profile)

        if c2['c2_probable']:
            print(f"   🎯 C2 Indicator: {c2['reasons'][0]}")
        if dns_tunnel['dns_tunneling_probable']:
            print(f"   🔐 DNS Tunneling: {dns_tunnel['reasons'][0]}")
        if exfil['exfiltration_probable']:
            print(f"   💾 Data Exfiltration: {exfil['reasons'][0]}")

    # YARA signature matches
    print_header("SIGNATURE DETECTION: YARA Rule Matches")

    yara_summary = yara_detector.get_summary()
    print(f"Total YARA Matches: {yara_summary['total_matches']}")
    print(f"  Critical: {yara_summary['critical']}")
    print(f"  High: {yara_summary['high']}")
    print(f"  Medium: {yara_summary['medium']}")
    print(f"  Low: {yara_summary['low']}")
    print(f"Unique IPs Matched: {yara_summary['unique_ips_matched']}\n")

    # Show high-severity matches
    for severity in ["critical", "high", "medium"]:
        matches = yara_detector.get_matches_by_severity(severity)
        if not matches:
            continue

        print(f"\n{severity.upper()} SEVERITY MATCHES ({len(matches)}):")
        for match in matches:
            print(f"\n  IP: {match.ip}")
            print(f"  Rule: {match.rule_name} ({match.rule_category})")
            print(f"  Pattern: {match.pattern}")
            print(f"  Confidence: {match.confidence:.1%}")
            print(f"  Description: {match.description}")

    # Correlation: IPs with BOTH behavioral and signature indicators
    print_header("🎯 CORRELATED THREATS (Behavioral + Signature Match)")

    correlated_threats = []
    behavioral_ips = {ip['ip'] for ip in suspicious_behavioral}
    yara_matched_ips = {match.ip for match in yara_detector.matches}

    for ip in behavioral_ips & yara_matched_ips:
        behavioral_data = next(x for x in suspicious_behavioral if x['ip'] == ip)
        yara_matches = [m for m in yara_detector.matches if m.ip == ip]

        correlated_threats.append({
            'ip': ip,
            'behavioral_score': behavioral_data['threat_score'],
            'yara_match_count': len(yara_matches),
            'yara_categories': list(set(m.rule_category for m in yara_matches))
        })

    if correlated_threats:
        for threat in sorted(correlated_threats, key=lambda x: x['behavioral_score'], reverse=True):
            print(f"\n🚨 {threat['ip']}")
            print(f"   Behavioral Score: {threat['behavioral_score']:.1f}/100")
            print(f"   YARA Matches: {threat['yara_match_count']}")
            print(f"   Threat Categories: {', '.join(threat['yara_categories'])}")
            print(f"   ALERT LEVEL: CRITICAL (Multi-Method Detection)")
    else:
        print("No IPs detected by both behavioral and signature analysis")

    # Export combined results
    print_header("💾 EXPORTING COMBINED RESULTS")

    combined_export = {
        "timestamp": datetime.now().isoformat(),
        "analysis": {
            "behavioral": {
                "total_suspicious_ips": len(suspicious_behavioral),
                "min_threat_score": 20.0
            },
            "signature": {
                "total_yara_matches": yara_summary['total_matches'],
                "critical": yara_summary['critical'],
                "high": yara_summary['high'],
                "medium": yara_summary['medium'],
                "low": yara_summary['low']
            },
            "correlated": {
                "multi_method_detections": len(correlated_threats),
                "threat_ips": [t['ip'] for t in correlated_threats]
            }
        },
        "suspicious_ips": suspicious_behavioral,
        "yara_matches": yara_detector.export_matches(),
        "correlated_threats": correlated_threats
    }

    print("[+] Combined analysis export prepared")
    print(json.dumps(combined_export, indent=2)[:1000] + "...")

    # Summary statistics
    print_header("📈 SUMMARY STATISTICS")

    total_events = len(events)
    unique_ips_count = len(unique_ips)
    behavioral_threats = len(suspicious_behavioral)
    yara_threat_ips = yara_summary['unique_ips_matched']
    multi_method = len(correlated_threats)

    print(f"Total Events Processed: {total_events}")
    print(f"Unique IPs: {unique_ips_count}")
    print(f"\nThreat Detection Results:")
    print(f"  Behavioral Analysis Found: {behavioral_threats} suspicious IPs")
    print(f"  YARA Signatures Matched: {yara_threat_ips} IPs")
    print(f"  Multi-Method Detections: {multi_method} IPs (HIGHEST CONFIDENCE)")

    if multi_method > 0:
        confidence_pct = (multi_method / max(behavioral_threats, yara_threat_ips, 1)) * 100
        print(f"  Detection Confidence: {confidence_pct:.1f}% (threats with multiple indicators)")

    print("\n✅ COMBINED ANALYSIS COMPLETE")
    print("\nKey Findings:")
    if multi_method > 0:
        print(f"  ⚠️  {multi_method} IP(s) detected by BOTH behavioral and signature methods")
        print(f"  → These represent the highest-confidence threats")
    if behavioral_threats > yara_threat_ips:
        print(f"  ✓ Behavioral analysis caught {behavioral_threats - yara_threat_ips} additional threats")
        print(f"  → These may be novel or unknown signatures")
    if yara_threat_ips > behavioral_threats:
        print(f"  ✓ YARA signatures caught {yara_threat_ips - behavioral_threats} additional threats")
        print(f"  → These match known malware/attack patterns")

    print("\nRecommendations:")
    print("  1. Investigate all multi-method detections with CRITICAL priority")
    print("  2. Behavioral-only threats may indicate zero-day or novel attacks")
    print("  3. Signature-only matches should be verified in threat intelligence")
    print("  4. Block all detected IPs in egress firewall rules")
    print("  5. Monitor for lateral movement to other internal IPs")


if __name__ == "__main__":
    demo_combined_analysis()
