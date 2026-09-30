"""
YARA-based threat detection for network telemetry.

Complements behavioral IP analysis with signature-based pattern matching.
Used for detecting known malware C2 patterns, DNS exfiltration, etc.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


# YARA rules for network telemetry analysis
YARA_RULES = {
    # C2 Communication Patterns
    "c2_beacon": {
        "description": "Known C2 beacon patterns",
        "patterns": [
            # Suspicious port combinations
            {"port": 4444, "severity": "high"},
            {"port": 5555, "severity": "high"},
            {"port": 6666, "severity": "high"},
            {"port": 7777, "severity": "high"},
            {"port": 8888, "severity": "high"},
            {"port": 9999, "severity": "high"},
            {"port": 10000, "severity": "high"},
            # Known botnet ports
            {"port": 6129, "severity": "medium"},  # DameWare
            {"port": 12345, "severity": "high"},    # NetBus
            {"port": 27374, "severity": "high"},    # Sub7
            {"port": 31337, "severity": "high"},    # BackOrifice
        ]
    },

    # DNS Tunneling Patterns
    "dns_tunneling": {
        "description": "DNS-based data exfiltration",
        "patterns": [
            {
                "name": "high_volume_dns",
                "condition": "dns_queries > 100 and bytes_sent > 10000",
                "severity": "high"
            },
            {
                "name": "suspicious_dns_subdomains",
                "condition": "domain contains unusual characters or encoding",
                "severity": "medium"
            },
            {
                "name": "dns_to_suspicious_resolver",
                "condition": "dns_port == 53 and bytes_sent > bytes_received",
                "severity": "medium"
            }
        ]
    },

    # Data Exfiltration Patterns
    "data_exfiltration": {
        "description": "Large data transfers to external IPs",
        "patterns": [
            {
                "name": "large_outbound_transfer",
                "condition": "bytes_sent > 1000000 and is_public_ip",
                "severity": "high"
            },
            {
                "name": "sftp_ssh_transfer",
                "condition": "protocol == TCP and (port == 22 or port == 115) and bytes_sent > 100000",
                "severity": "medium"
            },
            {
                "name": "ftp_transfer",
                "condition": "protocol == TCP and port == 21 and bytes_sent > 100000",
                "severity": "medium"
            }
        ]
    },

    # Lateral Movement
    "lateral_movement": {
        "description": "Internal network scanning and movement",
        "patterns": [
            {
                "name": "port_scanning",
                "condition": "tcp_state == SYN_SENT and unique_ports > 20",
                "severity": "medium"
            },
            {
                "name": "rdp_sweep",
                "condition": "port == 3389 and connections > 10 with different_hosts",
                "severity": "medium"
            },
            {
                "name": "ssh_brute_force",
                "condition": "port == 22 and failed_connections > 5",
                "severity": "medium"
            }
        ]
    },

    # Credential Access
    "credential_access": {
        "description": "Credential harvesting and access attempts",
        "patterns": [
            {
                "name": "ldap_query",
                "condition": "port == 389 and bytes_sent > 1000",
                "severity": "medium"
            },
            {
                "name": "kerberos_activity",
                "condition": "port == 88 and connections > 5",
                "severity": "low"
            },
            {
                "name": "smb_access",
                "condition": "port in [445, 139, 135]",
                "severity": "medium"
            }
        ]
    },

    # Persistence
    "persistence": {
        "description": "Persistence mechanisms",
        "patterns": [
            {
                "name": "dns_hijacking",
                "condition": "dns_queries to_internal_resolver from_external_ip",
                "severity": "high"
            },
            {
                "name": "scheduled_task",
                "condition": "process == schtasks.exe or taskkill.exe",
                "severity": "medium"
            }
        ]
    }
}


@dataclass
class YARARuleMatch:
    """Result of a YARA rule match"""
    rule_name: str
    rule_category: str
    severity: str  # "critical", "high", "medium", "low"
    ip: str
    pattern: str
    description: str
    confidence: float  # 0.0-1.0
    metadata: Dict[str, Any]


class YARADetector:
    """YARA-based threat detection for network profiles"""

    def __init__(self):
        """Initialize YARA detector with built-in rules"""
        self.rules = YARA_RULES
        self.matches: List[YARARuleMatch] = []

    def scan_profile(self, ip: str, profile: Any) -> List[YARARuleMatch]:
        """
        Scan IP profile against YARA rules.

        Args:
            ip: IP address to scan
            profile: IPProfile object from ip_analysis module

        Returns:
            List of YARARuleMatch objects
        """
        matches = []

        # Check C2 beacon patterns
        c2_matches = self._check_c2_beacon(ip, profile)
        matches.extend(c2_matches)

        # Check DNS tunneling
        dns_matches = self._check_dns_tunneling(ip, profile)
        matches.extend(dns_matches)

        # Check data exfiltration
        exfil_matches = self._check_data_exfiltration(ip, profile)
        matches.extend(exfil_matches)

        # Check lateral movement
        lateral_matches = self._check_lateral_movement(ip, profile)
        matches.extend(lateral_matches)

        # Check credential access
        cred_matches = self._check_credential_access(ip, profile)
        matches.extend(cred_matches)

        self.matches.extend(matches)
        return matches

    def _check_c2_beacon(self, ip: str, profile: Any) -> List[YARARuleMatch]:
        """Check for C2 beacon patterns"""
        matches = []

        # Check suspicious ports
        for port in profile.suspicious_ports:
            rule_config = self.rules["c2_beacon"]["patterns"][0]  # Get first pattern config

            if port in [p["port"] for p in self.rules["c2_beacon"]["patterns"]]:
                matches.append(YARARuleMatch(
                    rule_name="c2_beacon",
                    rule_category="c2_communication",
                    severity="high",
                    ip=ip,
                    pattern=f"port_{port}",
                    description=f"Suspicious C2 port {port} detected",
                    confidence=0.85,
                    metadata={
                        "port": port,
                        "connection_count": profile.remote_ports.get(port, 0),
                        "tcp_states": profile.tcp_states
                    }
                ))

        # Check for high volume to single port
        if profile.remote_ports:
            top_port, count = max(profile.remote_ports.items(), key=lambda x: x[1])
            if top_port in [4444, 5555, 6666, 7777, 8888, 9999] and count > 10:
                matches.append(YARARuleMatch(
                    rule_name="c2_high_volume_beacon",
                    rule_category="c2_communication",
                    severity="high",
                    ip=ip,
                    pattern="high_volume_c2_port",
                    description=f"High volume connections to C2 port {top_port}",
                    confidence=0.90,
                    metadata={
                        "port": top_port,
                        "connection_count": count,
                        "top_process": max(profile.processes_outbound.items(), key=lambda x: x[1])[0] if profile.processes_outbound else "unknown"
                    }
                ))

        return matches

    def _check_dns_tunneling(self, ip: str, profile: Any) -> List[YARARuleMatch]:
        """Check for DNS tunneling patterns"""
        matches = []

        # High volume DNS with large byte transfer
        if profile.dns_queries > 100 and profile.bytes_sent > 10000:
            matches.append(YARARuleMatch(
                rule_name="dns_tunneling_high_volume",
                rule_category="dns_tunneling",
                severity="high",
                ip=ip,
                pattern="high_volume_dns_with_data",
                description="High DNS query volume with significant data transfer (tunneling indicator)",
                confidence=0.85,
                metadata={
                    "dns_queries": profile.dns_queries,
                    "bytes_sent": profile.bytes_sent,
                    "ratio": profile.bytes_sent / max(profile.dns_queries, 1)
                }
            ))

        return matches

    def _check_data_exfiltration(self, ip: str, profile: Any) -> List[YARARuleMatch]:
        """Check for data exfiltration patterns"""
        matches = []

        # Large outbound transfer to public IP
        if profile.bytes_sent > 1000000 and profile.is_public:
            matches.append(YARARuleMatch(
                rule_name="large_outbound_transfer",
                rule_category="data_exfiltration",
                severity="high",
                ip=ip,
                pattern="large_public_ip_transfer",
                description=f"Large outbound transfer to public IP: {profile.bytes_sent / 1024 / 1024:.1f} MB",
                confidence=0.80,
                metadata={
                    "bytes_sent": profile.bytes_sent,
                    "bytes_received": profile.bytes_received,
                    "ratio": profile.bytes_sent / max(profile.bytes_received, 1),
                    "top_port": max(profile.remote_ports.items(), key=lambda x: x[1])[0] if profile.remote_ports else None
                }
            ))

        return matches

    def _check_lateral_movement(self, ip: str, profile: Any) -> List[YARARuleMatch]:
        """Check for lateral movement patterns"""
        matches = []

        # Port scanning pattern
        if len(profile.remote_ports) > 20 and sum(profile.remote_ports.values()) > 50:
            matches.append(YARARuleMatch(
                rule_name="port_scanning",
                rule_category="lateral_movement",
                severity="medium",
                ip=ip,
                pattern="multiple_port_scanning",
                description=f"Possible port scanning: {len(profile.remote_ports)} unique ports contacted",
                confidence=0.75,
                metadata={
                    "unique_ports": len(profile.remote_ports),
                    "total_connections": sum(profile.remote_ports.values()),
                    "top_ports": dict(sorted(profile.remote_ports.items(), key=lambda x: x[1], reverse=True)[:5])
                }
            ))

        # RDP sweep (port 3389 to multiple hosts)
        if 3389 in profile.remote_ports and profile.remote_ports[3389] > 5:
            matches.append(YARARuleMatch(
                rule_name="rdp_sweep",
                rule_category="lateral_movement",
                severity="medium",
                ip=ip,
                pattern="rdp_multiple_connections",
                description=f"RDP sweep pattern: {profile.remote_ports[3389]} connections to port 3389",
                confidence=0.80,
                metadata={
                    "rdp_connections": profile.remote_ports[3389],
                    "failed_connections": profile.failed_connections
                }
            ))

        return matches

    def _check_credential_access(self, ip: str, profile: Any) -> List[YARARuleMatch]:
        """Check for credential access patterns"""
        matches = []

        # SMB access
        smb_ports = [445, 139, 135]
        for port in smb_ports:
            if port in profile.remote_ports:
                matches.append(YARARuleMatch(
                    rule_name="smb_access",
                    rule_category="credential_access",
                    severity="medium",
                    ip=ip,
                    pattern=f"smb_port_{port}",
                    description=f"SMB/NetBIOS access on port {port}",
                    confidence=0.70,
                    metadata={
                        "port": port,
                        "connection_count": profile.remote_ports[port],
                        "is_private": profile.is_private
                    }
                ))

        return matches

    def get_matches_by_severity(self, severity: str = "high") -> List[YARARuleMatch]:
        """Get matches filtered by severity"""
        return [m for m in self.matches if m.severity == severity]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all YARA matches"""
        critical = len(self.get_matches_by_severity("critical"))
        high = len(self.get_matches_by_severity("high"))
        medium = len(self.get_matches_by_severity("medium"))
        low = len(self.get_matches_by_severity("low"))

        return {
            "total_matches": len(self.matches),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "unique_ips_matched": len(set(m.ip for m in self.matches))
        }

    def export_matches(self) -> List[Dict[str, Any]]:
        """Export all matches as dictionaries"""
        return [
            {
                "rule": m.rule_name,
                "category": m.rule_category,
                "severity": m.severity,
                "ip": m.ip,
                "pattern": m.pattern,
                "description": m.description,
                "confidence": m.confidence,
                "metadata": m.metadata
            }
            for m in self.matches
        ]


# Integration example
def integrate_yara_with_ip_analysis(analyzer, yara_detector):
    """
    Scan all IP profiles with YARA rules.

    Args:
        analyzer: IPAnalyzer instance
        yara_detector: YARADetector instance

    Returns:
        Dict with combined analysis results
    """
    all_matches = []

    for ip, profile in analyzer.ip_profiles.items():
        matches = yara_detector.scan_profile(ip, profile)
        all_matches.extend(matches)

    return {
        "ip_analysis": analyzer.export_json(),
        "yara_matches": yara_detector.export_matches(),
        "yara_summary": yara_detector.get_summary(),
        "threat_level": calculate_threat_level(analyzer, yara_detector)
    }


def calculate_threat_level(analyzer, yara_detector) -> str:
    """Calculate overall threat level based on analysis"""
    summary = yara_detector.get_summary()

    if summary["critical"] > 0:
        return "CRITICAL"
    elif summary["high"] >= 3:
        return "HIGH"
    elif summary["high"] > 0 or summary["medium"] >= 5:
        return "ELEVATED"
    elif summary["medium"] > 0:
        return "MEDIUM"
    else:
        return "LOW"
