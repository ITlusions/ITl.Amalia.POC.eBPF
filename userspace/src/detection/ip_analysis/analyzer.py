"""
IP-based threat analysis and aggregation for eBPF network telemetry.

Tracks unique IPs, build connection profiles, detect suspicious patterns,
and correlate with threat intelligence data.
"""

import json
import time
from typing import Dict, List, Set, Any, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime
import ipaddress
import socket


@dataclass
class IPProfile:
    """Comprehensive profile for a unique IP address"""
    ip: str
    first_seen: float
    last_seen: float

    # Connection patterns
    inbound_connections: int = 0
    outbound_connections: int = 0
    total_connections: int = 0

    # Protocols used
    protocols: Dict[str, int] = field(default_factory=lambda: {"TCP": 0, "UDP": 0})

    # Ports contacted/listening on
    remote_ports: Dict[int, int] = field(default_factory=dict)  # port -> count
    local_ports: Dict[int, int] = field(default_factory=dict)

    # Processes connecting to/from this IP
    processes_outbound: Dict[str, int] = field(default_factory=dict)  # process -> count
    processes_inbound: Dict[str, int] = field(default_factory=dict)

    # DNS queries (if applicable)
    dns_queries: int = 0
    dns_responses: int = 0

    # TCP states observed
    tcp_states: Dict[str, int] = field(default_factory=lambda: {})

    # Metrics
    bytes_sent: int = 0
    bytes_received: int = 0

    # Threat indicators
    suspicious_ports: List[int] = field(default_factory=list)
    failed_connections: int = 0

    # Geolocation (if enriched)
    country_code: Optional[str] = None
    asn: Optional[str] = None
    is_private: bool = False
    is_public: bool = False

    def update(self, event: Dict[str, Any]):
        """Update profile with new network event"""
        self.last_seen = event.get("timestamp", time.time())

        # Track connection direction
        if event.get("direction") == "inbound":
            self.inbound_connections += 1
        elif event.get("direction") == "outbound":
            self.outbound_connections += 1

        self.total_connections += 1

        # Protocol tracking
        protocol = event.get("protocol", "unknown")
        self.protocols[protocol] = self.protocols.get(protocol, 0) + 1

        # Port tracking (based on direction)
        if event.get("direction") == "outbound":
            port = event.get("dport")
            self.remote_ports[port] = self.remote_ports.get(port, 0) + 1
            # Track suspicious ports
            if port in [4444, 5555, 6666, 7777, 8888, 9999]:
                if port not in self.suspicious_ports:
                    self.suspicious_ports.append(port)
        else:
            port = event.get("sport")
            self.local_ports[port] = self.local_ports.get(port, 0) + 1

        # Process tracking
        process = event.get("comm", "unknown")
        if event.get("direction") == "outbound":
            self.processes_outbound[process] = self.processes_outbound.get(process, 0) + 1
        else:
            self.processes_inbound[process] = self.processes_inbound.get(process, 0) + 1

        # DNS tracking
        if event.get("is_dns"):
            if event.get("dport") == 53:
                self.dns_queries += 1
            else:
                self.dns_responses += 1

        # TCP state tracking
        if event.get("tcp_state"):
            state = event["tcp_state"]
            self.tcp_states[state] = self.tcp_states.get(state, 0) + 1

        # Bytes tracking
        self.bytes_sent += event.get("bytes_sent", 0)
        self.bytes_received += event.get("bytes_received", 0)

    def get_summary(self) -> Dict[str, Any]:
        """Get human-readable profile summary"""
        uptime = self.last_seen - self.first_seen

        return {
            "ip": self.ip,
            "is_private": self.is_private,
            "is_public": self.is_public,
            "country": self.country_code,
            "asn": self.asn,
            "first_seen_iso": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen_iso": datetime.fromtimestamp(self.last_seen).isoformat(),
            "duration_seconds": uptime,
            "inbound_connections": self.inbound_connections,
            "outbound_connections": self.outbound_connections,
            "total_connections": self.total_connections,
            "protocols_used": self.protocols,
            "top_remote_ports": dict(sorted(
                self.remote_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "top_local_ports": dict(sorted(
                self.local_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "top_outbound_processes": dict(sorted(
                self.processes_outbound.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            "top_inbound_processes": dict(sorted(
                self.processes_inbound.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            "dns_queries": self.dns_queries,
            "dns_responses": self.dns_responses,
            "tcp_states": self.tcp_states,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "suspicious_ports": self.suspicious_ports,
            "threat_score": self.calculate_threat_score(),
        }

    def calculate_threat_score(self) -> float:
        """Calculate threat score (0-100) based on behaviors"""
        score = 0.0

        # Suspicious ports usage
        score += len(self.suspicious_ports) * 10

        # High connection volume from single process
        if self.processes_outbound:
            top_process_count = max(self.processes_outbound.values())
            if top_process_count > 100:
                score += 15

        # DNS tunneling indicators
        if self.dns_queries > 100 and self.bytes_sent > 10000:
            score += 20

        # Connection failures
        score += min(self.failed_connections / 10, 10)

        # Uncommon port combinations
        if len(self.remote_ports) > 50:
            score += 10

        # Private IP connecting to many external ports
        if self.is_private and len(self.remote_ports) > 20:
            score += 5

        return min(score, 100.0)


class IPAnalyzer:
    """Analyze network events for unique IPs and threat patterns"""

    def __init__(self):
        """Initialize analyzer"""
        self.ip_profiles: Dict[str, IPProfile] = {}
        self.events_processed = 0
        self.start_time = time.time()

    def process_event(self, event: Dict[str, Any]):
        """Process network event and update IP profiles"""
        self.events_processed += 1

        timestamp = event.get("timestamp", time.time())

        # Track both source and destination IPs
        saddr = event.get("saddr")
        daddr = event.get("daddr")

        if saddr:
            if saddr not in self.ip_profiles:
                self.ip_profiles[saddr] = IPProfile(
                    ip=saddr,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    is_private=self._is_private_ip(saddr),
                    is_public=not self._is_private_ip(saddr)
                )
            self.ip_profiles[saddr].update(event)

        if daddr:
            if daddr not in self.ip_profiles:
                self.ip_profiles[daddr] = IPProfile(
                    ip=daddr,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    is_private=self._is_private_ip(daddr),
                    is_public=not self._is_private_ip(daddr)
                )
            self.ip_profiles[daddr].update(event)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private/RFC1918"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def get_unique_ips(self) -> List[str]:
        """Get all unique IPs seen"""
        return list(self.ip_profiles.keys())

    def get_ip_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get profile for specific IP"""
        if ip in self.ip_profiles:
            return self.ip_profiles[ip].get_summary()
        return None

    def get_external_ips(self) -> List[Dict[str, Any]]:
        """Get profiles for all external (public) IPs"""
        return [
            profile.get_summary()
            for profile in self.ip_profiles.values()
            if profile.is_public
        ]

    def get_internal_ips(self) -> List[Dict[str, Any]]:
        """Get profiles for all internal (private) IPs"""
        return [
            profile.get_summary()
            for profile in self.ip_profiles.values()
            if profile.is_private
        ]

    def get_suspicious_ips(self, min_threat_score: float = 20.0) -> List[Dict[str, Any]]:
        """Get IPs with high threat scores"""
        suspicious = []

        for profile in self.ip_profiles.values():
            threat_score = profile.calculate_threat_score()
            if threat_score >= min_threat_score:
                summary = profile.get_summary()
                summary["threat_score"] = threat_score
                suspicious.append(summary)

        # Sort by threat score descending
        return sorted(suspicious, key=lambda x: x["threat_score"], reverse=True)

    def get_top_ips_by_connections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get IPs with most connections"""
        sorted_ips = sorted(
            self.ip_profiles.values(),
            key=lambda p: p.total_connections,
            reverse=True
        )
        return [p.get_summary() for p in sorted_ips[:limit]]

    def get_top_ips_by_bytes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get IPs with most data transfer"""
        sorted_ips = sorted(
            self.ip_profiles.values(),
            key=lambda p: p.bytes_sent + p.bytes_received,
            reverse=True
        )
        return [p.get_summary() for p in sorted_ips[:limit]]

    def get_dns_queriers(self) -> List[Dict[str, Any]]:
        """Get IPs that performed DNS queries"""
        dns_ips = [
            p.get_summary()
            for p in self.ip_profiles.values()
            if p.dns_queries > 0
        ]
        return sorted(dns_ips, key=lambda x: x["dns_queries"], reverse=True)

    def get_connection_graph(self) -> Dict[str, List[str]]:
        """Get graph of IP connections (for visualization)"""
        graph = defaultdict(list)

        for profile in self.ip_profiles.values():
            # Add connections to remote ports
            if profile.remote_ports:
                for port in profile.remote_ports.keys():
                    graph[profile.ip].append(f"*:{port}")

        return dict(graph)

    def export_json(self) -> Dict[str, Any]:
        """Export all analysis as JSON"""
        return {
            "analysis_time": datetime.now().isoformat(),
            "duration": time.time() - self.start_time,
            "events_processed": self.events_processed,
            "unique_ips": len(self.ip_profiles),
            "unique_external_ips": len([p for p in self.ip_profiles.values() if p.is_public]),
            "unique_internal_ips": len([p for p in self.ip_profiles.values() if p.is_private]),
            "ip_profiles": {
                ip: profile.get_summary()
                for ip, profile in self.ip_profiles.items()
            },
            "statistics": {
                "total_connections": sum(p.total_connections for p in self.ip_profiles.values()),
                "total_inbound": sum(p.inbound_connections for p in self.ip_profiles.values()),
                "total_outbound": sum(p.outbound_connections for p in self.ip_profiles.values()),
                "total_bytes_sent": sum(p.bytes_sent for p in self.ip_profiles.values()),
                "total_bytes_received": sum(p.bytes_received for p in self.ip_profiles.values()),
            }
        }

    def get_summary_report(self) -> str:
        """Generate human-readable summary report"""
        external_ips = [p for p in self.ip_profiles.values() if p.is_public]
        internal_ips = [p for p in self.ip_profiles.values() if p.is_private]
        suspicious = self.get_suspicious_ips(min_threat_score=30)

        report = []
        report.append("\n" + "="*80)
        report.append("IP ANALYSIS REPORT")
        report.append("="*80)
        report.append(f"\nEvents processed: {self.events_processed}")
        report.append(f"Duration: {time.time() - self.start_time:.1f}s")
        report.append(f"\nUnique IPs: {len(self.ip_profiles)}")
        report.append(f"  - External (Public): {len(external_ips)}")
        report.append(f"  - Internal (Private): {len(internal_ips)}")

        # Statistics
        total_conn = sum(p.total_connections for p in self.ip_profiles.values())
        total_bytes = sum(p.bytes_sent + p.bytes_received for p in self.ip_profiles.values())
        report.append(f"\nTraffic Summary:")
        report.append(f"  - Total connections: {total_conn}")
        report.append(f"  - Total data: {total_bytes / 1024 / 1024:.1f} MB")

        # Top IPs
        report.append(f"\nTop 5 Most Connected IPs:")
        for i, ip_summary in enumerate(self.get_top_ips_by_connections(5), 1):
            report.append(f"  {i}. {ip_summary['ip']} - {ip_summary['total_connections']} connections")

        # Suspicious IPs
        if suspicious:
            report.append(f"\nSuspicious IPs (threat_score >= 30):")
            for ip_summary in suspicious[:5]:
                report.append(f"  - {ip_summary['ip']}: threat_score={ip_summary['threat_score']:.1f}")
                if ip_summary['suspicious_ports']:
                    report.append(f"    Suspicious ports: {ip_summary['suspicious_ports']}")

        # DNS activity
        dns_ips = self.get_dns_queriers()
        if dns_ips:
            report.append(f"\nTop DNS Queriers:")
            for ip_summary in dns_ips[:5]:
                report.append(f"  - {ip_summary['ip']}: {ip_summary['dns_queries']} queries")

        report.append("\n" + "="*80 + "\n")
        return "\n".join(report)


class IPThreatIntelligence:
    """Integrate with threat intelligence for IP enrichment"""

    # Known malicious IPs/ASNs (in production, use real threat feeds)
    KNOWN_C2_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 10000}
    KNOWN_PROXY_PORTS = {3128, 8080, 8888, 9090}
    KNOWN_BOTNET_ASNS = {"AS13335", "AS16276", "AS16284"}  # Example ASNs

    @staticmethod
    def check_c2_indicators(profile: IPProfile) -> Dict[str, Any]:
        """Check for C&C communication indicators"""
        indicators = {
            "c2_probable": False,
            "reasons": []
        }

        # Multiple suspicious ports
        if len(profile.suspicious_ports) >= 2:
            indicators["c2_probable"] = True
            indicators["reasons"].append(f"Multiple suspicious ports: {profile.suspicious_ports}")

        # High volume to single port
        if profile.remote_ports:
            top_port, count = max(profile.remote_ports.items(), key=lambda x: x[1])
            if top_port in IPThreatIntelligence.KNOWN_C2_PORTS and count > 10:
                indicators["c2_probable"] = True
                indicators["reasons"].append(f"High volume to known C2 port {top_port}: {count} connections")

        # Single process making many connections
        if profile.processes_outbound:
            top_process, count = max(profile.processes_outbound.items(), key=lambda x: x[1])
            if count > 50:
                indicators["c2_probable"] = True
                indicators["reasons"].append(f"Single process {top_process} made {count} connections")

        return indicators

    @staticmethod
    def check_dns_tunneling(profile: IPProfile) -> Dict[str, Any]:
        """Check for DNS tunneling indicators"""
        indicators = {
            "dns_tunneling_probable": False,
            "reasons": []
        }

        if profile.dns_queries > 100 and profile.bytes_sent > 10000:
            indicators["dns_tunneling_probable"] = True
            indicators["reasons"].append(
                f"High DNS volume ({profile.dns_queries} queries) with high bytes sent"
            )

        return indicators

    @staticmethod
    def check_data_exfiltration(profile: IPProfile) -> Dict[str, Any]:
        """Check for data exfiltration indicators"""
        indicators = {
            "exfiltration_probable": False,
            "reasons": []
        }

        if profile.bytes_sent > 1000000 and profile.is_public:
            indicators["exfiltration_probable"] = True
            indicators["reasons"].append(
                f"Large outbound transfer: {profile.bytes_sent / 1024 / 1024:.1f} MB to public IP"
            )

        return indicators
