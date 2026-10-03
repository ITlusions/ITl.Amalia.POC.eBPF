"""
Sigma-Lite: Behavioral Attack Chain Detection for eBPF Telemetry

Detects multi-stage attack sequences within a time window by correlating
network events, process creation, and file access patterns.

Complements YARA (point-in-time signatures) with behavioral sequence detection
for higher-confidence threat identification.
"""

import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class SigmaMatch:
    """Detected attack chain match"""
    timestamp: float
    chain_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    events: List[Dict[str, Any]]  # Correlated events
    process: str
    mitre_techniques: List[str]
    description: str
    confidence: float  # 0.0 - 1.0


class SigmaLiteDetector:
    """
    Detects behavioral attack chains by correlating events within time window.
    
    Patterns detected:
    1. DNS Exfiltration Chain - High DNS volume + large outbound transfer
    2. Lateral Movement Chain - Port scanning + remote access attempts
    3. Privilege Escalation + Persistence - Privesc + hidden file access
    4. Credential Access Chain - Multiple auth failures + success + new access
    5. Reconnaissance Chain - Port scanning + service enumeration
    6. Process Injection Chain - Process creation + memory access pattern
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Args:
            config: Configuration dict with keys:
                - time_window_sec: Size of event correlation window (default: 60)
                - enabled_chains: List of chains to detect (default: all)
                - export_chains: Whether to export detected chains (default: True)
        """
        self.time_window = config.get('time_window_sec', 60) if config else 60
        self.enabled_chains = (
            config.get('detection_rules', [
                'dns_exfil_chain',
                'lateral_movement_chain',
                'priv_esc_persistence',
                'credential_access_chain',
                'reconnaissance_chain',
                'injection_chain'
            ]) if config else [
                'dns_exfil_chain',
                'lateral_movement_chain',
                'priv_esc_persistence',
                'credential_access_chain',
                'reconnaissance_chain',
                'injection_chain'
            ]
        )
        self.export_chains = config.get('export_chains', True) if config else True
        
        # Event buffer: {process_id: [events]}
        self.event_buffer = defaultdict(list)
        self.detected_chains = []
    
    def add_event(self, event: Dict[str, Any]) -> List[SigmaMatch]:
        """
        Process new event and detect chains.
        
        Args:
            event: Network/process event dict
        
        Returns:
            List of detected attack chains
        """
        if not event:
            return []
        
        current_time = time.time()
        process_key = event.get('comm', 'unknown')
        
        # Add event to buffer
        self.event_buffer[process_key].append({
            **event,
            'ingestion_time': current_time
        })
        
        # Clean old events (outside time window)
        self.event_buffer[process_key] = [
            e for e in self.event_buffer[process_key]
            if current_time - e['ingestion_time'] < self.time_window
        ]
        
        # Detect chains
        matches = []
        
        if 'dns_exfil_chain' in self.enabled_chains:
            match = self._detect_dns_exfil_chain(process_key)
            if match:
                matches.append(match)
        
        if 'lateral_movement_chain' in self.enabled_chains:
            match = self._detect_lateral_movement_chain(process_key)
            if match:
                matches.append(match)
        
        if 'priv_esc_persistence' in self.enabled_chains:
            match = self._detect_priv_esc_persistence(process_key)
            if match:
                matches.append(match)
        
        if 'credential_access_chain' in self.enabled_chains:
            match = self._detect_credential_access_chain(process_key)
            if match:
                matches.append(match)
        
        if 'reconnaissance_chain' in self.enabled_chains:
            match = self._detect_reconnaissance_chain(process_key)
            if match:
                matches.append(match)
        
        if 'injection_chain' in self.enabled_chains:
            match = self._detect_injection_chain(process_key)
            if match:
                matches.append(match)
        
        # Store detected chains
        self.detected_chains.extend(matches)
        
        # Log detections
        for match in matches:
            logger.warning(f"[CHAIN] {match.chain_name} - {match.description}")
            logger.warning(f"  Severity: {match.severity}, Confidence: {match.confidence:.1%}")
            logger.warning(f"  MITRE: {', '.join(match.mitre_techniques)}")
        
        return matches
    
    def _detect_dns_exfil_chain(self, process_key: str) -> Optional[SigmaMatch]:
        """
        Detect: High DNS volume + Large outbound transfer within time window
        Pattern: Process makes many DNS queries, then transfers large amount of data
        Indicator: Possible DNS tunneling or staged exfiltration
        """
        events = self.event_buffer[process_key]
        
        # Find DNS events (>50 queries)
        dns_events = [e for e in events if e.get('is_dns')]
        dns_bytes = sum(e.get('bytes_sent', 0) for e in dns_events)
        dns_count = len(dns_events)
        
        if dns_count < 50:
            return None
        
        # Find large outbound transfers (>1MB)
        large_transfers = [e for e in events 
                          if not e.get('is_dns') and e.get('bytes_sent', 0) > 1_000_000]
        
        if not large_transfers:
            return None
        
        # Calculate time spread
        if not dns_events or not large_transfers:
            return None
        
        first_dns = min(e['ingestion_time'] for e in dns_events)
        last_transfer = max(e['ingestion_time'] for e in large_transfers)
        time_spread = last_transfer - first_dns
        
        # High confidence if within time window
        if time_spread <= self.time_window:
            total_bytes = sum(e.get('bytes_sent', 0) for e in large_transfers)
            
            return SigmaMatch(
                timestamp=time.time(),
                chain_name='DNS_EXFIL_CHAIN',
                severity='CRITICAL',
                events=dns_events + large_transfers,
                process=process_key,
                mitre_techniques=[
                    'T1020-AutomatedExfiltration',
                    'T1071.004-ProtocolTunneling-DNS'
                ],
                description=(
                    f"High DNS volume ({dns_count} queries, {dns_bytes}B) followed by "
                    f"large transfer ({total_bytes}B) from {process_key}"
                ),
                confidence=min(0.95, 0.8 + (time_spread / self.time_window) * 0.15)
            )
        
        return None
    
    def _detect_lateral_movement_chain(self, process_key: str) -> Optional[SigmaMatch]:
        """
        Detect: Port scanning + Remote access attempts within time window
        Pattern: Process scans multiple ports, then attempts RDP/SSH/SMB
        Indicator: Lateral movement reconnaissance followed by exploitation
        """
        events = self.event_buffer[process_key]
        
        # Port scanning: >20 unique remote ports
        outbound_events = [e for e in events if e.get('direction') == 'outbound']
        unique_ports = set(e.get('dport') for e in outbound_events if e.get('dport'))
        
        if len(unique_ports) < 20:
            return None
        
        # Remote access attempts: RDP (3389), SSH (22), SMB (445)
        remote_access_ports = {22, 445, 3389}
        remote_attempts = [
            e for e in outbound_events 
            if e.get('dport') in remote_access_ports
        ]
        
        if not remote_attempts:
            return None
        
        # Time spread check
        if outbound_events:
            first_scan = min(e['ingestion_time'] for e in outbound_events)
            last_attempt = max(e['ingestion_time'] for e in remote_attempts)
            time_spread = last_attempt - first_scan
            
            if time_spread <= self.time_window:
                return SigmaMatch(
                    timestamp=time.time(),
                    chain_name='LATERAL_MOVEMENT_CHAIN',
                    severity='HIGH',
                    events=outbound_events,
                    process=process_key,
                    mitre_techniques=[
                        'T1595.002-ActiveScanning-PortScanning',
                        'T1021-RemoteServices'
                    ],
                    description=(
                        f"Port scanning ({len(unique_ports)} unique ports) followed by "
                        f"remote access attempts on RDP/SSH/SMB"
                    ),
                    confidence=min(0.92, 0.75 + (time_spread / self.time_window) * 0.17)
                )
        
        return None
    
    def _detect_priv_esc_persistence(self, process_key: str) -> Optional[SigmaMatch]:
        """
        Detect: Privilege escalation + Persistence mechanism chain
        Pattern: Process transitions to root/SYSTEM, then accesses system files
        Indicator: Elevation followed by persistence setup
        """
        events = self.event_buffer[process_key]
        
        # Find uid/gid changes (normal user -> root transition)
        uid_events = [e for e in events if 'uid' in e]
        if len(uid_events) < 2:
            return None
        
        first_uid = uid_events[0].get('uid')
        last_uid = uid_events[-1].get('uid')
        
        # Escalation: normal (1000+) to privileged (0-100)
        if not (first_uid and first_uid > 100 and last_uid and last_uid < 100):
            return None
        
        # Find persistence indicators: system file access, cron jobs, etc.
        persistence_events = [
            e for e in events
            if any(path in str(e.get('path', '')) for path in [
                '/etc/cron', '/etc/systemd', '/var/spool', '/root/.ssh',
                '/etc/passwd', '/etc/shadow', '.bashrc', '.bash_profile'
            ])
        ]
        
        if not persistence_events:
            return None
        
        return SigmaMatch(
            timestamp=time.time(),
            chain_name='PRIV_ESC_PERSISTENCE',
            severity='CRITICAL',
            events=uid_events + persistence_events,
            process=process_key,
            mitre_techniques=[
                'T1548-PrivilegeEscalation',
                'T1547-BootOrLogonAutostart',
                'T1053-ScheduledTask'
            ],
            description=(
                f"Privilege escalation (uid {first_uid} -> {last_uid}) followed by "
                f"persistence file access ({len(persistence_events)} system paths)"
            ),
            confidence=0.88
        )
    
    def _detect_credential_access_chain(self, process_key: str) -> Optional[SigmaMatch]:
        """
        Detect: Multiple failed auth + successful access + privileged action
        Pattern: Failed logins, then successful login, then admin file access
        Indicator: Credential compromise or brute force success
        """
        events = self.event_buffer[process_key]
        
        # Failed auth attempts (high port count to auth services)
        auth_ports = {22, 23, 389, 445, 3306, 5432, 8080}  # SSH, Telnet, LDAP, SMB, MySQL, PostgreSQL, HTTP-alt
        failed_attempts = [
            e for e in events
            if e.get('dport') in auth_ports and e.get('tcp_state', '') in ['SYN_SENT', 'CLOSED']
        ]
        
        # Successful connections after failures
        successful = [
            e for e in events
            if e.get('dport') in auth_ports and e.get('tcp_state') == 'ESTABLISHED'
        ]
        
        # Privileged file access after auth
        priv_access = [
            e for e in events
            if any(admin_path in str(e.get('path', '')) for admin_path in [
                '/root', '/etc', '/var/log', 'admin', 'Administrator'
            ])
        ]
        
        if failed_attempts and successful and len(failed_attempts) >= 5:
            return SigmaMatch(
                timestamp=time.time(),
                chain_name='CREDENTIAL_ACCESS_CHAIN',
                severity='HIGH',
                events=failed_attempts + successful + priv_access,
                process=process_key,
                mitre_techniques=[
                    'T1110-BruteForce',
                    'T1021-RemoteServices',
                    'T1552-UnsecuredCredentials'
                ],
                description=(
                    f"Multiple failed auth attempts ({len(failed_attempts)}) followed by "
                    f"successful connection and privileged access"
                ),
                confidence=0.85
            )
        
        return None
    
    def _detect_reconnaissance_chain(self, process_key: str) -> Optional[SigmaMatch]:
        """
        Detect: Service enumeration + Information gathering chain
        Pattern: Multiple port connections + DNS queries for mapping
        Indicator: Active reconnaissance phase of attack
        """
        events = self.event_buffer[process_key]
        
        # Outbound connections to various ports (service discovery)
        outbound = [e for e in events if e.get('direction') == 'outbound']
        unique_hosts = set(e.get('daddr') for e in outbound if e.get('daddr'))
        unique_ports = set(e.get('dport') for e in outbound if e.get('dport'))
        
        # DNS queries for host enumeration
        dns_queries = [e for e in events if e.get('is_dns')]
        
        if len(unique_hosts) >= 5 and len(unique_ports) >= 10 and len(dns_queries) >= 20:
            return SigmaMatch(
                timestamp=time.time(),
                chain_name='RECONNAISSANCE_CHAIN',
                severity='MEDIUM',
                events=outbound + dns_queries,
                process=process_key,
                mitre_techniques=[
                    'T1595-ActiveScanning',
                    'T1046-NetworkServiceScanning',
                    'T1018-RemoteSystemDiscovery'
                ],
                description=(
                    f"Active reconnaissance: {len(unique_hosts)} hosts scanned, "
                    f"{len(unique_ports)} ports probed, {len(dns_queries)} DNS queries"
                ),
                confidence=0.72
            )
        
        return None
    
    def _detect_injection_chain(self, process_key: str) -> Optional[SigmaMatch]:
        """
        Detect: Process spawning + Memory access pattern
        Pattern: Parent process spawns child, followed by unusual memory access
        Indicator: Process injection or code execution
        """
        events = self.event_buffer[process_key]
        
        # Process creation events
        process_events = [e for e in events if e.get('type') == 'process']
        
        # File events that indicate memory operations (if available)
        file_events = [
            e for e in events
            if e.get('type') == 'file' and any(
                pattern in str(e.get('path', ''))
                for pattern in ['/proc/self', '/dev/mem', 'ptrace', '.text', '.data']
            )
        ]
        
        if process_events and file_events and len(process_events) >= 2:
            # Multiple child processes + memory access
            if len([e for e in process_events if e.get('ppid')]) >= 2:
                return SigmaMatch(
                    timestamp=time.time(),
                    chain_name='INJECTION_CHAIN',
                    severity='HIGH',
                    events=process_events + file_events,
                    process=process_key,
                    mitre_techniques=[
                        'T1055-ProcessInjection',
                        'T1106-NativeAPI'
                    ],
                    description=(
                        f"Multiple process creation ({len(process_events)}) "
                        f"with memory access patterns ({len(file_events)} suspicious paths)"
                    ),
                    confidence=0.78
                )
        
        return None
    
    def get_detected_chains(self) -> List[SigmaMatch]:
        """Get all detected chains"""
        return self.detected_chains
    
    def get_high_severity_chains(self) -> List[SigmaMatch]:
        """Get only CRITICAL and HIGH severity chains"""
        return [c for c in self.detected_chains if c.severity in ['CRITICAL', 'HIGH']]
    
    def clear_buffers(self):
        """Clear all event buffers (manual cleanup)"""
        self.event_buffer.clear()
        self.detected_chains.clear()
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export detected chains as dict"""
        return {
            'detected_chains': [asdict(c) for c in self.detected_chains],
            'summary': {
                'total_detections': len(self.detected_chains),
                'critical': len([c for c in self.detected_chains if c.severity == 'CRITICAL']),
                'high': len([c for c in self.detected_chains if c.severity == 'HIGH']),
                'medium': len([c for c in self.detected_chains if c.severity == 'MEDIUM']),
                'low': len([c for c in self.detected_chains if c.severity == 'LOW']),
            }
        }
    
    def export_to_json(self, filepath: str) -> str:
        """Export detected chains to JSON file"""
        data = self.export_to_dict()
        
        # Make timestamps JSON-serializable
        for chain in data['detected_chains']:
            chain['timestamp'] = chain['timestamp']
            chain['events'] = [
                {k: (v if not isinstance(v, float) else round(v, 6)) 
                 for k, v in e.items()}
                for e in chain['events']
            ]
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(data['detected_chains'])} chains to {filepath}")
        return filepath
    
    def export_to_report(self, filepath: str) -> str:
        """Export detected chains to human-readable report"""
        report = "SIGMA-LITE ATTACK CHAIN DETECTION REPORT\n"
        report += "=" * 80 + "\n\n"
        
        summary = self.export_to_dict()['summary']
        report += f"Total Detections: {summary['total_detections']}\n"
        report += f"  - CRITICAL: {summary['critical']}\n"
        report += f"  - HIGH:     {summary['high']}\n"
        report += f"  - MEDIUM:   {summary['medium']}\n"
        report += f"  - LOW:      {summary['low']}\n\n"
        
        report += "=" * 80 + "\n"
        report += "DETECTED CHAINS\n"
        report += "=" * 80 + "\n\n"
        
        for i, chain in enumerate(self.detected_chains, 1):
            report += f"{i}. [{chain.severity}] {chain.chain_name}\n"
            report += f"   Process: {chain.process}\n"
            report += f"   Time: {chain.timestamp}\n"
            report += f"   Confidence: {chain.confidence:.1%}\n"
            report += f"   Description: {chain.description}\n"
            report += f"   MITRE Techniques:\n"
            for technique in chain.mitre_techniques:
                report += f"     - {technique}\n"
            report += f"   Events Correlated: {len(chain.events)}\n"
            report += "\n"
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        logger.info(f"Exported report to {filepath}")
        return filepath


# Integration with existing implant_agent.py
def integrate_sigma_lite(implant_agent: 'EBPFImplantAgent') -> SigmaLiteDetector:
    """
    Factory function to integrate Sigma-Lite with implant agent.
    
    Usage in implant_agent.py:
    ```
    self.sigma_lite = integrate_sigma_lite(self)
    
    # In network_callback:
    sigma_matches = self.sigma_lite.add_event(event)
    for match in sigma_matches:
        logger.critical(f"Attack chain detected: {match.description}")
    ```
    """
    config = implant_agent.config.get('sigma_lite', {})
    detector = SigmaLiteDetector(config)
    logger.info("Sigma-Lite detector initialized")
    return detector


if __name__ == '__main__':
    # Example usage
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    # Create detector
    detector = SigmaLiteDetector({
        'time_window_sec': 60,
        'detection_rules': [
            'dns_exfil_chain',
            'lateral_movement_chain',
            'priv_esc_persistence'
        ]
    })
    
    # Simulate events
    print("Sigma-Lite Attack Chain Detector - Example")
    print("=" * 60)
    
    # Example: DNS exfiltration chain
    print("\n[+] Simulating DNS exfiltration chain...")
    
    for i in range(60):
        detector.add_event({
            'type': 'network',
            'comm': 'curl',
            'dport': 53,
            'is_dns': True,
            'bytes_sent': 1000,
            'direction': 'outbound',
            'daddr': '8.8.8.8'
        })
    
    # Large transfer
    detector.add_event({
        'type': 'network',
        'comm': 'curl',
        'dport': 443,
        'is_dns': False,
        'bytes_sent': 5_000_000,
        'direction': 'outbound',
        'daddr': 'attacker.com'
    })
    
    matches = detector.get_detected_chains()
    print(f"\n[*] Detected {len(matches)} chains")
    for match in matches:
        print(f"  - [{match.severity}] {match.chain_name}")
        print(f"    {match.description}")
        print(f"    Confidence: {match.confidence:.1%}")
    
    # Export results
    detector.export_to_json('/tmp/sigma-lite-chains.json')
    detector.export_to_report('/tmp/sigma-lite-report.txt')
    
    print("\n[+] Results exported to /tmp/sigma-lite-*.json and .txt")
