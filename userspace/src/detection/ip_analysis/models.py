"""IP analysis domain models"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


@dataclass
class IPProfile:
    """Comprehensive profile for a unique IP address"""
    ip: str
    first_seen: float
    last_seen: float

    inbound_connections: int = 0
    outbound_connections: int = 0
    total_connections: int = 0

    protocols: Dict[str, int] = field(default_factory=lambda: {"TCP": 0, "UDP": 0})
    remote_ports: Dict[int, int] = field(default_factory=dict)
    local_ports: Dict[int, int] = field(default_factory=dict)

    processes_outbound: Dict[str, int] = field(default_factory=dict)
    processes_inbound: Dict[str, int] = field(default_factory=dict)

    dns_queries: int = 0
    dns_responses: int = 0
    tcp_states: Dict[str, int] = field(default_factory=dict)

    bytes_sent: int = 0
    bytes_received: int = 0
    suspicious_ports: List[int] = field(default_factory=list)
    failed_connections: int = 0

    country_code: Optional[str] = None
    asn: Optional[str] = None
    is_private: bool = False
    is_public: bool = False

    def calculate_threat_score(self) -> float:
        """Calculate threat score (0-100)"""
        score = 0.0
        score += len(self.suspicious_ports) * 10
        if self.processes_outbound:
            if max(self.processes_outbound.values()) > 100:
                score += 15
        if self.dns_queries > 100 and self.bytes_sent > 10000:
            score += 20
        score += min(self.failed_connections / 10, 10)
        if len(self.remote_ports) > 50:
            score += 10
        if self.is_private and len(self.remote_ports) > 20:
            score += 5
        return min(score, 100.0)
