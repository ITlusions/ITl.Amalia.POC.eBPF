"""Collection domain models: event data structures"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class ProcessEvent:
    """Process execution event captured by eBPF"""
    timestamp: float
    timestamp_iso: str
    pid: int
    ppid: int
    uid: int
    gid: int
    comm: str
    filename: str
    argv: str
    type: str = "process"


@dataclass
class NetworkEvent:
    """Network connection event captured by eBPF"""
    timestamp: float
    timestamp_iso: str
    pid: int
    uid: int
    comm: str
    protocol: str  # TCP, UDP
    family: str    # IPv4, IPv6
    sport: int
    dport: int
    saddr: str
    daddr: str
    direction: str  # inbound, outbound, close
    tcp_state: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    retransmits: Optional[int] = None
    is_dns: bool = False
    type: str = "network"


@dataclass
class FileEvent:
    """File access event captured by eBPF"""
    timestamp: float
    timestamp_iso: str
    pid: int
    uid: int
    comm: str
    path: str
    flags: int
    mode: int
    op_type: str  # open, read, write, close
    type: str = "file"


@dataclass
class TelemetryCollection:
    """Aggregated telemetry collection"""
    implant_id: str
    exported_at: str
    collection_window: Dict[str, Any]
    events: Dict[str, list] = field(default_factory=lambda: {
        "process": [],
        "network": [],
        "file": []
    })
    summary: Dict[str, int] = field(default_factory=dict)
