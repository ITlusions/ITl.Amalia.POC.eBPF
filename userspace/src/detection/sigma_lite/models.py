"""Sigma-Lite behavioral detection domain models"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class SigmaMatch:
    """Detected attack chain match"""
    timestamp: float
    chain_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    events: List[Dict[str, Any]]
    process: str
    mitre_techniques: List[str]
    description: str
    confidence: float  # 0.0 - 1.0


@dataclass
class AttackChain:
    """Detected multi-event attack chain"""
    name: str
    severity: str
    mitre_techniques: List[str]
    description: str
    event_sequence: List[str]
