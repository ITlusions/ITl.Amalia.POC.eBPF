"""YARA detection domain models"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class YARARuleMatch:
    """Result of YARA rule matching"""
    timestamp: float
    rule: str
    category: str
    severity: str  # critical, high, medium, low
    ip: str
    pattern: str
    description: str
    confidence: float  # 0.0 - 1.0
    metadata: dict


@dataclass
class ThreatCategory:
    """YARA threat category definition"""
    name: str
    description: str
    patterns: List[dict]
