"""
Crash Detection Module - Zero-Day Crash Monitoring

This module detects application crashes that may indicate zero-day exploitation.
Integrates with eBPF kernel program to capture crash context at signal delivery.

Exports:
- CrashDetector: Main crash detection class
- CrashEvent: Crash event data structure
- RiskLevel: Crash risk classification enum
"""

from .detector import (
    CrashDetector,
    CrashEvent,
    CrashTriage,
    SignalType,
    RiskLevel,
    get_crash_detector,
)

__all__ = [
    "CrashDetector",
    "CrashEvent",
    "CrashTriage",
    "SignalType",
    "RiskLevel",
    "get_crash_detector",
]
