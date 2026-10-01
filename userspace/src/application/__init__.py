"""Application layer: main orchestrator and dependency injection"""

from .implant_agent import EBPFSensorAgent
from .services import ApplicationServices, get_services, reset_services

# Backwards compatibility alias
EBPFImplantAgent = EBPFSensorAgent

__all__ = [
    "EBPFSensorAgent",
    "EBPFImplantAgent",  # Backwards compatibility
    "ApplicationServices",
    "get_services",
    "reset_services",
]
