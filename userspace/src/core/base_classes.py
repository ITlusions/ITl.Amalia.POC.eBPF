"""Base classes, protocols, and exceptions for the eBPF implant"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


# Custom Exceptions

class ImplantException(Exception):
    """Base exception for implant errors"""
    pass


class CollectionException(ImplantException):
    """Event collection errors"""
    pass


class DetectionException(ImplantException):
    """Threat detection errors"""
    pass


class IntegrationException(ImplantException):
    """External integration errors"""
    pass


class ConfigurationException(ImplantException):
    """Configuration errors"""
    pass


# Abstract Base Classes

class EventCollector(ABC):
    """Abstract base for event collection"""

    @abstractmethod
    def start(self) -> None:
        """Start collecting events"""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop collecting events"""
        pass

    @abstractmethod
    def get_events(self) -> List[Dict[str, Any]]:
        """Retrieve collected events"""
        pass


class ThreatDetector(ABC):
    """Abstract base for threat detection"""

    @abstractmethod
    def analyze(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze event for threats"""
        pass

    @abstractmethod
    def get_summary(self) -> Dict[str, Any]:
        """Get detection summary"""
        pass


class StealthMechanism(ABC):
    """Abstract base for stealth features"""

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize stealth mechanism"""
        pass

    @abstractmethod
    def is_active(self) -> bool:
        """Check if mechanism is active"""
        pass


class C2Channel(ABC):
    """Abstract base for C2 communication channels"""

    @abstractmethod
    def send(self, data: bytes) -> bool:
        """Send data over channel"""
        pass

    @abstractmethod
    def receive(self) -> Optional[bytes]:
        """Receive data from channel"""
        pass


class ExternalIntegration(ABC):
    """Abstract base for external integrations"""

    @abstractmethod
    def connect(self) -> bool:
        """Connect to external system"""
        pass

    @abstractmethod
    def export(self, data: Dict[str, Any]) -> bool:
        """Export data to external system"""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from external system"""
        pass


# Protocol Interfaces (Structural Typing)

from typing import Protocol, runtime_checkable


@runtime_checkable
class EventSource(Protocol):
    """Anything that produces events"""
    
    def get_events(self) -> List[Dict[str, Any]]:
        """Get events"""
        ...


@runtime_checkable
class EventSink(Protocol):
    """Anything that consumes events"""
    
    def consume(self, events: List[Dict[str, Any]]) -> None:
        """Consume events"""
        ...


@runtime_checkable
class Configurable(Protocol):
    """Anything that can be configured"""
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Apply configuration"""
        ...


# Data Classes for Common Structures

@dataclass
class ThreatAlert:
    """Alert for detected threats"""
    timestamp: float
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    source: str  # component that detected the threat
    context: Dict[str, Any]


@dataclass
class HealthStatus:
    """System health status"""
    is_healthy: bool
    uptime_sec: float
    events_collected: int
    threats_detected: int
    last_error: Optional[str] = None
