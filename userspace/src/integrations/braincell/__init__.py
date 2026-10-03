"""BrainCell integration: persistent memory streaming"""

from .client import BrainCellWebSocketClient

# Alias for convenience
BrainCellClient = BrainCellWebSocketClient

__all__ = [
    "BrainCellClient",
    "BrainCellWebSocketClient",
]
