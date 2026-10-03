"""Logging configuration for the sensor"""

import logging
import sys
from typing import Optional


class SensorLogger:
    """Centralized logging setup for threat detection sensor"""

    _instance: Optional["SensorLogger"] = None
    _logger: Optional[logging.Logger] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, level: str = "INFO"):
        if self._logger is not None:
            return  # Already initialized

        self._logger = logging.getLogger("ebpf-sensor")

        # Normal logging
        log_level = getattr(logging, level.upper(), logging.INFO)
        self._logger.setLevel(log_level)

        # Console handler
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '[%(asctime)s] %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

    def get_logger(self) -> logging.Logger:
        """Get the global logger instance"""
        return self._logger

    @staticmethod
    def debug(message: str) -> None:
        """Log debug message"""
        if SensorLogger._logger:
            SensorLogger._logger.debug(message)

    @staticmethod
    def info(message: str) -> None:
        """Log info message"""
        if SensorLogger._logger:
            SensorLogger._logger.info(message)

    @staticmethod
    def warning(message: str) -> None:
        """Log warning message"""
        if SensorLogger._logger:
            SensorLogger._logger.warning(message)

    @staticmethod
    def error(message: str) -> None:
        """Log error message"""
        if SensorLogger._logger:
            SensorLogger._logger.error(message)


# Backwards compatibility alias
ImplantLogger = SensorLogger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(name)
