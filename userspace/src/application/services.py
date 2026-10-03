"""Application services: Dependency Injection composition root"""

from typing import Optional

from core import ConfigManager, ImplantLogger, ConfigurationSettings
from collection.models import TelemetryCollection
from detection.ip_analysis import IPAnalyzer
from detection.yara import YARADetector
from detection.sigma_lite import SigmaLiteDetector
from detection.correlation import ThreatCorrelator
from integrations import BrainCellClient, AmaliaExporter


class ApplicationServices:
    """Factory for creating application services with proper DI wiring"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.settings
        self.logger = ImplantLogger().get_logger()

    def create_threat_detection_stack(self) -> ThreatCorrelator:
        """Create and wire threat detection services"""
        ip_analyzer = None
        yara_detector = None
        sigma_detector = None

        if self.config.enable_ip_analysis:
            ip_analyzer = IPAnalyzer()

        if self.config.enable_yara_detection:
            yara_detector = YARADetector()

        if self.config.enable_sigma_detection:
            sigma_detector = SigmaLiteDetector()

        correlator = ThreatCorrelator()
        return correlator

    def create_braincell_integration(self) -> Optional[BrainCellClient]:
        """Create BrainCell integration if enabled"""
        if not self.config.enable_braincell_streaming or not self.config.braincell_url:
            return None

        try:
            client = BrainCellClient(self.config.braincell_url)
            return client
        except Exception as e:
            self.logger.error(f"BrainCell integration failed: {e}")
            return None

    def create_amalia_exporter(self) -> Optional[AmaliaExporter]:
        """Create Amalia exporter if enabled"""
        if not self.config.enable_amalia_export or not self.config.amalia_url:
            return None

        try:
            exporter = AmaliaExporter(self.config.amalia_url)
            return exporter
        except Exception as e:
            self.logger.error(f"Amalia exporter failed: {e}")
            return None


# Global service instances
_services = None


def get_services(config_manager: ConfigManager = None) -> ApplicationServices:
    """Get or create application services"""
    global _services
    if _services is None:
        if config_manager is None:
            config_manager = ConfigManager()
        _services = ApplicationServices(config_manager)
    return _services


def reset_services() -> None:
    """Reset services (for testing)"""
    global _services
    _services = None
