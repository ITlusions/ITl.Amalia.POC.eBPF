"""Application services: Dependency Injection composition root"""

from typing import Optional

from core import ConfigManager, ImplantLogger, ConfigurationSettings
from collection.models import TelemetryCollection
from detection.ip_analysis import IPAnalyzer
from detection.yara import YARADetector
from detection.sigma_lite import SigmaLiteDetector
from detection.correlation import ThreatCorrelator
from integrations import BrainCellClient, AmaliaExporter

# Optional stealth package (itl-ebpf-stealth)
STEALTH_AVAILABLE = False
StealthyImplantBootstrap = None
C2ClientOrchestrator = None
C2Configuration = None

try:
    from itl_ebpf_stealth import StealthyImplantBootstrap
    from itl_ebpf_stealth import C2ClientOrchestrator, C2Configuration
    STEALTH_AVAILABLE = True
except ImportError:
    pass


class ApplicationServices:
    """Factory for creating application services with proper DI wiring"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.settings
        self.logger = ImplantLogger(stealth_mode=self.config.enable_stealth).get_logger()

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

    def create_stealth_layer(self) -> Optional[object]:
        """Create stealth mechanism orchestrator (OPTIONAL)"""
        if not STEALTH_AVAILABLE or not StealthyImplantBootstrap:
            self.logger.info("Stealth layer not available (itl-ebpf-stealth not installed)")
            return None

        try:
            return StealthyImplantBootstrap()
        except Exception as e:
            self.logger.error(f"Stealth initialization failed: {e}")
            return None

    def create_c2_client(self) -> Optional[object]:
        """Create C2 client if enabled (OPTIONAL)"""
        if not self.config.c2_enabled or not self.config.c2_server_url:
            return None

        if not STEALTH_AVAILABLE or not C2ClientOrchestrator:
            self.logger.warning("C2 requested but itl-ebpf-stealth not installed")
            return None

        try:
            c2_config = C2Configuration(server_url=self.config.c2_server_url)
            return C2ClientOrchestrator(c2_config)
        except Exception as e:
            self.logger.error(f"C2 initialization failed: {e}")
            return None

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

    def create_telemetry_collection(self, duration_sec: int = 60) -> TelemetryCollection:
        """Create telemetry collection container"""
        from datetime import datetime
        import time
        
        return TelemetryCollection(
            implant_id=self.config.implant_id,
            exported_at=datetime.now().isoformat(),
            collection_window={
                "start": time.time(),
                "end": time.time() + duration_sec,
                "duration_sec": duration_sec
            }
        )

    def get_logger(self):
        """Get application logger"""
        return self.logger

    def get_config(self) -> ConfigurationSettings:
        """Get configuration settings"""
        return self.config


# Global service factory instance
_services_instance: Optional[ApplicationServices] = None


def get_services(config_manager: Optional[ConfigManager] = None) -> ApplicationServices:
    """Get or create the global services instance"""
    global _services_instance
    
    if _services_instance is None:
        if config_manager is None:
            config_manager = ConfigManager()
        _services_instance = ApplicationServices(config_manager)
    
    return _services_instance


def reset_services() -> None:
    """Reset services (for testing)"""
    global _services_instance
    _services_instance = None
