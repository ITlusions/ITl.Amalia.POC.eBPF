"""Core configuration management"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class ConfigurationSettings:
    """Sensor configuration"""
    implant_id: str = "ebpf-sensor-poc-01"
    collection_interval: int = 60
    max_events_per_batch: int = 100
    enable_ip_analysis: bool = True
    enable_yara_detection: bool = True
    enable_sigma_detection: bool = True
    enable_braincell_streaming: bool = False
    braincell_url: Optional[str] = None
    enable_amalia_export: bool = False
    amalia_url: Optional[str] = None
    log_level: str = "INFO"


class ConfigManager:
    """Centralized configuration management"""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize from config file or environment"""
        self.settings = ConfigurationSettings()
        
        if config_file and Path(config_file).exists():
            self.load_from_file(config_file)
        else:
            self.load_from_env()

    def load_from_file(self, config_file: str) -> None:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            for key, value in config_data.items():
                if hasattr(self.settings, key):
                    setattr(self.settings, key, value)
        except Exception as e:
            print(f"Failed to load config file: {e}")

    def load_from_env(self) -> None:
        """Load configuration from environment variables"""
        env_mapping = {
            "IMPLANT_ID": ("implant_id", str),
            "COLLECTION_INTERVAL": ("collection_interval", int),
            "MAX_EVENTS_PER_BATCH": ("max_events_per_batch", int),
            "ENABLE_IP_ANALYSIS": ("enable_ip_analysis", bool),
            "ENABLE_YARA_DETECTION": ("enable_yara_detection", bool),
            "ENABLE_SIGMA_DETECTION": ("enable_sigma_detection", bool),
            "BRAINCELL_URL": ("braincell_url", str),
            "AMALIA_URL": ("amalia_url", str),
            "C2_SERVER_URL": ("c2_server_url", str),
            "LOG_LEVEL": ("log_level", str),
        }
        
        for env_var, (attr_name, attr_type) in env_mapping.items():
            env_value = os.getenv(env_var)
            if env_value:
                if attr_type == bool:
                    setattr(self.settings, attr_name, env_value.lower() in ['true', '1', 'yes'])
                elif attr_type == int:
                    setattr(self.settings, attr_name, int(env_value))
                else:
                    setattr(self.settings, attr_name, env_value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            "implant_id": self.settings.implant_id,
            "collection_interval": self.settings.collection_interval,
            "max_events_per_batch": self.settings.max_events_per_batch,
            "enable_ip_analysis": self.settings.enable_ip_analysis,
            "enable_yara_detection": self.settings.enable_yara_detection,
            "enable_sigma_detection": self.settings.enable_sigma_detection,
            "enable_braincell_streaming": self.settings.enable_braincell_streaming,
            "braincell_url": self.settings.braincell_url,
            "enable_amalia_export": self.settings.enable_amalia_export,
            "amalia_url": self.settings.amalia_url,
            "c2_enabled": self.settings.c2_enabled,
            "c2_server_url": self.settings.c2_server_url,
            "enable_stealth": self.settings.enable_stealth,
            "log_level": self.settings.log_level,
        }

    def save_to_file(self, config_file: str) -> None:
        """Save current settings to JSON file"""
        try:
            with open(config_file, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
        except Exception as e:
            print(f"Failed to save config file: {e}")
