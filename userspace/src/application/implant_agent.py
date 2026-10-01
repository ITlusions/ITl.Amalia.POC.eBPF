#!/usr/bin/env python3
"""
eBPF Sensor Agent - Thin Orchestrator

Orchestrates kernel-level event collection, threat detection, and external
integrations. Optionally supports advanced stealth testing via itl-ebpf-stealth.

Delegates to domain-specific services via dependency injection.
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from core import ConfigManager, ImplantLogger
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


class EBPFImplantAgent:
    """Main implant orchestrator"""

    def __init__(self, config_file: str = "config.json", stealth_mode: bool = False):
        """
        Initialize orchestrator with configuration

        Args:
            config_file: Path to JSON configuration file
            stealth_mode: Enable optional stealth features (requires itl-ebpf-stealth)
        """
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.settings
        self.logger = ImplantLogger(stealth_mode=stealth_mode).get_logger()

        # Initialize threat detection services (CORE)
        self.ip_analyzer = IPAnalyzer() if self.config.enable_ip_analysis else None
        self.yara_detector = YARADetector() if self.config.enable_yara_detection else None
        self.sigma_detector = SigmaLiteDetector() if self.config.enable_sigma_detection else None
        self.threat_correlator = ThreatCorrelator()

        # Initialize stealth layer (OPTIONAL - itl-ebpf-stealth)
        self.stealth = None
        if stealth_mode:
            if STEALTH_AVAILABLE:
                try:
                    self.stealth = StealthyImplantBootstrap()
                except Exception as e:
                    self.logger.warning(f"Stealth initialization failed: {e}. Continuing without stealth.")
            else:
                self.logger.info("Stealth mode requested but itl-ebpf-stealth not installed. "
                               "Install with: pip install itl-ebpf-stealth")

        # Initialize C2 if enabled (OPTIONAL - itl-ebpf-stealth)
        self.c2_client = None
        if self.config.c2_enabled and self.config.c2_server_url:
            if STEALTH_AVAILABLE:
                try:
                    c2_config = C2Configuration(server_url=self.config.c2_server_url)
                    self.c2_client = C2ClientOrchestrator(c2_config)
                except Exception as e:
                    self.logger.error(f"C2 initialization failed: {e}")
            else:
                self.logger.warning("C2 enabled but itl-ebpf-stealth not installed. "
                                  "Install with: pip install itl-ebpf-stealth")

        # Initialize external integrations (CORE)
        self.braincell_client = None
        if self.config.enable_braincell_streaming and self.config.braincell_url:
            self.braincell_client = BrainCellClient(self.config.braincell_url)

        self.amalia_exporter = None
        if self.config.enable_amalia_export and self.config.amalia_url:
            self.amalia_exporter = AmaliaExporter(self.config.amalia_url)

        self.running = False
        self.telemetry_collection = None

    def start_collection(self, duration_sec: int = 60) -> None:
        """Start event collection and threat detection"""
        try:
            # Initialize stealth mechanisms (OPTIONAL)
            if self.stealth:
                stealth_status = self.stealth.initialize()
                self.logger.info(f"Stealth initialized: {stealth_status}")

            # Start C2 if enabled (OPTIONAL)
            if self.c2_client:
                self.c2_client.start()
                self.logger.info("C2 client started")

            # Initialize telemetry collection
            self.telemetry_collection = TelemetryCollection(
                implant_id=self.config.implant_id,
                exported_at=datetime.now().isoformat(),
                collection_window={
                    "start": time.time(),
                    "end": time.time() + duration_sec,
                    "duration_sec": duration_sec
                }
            )
            
            self.running = True
            self.logger.info(f"Collection started for {duration_sec} seconds")
            
            # Main collection loop
            start_time = time.time()
            while self.running and (time.time() - start_time) < duration_sec:
                # Process events from various sources
                self._process_events()
                time.sleep(1)
            
            self.running = False
            self.logger.info("Collection completed")
        
        except Exception as e:
            self.logger.error(f"Collection error: {e}")
            self.running = False

    def _process_events(self) -> None:
        """Process and correlate events through all detection layers"""
        try:
            # This would be called per event batch from the kernel
            # For now, we delegate to detection services
            
            # Threat detection would analyze incoming events
            # and correlation would combine results
            pass
        except Exception as e:
            self.logger.error(f"Event processing error: {e}")

    def export_telemetry(self, output_file: str = "/tmp/ebpf-telemetry.json") -> bool:
        """Export collected telemetry"""
        try:
            if not self.telemetry_collection:
                return False
            
            output_data = {
                "implant_id": self.telemetry_collection.implant_id,
                "exported_at": self.telemetry_collection.exported_at,
                "collection_window": self.telemetry_collection.collection_window,
                "events": self.telemetry_collection.events,
                "summary": self.telemetry_collection.summary,
            }
            
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            self.logger.info(f"Telemetry exported to {output_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Export error: {e}")
            return False

    def stop(self) -> None:
        """Stop collection and cleanup"""
        self.running = False
        
        if self.c2_client:
            self.c2_client.stop()
        
        if self.braincell_client:
            self.braincell_client.stop()
        
        self.logger.info("Implant stopped")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="eBPF Implant Agent")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--collect", type=int, default=60, help="Collection duration (seconds)")
    parser.add_argument("--export", default="/tmp/ebpf-telemetry.json", help="Export file path")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    try:
        # Initialize implant
        implant = EBPFImplantAgent(config_file=args.config, stealth_mode=args.stealth)
        
        # Start collection
        implant.start_collection(duration_sec=args.collect)
        
        # Export telemetry
        implant.export_telemetry(output_file=args.export)
        
        # Cleanup
        implant.stop()
        
        print(f"[+] Implant completed. Telemetry exported to {args.export}")
    
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
