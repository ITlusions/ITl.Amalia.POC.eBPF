#!/usr/bin/env python3
"""
eBPF Sensor Agent - Threat Detection Orchestrator

Orchestrates kernel-level event collection, threat detection, and external integrations.
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


class EBPFSensorAgent:
    """Threat detection sensor orchestrator"""

    def __init__(self, config_file: str = "config.json"):
        """
        Initialize sensor with configuration

        Args:
            config_file: Path to JSON configuration file
        """
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.settings
        self.logger = ImplantLogger().get_logger()

        # Initialize threat detection services
        self.ip_analyzer = IPAnalyzer() if self.config.enable_ip_analysis else None
        self.yara_detector = YARADetector() if self.config.enable_yara_detection else None
        self.sigma_detector = SigmaLiteDetector() if self.config.enable_sigma_detection else None
        self.threat_correlator = ThreatCorrelator()

        # Initialize external integrations
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

            self.stop()
        except Exception as e:
            self.logger.error(f"Collection error: {e}", exc_info=True)
            raise

    def _process_events(self) -> None:
        """Process and analyze collected events"""
        # Placeholder for event processing
        pass

    def export_telemetry(self, output_file: str = None) -> Dict[str, Any]:
        """Export collected telemetry to file and/or streaming"""
        if not self.telemetry_collection:
            self.logger.warning("No telemetry collection available")
            return {}

        # Prepare telemetry for export
        telemetry_dict = {
            "implant_id": self.telemetry_collection.implant_id,
            "exported_at": self.telemetry_collection.exported_at,
            "collection_window": self.telemetry_collection.collection_window,
            "events": {
                "process": [e.__dict__ for e in self.telemetry_collection.events.get("process", [])],
                "network": [e.__dict__ for e in self.telemetry_collection.events.get("network", [])],
                "file": [e.__dict__ for e in self.telemetry_collection.events.get("file", [])]
            },
            "summary": self.telemetry_collection.summary
        }

        # Export to file if specified
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(telemetry_dict, f, indent=2)
            self.logger.info(f"Telemetry exported to {output_file}")

        # Stream to integrations
        if self.braincell_client:
            try:
                self.braincell_client.stream_batch(self.telemetry_collection.events)
                self.logger.info("Telemetry streamed to BrainCell")
            except Exception as e:
                self.logger.error(f"BrainCell streaming failed: {e}")

        if self.amalia_exporter:
            try:
                self.amalia_exporter.send(telemetry_dict)
                self.logger.info("Telemetry exported to Amalia")
            except Exception as e:
                self.logger.error(f"Amalia export failed: {e}")

        return telemetry_dict

    def stop(self) -> None:
        """Stop collection and cleanup"""
        self.running = False
        self.logger.info("Sensor stopped")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="eBPF Threat Detection Sensor")
    parser.add_argument("--config", default="config.json", help="Configuration file")
    parser.add_argument("--collect", type=int, default=60, help="Collection duration (seconds)")
    parser.add_argument("--export", help="Export telemetry to file")

    args = parser.parse_args()

    # Create and run sensor
    sensor = EBPFSensorAgent(config_file=args.config)
    sensor.start_collection(duration_sec=args.collect)

    if args.export:
        sensor.export_telemetry(output_file=args.export)

    return 0


if __name__ == "__main__":
    sys.exit(main())
