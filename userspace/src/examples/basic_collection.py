#!/usr/bin/env python3
"""Example: Basic event collection only"""

import sys
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import ConfigManager, ImplantLogger
from collection import TelemetryCollection


def main():
    """Run basic collection example"""
    print("[*] Basic Collection Example")
    print("=" * 50)
    
    # Initialize configuration
    config_manager = ConfigManager()
    logger = ImplantLogger(stealth_mode=False).get_logger()
    
    print(f"[+] Implant ID: {config_manager.settings.implant_id}")
    print(f"[+] Collection interval: {config_manager.settings.collection_interval}s")
    
    # Create telemetry container
    telemetry = TelemetryCollection(
        implant_id=config_manager.settings.implant_id,
        exported_at="2026-10-01T12:00:00Z",
        collection_window={
            "start": time.time(),
            "end": time.time() + 30,
            "duration_sec": 30
        }
    )
    
    # Simulate collecting events
    print("\n[*] Simulating event collection...")
    for i in range(10):
        process_event = {
            "type": "process",
            "timestamp": time.time(),
            "pid": 1000 + i,
            "comm": f"example_process_{i}",
            "event_id": i
        }
        telemetry.events["process"].append(process_event)
        print(f"  [+] Collected process event {i}")
        time.sleep(0.5)
    
    # Update summary
    telemetry.summary = {
        "process_events": len(telemetry.events["process"]),
        "network_events": len(telemetry.events["network"]),
        "file_events": len(telemetry.events["file"]),
        "total_events": sum(len(v) for v in telemetry.events.values()),
    }
    
    # Export telemetry
    import json
    output_file = "/tmp/basic_collection_example.json"
    with open(output_file, 'w') as f:
        json.dump({
            "implant_id": telemetry.implant_id,
            "exported_at": telemetry.exported_at,
            "collection_window": telemetry.collection_window,
            "events": telemetry.events,
            "summary": telemetry.summary,
        }, f, indent=2)
    
    print(f"\n[+] Telemetry exported to {output_file}")
    print(f"[+] Total events collected: {telemetry.summary['total_events']}")


if __name__ == "__main__":
    main()
