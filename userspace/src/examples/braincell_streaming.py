#!/usr/bin/env python3
"""Example: BrainCell persistent memory streaming"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import ConfigManager, ImplantLogger
from integrations import BrainCellClient


def main():
    """Run BrainCell streaming example"""
    print("[*] BrainCell Integration Example")
    print("=" * 50)
    
    # Initialize
    config_manager = ConfigManager()
    logger = ImplantLogger(stealth_mode=False).get_logger()
    
    # Note: This example assumes BrainCell is running locally
    braincell_url = config_manager.settings.braincell_url or "http://localhost:9504"
    
    print(f"[+] BrainCell URL: {braincell_url}")
    print("[*] Initializing BrainCell client...")
    
    try:
        client = BrainCellClient(braincell_url)
        print("[+] BrainCell client initialized")
        
        # Simulate telemetry events
        print("\n[*] Queueing telemetry events...")
        events = [
            {
                "type": "network",
                "timestamp": time.time(),
                "ip": "192.168.1.100",
                "port": 443,
                "direction": "outbound",
                "protocol": "TCP",
            },
            {
                "type": "process",
                "timestamp": time.time() + 1,
                "pid": 1234,
                "comm": "curl",
                "argv": "curl https://example.com",
            },
            {
                "type": "file",
                "timestamp": time.time() + 2,
                "pid": 1234,
                "path": "/etc/passwd",
                "op_type": "open",
            },
        ]
        
        for event in events:
            client.queue_event(event)
            print(f"  [+] Queued {event['type']} event")
        
        # Start worker thread (would stream in background)
        print("\n[*] Starting BrainCell streaming worker...")
        client.start_worker()
        
        # Let it stream for a bit
        print("[*] Streaming events (5 seconds)...")
        time.sleep(5)
        
        # Stop worker
        print("[*] Stopping BrainCell worker...")
        client.stop_worker()
        
        print("\n[+] BrainCell streaming example completed")
        print(f"[+] Events queued: {len(events)}")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        print("[*] Note: BrainCell server may not be running. This is a demonstration.")


if __name__ == "__main__":
    main()
