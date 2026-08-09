#!/usr/bin/env python3
"""
eBPF Implant Agent - Userspace loader and telemetry collector

Loads compiled eBPF programs into the kernel and collects telemetry
from process execution, network connections, and file access events.

Integrates with Amalia red team analysis platform.

Configuration via config.json allows enabling/disabling specific event types.
"""

import sys
import json
import struct
import time
import subprocess
import argparse
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ConfigManager:
    """Manages configuration loading and defaults"""

    @staticmethod
    def load_config(config_file: str = "config.json") -> Dict[str, Any]:
        """Load configuration from JSON file"""
        config_path = Path(config_file)

        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Failed to load config: {e}")
                return ConfigManager.default_config()
        else:
            print(f"[*] Config file not found: {config_file}, using defaults")
            return ConfigManager.default_config()

    @staticmethod
    def default_config() -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "implant": {
                "id": "ebpf-sensor-poc-01",
                "sensor_type": "ebpf-kernel-level"
            },
            "collection": {
                "process_events": {"enabled": False},
                "network_events": {"enabled": True},
                "file_events": {"enabled": False}
            },
            "output": {
                "directory": "/tmp/ebpf-telemetry",
                "format": "json",
                "export_enabled": True
            },
            "amalia": {
                "enabled": False,
                "url": "http://localhost:8000/api/ingest",
                "timeout_seconds": 10
            },
            "debugging": {
                "verbose": False,
                "print_events": True
            }
        }

    @staticmethod
    def save_config(config: Dict[str, Any], config_file: str = "config.json"):
        """Save configuration to JSON file"""
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[+] Configuration saved to {config_file}")


class EBPFImplantAgent:
    """Main implant agent for eBPF telemetry collection"""

    def __init__(self, bpf_file: str, config_file: str = "config.json"):
        # Load configuration
        self.config = ConfigManager.load_config(config_file)

        # Setup paths
        self.bpf_file = Path(bpf_file)
        output_dir = self.config.get("output", {}).get("directory", "/tmp/ebpf-telemetry")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Get enabled event types
        self.collect_config = self.config.get("collection", {})
        self.enabled_types = {
            k: v.get("enabled", False)
            for k, v in self.collect_config.items()
            if isinstance(v, dict) and "enabled" in v
        }

        # Initialize state
        self.bpf = None
        self.start_time = time.time()

        self.events_collected = {
            "process": [],
            "network": [],
            "file": []
        }

        # Print configuration summary
        self._print_config_summary()

    def _print_config_summary(self):
        """Print current configuration summary"""
        print("\n[*] Configuration Summary:")
        print(f"    Implant ID: {self.config.get('implant', {}).get('id')}")
        print(f"    Events to collect:")
        for event_type, enabled in self.enabled_types.items():
            status = "✓ ENABLED" if enabled else "✗ disabled"
            print(f"      - {event_type}: {status}")
        print()

    def compile_bpf(self) -> bool:
        """Compile sensor.bpf.c using clang"""
        print("[*] Compiling eBPF program...")

        output_file = self.bpf_file.with_suffix(".o")

        try:
            cmd = [
                "clang", "-O2", "-target", "bpf",
                "-c", str(self.bpf_file),
                "-o", str(output_file)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"[!] Compilation failed: {result.stderr}")
                return False

            print(f"[+] Compiled to {output_file}")
            return True
        except FileNotFoundError:
            print("[!] clang not found. Install LLVM toolchain.")
            return False

    def load_bpf(self) -> bool:
        """Load compiled eBPF bytecode into kernel"""
        print("[*] Loading eBPF program into kernel...")

        if not HAS_BCC:
            print("[!] BCC not available. Install python3-bcc or pip install bcc")
            return False

        try:
            # Try to load pre-compiled object file
            obj_file = self.bpf_file.with_suffix(".o")
            if not obj_file.exists():
                print(f"[!] Compiled object not found: {obj_file}")
                return False

            # Read compiled bytecode
            with open(obj_file, "rb") as f:
                bytecode = f.read()

            # Load into kernel via BCC
            self.bpf = BPF(raw_cb=bytecode)

            print("[+] eBPF program loaded successfully")
            return True
        except Exception as e:
            print(f"[!] Failed to load eBPF: {e}")
            return False

    def parse_process_event(self, data: bytes) -> Dict[str, Any]:
        """Parse process_event struct from ringbuf data"""
        try:
            # struct process_event: u64, u32, u32, u32, u32, [16]char, [256]char, [512]char
            if len(data) < 32:
                return None

            timestamp, pid, ppid, uid, gid = struct.unpack("=QIIII", data[:20])
            comm = data[20:36].rstrip(b'\x00').decode('utf-8', errors='ignore')
            filename = data[36:292].rstrip(b'\x00').decode('utf-8', errors='ignore')
            argv = data[292:804].rstrip(b'\x00').decode('utf-8', errors='ignore')

            return {
                "type": "process",
                "timestamp": timestamp / 1e9,
                "timestamp_iso": datetime.fromtimestamp(timestamp / 1e9).isoformat(),
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "gid": gid,
                "comm": comm,
                "filename": filename,
                "argv": argv
            }
        except Exception as e:
            print(f"[!] Error parsing process event: {e}")
            return None

    def parse_network_event(self, data: bytes) -> Dict[str, Any]:
        """Parse network_event struct from ringbuf data"""
        try:
            # struct network_event
            if len(data) < 28:
                return None

            timestamp, pid, uid = struct.unpack("=QII", data[:12])
            comm = data[12:28].rstrip(b'\x00').decode('utf-8', errors='ignore')

            if len(data) < 40:
                return None

            protocol, sport, dport, saddr, daddr, direction = struct.unpack(
                "=BHHIIB", data[28:40]
            )

            return {
                "type": "network",
                "timestamp": timestamp / 1e9,
                "timestamp_iso": datetime.fromtimestamp(timestamp / 1e9).isoformat(),
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "protocol": "TCP" if protocol == 1 else "UDP",
                "sport": sport,
                "dport": dport,
                "saddr": self._ip_to_string(saddr),
                "daddr": self._ip_to_string(daddr),
                "direction": "inbound" if direction == 1 else "outbound"
            }
        except Exception as e:
            print(f"[!] Error parsing network event: {e}")
            return None

    def parse_file_event(self, data: bytes) -> Dict[str, Any]:
        """Parse file_event struct from ringbuf data"""
        try:
            if len(data) < 32:
                return None

            timestamp, pid, uid = struct.unpack("=QII", data[:12])
            comm = data[12:28].rstrip(b'\x00').decode('utf-8', errors='ignore')

            if len(data) < 296:
                return None

            path = data[28:284].rstrip(b'\x00').decode('utf-8', errors='ignore')
            flags, mode, op_type = struct.unpack("=IIB", data[284:293])

            op_names = {1: "open", 2: "close", 3: "read", 4: "write"}

            return {
                "type": "file",
                "timestamp": timestamp / 1e9,
                "timestamp_iso": datetime.fromtimestamp(timestamp / 1e9).isoformat(),
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "path": path,
                "flags": flags,
                "mode": mode,
                "op_type": op_names.get(op_type, "unknown")
            }
        except Exception as e:
            print(f"[!] Error parsing file event: {e}")
            return None

    @staticmethod
    def _ip_to_string(ip: int) -> str:
        """Convert 32-bit IP to dotted decimal notation"""
        return ".".join(str((ip >> (i*8)) & 0xFF) for i in range(4))

    def start_collection(self, duration: int = 60) -> bool:
        """Poll ringbufs and collect events based on configuration"""
        if not self.bpf:
            print("[!] eBPF program not loaded")
            return False

        # Check if any event types are enabled
        if not any(self.enabled_types.values()):
            print("[!] No event types enabled in configuration")
            return False

        print(f"[*] Collecting events for {duration} seconds...")
        print(f"[*] Enabled collectors: {', '.join(k for k, v in self.enabled_types.items() if v)}\n")

        def process_callback(cpu, data, size):
            if not self.enabled_types.get("process_events", False):
                return
            event = self.parse_process_event(data)
            if event:
                self.events_collected["process"].append(event)
                if self.config.get("debugging", {}).get("print_events", True):
                    print(f"[+] PROCESS: {event['comm']}({event['pid']}) → {event['filename']}")

        def network_callback(cpu, data, size):
            if not self.enabled_types.get("network_events", False):
                return
            event = self.parse_network_event(data)
            if event:
                self.events_collected["network"].append(event)
                if self.config.get("debugging", {}).get("print_events", True):
                    print(f"[+] NETWORK: {event['comm']}({event['pid']}) → {event['daddr']}:{event['dport']}")

        def file_callback(cpu, data, size):
            if not self.enabled_types.get("file_events", False):
                return
            event = self.parse_file_event(data)
            if event:
                self.events_collected["file"].append(event)
                if self.config.get("debugging", {}).get("print_events", True):
                    if event['op_type'] in ['open', 'read', 'write']:
                        print(f"[+] FILE: {event['comm']} {event['op_type']} {event['path']}")

        try:
            # Attach only enabled ringbuffer readers
            if self.enabled_types.get("process_events", False):
                self.bpf["process_events"].open_ring_buffer(process_callback)

            if self.enabled_types.get("network_events", False):
                self.bpf["network_events"].open_ring_buffer(network_callback)

            if self.enabled_types.get("file_events", False):
                self.bpf["file_events"].open_ring_buffer(file_callback)

            # Poll for duration
            start = time.time()
            while time.time() - start < duration:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    break

            print(f"\n[+] Collection complete")
            return True
        except Exception as e:
            print(f"[!] Collection error: {e}")
            return False

    def export_telemetry(self, format: str = "json", filename: Optional[str] = None) -> str:
        """Export collected events as JSON (only enabled types)"""
        print("[*] Exporting telemetry...")

        # Only include enabled event types
        events = {}
        for event_type, enabled in self.enabled_types.items():
            if enabled:
                key = event_type.replace("_events", "")
                events[key] = self.events_collected[key]

        telemetry = {
            "implant_id": self.config.get("implant", {}).get("id", "ebpf-sensor-poc-01"),
            "sensor_type": self.config.get("implant", {}).get("sensor_type", "ebpf-kernel-level"),
            "exported_at": datetime.now().isoformat(),
            "collection_window": {
                "start": self.start_time,
                "end": time.time(),
                "duration_sec": time.time() - self.start_time
            },
            "events": events,
            "summary": {
                "total_events": sum(len(v) for v in events.values())
            }
        }

        # Add individual counts for enabled types
        for event_type, enabled in self.enabled_types.items():
            if enabled:
                key = event_type.replace("_events", "")
                telemetry["summary"][f"{key}_events"] = len(events.get(key, []))

        if not filename:
            filename = f"telemetry-{int(time.time())}.json"

        output_file = self.output_dir / filename

        with open(output_file, 'w') as f:
            json.dump(telemetry, f, indent=2)

        print(f"[+] Telemetry exported to {output_file}")
        print(f"[+] Summary: {telemetry['summary']}")
        return str(output_file)

    def export_to_amalia(self, amalia_url: Optional[str] = None,
                         token: Optional[str] = None) -> bool:
        """Export telemetry to Amalia for analysis"""
        if not HAS_REQUESTS:
            print("[!] requests library not available. Install: pip install requests")
            return False

        # Use config values if not overridden
        amalia_config = self.config.get("amalia", {})
        if not amalia_config.get("enabled", False):
            print("[!] Amalia export disabled in configuration")
            return False

        if not amalia_url:
            amalia_url = amalia_config.get("url", "http://localhost:8000/api/ingest")

        if not token:
            token = amalia_config.get("token")

        print(f"[*] Sending telemetry to Amalia ({amalia_url})...")

        # Only include enabled event types
        events = {}
        for event_type, enabled in self.enabled_types.items():
            if enabled:
                key = event_type.replace("_events", "")
                events[key] = self.events_collected[key]

        telemetry = {
            "implant_id": self.config.get("implant", {}).get("id", "ebpf-sensor-poc-01"),
            "sensor_type": self.config.get("implant", {}).get("sensor_type", "ebpf-kernel-level"),
            "collection_window": {
                "start": self.start_time,
                "end": time.time(),
                "duration_sec": time.time() - self.start_time
            },
            "events": events,
            "summary": {
                "total_events": sum(len(v) for v in events.values())
            }
        }

        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            timeout = amalia_config.get("timeout_seconds", 10)
            resp = requests.post(
                amalia_url,
                json=telemetry,
                headers=headers,
                timeout=timeout
            )

            if resp.status_code == 200:
                print(f"[+] Sent {telemetry['summary']['total_events']} events to Amalia")
                return True
            else:
                print(f"[!] Amalia responded with status {resp.status_code}")
                return False
        except Exception as e:
            print(f"[!] Failed to reach Amalia: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Implant Agent - Kernel-level telemetry collection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show current configuration
  python3 implant_agent.py --config-show

  # Enable only network collection
  python3 implant_agent.py --config-set collection.network_events.enabled true
  python3 implant_agent.py --config-set collection.process_events.enabled false

  # Collect and export (with current config)
  sudo python3 implant_agent.py --load --collect 60 --export

  # Use custom config file
  sudo python3 implant_agent.py --config myconfig.json --load --collect 60
        """
    )

    # Configuration options
    parser.add_argument("--config", default="config.json",
                        help="Configuration file (default: config.json)")
    parser.add_argument("--config-show", action="store_true",
                        help="Show current configuration and exit")
    parser.add_argument("--config-set", nargs=2, metavar=("KEY", "VALUE"),
                        help="Set config value (e.g., collection.network_events.enabled true)")

    # Execution options
    parser.add_argument("--bpf", default="/opt/ebpf-implant/sensor.bpf.c",
                        help="Path to eBPF source file")
    parser.add_argument("--compile", action="store_true",
                        help="Compile eBPF program")
    parser.add_argument("--load", action="store_true",
                        help="Load eBPF program into kernel")
    parser.add_argument("--collect", type=int, default=0,
                        help="Collect events for N seconds")
    parser.add_argument("--export", action="store_true",
                        help="Export telemetry to JSON file")
    parser.add_argument("--amalia", action="store_true",
                        help="Export telemetry to Amalia")

    args = parser.parse_args()

    # Handle config show
    if args.config_show:
        config = ConfigManager.load_config(args.config)
        print("\n[*] Current Configuration:")
        print(json.dumps(config, indent=2))
        sys.exit(0)

    # Handle config set
    if args.config_set:
        key_path, value = args.config_set
        config = ConfigManager.load_config(args.config)

        # Parse nested keys (e.g., "collection.network_events.enabled")
        keys = key_path.split(".")
        target = config
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]

        # Convert value to appropriate type
        if value.lower() in ("true", "false"):
            target[keys[-1]] = value.lower() == "true"
        elif value.isdigit():
            target[keys[-1]] = int(value)
        else:
            target[keys[-1]] = value

        ConfigManager.save_config(config, args.config)
        sys.exit(0)

    # Check if running as root (required for loading eBPF)
    if (args.load or args.compile) and os.geteuid() != 0:
        print("[!] This tool requires root privileges for --load or --compile")
        sys.exit(1)

    # Create agent with config
    agent = EBPFImplantAgent(args.bpf, args.config)

    if args.compile:
        if not agent.compile_bpf():
            sys.exit(1)

    if args.load:
        if not agent.load_bpf():
            sys.exit(1)

    if args.collect > 0:
        if not agent.start_collection(args.collect):
            sys.exit(1)

    if args.export:
        agent.export_telemetry()

    if args.amalia:
        if not agent.export_to_amalia():
            sys.exit(1)

    if not any([args.compile, args.load, args.collect, args.export, args.amalia]):
        print("[*] No action specified. Use --help for options")

    print("[+] Done")


if __name__ == "__main__":
    main()
