#!/usr/bin/env python3
"""
eBPF Implant Agent - Userspace loader and telemetry collector

Loads compiled eBPF programs into the kernel and collects telemetry
from process execution, network connections, and file access events.

Integrates with Amalia red team analysis platform.
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


class EBPFImplantAgent:
    """Main implant agent for eBPF telemetry collection"""

    def __init__(self, bpf_file: str, output_dir: str = "/tmp/ebpf-telemetry"):
        self.bpf_file = Path(bpf_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.bpf = None
        self.start_time = time.time()

        self.events_collected = {
            "process": [],
            "network": [],
            "file": []
        }

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
        """Poll ringbufs and collect events"""
        if not self.bpf:
            print("[!] eBPF program not loaded")
            return False

        print(f"[*] Collecting events for {duration} seconds...")

        def process_callback(cpu, data, size):
            event = self.parse_process_event(data)
            if event:
                self.events_collected["process"].append(event)
                print(f"[+] PROCESS: {event['comm']}({event['pid']}) → {event['filename']}")

        def network_callback(cpu, data, size):
            event = self.parse_network_event(data)
            if event:
                self.events_collected["network"].append(event)
                print(f"[+] NETWORK: {event['comm']} → {event['daddr']}:{event['dport']}")

        def file_callback(cpu, data, size):
            event = self.parse_file_event(data)
            if event:
                self.events_collected["file"].append(event)
                if event['op_type'] in ['open', 'read', 'write']:
                    print(f"[+] FILE: {event['comm']} {event['op_type']} {event['path']}")

        try:
            # Attach ringbuffer readers
            self.bpf["process_events"].open_ring_buffer(process_callback)
            self.bpf["network_events"].open_ring_buffer(network_callback)
            self.bpf["file_events"].open_ring_buffer(file_callback)

            # Poll for duration
            start = time.time()
            while time.time() - start < duration:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    break

            print(f"[+] Collection complete")
            return True
        except Exception as e:
            print(f"[!] Collection error: {e}")
            return False

    def export_telemetry(self, format: str = "json", filename: Optional[str] = None) -> str:
        """Export collected events as JSON"""
        print("[*] Exporting telemetry...")

        telemetry = {
            "implant_id": "ebpf-sensor-poc-01",
            "sensor_type": "ebpf-kernel-level",
            "exported_at": datetime.now().isoformat(),
            "collection_window": {
                "start": self.start_time,
                "end": time.time(),
                "duration_sec": time.time() - self.start_time
            },
            "events": self.events_collected,
            "summary": {
                "process_events": len(self.events_collected["process"]),
                "network_events": len(self.events_collected["network"]),
                "file_events": len(self.events_collected["file"]),
                "total_events": sum(len(v) for v in self.events_collected.values())
            }
        }

        if not filename:
            filename = f"telemetry-{int(time.time())}.json"

        output_file = self.output_dir / filename

        with open(output_file, 'w') as f:
            json.dump(telemetry, f, indent=2)

        print(f"[+] Telemetry exported to {output_file}")
        return str(output_file)

    def export_to_amalia(self, amalia_url: str = "http://localhost:8000/api/ingest",
                         token: Optional[str] = None) -> bool:
        """Export telemetry to Amalia for analysis"""
        if not HAS_REQUESTS:
            print("[!] requests library not available. Install: pip install requests")
            return False

        print("[*] Sending telemetry to Amalia...")

        telemetry = {
            "implant_id": "ebpf-sensor-poc-01",
            "sensor_type": "ebpf-kernel-level",
            "collection_window": {
                "start": self.start_time,
                "end": time.time(),
                "duration_sec": time.time() - self.start_time
            },
            "events": self.events_collected,
            "summary": {
                "process_events": len(self.events_collected["process"]),
                "network_events": len(self.events_collected["network"]),
                "file_events": len(self.events_collected["file"]),
                "total_events": sum(len(v) for v in self.events_collected.values())
            }
        }

        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            resp = requests.post(
                amalia_url,
                json=telemetry,
                headers=headers,
                timeout=10
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
    parser = argparse.ArgumentParser(description="eBPF Implant Agent")
    parser.add_argument("--bpf", default="/opt/ebpf-implant/sensor.bpf.c",
                        help="Path to eBPF source file")
    parser.add_argument("--output", default="/tmp/ebpf-telemetry",
                        help="Output directory for telemetry")
    parser.add_argument("--compile", action="store_true",
                        help="Compile eBPF program")
    parser.add_argument("--load", action="store_true",
                        help="Load eBPF program into kernel")
    parser.add_argument("--collect", type=int, default=60,
                        help="Collect events for N seconds")
    parser.add_argument("--export", action="store_true",
                        help="Export telemetry to JSON file")
    parser.add_argument("--amalia", action="store_true",
                        help="Export telemetry to Amalia")
    parser.add_argument("--amalia-url", default="http://localhost:8000/api/ingest",
                        help="Amalia API endpoint")
    parser.add_argument("--amalia-token", help="Amalia API token")

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges")
        sys.exit(1)

    agent = EBPFImplantAgent(args.bpf, args.output)

    if args.compile:
        if not agent.compile_bpf():
            sys.exit(1)

    if args.load:
        if not agent.load_bpf():
            sys.exit(1)

    if args.collect:
        if not agent.start_collection(args.collect):
            sys.exit(1)

    if args.export:
        agent.export_telemetry()

    if args.amalia:
        agent.export_to_amalia(args.amalia_url, args.amalia_token)

    print("[+] Done")


if __name__ == "__main__":
    main()
