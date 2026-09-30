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
import asyncio
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from queue import Queue

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

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from ip_analysis import IPAnalyzer, IPThreatIntelligence
    HAS_IP_ANALYSIS = True
except ImportError:
    HAS_IP_ANALYSIS = False

try:
    from yara_detection import YARADetector
    HAS_YARA_DETECTION = True
except ImportError:
    HAS_YARA_DETECTION = False


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
            "network": {
                "capture_ipv4": True,
                "capture_ipv6": True,
                "capture_tcp": True,
                "capture_udp": True,
                "capture_dns": True,
                "capture_payload": True,
                "max_payload_size": 96,
                "track_connection_close": True,
                "track_tcp_metrics": True
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
            "braincell": {
                "enabled": False,
                "url": "http://localhost:8000",
                "api_token": "",
                "batch_size": 50,
                "flush_interval_sec": 10,
                "max_retries": 3
            },
            "ip_analysis": {
                "enabled": False,
                "track_ips": True,
                "threat_scoring": True,
                "min_threat_score_report": 20.0,
                "export_summary": True,
                "export_top_ips": 10
            },
            "yara_analysis": {
                "enabled": False,
                "scan_profiles": True,
                "export_matches": True,
                "min_confidence": 0.5,
                "threat_categories": ["c2_beacon", "dns_tunneling", "data_exfiltration", "lateral_movement", "credential_access", "persistence"]
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


class BrainCellClient:
    """BrainCell persistent memory ingestion client"""

    def __init__(self, config: Dict[str, Any]):
        """Initialize BrainCell client with configuration"""
        if not HAS_HTTPX:
            print("[!] httpx not available. Install: pip install httpx")
            self.enabled = False
            return

        self.enabled = True
        self.url = config.get("url", "http://localhost:8000")
        self.token = config.get("api_token", "")
        self.batch_size = config.get("batch_size", 50)
        self.flush_interval = config.get("flush_interval_sec", 10)
        self.max_retries = config.get("max_retries", 3)

        self.event_queue = Queue()
        self.session = None
        self.worker_thread = None
        self.running = False

        print(f"[*] BrainCell client configured: {self.url}")

    def start(self):
        """Start background batch worker thread"""
        if not self.enabled:
            return

        self.running = True
        self.worker_thread = threading.Thread(
            target=self._batch_worker,
            daemon=True
        )
        self.worker_thread.start()
        print("[+] BrainCell batch worker started")

    def stop(self):
        """Stop background worker and flush remaining events"""
        if not self.enabled:
            return

        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        print("[+] BrainCell worker stopped")

    def queue_event(self, event: Dict[str, Any]):
        """Queue network event for batch ingestion"""
        if not self.enabled:
            return

        # Strip payload data, keep only metadata
        metadata_event = self._extract_metadata(event)
        self.event_queue.put(metadata_event)

    def _extract_metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract essential metadata from network event (no payloads)"""
        return {
            "timestamp": event.get("timestamp"),
            "timestamp_iso": event.get("timestamp_iso"),
            "pid": event.get("pid"),
            "uid": event.get("uid"),
            "comm": event.get("comm"),
            "protocol": event.get("protocol"),
            "family": event.get("family"),
            "sport": event.get("sport"),
            "dport": event.get("dport"),
            "saddr": event.get("saddr"),
            "daddr": event.get("daddr"),
            "direction": event.get("direction"),
            "tcp_state": event.get("tcp_state"),
            "bytes_sent": event.get("bytes_sent"),
            "bytes_received": event.get("bytes_received"),
            "retransmits": event.get("retransmits"),
            "is_dns": event.get("is_dns", False)
        }

    def _event_to_note(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert network event metadata to BrainCell note"""
        title = (f"{event['protocol']} {event['direction'].upper()}: "
                f"{event['comm']}({event['pid']}) → "
                f"{event['daddr']}:{event['dport']}")

        # Format content as markdown
        content = self._format_event_content(event)

        # Extract threat-hunting tags
        tags = self._extract_tags(event)

        return {
            "title": title,
            "content": content,
            "tags": tags,
            "source": "ebpf-implant",
            "meta_data": event
        }

    def _format_event_content(self, event: Dict[str, Any]) -> str:
        """Format event as readable markdown"""
        lines = [
            f"**Process**: {event['comm']} (PID: {event['pid']}, UID: {event['uid']})",
            f"**Direction**: {event['direction'].upper()}",
            f"**Protocol**: {event['protocol']}/{event['family']}",
            f"**Source**: {event['saddr']}:{event['sport']}",
            f"**Destination**: {event['daddr']}:{event['dport']}",
            f"**Timestamp**: {event.get('timestamp_iso', 'N/A')}"
        ]

        if event.get('tcp_state'):
            lines.append(f"**TCP State**: {event['tcp_state']}")

        if event.get('bytes_sent') is not None:
            lines.append(f"**Bytes Sent**: {event['bytes_sent']}")
        if event.get('bytes_received') is not None:
            lines.append(f"**Bytes Received**: {event['bytes_received']}")

        if event.get('retransmits'):
            lines.append(f"**Retransmits**: {event['retransmits']}")

        if event.get('is_dns'):
            lines.append(f"**Type**: 🔍 DNS Query")

        return "\n".join(lines)

    def _extract_tags(self, event: Dict[str, Any]) -> List[str]:
        """Extract searchable tags for threat hunting"""
        tags = [
            "network",
            event['protocol'].lower(),
            event['direction'],
            event['family'],
            f"port-{event['dport']}"
        ]

        if event.get('is_dns'):
            tags.append("dns")

        # Threat hunting tags
        if event['dport'] in [22, 3389, 5900, 21]:
            tags.append("remote-access")
        if event['dport'] in [445, 139, 135]:
            tags.append("smb")
        if event['dport'] in [4444, 5555, 6666, 7777, 8888, 9999]:
            tags.append("suspicious-port")
        if event['dport'] == 53 or event.get('is_dns'):
            tags.append("dns-query")
        if event['direction'] == 'outbound' and event['dport'] not in [80, 443, 53]:
            tags.append("unusual-egress")

        return tags

    def _batch_worker(self):
        """Background worker: batch and send events to BrainCell"""
        batch = []
        last_flush = time.time()
        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })

        print("[*] BrainCell batch worker initialized")

        while self.running:
            try:
                # Try to get event with timeout
                event = self.event_queue.get(timeout=self.flush_interval)
                batch.append(event)

                # Flush if batch is full
                if len(batch) >= self.batch_size:
                    self._flush_batch(session, batch)
                    batch = []
                    last_flush = time.time()

            except Exception:
                # Timeout or other error - check if we should flush by time
                elapsed = time.time() - last_flush
                if elapsed >= self.flush_interval and batch:
                    self._flush_batch(session, batch)
                    batch = []
                    last_flush = time.time()

        # Final flush on shutdown
        if batch:
            self._flush_batch(session, batch)

    def _flush_batch(self, session: requests.Session, events: List[Dict]):
        """Send batch of events to BrainCell"""
        if not events:
            return

        # Convert events to BrainCell notes
        notes = [self._event_to_note(e) for e in events]

        payload = {"items": notes}

        retry_count = 0
        while retry_count < self.max_retries:
            try:
                resp = session.post(
                    f"{self.url}/api/notes",
                    json=payload,
                    timeout=30
                )

                if resp.status_code == 200 or resp.status_code == 201:
                    print(f"[+] Ingested {len(notes)} network events to BrainCell")
                    return True
                else:
                    print(f"[!] BrainCell returned {resp.status_code}: {resp.text[:100]}")
                    retry_count += 1
                    time.sleep(2 ** retry_count)  # Exponential backoff

            except Exception as e:
                print(f"[!] BrainCell ingestion error (attempt {retry_count + 1}): {e}")
                retry_count += 1
                time.sleep(2 ** retry_count)

        print(f"[!] Failed to ingest {len(notes)} events after {self.max_retries} retries")


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

        # Initialize BrainCell client if enabled
        self.braincell = None
        if self.config.get("braincell", {}).get("enabled"):
            self.braincell = BrainCellClient(self.config.get("braincell", {}))

        # Initialize IP analysis if enabled
        self.ip_analyzer = None
        if self.config.get("ip_analysis", {}).get("enabled") and HAS_IP_ANALYSIS:
            self.ip_analyzer = IPAnalyzer()
            print("[+] IP analysis enabled")
        elif self.config.get("ip_analysis", {}).get("enabled"):
            print("[!] IP analysis module not available. Install: pip install ip_analysis")

        # Initialize YARA detection if enabled
        self.yara_detector = None
        if self.config.get("yara_analysis", {}).get("enabled") and HAS_YARA_DETECTION:
            self.yara_detector = YARADetector()
            print("[+] YARA signature detection enabled")
        elif self.config.get("yara_analysis", {}).get("enabled"):
            print("[!] YARA detection module not available. Install: pip install yara-detection")

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
        """Parse expanded network_event struct from ringbuf data"""
        try:
            # Updated struct network_event with IPv6 and additional fields
            # timestamp(8) + pid(4) + uid(4) + comm(16) = 32
            if len(data) < 32:
                return None

            timestamp, pid, uid = struct.unpack("=QII", data[:12])
            comm = data[12:28].rstrip(b'\x00').decode('utf-8', errors='ignore')

            # protocol(1) + family(1) + sport(2) + dport(2) + saddr(4) + daddr(4) = 14
            # saddr6(16) + daddr6(16) + direction(1) + bytes_sent(4) + bytes_recv(4) = 41
            # tcp_state(1) + retransmits(1) + payload_size(4) + payload(96) + is_dns(1) = 103
            # Total after first 28: 14 + 41 + 103 = 158, so min total = 186

            if len(data) < 186:
                return None

            offset = 28
            protocol, family = struct.unpack("=BB", data[offset:offset+2])
            offset += 2
            sport, dport = struct.unpack("=HH", data[offset:offset+4])
            offset += 4
            saddr, daddr = struct.unpack("=II", data[offset:offset+8])
            offset += 8
            saddr6 = data[offset:offset+16]
            offset += 16
            daddr6 = data[offset:offset+16]
            offset += 16
            direction, bytes_sent, bytes_recv = struct.unpack("=BII", data[offset:offset+9])
            offset += 9
            tcp_state, retransmits = struct.unpack("=BB", data[offset:offset+2])
            offset += 2
            payload_size = struct.unpack("=I", data[offset:offset+4])[0]
            offset += 4
            payload = data[offset:offset+96]
            offset += 96
            is_dns = struct.unpack("=B", data[offset:offset+1])[0]

            # Format addresses based on family
            if family == 2:  # AF_INET
                src_addr = self._ip_to_string(saddr)
                dst_addr = self._ip_to_string(daddr)
                addr_type = "IPv4"
            elif family == 10:  # AF_INET6
                src_addr = self._ipv6_to_string(saddr6)
                dst_addr = self._ipv6_to_string(daddr6)
                addr_type = "IPv6"
            else:
                src_addr = "unknown"
                dst_addr = "unknown"
                addr_type = "unknown"

            # Map protocol values
            protocol_name = {1: "TCP", 2: "UDP"}.get(protocol, f"unknown({protocol})")

            # Map direction values
            if direction == 1:
                direction_str = "inbound"
            elif direction == 2:
                direction_str = "outbound"
            elif direction == 3:
                direction_str = "close"
            else:
                direction_str = f"unknown({direction})"

            # TCP state names
            tcp_states = {
                1: "ESTABLISHED",
                2: "SYN_SENT",
                3: "SYN_RECV",
                4: "FIN_WAIT1",
                5: "FIN_WAIT2",
                6: "TIME_WAIT",
                7: "CLOSE",
                8: "CLOSE_WAIT",
                9: "LAST_ACK",
                10: "LISTEN",
                11: "CLOSING"
            }

            event = {
                "type": "network",
                "timestamp": timestamp / 1e9,
                "timestamp_iso": datetime.fromtimestamp(timestamp / 1e9).isoformat(),
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "protocol": protocol_name,
                "family": addr_type,
                "sport": sport,
                "dport": dport,
                "saddr": src_addr,
                "daddr": dst_addr,
                "direction": direction_str,
                "tcp_state": tcp_states.get(tcp_state, f"unknown({tcp_state})") if protocol == 1 else None,
                "bytes_sent": bytes_sent if protocol == 1 else None,
                "bytes_received": bytes_recv if protocol == 1 else None,
                "retransmits": retransmits if protocol == 1 else None,
                "is_dns": bool(is_dns),
                "payload_size": payload_size,
                "payload_preview": payload[:min(payload_size, 96)].rstrip(b'\x00').decode('utf-8', errors='ignore') if payload_size > 0 else None
            }

            return event
        except Exception as e:
            print(f"[!] Error parsing network event: {e}")
            import traceback
            traceback.print_exc()
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

    @staticmethod
    def _ipv6_to_string(ip6: bytes) -> str:
        """Convert 16-byte IPv6 address to colon-separated notation"""
        if len(ip6) != 16:
            return "invalid"
        # Convert bytes to 8 16-bit groups
        groups = []
        for i in range(0, 16, 2):
            val = (ip6[i] << 8) | ip6[i + 1]
            groups.append(f"{val:x}")
        # Join with colons (simplified - doesn't compress ::)
        return ":".join(groups)

    def start_collection(self, duration: int = 60) -> bool:
        """Poll ringbufs and collect events based on configuration"""
        if not self.bpf:
            print("[!] eBPF program not loaded")
            return False

        # Check if any event types are enabled
        if not any(self.enabled_types.values()):
            print("[!] No event types enabled in configuration")
            return False

        # Start BrainCell ingestion if enabled
        if self.braincell:
            self.braincell.start()

        print(f"[*] Collecting events for {duration} seconds...")
        print(f"[*] Enabled collectors: {', '.join(k for k, v in self.enabled_types.items() if v)}")
        if self.braincell and self.braincell.enabled:
            print(f"[*] BrainCell ingestion: {self.braincell.url}\n")
        else:
            print()

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

                # Process through IP analyzer if enabled
                if self.ip_analyzer:
                    self.ip_analyzer.process_event(event)

                # Queue to BrainCell if enabled
                if self.braincell:
                    self.braincell.queue_event(event)

                if self.config.get("debugging", {}).get("print_events", True):
                    dns_marker = " [DNS]" if event.get('is_dns') else ""
                    proto = event.get('protocol', 'unknown')
                    family = event.get('family', 'IPv4')
                    direction = event.get('direction', 'unknown')
                    state = f" ({event['tcp_state']})" if event.get('tcp_state') else ""
                    print(f"[+] NET: {event['comm']}({event['pid']}) {proto}/{family} {direction} {event['saddr']}:{event['sport']}→{event['daddr']}:{event['dport']}{state}{dns_marker}")

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

            # Stop BrainCell ingestion and flush remaining events
            if self.braincell:
                self.braincell.stop()
                time.sleep(1)  # Give worker thread time to flush

            return True
        except Exception as e:
            print(f"[!] Collection error: {e}")
            # Ensure BrainCell worker is stopped
            if self.braincell:
                self.braincell.stop()
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

        # Export IP analysis if enabled
        if self.ip_analyzer:
            self.export_ip_analysis()

        # Export YARA analysis if enabled
        if self.yara_detector and self.ip_analyzer:
            self.export_yara_analysis()

        return str(output_file)

    def export_ip_analysis(self, filename: Optional[str] = None) -> str:
        """Export IP analysis results as JSON and human-readable report"""
        if not self.ip_analyzer:
            print("[!] IP analysis not enabled")
            return None

        print("[*] Exporting IP analysis...")

        # Export JSON analysis
        analysis_json = self.ip_analyzer.export_json()

        if not filename:
            filename = f"ip-analysis-{int(time.time())}.json"

        output_file = self.output_dir / filename

        with open(output_file, 'w') as f:
            json.dump(analysis_json, f, indent=2)

        print(f"[+] IP analysis exported to {output_file}")

        # Export human-readable report
        report = self.ip_analyzer.get_summary_report()
        report_file = self.output_dir / f"ip-analysis-report-{int(time.time())}.txt"

        with open(report_file, 'w') as f:
            f.write(report)

        print(f"[+] IP analysis report exported to {report_file}")

        # Print summary to console
        print(report)

        return str(output_file)

    def export_yara_analysis(self, filename: Optional[str] = None) -> str:
        """Export YARA detection results as JSON and human-readable report"""
        if not self.yara_detector or not self.ip_analyzer:
            print("[!] YARA or IP analysis not enabled")
            return None

        print("[*] Scanning IP profiles with YARA rules...")

        # Scan all IP profiles with YARA rules
        for ip, profile in self.ip_analyzer.ip_profiles.items():
            matches = self.yara_detector.scan_profile(ip, profile)
            if matches:
                print(f"[+] Found {len(matches)} YARA matches for {ip}")

        # Export YARA matches as JSON
        if not filename:
            filename = f"yara-matches-{int(time.time())}.json"

        output_file = self.output_dir / filename

        yara_export = {
            "timestamp": datetime.now().isoformat(),
            "total_matches": len(self.yara_detector.matches),
            "matches_by_severity": self.yara_detector.get_summary(),
            "matches": self.yara_detector.export_matches()
        }

        with open(output_file, 'w') as f:
            json.dump(yara_export, f, indent=2)

        print(f"[+] YARA matches exported to {output_file}")

        # Generate human-readable report
        report_file = self.output_dir / f"yara-report-{int(time.time())}.txt"
        report_lines = self._generate_yara_report()

        with open(report_file, 'w') as f:
            f.write("\n".join(report_lines))

        print(f"[+] YARA report exported to {report_file}")

        # Print summary
        if report_lines:
            print("\n" + "\n".join(report_lines[:50]))
            if len(report_lines) > 50:
                print(f"... ({len(report_lines) - 50} more lines)")

        return str(output_file)

    def _generate_yara_report(self) -> List[str]:
        """Generate human-readable YARA analysis report"""
        lines = [
            "=" * 80,
            "YARA SIGNATURE-BASED THREAT DETECTION REPORT",
            "=" * 80,
            "",
            f"Generated: {datetime.now().isoformat()}",
            ""
        ]

        summary = self.yara_detector.get_summary()
        lines.extend([
            "SUMMARY",
            "-" * 80,
            f"Total Matches: {summary['total_matches']}",
            f"Critical: {summary['critical']}",
            f"High: {summary['high']}",
            f"Medium: {summary['medium']}",
            f"Low: {summary['low']}",
            f"Unique IPs Matched: {summary['unique_ips_matched']}",
            ""
        ])

        # Group matches by severity
        for severity in ["critical", "high", "medium", "low"]:
            matches = self.yara_detector.get_matches_by_severity(severity)
            if not matches:
                continue

            lines.extend([
                f"{severity.upper()} SEVERITY MATCHES ({len(matches)})",
                "-" * 80
            ])

            for match in matches:
                lines.extend([
                    f"IP: {match.ip}",
                    f"  Rule: {match.rule_name} ({match.rule_category})",
                    f"  Pattern: {match.pattern}",
                    f"  Description: {match.description}",
                    f"  Confidence: {match.confidence:.1%}",
                    f"  Metadata: {match.metadata}",
                    ""
                ])

        return lines

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
    parser.add_argument("--braincell", action="store_true",
                        help="Ingest network telemetry to BrainCell")
    parser.add_argument("--ip-analysis", action="store_true",
                        help="Enable IP-level analysis and threat scoring")
    parser.add_argument("--yara-rules", action="store_true",
                        help="Enable YARA signature-based threat detection")

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

    # Load config and enable BrainCell if requested
    config = ConfigManager.load_config(args.config)
    if args.braincell:
        if not config.get("braincell", {}).get("api_token"):
            print("[!] BrainCell API token not configured")
            print("[*] Set it with: --config-set braincell.api_token YOUR_TOKEN")
            sys.exit(1)
        config["braincell"]["enabled"] = True

    # Enable IP analysis if requested
    if args.ip_analysis:
        if not HAS_IP_ANALYSIS:
            print("[!] IP analysis module not available")
            print("[*] Install with: pip install -e /path/to/ip_analysis/module")
            sys.exit(1)
        config["ip_analysis"]["enabled"] = True

    # Enable YARA detection if requested
    if args.yara_rules:
        if not HAS_YARA_DETECTION:
            print("[!] YARA detection module not available")
            print("[*] Install with: pip install -e /path/to/yara_detection/module")
            sys.exit(1)
        config["yara_analysis"]["enabled"] = True
        # YARA detection requires IP analysis
        if not args.ip_analysis and not config.get("ip_analysis", {}).get("enabled"):
            print("[*] Enabling IP analysis (required for YARA detection)")
            if not HAS_IP_ANALYSIS:
                print("[!] IP analysis module not available")
                sys.exit(1)
            config["ip_analysis"]["enabled"] = True

    # Check if running as root (required for loading eBPF)
    if (args.load or args.compile) and os.geteuid() != 0:
        print("[!] This tool requires root privileges for --load or --compile")
        sys.exit(1)

    # Create agent with config (already loaded above for BrainCell check)
    agent = EBPFImplantAgent(args.bpf, args.config)
    # Apply BrainCell override if configured
    if args.braincell and "braincell" in config:
        agent.config["braincell"] = config["braincell"]
        # Reinitialize BrainCell client with updated config
        if config["braincell"].get("enabled"):
            agent.braincell = BrainCellClient(config["braincell"])

    # Apply IP analysis override if configured
    if args.ip_analysis and "ip_analysis" in config:
        agent.config["ip_analysis"] = config["ip_analysis"]
        # Reinitialize IP analyzer with updated config
        if config["ip_analysis"].get("enabled") and HAS_IP_ANALYSIS:
            agent.ip_analyzer = IPAnalyzer()

    # Apply YARA detection override if configured
    if args.yara_rules and "yara_analysis" in config:
        agent.config["yara_analysis"] = config["yara_analysis"]
        # Reinitialize YARA detector with updated config
        if config["yara_analysis"].get("enabled") and HAS_YARA_DETECTION:
            agent.yara_detector = YARADetector()

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

    if not any([args.compile, args.load, args.collect, args.export, args.amalia, args.braincell, args.ip_analysis, args.yara_rules]):
        print("[*] No action specified. Use --help for options")

    print("[+] Done")


if __name__ == "__main__":
    main()
