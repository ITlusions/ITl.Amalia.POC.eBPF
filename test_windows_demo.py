#!/usr/bin/env python3
"""
Windows/MSYS2 Demo - Simulates what the implant does
Shows network event parsing and JSON export (without actual kernel collection)
"""

import json
import struct
from datetime import datetime
from pathlib import Path

class NetworkEventParser:
    """Parse simulated network events (what the implant would capture)"""

    @staticmethod
    def create_mock_event(pid, comm, saddr, sport, daddr, dport, direction="outbound"):
        """Create a mock network event for testing"""
        timestamp = datetime.now().timestamp()

        return {
            "type": "network",
            "timestamp": timestamp,
            "timestamp_iso": datetime.fromtimestamp(timestamp).isoformat(),
            "pid": pid,
            "uid": 1000,
            "comm": comm,
            "protocol": "TCP",
            "sport": sport,
            "dport": dport,
            "saddr": saddr,
            "daddr": daddr,
            "direction": direction
        }

    @staticmethod
    def parse_network_event_binary(data: bytes):
        """
        Parse binary network_event struct from eBPF

        struct network_event {
            u64 timestamp;        // 8 bytes
            u32 pid;              // 4 bytes
            u32 uid;              // 4 bytes
            char comm[16];        // 16 bytes
            u8 protocol;          // 1 byte
            u16 sport;            // 2 bytes
            u16 dport;            // 2 bytes
            u32 saddr;            // 4 bytes
            u32 daddr;            // 4 bytes
            u8 direction;         // 1 byte
        };
        Total: 42 bytes
        """
        if len(data) < 42:
            return None

        try:
            # Unpack: Q=u64, I=u32, 16s=char[16], B=u8, H=u16, etc.
            timestamp, pid, uid = struct.unpack("=QII", data[:12])
            comm = data[12:28].rstrip(b'\x00').decode('utf-8', errors='ignore')
            protocol, sport, dport, saddr, daddr, direction = struct.unpack(
                "=BHHIIB", data[28:42]
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
                "saddr": NetworkEventParser._ip_to_string(saddr),
                "daddr": NetworkEventParser._ip_to_string(daddr),
                "direction": "inbound" if direction == 1 else "outbound"
            }
        except Exception as e:
            print(f"[!] Error parsing event: {e}")
            return None

    @staticmethod
    def _ip_to_string(ip: int) -> str:
        """Convert 32-bit IP to dotted decimal notation"""
        return ".".join(str((ip >> (i*8)) & 0xFF) for i in range(4))


def simulate_network_events():
    """Simulate network events that would be captured by the implant"""

    print("[*] Network Event Simulation (Without Kernel Collection)")
    print("=" * 70)
    print()

    # Simulate some network events
    events = [
        NetworkEventParser.create_mock_event(
            pid=1234, comm="curl",
            saddr="192.168.1.100", sport=54821,
            daddr="93.184.216.34", dport=443  # example.com
        ),
        NetworkEventParser.create_mock_event(
            pid=5678, comm="ssh",
            saddr="192.168.1.100", sport=22,
            daddr="10.0.0.1", dport=22
        ),
        NetworkEventParser.create_mock_event(
            pid=9012, comm="python3",
            saddr="192.168.1.100", sport=8080,
            daddr="1.2.3.4", dport=443,  # C2 callback
            direction="outbound"
        ),
        NetworkEventParser.create_mock_event(
            pid=3456, comm="nc",
            saddr="192.168.1.100", sport=5555,
            daddr="10.20.30.40", dport=4444,
            direction="inbound"
        ),
    ]

    # Print events
    print("[+] Captured Network Events:")
    print()
    for i, event in enumerate(events, 1):
        print(f"  Event {i}:")
        print(f"    Process: {event['comm']} (PID: {event['pid']})")
        print(f"    Connection: {event['saddr']}:{event['sport']} → {event['daddr']}:{event['dport']}")
        print(f"    Direction: {event['direction'].upper()}")
        print(f"    Timestamp: {event['timestamp_iso']}")
        print()

    return events


def export_telemetry(events, output_file="telemetry-demo.json"):
    """Export events as JSON (what implant does)"""

    print("=" * 70)
    print("[*] Exporting Telemetry to JSON")
    print()

    telemetry = {
        "implant_id": "ebpf-sensor-poc-01",
        "sensor_type": "ebpf-kernel-level",
        "exported_at": datetime.now().isoformat(),
        "collection_window": {
            "start": datetime.now().timestamp(),
            "end": datetime.now().timestamp(),
            "duration_sec": 60.0
        },
        "events": {
            "network": events
        },
        "summary": {
            "network_events": len(events),
            "total_events": len(events)
        }
    }

    # Save to file
    with open(output_file, 'w') as f:
        json.dump(telemetry, f, indent=2)

    print(f"[+] Telemetry exported to: {output_file}")
    print()
    print("[+] Content:")
    print(json.dumps(telemetry, indent=2))

    return output_file


def test_binary_parsing():
    """Test the binary event parser (what happens with real ring buffer data)"""

    print("\n" + "=" * 70)
    print("[*] Testing Binary Event Parsing")
    print("=" * 70)
    print()

    # Create a mock binary event (this would come from ring buffer)
    # Fields: timestamp(u64), pid(u32), uid(u32), comm(16), protocol(u8),
    #         sport(u16), dport(u16), saddr(u32), daddr(u32), direction(u8)

    # Example: curl process connecting to example.com
    timestamp_ns = int(datetime.now().timestamp() * 1e9)
    pid = 1234
    uid = 1000
    comm = b"curl\x00\x00\x00\x00\x00\x00\x00\x00"  # 16 bytes
    protocol = 1  # TCP
    sport = 54821
    dport = 443
    saddr = 0xc0a80164  # 192.168.1.100 in big-endian
    daddr = 0x5db8d822  # 93.184.216.34
    direction = 2  # outbound

    # Pack binary data
    binary_data = struct.pack(
        "=QII16sBHHIIB",
        timestamp_ns, pid, uid, comm, protocol, sport, dport, saddr, daddr, direction
    )

    print(f"[*] Binary data size: {len(binary_data)} bytes")
    print(f"[*] Hex dump (first 32 bytes): {binary_data[:32].hex()}")
    print()

    # Parse it
    parsed = NetworkEventParser.parse_network_event_binary(binary_data)

    if parsed:
        print("[+] Successfully parsed binary event:")
        print(json.dumps(parsed, indent=2))
    else:
        print("[!] Failed to parse binary event")


def main():
    """Main demo"""
    print("\n")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║  eBPF Implant - Network Collection Demo (Windows/MSYS2)           ║")
    print("║  Simulates what happens in real Linux/WSL 2                       ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()

    # Simulate network events
    events = simulate_network_events()

    # Export to JSON
    export_telemetry(events)

    # Test binary parsing
    test_binary_parsing()

    print()
    print("=" * 70)
    print("[+] Demo Complete!")
    print()
    print("To test with REAL network collection:")
    print("  1. Switch to WSL 2 or Linux system")
    print("  2. Run: sudo bash build/install.sh")
    print("  3. Run: sudo /opt/ebpf-implant/implant_agent.py --load --collect 60 --export")
    print("=" * 70)


if __name__ == "__main__":
    main()
