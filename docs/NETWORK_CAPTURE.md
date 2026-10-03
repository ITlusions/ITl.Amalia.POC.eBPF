# Enhanced Network Traffic Capture

## Overview

The eBPF implant now provides comprehensive network traffic monitoring with support for IPv4/IPv6, TCP/UDP, DNS tracking, connection lifecycle monitoring, and payload inspection.

## Captured Network Events

### IPv4 TCP Connections

**Outbound (tcp_v4_connect):**
- Source and destination IPv4 addresses
- Source and destination ports
- Process ID, UID, command name
- TCP connection state
- Timestamp with nanosecond precision

**Inbound (tcp_v4_syn_recv_sock):**
- Remote client IPv4 address
- Server listening port
- Process accepting the connection
- TCP state at acceptance time

**Connection Close (tcp_v4_destroy_sock):**
- Records when TCP connections terminate
- Useful for tracking connection duration and lifecycle

### IPv6 TCP Connections

**Outbound (tcp_v6_connect):**
- Full IPv6 source and destination addresses (128-bit)
- Ports and TCP state
- Same metadata as IPv4

**Inbound (tcp_v6_syn_recv_sock):**
- IPv6 client connections
- Server process and listening port

### UDP Packets

**Outbound (udp_sendmsg):**
- IPv4 or IPv6 addresses
- Source and destination ports
- Automatic DNS detection (port 53)
- Packet size information

**Inbound (__udp4_lib_rcv):**
- Inbound UDP packet tracking
- DNS query/response capture
- Multi-protocol support (IPv4/IPv6)

### DNS Specific Tracking

All network events include DNS detection:
- `is_dns: true` when source or destination port is 53
- Works for both TCP and UDP
- Identifies DNS queries and responses automatically

Example DNS event:
```json
{
  "type": "network",
  "protocol": "UDP",
  "sport": 54821,
  "dport": 53,
  "saddr": "192.168.1.100",
  "daddr": "8.8.8.8",
  "is_dns": true,
  "direction": "outbound"
}
```

## Event Structure

Each network event includes:

```python
{
    "type": "network",
    "timestamp": 1691234568.90,              # Unix timestamp
    "timestamp_iso": "2024-08-09T19:23:45",  # ISO 8601 format
    "pid": 1234,                              # Process ID
    "uid": 1000,                              # User ID
    "comm": "curl",                           # Command name
    "protocol": "TCP",                        # TCP or UDP
    "family": "IPv4",                         # IPv4 or IPv6
    "sport": 54821,                           # Source port
    "dport": 443,                             # Destination port
    "saddr": "192.168.1.100",                # Source address
    "daddr": "93.184.216.34",                # Destination address
    "direction": "outbound",                  # inbound/outbound/close
    "tcp_state": "ESTABLISHED",              # TCP connection state
    "bytes_sent": 1024,                      # Bytes sent (TCP only)
    "bytes_received": 2048,                  # Bytes received (TCP only)
    "retransmits": 0,                        # Retransmit count (TCP only)
    "is_dns": false,                         # DNS traffic detected
    "payload_size": 512,                     # Captured payload bytes
    "payload_preview": "HTTP/1.1 200 OK"    # First 96 bytes of payload
}
```

## TCP Connection States

| State | Value | Meaning |
|-------|-------|---------|
| ESTABLISHED | 1 | Connection is open |
| SYN_SENT | 2 | Waiting for remote ACK |
| SYN_RECV | 3 | Received SYN, waiting to send ACK |
| FIN_WAIT1 | 4 | Sent FIN, waiting for ACK |
| FIN_WAIT2 | 5 | Received ACK, waiting for FIN |
| TIME_WAIT | 6 | Waiting for timeout after close |
| CLOSE | 7 | Connection closed |
| CLOSE_WAIT | 8 | Received FIN, waiting to send |
| LAST_ACK | 9 | Sent FIN, received FIN from remote |
| LISTEN | 10 | Listening for connections |
| CLOSING | 11 | Both sides sent FIN simultaneously |

## Configuration

Enable/disable network capture features in `config.json`:

```json
{
  "network": {
    "capture_ipv4": true,
    "capture_ipv6": true,
    "capture_tcp": true,
    "capture_udp": true,
    "capture_dns": true,
    "capture_payload": true,
    "max_payload_size": 96,
    "track_connection_close": true,
    "track_tcp_metrics": true
  }
}
```

## Usage Examples

### Capture all network traffic

```bash
sudo python3 implant_agent.py --load --collect 60 --export
```

### Monitor only DNS queries

```bash
sudo python3 implant_agent.py --load --collect 60 --export | grep "is_dns.*true"
```

### Track connection lifecycle

```bash
# Enable all network captures and observe direction: "close" events
sudo python3 implant_agent.py --load --collect 300 --export
cat /tmp/ebpf-telemetry/telemetry-*.json | jq '.events.network[] | select(.direction=="close")'
```

### Identify outbound C2 traffic

```bash
# Look for outbound connections to suspicious ports
cat /tmp/ebpf-telemetry/telemetry-*.json | jq '.events.network[] | select(.direction=="outbound" and (.dport==4444 or .dport==8888))'
```

### IPv6 traffic analysis

```bash
# Find all IPv6 connections
cat /tmp/ebpf-telemetry/telemetry-*.json | jq '.events.network[] | select(.family=="IPv6")'
```

### Payload inspection

```bash
# Find HTTP traffic by inspecting payload preview
cat /tmp/ebpf-telemetry/telemetry-*.json | jq '.events.network[] | select(.payload_preview | contains("HTTP"))'
```

## Red Team Applications

### Network reconnaissance
- Map internal network topology (identifying all services)
- Discover listening ports and services
- Track inter-service communications

### Traffic analysis
- Identify command & control (C2) channels
- Detect exfiltration attempts (DNS tunneling, HTTP POST)
- Monitor lateral movement traffic

### DNS tracking
- Identify external lookups and data exfiltration via DNS
- Detect DNS tunneling attacks
- Track C2 domain resolution

### Connection monitoring
- Track all inbound/outbound connections in real-time
- Detect port scanning activity
- Monitor connection patterns for anomalies

### Payload inspection
- Capture initial bytes of connections for protocol identification
- Detect encrypted vs. plaintext communication
- Identify application protocols (HTTP, TLS, SSH, etc.)

## Performance Impact

Minimal overhead per connection:
- Event size: ~280 bytes (includes IPv6 and payload buffer)
- Ring buffer: 256KB (typically < 50% utilization)
- CPU overhead: ~0.5% per 100 connections/sec
- Memory: ~30MB base + ring buffer

## Kernel Requirements

- Linux kernel 5.8+ (for eBPF kprobes)
- CONFIG_KPROBES enabled
- CONFIG_BPF enabled
- CONFIG_HAVE_EBPF_JIT enabled (recommended for performance)

## Limitations

### IPv6 Address Extraction
- Requires kernel 5.8+ with proper in6_addr struct support
- Some kernel versions may not expose full IPv6 socket fields

### Payload Inspection
- Limited to first 96 bytes per event
- No deep packet inspection (DPI) - layer 4 payload only
- UDP payload not captured at socket level (use XDP for this)

### Connection Metrics
- TCP metrics (bytes_sent/received) tracked at socket level
- May not reflect actual wire bytes (includes overhead)
- Retransmit count from socket, not per-packet

### UDP Tracking
- Inbound UDP tracking via __udp4_lib_rcv (IPv4 only currently)
- IPv6 UDP inbound may require additional hooks
- No payload for UDP events at socket level

## Troubleshooting

### No network events collected

```bash
# Generate test traffic
curl https://example.com
dig example.com
nc -zv 8.8.8.8 53

# Check if hooks are loaded
sudo bpftool prog list | grep tcp_
```

### IPv6 connections not captured

- Verify kernel supports IPv6 sockets
- Check CONFIG_IPV6 is enabled
- Ensure tcp_v6_connect hook is loaded

### DNS events not detected

- Check network events are enabled
- Verify port 53 traffic is actually UDP
- DNS over TLS/HTTPS uses different ports (443)

### High event volume

- Reduce collection duration
- Filter by PID or UID
- Export to file and process offline

## Integration with Amalia

Export network telemetry to Amalia red team platform:

```bash
sudo python3 implant_agent.py \
  --load --collect 3600 \
  --amalia \
  --amalia-url "http://amalia.local:8000/api/ingest"
```

Network events automatically included in telemetry payload:
- All connections mapped to processes
- DNS queries linked to source process
- Connection lifecycle tracked for pattern analysis

## Future Enhancements

- [ ] XDP-based packet inspection (full payload capture)
- [ ] TLS/SSL certificate extraction
- [ ] DNS response content capture
- [ ] HTTP header parsing
- [ ] Connection state machine tracking
- [ ] Encrypted tunnel detection
- [ ] IPv6 UDP inbound tracking
- [ ] Per-connection statistics (throughput, jitter, loss)
