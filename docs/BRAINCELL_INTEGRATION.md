# eBPF Implant → BrainCell Integration Guide

## Overview

Stream network telemetry from the eBPF implant directly into BrainCell's persistent memory system for long-term storage, threat hunting, and analysis.

**What's sent:** Network event metadata only (no payloads)
- Timestamps, process info (PID, UID, command)
- Network addresses (IPv4/IPv6), ports, protocols
- Connection metadata (TCP state, bytes, retransmits)
- DNS detection flags

**What's stored:** BrainCell Notes cell with rich metadata and searchable tags

---

## Setup

### 1. Configure BrainCell Details

Get your BrainCell API token and update `config.json`:

```json
{
  "braincell": {
    "enabled": false,
    "url": "http://braincell.local:8000",
    "api_token": "sk-your-braincell-token-here",
    "batch_size": 50,
    "flush_interval_sec": 10,
    "max_retries": 3
  }
}
```

**Or set via command line:**
```bash
python3 implant_agent.py \
  --config-set braincell.url "http://braincell.local:8000" \
  --config-set braincell.api_token "sk-xxx"
```

### 2. Ensure Network Events Enabled

Verify network collection is enabled:
```bash
python3 implant_agent.py --config-set collection.network_events.enabled true
```

---

## Usage

### Real-Time Collection with BrainCell Ingestion

```bash
# Collect for 1 hour and stream to BrainCell
sudo python3 implant_agent.py --load --collect 3600 --braincell

# Sample output:
# [*] BrainCell client configured: http://braincell.local:8000
# [+] BrainCell batch worker started
# [*] Collecting events for 3600 seconds...
# [*] Enabled collectors: network_events
# [*] BrainCell ingestion: http://braincell.local:8000
#
# [+] NET: curl(1234) TCP/IPv4 outbound 192.168.1.100:54821→93.184.216.34:443
# [+] NET: firefox(5678) UDP/IPv4 outbound 192.168.1.100:54822→8.8.8.8:53 [DNS]
# [+] Ingested 50 network events to BrainCell
# [+] Collection complete
# [+] BrainCell worker stopped
```

### Collect + Export JSON + BrainCell

```bash
# Collect locally and stream to BrainCell
sudo python3 implant_agent.py \
  --load --collect 60 --export --braincell

# Creates local telemetry JSON AND ingests to BrainCell
```

---

## Data Stored in BrainCell

Each network event becomes a searchable Note:

```json
{
  "title": "TCP OUTBOUND: curl(1234) → 93.184.216.34:443",
  "content": "**Process**: curl (PID: 1234, UID: 1000)\n**Direction**: OUTBOUND\n**Protocol**: TCP/IPv4\n**Source**: 192.168.1.100:54821\n**Destination**: 93.184.216.34:443\n**Timestamp**: 2024-08-09T19:23:45.123456\n**TCP State**: ESTABLISHED",
  "tags": [
    "network",
    "tcp",
    "outbound",
    "ipv4",
    "port-443",
    "unusual-egress"
  ],
  "source": "ebpf-implant",
  "meta_data": {
    "timestamp": 1691234568.90,
    "timestamp_iso": "2024-08-09T19:23:45.123456",
    "pid": 1234,
    "uid": 1000,
    "comm": "curl",
    "protocol": "TCP",
    "family": "IPv4",
    "sport": 54821,
    "dport": 443,
    "saddr": "192.168.1.100",
    "daddr": "93.184.216.34",
    "direction": "outbound",
    "tcp_state": "ESTABLISHED",
    "bytes_sent": 512,
    "bytes_received": 2048,
    "retransmits": 0,
    "is_dns": false
  }
}
```

---

## Querying from BrainCell

Once data is in BrainCell, query via API:

### Find All DNS Queries

```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  "http://braincell.local:8000/api/notes?tags=dns-query"
```

### Find Suspicious Outbound Connections

```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  "http://braincell.local:8000/api/notes?tags=unusual-egress"
```

### Find Remote Access Attempts

```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  "http://braincell.local:8000/api/notes?tags=remote-access"
```

### Find Connections to Specific Port

```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  "http://braincell.local:8000/api/notes?tags=port-4444"
```

### Find SMB Traffic

```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  "http://braincell.local:8000/api/notes?tags=smb"
```

### Search by Process Name

```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  "http://braincell.local:8000/api/notes?search=powershell"
```

---

## Automatic Threat Tags

The client automatically applies tags for threat hunting:

| Condition | Tag |
|-----------|-----|
| Protocol = TCP or UDP | `tcp`, `udp` |
| Direction = inbound/outbound | `inbound`, `outbound` |
| IPv4 or IPv6 | `ipv4`, `ipv6` |
| Destination Port | `port-443`, `port-53`, etc. |
| DNS query detected | `dns-query` |
| Ports 22, 3389, 5900, 21 | `remote-access` |
| Ports 445, 139, 135 | `smb` |
| Suspicious ports (4444, 8888, etc) | `suspicious-port` |
| Outbound non-standard ports | `unusual-egress` |

---

## Configuration Options

### batch_size
**Default:** 50  
**Description:** Number of events to batch before sending to BrainCell  
**Impact:** Higher = fewer requests, lower latency, more memory usage

```json
"batch_size": 100
```

### flush_interval_sec
**Default:** 10  
**Description:** Maximum seconds to wait before flushing partial batch  
**Impact:** Lower = more real-time but more requests

```json
"flush_interval_sec": 5
```

### max_retries
**Default:** 3  
**Description:** Retry attempts with exponential backoff (2^n seconds)  
**Impact:** Higher = more resilient to network issues

```json
"max_retries": 3
```

---

## Advanced Usage

### Continuous Monitoring

Run in background with systemd:

```ini
[Unit]
Description=eBPF Implant with BrainCell Ingestion
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/ebpf-implant/implant_agent.py \
  --load --collect 86400 --braincell
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ebpf-braincell
sudo systemctl start ebpf-braincell
sudo journalctl -u ebpf-braincell -f
```

### Selective Ingestion

Only ingest high-risk traffic:

```bash
# Modify implant to filter before queuing
# In network_callback:
if event['dport'] in [4444, 8888, 9999]:  # Suspicious ports
    if self.braincell:
        self.braincell.queue_event(event)
```

### Multiple Implants

Configure each implant with unique source tag:

```json
{
  "implant": {
    "id": "ebpf-sensor-rpi-01"
  },
  "braincell": {
    "enabled": true
  }
}
```

All events tagged with source implant ID for correlation.

---

## Troubleshooting

### Events Not Ingesting

**Check BrainCell connectivity:**
```bash
curl -H "Authorization: Bearer $BRAINCELL_TOKEN" \
  http://braincell.local:8000/api/notes
```

**Enable verbose logging:**
```bash
python3 implant_agent.py --config-set debugging.verbose true
```

**Check configuration:**
```bash
python3 implant_agent.py --config-show | grep braincell
```

### High Memory Usage

Reduce batch size or flush interval:
```bash
python3 implant_agent.py \
  --config-set braincell.batch_size 25 \
  --config-set braincell.flush_interval_sec 5
```

### Network Timeouts

Increase timeout or retry count:
```bash
python3 implant_agent.py \
  --config-set braincell.max_retries 5
```

### Events Lost After Batch Failure

Configure local fallback:
```json
{
  "braincell": {
    "enabled": true,
    "fallback_file": "/tmp/ebpf-failed-events.json"
  }
}
```

---

## Performance Characteristics

**Metadata per event:** ~200 bytes
**Batch overhead:** ~50 bytes (minimal)
**Network per 50 events:** ~10KB
**BrainCell database growth:** ~250MB per 1M events

**Impact on collection:**
- CPU overhead: <0.5% (background thread)
- Memory: ~5MB for queues/buffers
- Latency to BrainCell: 1-5 seconds (batch window)

---

## Integration with Other Services

### Export to Amalia + BrainCell

```bash
sudo python3 implant_agent.py \
  --load --collect 60 \
  --export \
  --amalia \
  --braincell
```

This:
1. Collects locally
2. Exports to JSON file (`/tmp/ebpf-telemetry/`)
3. Sends to Amalia API
4. Streams to BrainCell

---

## Future Enhancements

- [ ] Deduplication (ignore duplicate connection patterns)
- [ ] Anomaly scoring (AI-driven risk assessment)
- [ ] Connection grouping (related flows)
- [ ] Payload metadata (protocol hints from first bytes)
- [ ] GeoIP enrichment (country-based threat tags)
- [ ] Hash indexing (fast pattern matching)
- [ ] Weaviate semantic search integration

---

## API Reference

### Event Metadata Structure

```python
{
    "timestamp": float,           # Unix timestamp (seconds)
    "timestamp_iso": str,         # ISO 8601 format
    "pid": int,                   # Process ID
    "uid": int,                   # User ID
    "comm": str,                  # Process command name (16 chars max)
    "protocol": str,              # "TCP" or "UDP"
    "family": str,                # "IPv4" or "IPv6"
    "sport": int,                 # Source port
    "dport": int,                 # Destination port
    "saddr": str,                 # Source IP address
    "daddr": str,                 # Destination IP address
    "direction": str,             # "inbound", "outbound", "close"
    "tcp_state": str | None,      # "ESTABLISHED", "SYN_SENT", etc.
    "bytes_sent": int | None,     # Bytes sent (TCP only)
    "bytes_received": int | None, # Bytes received (TCP only)
    "retransmits": int | None,    # Retransmit count (TCP only)
    "is_dns": bool,               # DNS query detected
}
```

### BrainCell Note Structure

```python
{
    "title": str,        # Human-readable summary
    "content": str,      # Markdown-formatted details
    "tags": List[str],   # Searchable tags
    "source": str,       # "ebpf-implant"
    "meta_data": dict,   # Full event metadata
}
```

---

## Support & Contributing

For issues or improvements:
- Check `/docs/NETWORK_CAPTURE.md` for network telemetry details
- Review `/docs/BRAINCELL_INTEGRATION_PLAN.md` for architecture
- Report bugs: include config, network events count, BrainCell version
