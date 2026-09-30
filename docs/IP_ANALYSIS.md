# IP Analysis for eBPF Network Telemetry

Comprehensive per-IP threat analysis and profiling for network telemetry collected by the eBPF implant.

---

## Overview

The IP Analysis module builds detailed profiles for each unique IP address observed in network traffic, tracking:

- **Connection patterns** (inbound/outbound counts, top connections)
- **Protocol usage** (TCP vs UDP distribution)
- **Port activity** (remote and local ports contacted/listened on)
- **Process correlation** (which processes communicate with which IPs)
- **DNS activity** (queries and responses)
- **TCP metrics** (connection states, retransmits, bytes transferred)
- **Threat indicators** (suspicious ports, connection failures)
- **Geolocation** (country code, ASN) - when enriched

---

## Quick Start

### Enable IP Analysis During Collection

```bash
# Collect for 60 seconds and analyze IPs
sudo python3 implant_agent.py --load --collect 60 --ip-analysis --export

# Output:
# [+] IP analysis enabled
# [+] Collecting events for 60 seconds...
# [+] NET: curl(1234) TCP/IPv4 outbound 192.168.1.100:54821→93.184.216.34:443
# [+] NET: firefox(5678) UDP/IPv4 outbound 192.168.1.100:54822→8.8.8.8:53 [DNS]
# [+] IP analysis exported to /tmp/ebpf-telemetry/ip-analysis-<timestamp>.json
# [+] IP analysis report exported to /tmp/ebpf-telemetry/ip-analysis-report-<timestamp>.txt
```

### View IP Analysis Report

```bash
cat /tmp/ebpf-telemetry/ip-analysis-report-*.txt
```

Output:
```
================================================================================
IP ANALYSIS REPORT
================================================================================

Events processed: 127
Duration: 60.0s

Unique IPs: 12
  - External (Public): 8
  - Internal (Private): 4

Traffic Summary:
  - Total connections: 95
  - Total data: 2.5 MB

Top 5 Most Connected IPs:
  1. 93.184.216.34 - 23 connections
  2. 8.8.8.8 - 15 connections
  3. 192.168.1.1 - 12 connections
  4. 1.1.1.1 - 8 connections
  5. 10.0.0.1 - 7 connections

Suspicious IPs (threat_score >= 30):
  - 93.184.216.34: threat_score=45.0
    Suspicious ports: [4444, 8888]

Top DNS Queriers:
  - 192.168.1.100: 5 queries

================================================================================
```

---

## IP Profiles

Each unique IP gets a comprehensive profile:

### Profile Structure

```python
{
  "ip": "93.184.216.34",
  "is_private": false,
  "is_public": true,
  "country": "US",
  "asn": "AS15169",
  "first_seen_iso": "2024-08-09T19:23:45.123456",
  "last_seen_iso": "2024-08-09T19:24:45.987654",
  "duration_seconds": 60.5,
  "inbound_connections": 0,
  "outbound_connections": 23,
  "total_connections": 23,
  "protocols_used": {
    "TCP": 18,
    "UDP": 5
  },
  "top_remote_ports": {
    "443": 18,
    "80": 5
  },
  "top_local_ports": {
    "54821": 10,
    "54822": 8
  },
  "top_outbound_processes": {
    "curl": 12,
    "firefox": 11
  },
  "top_inbound_processes": {},
  "dns_queries": 0,
  "dns_responses": 0,
  "tcp_states": {
    "ESTABLISHED": 15,
    "SYN_SENT": 3
  },
  "bytes_sent": 2048000,
  "bytes_received": 1024000,
  "suspicious_ports": [4444, 8888],
  "threat_score": 45.0
}
```

---

## Threat Scoring

Each IP gets a threat score (0-100) based on multiple behavioral indicators:

| Indicator | Points | Threshold |
|-----------|--------|-----------|
| Suspicious port usage | 10 per port | - |
| High connection volume | 15 | >100 from single process |
| DNS tunneling | 20 | >100 queries + >10KB sent |
| Connection failures | 0-10 | per 10 failures |
| High port diversity | 10 | >50 unique remote ports |
| Private-to-external pattern | 5 | Private IP + >20 ports |

**Example scoring:**
- IP with 2 suspicious ports + high process connections = 10 + 15 = 25 (moderate threat)
- IP with DNS tunneling indicators = 20 (elevated)
- Multiple suspicious ports + DNS tunneling + high volume = 10 + 20 + 15 = 45+ (high threat)

---

## Threat Detection

### C2 Detection

Looks for signs of command-and-control communication:

```python
indicators = analyzer.check_c2_indicators(ip_profile)
# Returns:
# {
#   "c2_probable": True,
#   "reasons": [
#     "Multiple suspicious ports: [4444, 8888]",
#     "High volume to known C2 port 4444: 45 connections",
#     "Single process curl made 50 connections"
#   ]
# }
```

**Triggers:**
- Multiple suspicious ports (4444, 5555, 6666, 7777, 8888, 9999, 10000)
- High volume (>10 connections) to known C2 port
- Single process making >50 connections

### DNS Tunneling Detection

Identifies potential DNS exfiltration:

```python
indicators = analyzer.check_dns_tunneling(ip_profile)
# Returns:
# {
#   "dns_tunneling_probable": True,
#   "reasons": [
#     "High DNS volume (250 queries) with high bytes sent"
#   ]
# }
```

**Triggers:**
- >100 DNS queries AND >10KB bytes sent

### Data Exfiltration Detection

Finds potential unauthorized data transfers:

```python
indicators = analyzer.check_data_exfiltration(ip_profile)
# Returns:
# {
#   "exfiltration_probable": True,
#   "reasons": [
#     "Large outbound transfer: 2500.5 MB to public IP"
#   ]
# }
```

**Triggers:**
- >1MB bytes sent to public IP address

---

## Query Methods

### Get Unique IPs

```bash
python3 -c "
from ip_analysis import IPAnalyzer
import json

# Load telemetry
with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Get all unique IPs
ips = analyzer.get_unique_ips()
print(f'Found {len(ips)} unique IPs')
for ip in ips:
    print(f'  - {ip}')
"
```

### Get Suspicious IPs

```bash
python3 -c "
from ip_analysis import IPAnalyzer
import json

# Load and analyze
with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Get suspicious IPs (threat score >= 30)
suspicious = analyzer.get_suspicious_ips(min_threat_score=30)
print(f'Found {len(suspicious)} suspicious IPs')
for ip_summary in suspicious:
    print(f'  - {ip_summary[\"ip\"]}: threat_score={ip_summary[\"threat_score\"]}')
    if ip_summary['suspicious_ports']:
        print(f'    Ports: {ip_summary[\"suspicious_ports\"]}')
"
```

### Get Top IPs by Connections

```bash
python3 -c "
from ip_analysis import IPAnalyzer
import json

with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Get top 5 most connected IPs
top_ips = analyzer.get_top_ips_by_connections(limit=5)
for i, ip_summary in enumerate(top_ips, 1):
    print(f'{i}. {ip_summary[\"ip\"]} - {ip_summary[\"total_connections\"]} connections')
"
```

### Get DNS Queriers

```bash
python3 -c "
from ip_analysis import IPAnalyzer
import json

with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Get IPs that performed DNS queries
dns_ips = analyzer.get_dns_queriers()
for ip_summary in dns_ips:
    print(f'{ip_summary[\"ip\"]}: {ip_summary[\"dns_queries\"]} queries')
"
```

### Get Connection Graph

```bash
python3 -c "
from ip_analysis import IPAnalyzer
import json

with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Get connection graph (for visualization)
graph = analyzer.get_connection_graph()
# Returns: {
#   '192.168.1.100': ['*:443', '*:80', '*:53'],
#   '93.184.216.34': [...]
# }
"
```

---

## Configuration

### Enable via Command Line

```bash
# Enable IP analysis during collection
sudo python3 implant_agent.py --load --collect 60 --ip-analysis --export
```

### Enable via Configuration File

```json
{
  "ip_analysis": {
    "enabled": true,
    "track_ips": true,
    "threat_scoring": true,
    "min_threat_score_report": 20.0,
    "export_summary": true,
    "export_top_ips": 10
  }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | false | Enable IP analysis |
| `track_ips` | true | Build IP profiles |
| `threat_scoring` | true | Calculate threat scores |
| `min_threat_score_report` | 20.0 | Minimum score for report inclusion |
| `export_summary` | true | Export human-readable report |
| `export_top_ips` | 10 | Number of top IPs in report |

---

## Use Cases

### 1. Red Team - Attacker Infrastructure Mapping

```bash
# Collect during attack simulation
sudo python3 implant_agent.py --load --collect 3600 --ip-analysis --export

# Analyze which external IPs were contacted
cat /tmp/ebpf-telemetry/ip-analysis-report-*.txt | grep "External"
```

### 2. Threat Hunting - C2 Detection

```bash
# Look for C2 indicators
python3 -c "
from ip_analysis import IPAnalyzer, IPThreatIntelligence
import json

# Load and analyze
with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Check each suspicious IP for C2 patterns
suspicious = analyzer.get_suspicious_ips(min_threat_score=30)
for ip_profile in analyzer.ip_profiles.values():
    if ip_profile.calculate_threat_score() >= 30:
        c2_check = IPThreatIntelligence.check_c2_indicators(ip_profile)
        if c2_check['c2_probable']:
            print(f'⚠️  {ip_profile.ip}: Possible C2')
            for reason in c2_check['reasons']:
                print(f'    - {reason}')
"
```

### 3. Forensics - Network Timeline

```bash
# Export IP profiles with temporal data
python3 -c "
from ip_analysis import IPAnalyzer
import json

with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Generate timeline: when did each IP first/last appear?
analysis = analyzer.export_json()
for ip, profile in analysis['ip_profiles'].items():
    duration = profile['duration_seconds']
    print(f'{ip}: first={profile[\"first_seen_iso\"]}, last={profile[\"last_seen_iso\"]}, active={duration}s')
"
```

### 4. Incident Response - Lateral Movement Detection

```bash
# Find IPs with high internal activity
python3 -c "
from ip_analysis import IPAnalyzer
import json

with open('/tmp/ebpf-telemetry/telemetry-*.json') as f:
    events = json.load(f)

analyzer = IPAnalyzer()
for event in events['events']['network']:
    analyzer.process_event(event)

# Find private IPs connecting to many other IPs (lateral movement)
internal_ips = analyzer.get_internal_ips()
for ip in internal_ips:
    if ip['total_connections'] > 20:
        print(f'⚠️  {ip[\"ip\"]}: {ip[\"total_connections\"]} connections (potential lateral movement)')
"
```

---

## Output Files

### JSON Analysis

**File:** `ip-analysis-<timestamp>.json`

Complete structured analysis with all IP profiles, statistics, and threat data.

```json
{
  "analysis_time": "2024-08-09T19:24:45.987654",
  "duration": 60.0,
  "events_processed": 127,
  "unique_ips": 12,
  "unique_external_ips": 8,
  "unique_internal_ips": 4,
  "ip_profiles": {
    "93.184.216.34": { ... },
    "8.8.8.8": { ... }
  },
  "statistics": {
    "total_connections": 95,
    "total_inbound": 0,
    "total_outbound": 95,
    "total_bytes_sent": 2560000,
    "total_bytes_received": 1536000
  }
}
```

### Human-Readable Report

**File:** `ip-analysis-report-<timestamp>.txt`

Formatted report with:
- Summary statistics (unique IPs, traffic volume)
- Top IPs by connection count
- Suspicious IPs with threat scores
- DNS querier list
- Port usage statistics

---

## Performance

**Overhead per IP profile:**
- Memory: ~2KB per unique IP
- CPU: <1% background analysis
- Latency: <1ms per event processing

**With 1000 unique IPs:**
- Memory: ~2MB
- Processing: Negligible (<0.1%)

---

## Future Enhancements

- [ ] GeoIP enrichment (MaxMind, IP2Location)
- [ ] ASN lookup and autonomous system tracking
- [ ] Connection clustering (group related flows)
- [ ] Payload-based protocol detection
- [ ] Machine learning anomaly scoring
- [ ] Temporal pattern analysis (time-of-day, periodicity)
- [ ] Multi-implant correlation (correlate IPs across sensors)
- [ ] Weaviate semantic search integration
- [ ] Export to MISP threat intelligence format
- [ ] Real-time alerting for high-threat IPs

---

## Troubleshooting

### IP Analysis Not Running

**Problem:** IP analysis enabled but no output files generated

**Solution:**
1. Check if `HAS_IP_ANALYSIS` is True: `python3 -c "from ip_analysis import IPAnalyzer; print('OK')"`
2. Verify network events are being collected: `--collect 60 --export` first without `--ip-analysis`
3. Check console output for `[+] IP analysis enabled`

### Memory Usage High

**Problem:** High memory usage with many IP profiles

**Solution:**
- The ip_analysis module caches all profiles in memory
- Memory is ~2KB per IP profile
- For >10K unique IPs, consider streaming analysis instead

### Slow Analysis

**Problem:** Analysis is slow with large event counts

**Solution:**
- IP analysis processes events sequentially
- With >100K events, consider pre-filtering network events
- Use `--collect` with shorter duration to reduce event volume

---

## References

- `userspace/src/ip_analysis.py` - Full implementation
- `docs/NETWORK_CAPTURE.md` - Network event format
- `docs/BRAINCELL_INTEGRATION.md` - BrainCell integration
- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [DNS Tunneling Detection](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
