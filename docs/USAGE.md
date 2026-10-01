# Detailed Usage Guide

Advanced usage patterns and configurations for the eBPF implant.

## Basic Usage

### Manual Collection

```bash
# Compile, load, and collect for 60 seconds
sudo /opt/ebpf-implant/implant_agent.py --compile --load --collect 60 --export

# Load pre-compiled binary only
sudo /opt/ebpf-implant/implant_agent.py --load --collect 60

# Just collect (assume already loaded)
sudo /opt/ebpf-implant/implant_agent.py --collect 120

# Export only (don't run collection)
sudo /opt/ebpf-implant/implant_agent.py --export
```

## Systemd Service Usage

### Start/Stop

```bash
# Start service
sudo systemctl start ebpf-implant.service

# Stop service
sudo systemctl stop ebpf-implant.service

# Restart service
sudo systemctl restart ebpf-implant.service

# Check status
sudo systemctl status ebpf-implant.service

# Enable auto-start on boot
sudo systemctl enable ebpf-implant.service

# Disable auto-start
sudo systemctl disable ebpf-implant.service
```

### Monitor Logs

```bash
# Real-time logs
sudo journalctl -u ebpf-implant.service -f

# Last 100 lines
sudo journalctl -u ebpf-implant.service -n 100

# Errors only
sudo journalctl -u ebpf-implant.service -p err

# Since last boot
sudo journalctl -u ebpf-implant.service -b
```

## Event Filtering

### Filter Network Connections

```bash
# SSH connections only
cat /tmp/ebpf-telemetry/*.json | python3 << 'EOF'
import json, sys
data = json.load(sys.stdin)
for evt in data['events']['network']:
    if evt['dport'] == 22 or 'ssh' in evt['comm']:
        print(f"{evt['timestamp_iso']} {evt['comm']}:{evt['pid']} -> {evt['daddr']}:{evt['dport']}"
EOF
```

### Filter File Access

```bash
# Sensitive file reads
cat /tmp/ebpf-telemetry/*.json | python3 << 'EOF'
import json, sys
data = json.load(sys.stdin)
sensitive = ['/etc/shadow', '/etc/passwd', '/root/.ssh', '/home/.ssh']
for evt in data['events']['file']:
    if evt['op_type'] == 'open' and any(s in evt['path'] for s in sensitive):
        print(f"SENSITIVE: {evt['comm']}({evt['pid']}) accessed {evt['path']}")
EOF
```

### Filter by UID

```bash
# Root-only processes
cat /tmp/ebpf-telemetry/*.json | python3 << 'EOF'
import json, sys
data = json.load(sys.stdin)
for evt in data['events']['process']:
    if evt['uid'] == 0:
        print(f"ROOT: {evt['comm']} -> {evt['filename']}"
EOF
```

## Amalia Integration

### Send Telemetry to Amalia

```bash
# Export directly to Amalia
sudo /opt/ebpf-implant/implant_agent.py \
  --load --collect 60 \
  --amalia \
  --amalia-url "http://amalia.local:8000/api/ingest" \
  --amalia-token "YOUR_TOKEN_HERE"
```

### Manual Integration

```python
import json
import requests

# Load telemetry
with open('/tmp/ebpf-telemetry/telemetry-1234567890.json') as f:
    telemetry = json.load(f)

# Send to Amalia
resp = requests.post(
    "http://amalia.local:8000/api/ingest",
    json=telemetry,
    headers={"Authorization": "Bearer YOUR_TOKEN"}
)

print(f"Status: {resp.status_code}")
print(f"Response: {resp.json()}")
```

## Red Team Scenarios

### Honeypot Monitoring

```bash
# 1. Deploy honeypot file
python3 -m http.server 8080 &

# 2. Start implant (in background)
sudo /opt/ebpf-implant/implant_agent.py --load --collect 3600 &

# 3. Simulate blue team investigation
curl http://localhost:8080/
unzip /tmp/file.zip
tar -czf /tmp/archive.tar.gz /tmp/data

# 4. Check what was captured
cat /tmp/ebpf-telemetry/*.json | python3 -m json.tool | grep -A2 "unzip\|tar"
```

### Exfiltration Detection

```bash
# Capture potential exfiltration
cat /tmp/ebpf-telemetry/*.json | python3 << 'EOF'
import json, sys
from datetime import datetime

data = json.load(sys.stdin)

# Build process tree
processes = {e['pid']: e for e in data['events']['process']}

# Find data access -> network correlation
print("POTENTIAL EXFILTRATION CHAINS:")
for net_evt in data['events']['network']:
    pid = net_evt['pid']
    if pid in processes:
        proc = processes[pid]
        print(f"\n[{net_evt['timestamp_iso']}]")
        print(f"  Process: {proc['comm']} ({pid})")
        print(f"  Target: {net_evt['daddr']}:{net_evt['dport']}")
        print(f"  Direction: {net_evt['direction']}")
EOF
```

### Persistence Validation

```bash
# Check if implant survives reboot
sudo systemctl start ebpf-implant.service
sudo systemctl enable ebpf-implant.service

# Reboot
sudo reboot

# After reboot, check if running
sudo systemctl status ebpf-implant.service
sudo journalctl -u ebpf-implant.service -n 20
```

## Performance Tuning

### Adjust Ring Buffer Size

```bash
# Edit sensor.bpf.c for specific ring buffer size
# Default: 256KB
# For high-volume: 512KB or 1MB
# For low-volume: 64KB

# Recompile after changes
clang -O2 -target bpf -c sensor.bpf.c -o sensor.o
```

### Monitor Resource Usage

```bash
# CPU usage
top -p $(pgrep -f implant_agent)

# Memory usage
ps aux | grep implant_agent

# Events per second
cat /tmp/ebpf-telemetry/*.json | python3 -c "
import json, sys, time
data = json.load(sys.stdin)
total = data['summary']['total_events']
duration = data['collection_window']['duration_sec']
print(f'Events/sec: {total/duration:.1f}')
"
```

## Debugging

### Enable Verbose Logging

```bash
# Modify systemd service for debug output
sudo systemctl edit ebpf-implant.service

# Add or modify:
[Service]
ExecStart=/opt/ebpf-implant/venv/bin/python3 -u /opt/ebpf-implant/implant_agent.py --load --collect 3600 --export
StandardOutput=journal
StandardError=journal
```

### Inspect Loaded Programs

```bash
# List all loaded eBPF programs
sudo bpftool prog list

# Show details of specific program
sudo bpftool prog show id <ID>

# Dump program bytecode
sudo bpftool prog dump xlated id <ID>

# List ring buffers
sudo bpftool map list | grep RINGBUF
```

### Trace System Calls

```bash
# Monitor bpf() syscalls
sudo auditctl -a exit,always -F arch=b64 -S bpf -k ebpf_load

# View audit logs
sudo ausearch -k ebpf_load -i
```

## Blue Team Detection

### Detect Implant Presence

```bash
# List loaded eBPF programs
sudo bpftool prog list

# Monitor for unexpected programs
watch -n 1 'sudo bpftool prog list | grep -v kprobes'

# Check audit logs for eBPF loads
sudo ausearch -k ebpf_load -i --message all
```

### Kill the Implant

```bash
# List programs and find implant
sudo bpftool prog list

# Unload specific program
sudo bpftool prog del id <ID>

# Kill userspace agent
sudo pkill -f implant_agent

# Dump ring buffer data for forensics
sudo bpftool map dump id <ringbuf_id>
```

## Troubleshooting

### No Events Captured

```bash
# 1. Verify eBPF is loaded
sudo bpftool prog list | grep tracepoint

# 2. Generate traffic
curl https://example.com
ls -la /

# 3. Check if tracepoints are available
cat /sys/kernel/debug/tracing/available_events | grep sched

# 4. Check ringbuf availability
cat /proc/sys/kernel/perf_event_paranoid

# 5. Monitor in real-time
sudo bpftool prog tracelog
```

### Ring Buffer Overflow

```bash
# Increase ring buffer size in sensor.bpf.c
# Change: BPF_RINGBUF_OUTPUT(events, 256);
# To: BPF_RINGBUF_OUTPUT(events, 1024);

# Recompile and reload
clang -O2 -target bpf -c sensor.bpf.c -o sensor.o
sudo bpftool prog del id <old_id>
sudo /opt/ebpf-implant/implant_agent.py --load
```

### Permission Issues

```bash
# Ensure running as root
sudo -i
/opt/ebpf-implant/implant_agent.py --load --collect 60

# Or use sudo explicitly
sudo /opt/ebpf-implant/implant_agent.py --load --collect 60
```
