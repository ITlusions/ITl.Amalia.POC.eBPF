# Quick Start Guide - eBPF Implant PoC

Deploy the eBPF implant in 5 minutes.

## Prerequisites

- Linux system (Raspberry Pi, Ubuntu, Fedora, etc.)
- Kernel 5.8+
- Root access
- Internet connection for dependency installation

## Installation (3 minutes)

```bash
# 1. Copy to target system
scp -r /path/to/ITL.Amalia.Poc.eBpf pi@target.local:/tmp/ebpf-implant

# 2. SSH into target
ssh pi@target.local

# 3. Run installation (with sudo)
cd /tmp/ebpf-implant
sudo bash build/install.sh

# This will:
# ├─ Detect OS and install dependencies (clang, llvm, linux-headers)
# ├─ Verify kernel >= 5.8
# ├─ Compile sensor.bpf.c to sensor.o
# ├─ Setup Python virtual environment
# └─ Install systemd service

# Time: ~2-3 minutes on Raspberry Pi, ~30s on modern systems
```

## Verification (1 minute)

```bash
# Test system capabilities
sudo bash build/test_setup.sh

# Output should show:
# [PASS] Kernel version 5.8+
# [PASS] clang, llvm, python3 installed
# [PASS] bpftool available
# [PASS] eBPF load capability works
```

## Deployment (1 minute)

### Option A: Manual Collection (Ad-hoc)

```bash
# Collect events for 60 seconds
sudo /opt/ebpf-implant/implant_agent.py --load --collect 60 --export

# Output:
# [*] Loading eBPF program into kernel...
# [+] eBPF program loaded successfully
# [*] Collecting events for 60 seconds...
# [+] PROCESS: curl(1234) -> /usr/bin/curl
# [+] NETWORK: curl -> 1.2.3.4:443
# [+] FILE: curl open /etc/resolv.conf
# [*] Exporting telemetry...
# [+] Telemetry exported to /tmp/ebpf-telemetry/telemetry-1691234567.json
```

### Option B: Persistent Service

```bash
# Enable auto-start
sudo systemctl enable ebpf-implant.service

# Start service
sudo systemctl start ebpf-implant.service

# Monitor real-time
sudo journalctl -u ebpf-implant.service -f

# Stop service (if needed)
sudo systemctl stop ebpf-implant.service
```

## Verify Collection

```bash
# View collected telemetry
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 -m json.tool

# Sample output:
{
  "implant_id": "ebpf-sensor-poc-01",
  "exported_at": "2024-08-09T19:23:45.123456",
  "events": {
    "process": [
      {
        "timestamp": 1691234567.89,
        "pid": 1234,
        "comm": "curl",
        "filename": "/usr/bin/curl",
        "argv": "curl https://example.com"
      }
    ],
    "network": [
      {
        "timestamp": 1691234568.90,
        "pid": 1234,
        "comm": "curl",
        "protocol": "TCP",
        "daddr": "93.184.216.34",
        "dport": 443,
        "direction": "outbound"
      }
    ],
    "file": [
      {
        "timestamp": 1691234569.12,
        "pid": 1234,
        "comm": "curl",
        "path": "/etc/resolv.conf",
        "op_type": "open"
      }
    ]
  },
  "summary": {
    "process_events": 15,
    "network_events": 3,
    "file_events": 42,
    "total_events": 60
  }
}
```

## Generate Test Traffic

```bash
# Terminal 1: Start implant
sudo /opt/ebpf-implant/implant_agent.py --load --collect 120 --export

# Terminal 2: Generate activity
curl https://example.com
ls -la /tmp
cat /etc/passwd
scp file.txt user@remote:/tmp/

# Terminal 3: Check results
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 -m json.tool | grep -E 'comm|daddr|path'
```

## Troubleshooting

### "Permission denied"
```bash
# Ensure running as root
sudo /opt/ebpf-implant/implant_agent.py ...
```

### "No module named bcc"
```bash
# Install BCC
sudo apt-get install python3-bcc
# OR
source /opt/ebpf-implant/venv/bin/activate
pip install bcc
```

### "Cannot find sensor.o"
```bash
# Recompile eBPF program
cd /opt/ebpf-implant
clang -O2 -target bpf -c sensor.bpf.c -o sensor.o
```

### No events collected
```bash
# Ensure you generate activity during collection
# Check available tracepoints
cat /sys/kernel/debug/tracing/available_events | grep -E sched
```

## Analyze Network IPs

Analyze each unique IP with threat scoring and behavioral profiling:

```bash
# Collect and analyze IPs
sudo /opt/ebpf-implant/implant_agent.py --load --collect 60 --ip-analysis --export

# Output:
# [+] IP analysis enabled
# [*] IP analysis exported to /tmp/ebpf-telemetry/ip-analysis-<timestamp>.json
# [+] IP analysis report exported to /tmp/ebpf-telemetry/ip-analysis-report-<timestamp>.txt

# View report
cat /tmp/ebpf-telemetry/ip-analysis-report-*.txt

# Sample output:
# ================================================================================
# IP ANALYSIS REPORT
# ================================================================================
# Unique IPs: 12
#   - External (Public): 8
#   - Internal (Private): 4
#
# Top 5 Most Connected IPs:
#   1. 93.184.216.34 - 23 connections
#   2. 8.8.8.8 - 15 connections
#   3. 192.168.1.1 - 12 connections
#
# Suspicious IPs (threat_score >= 30):
#   - 93.184.216.34: threat_score=45.0
#     Suspicious ports: [4444, 8888]
```

For detailed IP analysis usage, see: `docs/IP_ANALYSIS.md`

## Next Steps

1. **Review telemetry**: Analyze collected events in `/tmp/ebpf-telemetry/`
2. **Analyze IPs**: Use `--ip-analysis` for threat scoring and profiling
3. **Stream to BrainCell**: Use `--braincell` to ingest into persistent memory
4. **Send to Amalia**: Integrate with red team analysis platform
5. **Customize hooks**: Modify `kernel/programs/sensor.bpf.c` for specific events
6. **Enable persistence**: Use systemd service for continuous monitoring

## Support

For detailed usage patterns, see: `docs/USAGE.md`
For IP analysis, see: `docs/IP_ANALYSIS.md`
For BrainCell integration, see: `docs/BRAINCELL_INTEGRATION.md`
For architecture details, see: `docs/ARCHITECTURE.md`
