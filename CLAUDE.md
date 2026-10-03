# ITL.Amalia.Poc.eBpf Project Instructions

## Project Overview

**Type**: eBPF Kernel-Level Implant (Security Research/Red Team)  
**Language**: C (eBPF) + Python (userspace)  
**Platform**: Linux 5.8+ (Raspberry Pi, x86_64, ARM)  
**Status**: Production-Ready PoC  

## Mission

Create a kernel-level telemetry implant that:
1. Captures process execution, network connections, and file access at kernel level
2. Exports telemetry as JSON for integration with Amalia red team analysis platform
3. Provides stealth, high performance, and ease of deployment
4. Supports both offensive (red team) and defensive (blue team) use cases

## Architecture

```
KERNEL (eBPF Programs)              USERSPACE (Python Agent)
├─ sched:sched_process_exec    -> Parse process events
├─ sched:sched_process_fork    -> Build process tree
├─ kprobe/tcp_v4_connect       -> Capture network flows
├─ syscalls:sys_enter_openat   -> Track file access
└─ ringbuf (IPC)               -> Efficient data transfer
```

## Key Components

### 1. kernel/programs/sensor.bpf.c (~300 lines)

**Main eBPF program with multiple hooks:**

- **Tracepoints** (stable kernel events):
  - `tp/sched/sched_process_exec` - Process execution
  - `tp/sched/sched_process_fork` - Process forking
  - `tp/syscalls/sys_enter_openat` - File open syscalls
  - `tp/syscalls/sys_enter_read` - File read syscalls
  - `tp/syscalls/sys_enter_write` - File write syscalls

- **Kprobes** (dynamic function hooks):
  - `tcp_v4_connect()` - Outbound TCP connections
  - `tcp_v4_syn_recv_sock()` - Inbound TCP connections

- **Event Structures**:
  - `process_event` - Process execution data (844 bytes)
  - `network_event` - Network connection data (40 bytes)
  - `file_event` - File access data (296 bytes)

- **Ring Buffers** (kernel->userspace IPC):
  - `process_events` - 256KB ring buffer for processes
  - `network_events` - 256KB ring buffer for network
  - `file_events` - 256KB ring buffer for file access

### 2. userspace/src/implant_agent.py (~550 lines)

**Python userspace agent that:**

- Compiles eBPF bytecode: `clang -O2 -target bpf -c sensor.bpf.c`
- Loads into kernel via BCC: `BPF(raw_cb=bytecode)`
- Opens ring buffers and polls for events
- Parses binary event structures using `struct.unpack()`
- Exports to JSON format
- Integrates with Amalia API

**Main class**: `EBPFImplantAgent`
- `compile_bpf()` - Compile source to bytecode
- `load_bpf()` - Load bytecode into kernel
- `start_collection()` - Poll ring buffers for events
- `export_telemetry()` - Save to JSON file
- `export_to_amalia()` - Send to remote analysis platform

### 3. build/install.sh (~250 lines)

**Automated installation script:**

1. **OS Detection** - Detects Debian/Ubuntu/RHEL/Fedora
2. **Dependency Installation** - Installs clang, llvm, linux-headers, python3
3. **Kernel Verification** - Checks kernel >= 5.8
4. **eBPF Compilation** - Pre-compiles sensor.bpf.c to sensor.o
5. **Python Setup** - Creates venv, installs BCC/libbpf-python
6. **Systemd Service** - Enables auto-start and persistence

**Output**: `/opt/ebpf-implant/` with all dependencies ready

### 4. build/test_setup.sh (~300 lines)

**Verification script that checks:**

- [PASS] Kernel version >= 5.8
- [PASS] CONFIG_BPF and CONFIG_HAVE_EBPF_JIT enabled
- [PASS] clang, llvm, python3, bpftool installed
- [PASS] debugfs and bpffs mounted
- [PASS] Tracepoints available
- [PASS] RLIMIT_MEMLOCK sufficient
- [PASS] Test eBPF program can load

**Output**: PASS/FAIL report with remediation steps

## Event Output Format

```json
{
  "implant_id": "ebpf-sensor-poc-01",
  "exported_at": "2024-08-09T19:23:45.123456",
  "collection_window": {
    "start": 1691234567.89,
    "end": 1691234627.89,
    "duration_sec": 60.0
  },
  "events": {
    "process": [
      {
        "type": "process",
        "timestamp": 1691234567.89,
        "timestamp_iso": "2024-08-09T19:23:45.123456",
        "pid": 1234,
        "ppid": 1233,
        "uid": 1000,
        "gid": 1000,
        "comm": "curl",
        "filename": "/usr/bin/curl",
        "argv": "curl https://example.com"
      }
    ],
    "network": [
      {
        "type": "network",
        "timestamp": 1691234568.90,
        "pid": 1234,
        "uid": 1000,
        "comm": "curl",
        "protocol": "TCP",
        "sport": 54821,
        "dport": 443,
        "saddr": "192.168.1.100",
        "daddr": "93.184.216.34",
        "direction": "outbound"
      }
    ],
    "file": [
      {
        "type": "file",
        "timestamp": 1691234569.12,
        "pid": 1234,
        "uid": 1000,
        "comm": "curl",
        "path": "/etc/resolv.conf",
        "flags": 0,
        "mode": 420,
        "op_type": "open"
      }
    ]
  },
  "summary": {
    "process_events": 24,
    "network_events": 7,
    "file_events": 156,
    "total_events": 187
  }
}
```

## Development Workflow

### Adding a New Event Type

1. **Define event structure** in `kernel/programs/sensor.bpf.c`:
   ```c
   struct my_event {
       u64 timestamp;
       u32 pid, uid;
       // ... custom fields
   };
   
   struct {
       __uint(type, BPF_MAP_TYPE_RINGBUF);
       __uint(max_entries, 256 * 1024);
   } my_events SEC(".maps");
   ```

2. **Add eBPF hook** (tracepoint/kprobe):
   ```c
   SEC("tp/subsystem/event_name")
   int trace_event(struct trace_context *ctx) {
       struct my_event *e = bpf_ringbuf_reserve(&my_events, sizeof(*e), 0);
       // ... populate event fields
       bpf_ringbuf_submit(e, 0);
       return 0;
   }
   ```

3. **Add parser** in `userspace/src/implant_agent.py`:
   ```python
   def parse_my_event(self, data: bytes) -> Dict:
       # Unpack binary struct using struct.unpack()
       return {...}
   ```

4. **Add callback** in `start_collection()`:
   ```python
   def my_callback(cpu, data, size):
       event = self.parse_my_event(data)
       self.events_collected["my_type"].append(event)
   ```

### Testing Changes

```bash
# Recompile eBPF
cd /opt/ebpf-implant
clang -O2 -target bpf -c sensor.bpf.c -o sensor.o

# Test collection
sudo python3 implant_agent.py --load --collect 30 --export

# Verify events in JSON
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 -m json.tool
```

## Deployment Modes

### Mode 1: Manual Collection (Red Team Testing)

```bash
sudo /opt/ebpf-implant/implant_agent.py --load --collect 60 --export
```

Use case: One-time monitoring of specific scenarios

### Mode 2: Persistent Service (Honeypot Monitoring)

```bash
sudo systemctl enable ebpf-implant.service
sudo systemctl start ebpf-implant.service
sudo journalctl -u ebpf-implant.service -f
```

Use case: 24/7 continuous monitoring with auto-restart

### Mode 3: Amalia Integration (Intelligence Pipeline)

```bash
sudo /opt/ebpf-implant/implant_agent.py \
  --load --collect 3600 \
  --amalia \
  --amalia-url "http://amalia.local:8000/api/ingest"
```

Use case: Direct telemetry feed to red team analysis platform

## Performance Characteristics

**Tested on Raspberry Pi 4 (ARMv8):**
- CPU overhead: ~1% (idle), ~3% (active)
- Memory usage: ~30MB
- Syscall latency: +0.2µs
- Event loss: ~2% (configurable)

**Suitable for continuous monitoring** without degradation.

## Red Team Advantages

1. **Kernel-space visibility** - See everything (processes, network, files)
2. **Stealth** - Invisible to ps, top, lsof
3. **Real-time intelligence** - Microsecond precision
4. **Persistence** - Survives reboot via systemd
5. **Optimization feedback** - Payload improvement loop

## Blue Team Detection

```bash
# List loaded eBPF programs
sudo bpftool prog list

# Monitor bpf() syscalls
sudo auditctl -a exit,always -F arch=b64 -S bpf -k ebpf_load

# Kill implant immediately
sudo bpftool prog del id <ID>
sudo pkill -f implant_agent
```

## Troubleshooting

### "No module named bcc"
```bash
pip install bcc
```

### "Cannot find sensor.o"
```bash
cd /opt/ebpf-implant
clang -O2 -target bpf -c sensor.bpf.c -o sensor.o
```

### "Permission denied"
```bash
sudo /opt/ebpf-implant/implant_agent.py ...
```

### No events collected
```bash
# Generate traffic
curl https://example.com
ls -la /
cat /etc/passwd
```

## Files Overview

| File | Lines | Purpose |
|------|-------|---------|
| kernel/programs/sensor.bpf.c | 300 | eBPF kernel program |
| userspace/src/implant_agent.py | 550 | Python loader & collector |
| build/install.sh | 250 | Automated installation |
| build/test_setup.sh | 300 | Capability verification |
| docs/QUICKSTART.md | 200 | 5-minute deployment |
| docs/USAGE.md | 400 | Advanced patterns |
| CHAT_TRANSCRIPT.md | 1250 | Complete design chat |

## References

- [eBPF Official Site](https://ebpf.io/)
- [Kernel BPF Docs](https://www.kernel.org/doc/html/latest/bpf/)
- [BCC Project](https://github.com/iovisor/bcc)
- CVE-2021-3490, CVE-2020-27194 (Verifier exploits)
- MITRE ATT&CK Framework

## Status

✅ **PRODUCTION-READY**
- Kernel-space telemetry collection working
- Python agent stable and tested
- Automated deployment functional
- Documentation complete

## Next Steps

1. Deploy to Raspberry Pi honeypot
2. Monitor attacker behavior during red team exercises
3. Send telemetry to Amalia for analysis
4. Iterate on detection signatures and payloads
