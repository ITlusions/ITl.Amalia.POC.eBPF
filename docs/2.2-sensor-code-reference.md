# Sensor Code Reference

## File: kernel/programs/sensor.bpf.c (508 lines)

### Data Structures

#### process_event
```
timestamp: u64              // nanoseconds
pid: u32
ppid: u32
uid: u32
gid: u32
comm[16]: char              // process name
filename[256]: char         // binary path
argv[512]: char             // command line
```

#### network_event
```
timestamp: u64
pid: u32
uid: u32
comm[16]: char
protocol: u8                // TCP=1, UDP=2
family: u8                  // AF_INET=2, AF_INET6=10
sport: u16
dport: u16
saddr: u32                  // IPv4 source
daddr: u32                  // IPv4 dest
saddr6[16]: u8              // IPv6 source
daddr6[16]: u8              // IPv6 dest
direction: u8               // inbound=1, outbound=2
bytes_sent: u32
bytes_received: u32
tcp_state: u8
retransmits: u8
payload_size: u32
payload[96]: char           // First 96 bytes
is_dns: u8                  // DNS detected (1=yes)
```

#### file_event
```
timestamp: u64
pid: u32
uid: u32
comm[16]: char
path[256]: char
flags: u32
mode: u32
op_type: u8                 // open=1, close=2, read=3, write=4
```

### Ring Buffers (IPC)

```
process_events: 256 KB
network_events: 256 KB
file_events: 256 KB
```

### Tracepoints Attached

| Hook | Purpose | Section |
|------|---------|---------|
| tp/sched/sched_process_exec | Capture execve() | PROCESS EXECUTION |
| tp/sched/sched_process_fork | Capture fork() | PROCESS EXECUTION |
| tp/syscalls/sys_enter_openat | File open | FILE ACCESS |
| tp/syscalls/sys_enter_read | File read | FILE ACCESS |
| tp/syscalls/sys_enter_write | File write | FILE ACCESS |
| kprobe/tcp_v4_connect | TCP outbound | NETWORK CONNECTIONS |
| kprobe/tcp_v4_syn_recv_sock | TCP inbound accept | NETWORK CONNECTIONS |

### Helper Functions

```
read_user_str()             // Safely read user-space strings
read_kernel_str()           // Safely read kernel-space strings
copy_ipv6_addr()            // Copy IPv6 address (unrolled loop)
is_dns_query()              // Detect DNS (port 53)
read_socket_payload()       // Read socket payload (simplified)
```

### Event Processing

1. Reserve space in ring buffer
2. Populate event struct with kernel context
3. Submit to ring buffer
4. Userspace polls and reads

### Performance Characteristics

- Per-event overhead: <1ms
- CPU impact: ~1-3% idle system
- Memory: ~30 MB runtime
- Syscall latency: +0.2µs

---

## Integration Points

### Userspace Consumer

File: `userspace/src/application/implant_agent.py`

```
Poll ringbuf
  ↓
Parse binary event
  ↓
Create Python dataclass
  ↓
Feed to detection pipeline
  ↓
Export/stream results
```

### Detection Pipeline

1. IP Analysis - network behavioral scoring
2. YARA Detection - signature matching
3. Sigma-Lite - attack chain correlation
4. Threat Correlator - unified verdict

### Export Targets

1. BrainCell WebSocket - real-time streaming
2. Amalia REST API - batch verdicts
3. JSON file - local storage
