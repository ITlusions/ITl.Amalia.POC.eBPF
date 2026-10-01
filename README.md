# ITL.Amalia.Poc.eBpf - eBPF Kernel Telemetry Sensor

**Kernel-level threat detection and telemetry collection for blue team testing**

A production-ready eBPF sensor that captures process execution, network connections, and file access at kernel level. Designed for blue team validation and integration with the Amalia threat analysis platform.

## Authorization and Operating Boundary

- **Operator:** Niels Weistra, CISSP
- **Authorization:** [RoE-ITlusions-Testlab-2026](../ITL.Amalia/docs/engagements/RoE-ITlusions-Testlab-2026.md)
- **Validity:** 27 April 2026 through 31 December 2026, unless the engagement closes earlier
- **Permitted environment:** ITlusions-owned or fully managed testlab systems listed in the RoE
- **Excluded:** Customer production systems, unauthorized external cloud tenants, and third-party systems without a separate written RoE
- **Evidence handling:** Use synthetic test data; record critical findings in BrainCell `incidents` and `vuln_reports`

CISSP certification establishes professional context but does not replace written authorization. The referenced RoE is the controlling authority for every deployment, crash reproduction, and PoC execution.

## Objective

Monitor honeypot systems and capture attacker behavior in real-time using eBPF, providing actionable intelligence for red team operations and blue team defense validation.

## Features

- **Kernel-level visibility**: Capture processes, network connections, and file I/O at kernel level
- **Real-time threat detection**: 4-layer detection engine (IP analysis, YARA, Sigma-Lite, correlation)
- **High performance**: Microsecond-level latency, minimal CPU impact (~1-3%)
- **JSON telemetry**: Structured event export for integration with analysis platforms
- **Threat verdicts**: Unified threat assessment combining multiple detection methods
- **Amalia & BrainCell integration**: Stream verdicts to red team analysis and persistent memory platforms
- **Automated deployment**: One-command installation on Linux servers (5.8+)
- **Scalable**: Ring buffer design handles high-frequency events
- **Complete documentation**: Architecture guides, deployment instructions, and examples

## Project Structure

```
ITL.Amalia.Poc.eBpf/
├── kernel/programs/           # eBPF kernel programs
│   ├── sensor.bpf.c           # Main eBPF program (~300 lines)
│   └── README.md
├── userspace/src/             # Python threat detection framework
│   ├── core/                  # Configuration, logging, ABCs
│   ├── collection/            # Event data models
│   ├── detection/             # 4-layer threat detection
│   ├── integrations/          # Amalia, BrainCell exports
│   ├── application/           # Main orchestrator
│   ├── examples/              # Usage demonstrations
│   └── README.md
├── build/                     # Installation & testing
│   ├── install.sh             # Automated OS detection & setup
│   └── test_setup.sh          # Capability verification
├── docs/                      # Documentation
│   ├── ARCHITECTURE.md        # System design & data flow
│   ├── SETUP.md               # Development environment
│   ├── USAGE.md               # Advanced usage patterns
│   ├── QUICKSTART.md          # 5-minute deployment
│   └── SECURITY.md            # Detection considerations
├── CMakeLists.txt             # Build configuration
├── Makefile                   # Alternative build
└── CLAUDE.md                  # Project guidelines
```

## Quick Start

### Installation (3 minutes)

```bash
# Copy to target system
scp -r ITL.Amalia.Poc.eBpf root@target:/tmp/

# Install dependencies and setup
ssh root@target
cd /tmp/ITL.Amalia.Poc.eBpf
sudo bash build/install.sh

# Verify system capabilities
sudo bash build/test_setup.sh
```

### Collect Telemetry (1 minute)

```bash
# Collect for 60 seconds
sudo /opt/ebpf-implant/implant_agent.py --load --collect 60 --export

# Enable persistent monitoring
sudo systemctl enable ebpf-implant.service
sudo systemctl start ebpf-implant.service

# View results
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 -m json.tool
```

### Integration with Amalia

```bash
# Send telemetry to Amalia
sudo /opt/ebpf-implant/implant_agent.py \
  --load --collect 3600 \
  --amalia \
  --amalia-url "http://amalia.local:8000/api/ingest" \
  --amalia-token "YOUR_TOKEN"
```

## Event Collection

### Process Execution
- PID, parent PID, UID/GID
- Command name and full argv
- Nanosecond-precision timestamps

### Network Connections
- TCP/UDP 5-tuple (source/dest IP:port)
- Direction (inbound/outbound)
- Process and user context

### File Access
- Path accessed
- Operation type (open, read, write)
- Access flags and mode bits
- Process context

## Architecture

```
┌─────────────────────────────────────┐
│  User-Space Application (Python)    │
│  - Load eBPF bytecode               │
│  - Attach to hooks                  │
│  - Poll ring buffers                │
│  - Export to JSON / Amalia          │
└────────────────┬────────────────────┘
                 │
         Ring Buffer (IPC)
                 │
┌────────────────▼────────────────────┐
│  Kernel Space (eBPF Programs)       │
│  - Tracepoints (sched, syscalls)    │
│  - Kprobes (TCP connections)        │
│  - Event filtering & aggregation    │
│  - Direct kernel data access        │
└─────────────────────────────────────┘
```

## Performance

| Metric | Value | Impact |
|--------|-------|--------|
| CPU overhead | ~1-3% | Negligible |
| Memory usage | ~30MB | Minimal |
| Syscall latency | +0.2µs | Imperceptible |
| Event loss | ~2% (configurable) | Acceptable |

**Suitable for 24/7 continuous monitoring** without performance degradation.

## Requirements

### System
- Linux kernel 5.8+ (for ringbuf support)
- Root access
- Internet for initial setup

### Build
- clang/LLVM
- Python 3.6+
- BCC (or libbpf-python)
- Linux headers

### Supported Platforms
- Raspberry Pi (ARMv7/ARMv8)
- Ubuntu/Debian
- RHEL/CentOS/Fedora
- Any Linux with kernel 5.8+

## Documentation

- **[QUICKSTART.md](docs/QUICKSTART.md)** - 5-minute deployment guide
- **[USAGE.md](docs/USAGE.md)** - Advanced usage patterns and integration
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design and concepts
- **[SETUP.md](docs/SETUP.md)** - Development environment configuration

## Use Cases

### Blue Team Detection Tuning
- Validate threat detection signatures (YARA, Sigma-Lite)
- Test response procedures against real kernel-level telemetry
- Measure detection latency and accuracy
- Tune threat correlation thresholds

### Lab Environment Monitoring
- Continuous telemetry collection in isolated test networks
- Real-time process, network, and file access visibility
- Integration with SIEM and threat analysis platforms
- Incident response testing and validation

### Security Research
- Kernel-level event collection research
- eBPF performance and reliability testing
- Threat emulation and detection validation
- Blue team capability assessment

## Authorization & Legal Notice

⚠️ **AUTHORIZATION REQUIRED**

This tool generates realistic threat telemetry. Use only in:
- ✅ Authorized lab environments
- ✅ With proper Rules of Engagement (RoE)
- ✅ With system owner consent
- ✅ For defensive testing purposes

Unauthorized use is illegal.

## Blue Team Detection Considerations

**What This Tool Does**:
- Generates realistic process, network, and file access events
- Tests detection coverage for kernel-level visibility
- Validates threat analysis pipelines
- Provides telemetry for incident response validation

**What Monitoring Should Catch**:
- eBPF program loading (via audit or syscall monitoring)
- Ring buffer memory access patterns
- Process execution events flowing through detection systems
- Network connection events in detection pipeline

## 🤝 Contributing

Contributions welcome! Focus areas:
- Additional event types (DNS, IPC, memory access)
- Evasion techniques (rootkit integration, audit log filtering)
- Detection improvements and signatures
- Platform support (ARM, x86_64, other architectures)

## License

[To be determined]

## 👥 Contact

**Author**: Niels Weistra  
**Organization**: ITL (ITLusions)  
**Project**: Amalia Red Team Platform  
**Date**: August 9, 2026

## 🔗 References

- [eBPF Official Guide](https://ebpf.io/)
- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [BCC Project](https://github.com/iovisor/bcc)
- MITRE ATT&CK Framework
- CVE-2021-3490, CVE-2020-27194 (eBPF verifier)
