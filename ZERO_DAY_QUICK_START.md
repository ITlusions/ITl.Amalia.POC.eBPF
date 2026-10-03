# Quick Start: Zero-Day Crash Analysis Runbook

**Doel:** Stap-voor-stap implementatie van crash detection en reverse engineering workflow

---

## Inleiding

Dit document begeleidt je door het gebruik van de **Zero-Day Crash Analysis Runbook** met de eBPF implant. Je gaat:

1. Crash detection activeren
2. Automatische triage uitvoeren
3. Forensische collectie starten
4. Reverse engineering beginnen
5. POC reproduceren

**Vereisten:**
- Linux 5.8+ kernel
- Root privileges
- GDB installed (`sudo apt install gdb`)
- Core dumps enabled

---

## Fase 1: Crash Detection Inschakelen

### Stap 1: Configuration Update

```json
{
  "implant_id": "ebpf-sensor-poc-01",
  "enable_crash_detection": true,
  
  "crash_detection": {
    "monitored_signals": [4, 6, 7, 11],
    "monitored_processes": ["*apache*", "*nginx*", "*java*", "*python*"],
    "coredump_enabled": true,
    "coredump_path": "/var/crashes",
    "alert_threshold": "HIGH"
  },
  
  "braincell_url": "ws://braincell.local:8000/ws/telemetry",
  "enable_crash_export": true
}
```

### Stap 2: Python Agent Start

```bash
cd d:\repos\ITL.Amalia.Poc.eBpf\userspace\src

# Start implant met crash detection
python examples/crash_demo.py --config config.json --crash-monitor

# Output:
# [+] eBPF crash detector initialized
# [+] Core dumps enabled at /var/crashes/
# [+] Monitoring signals: SIGILL, SIGABRT, SIGBUS, SIGSEGV
# [+] Listening for crashes...
```

---

## Fase 2: Crash Detection In Action

### Als een crash optreedt:

```
=== CRASH DETECTED ===
Timestamp: 2026-10-01T14:23:45.123456
Process: vulnerable_app (PID 12345)
Signal: SIGSEGV (11)
Binary: /usr/local/bin/vulnerable_app
RIP: 0x7ffff7ab4000 (in HEAP)

INITIAL TRIAGE:
├─ Signal type: SIGSEGV (+3 points)
├─ RIP location: HEAP (+2 points)
├─ Network activity before crash (+2 points)
├─ Coredump available (+1 point)
└─ Risk Score: 8/10 = HIGH

ACTION: P2 - Urgent Investigation
RECOMMENDATION: Begin reverse engineering

COREDUMP: /var/crashes/core-vulnerable_app-12345-1696167825
```

### Automatische Actie

De agent stuurt automatisch:

```
1. Alert naar BrainCell:
   POST ws://braincell.local:8000/ws/telemetry
   {
     "type": "crash_alert",
     "risk_level": "HIGH",
     "process": "vulnerable_app",
     "coredump": "/var/crashes/core-vulnerable_app-12345-1696167825"
   }

2. Alert naar SOC (email/Slack/PagerDuty)

3. Begint forensische collectie:
   - Syscall trace
   - Network activity
   - File access
   - Memory maps
```

---

## Fase 3: Forensische Analyse

### Python Code Voorbeeld

```python
from detection.crash_detection import get_crash_detector
import json

# Get crash detector
detector = get_crash_detector()

# Simuleer crash event (van eBPF)
crash_event = {
    "timestamp": 1696167825.123,
    "pid": 12345,
    "ppid": 1234,
    "uid": 1000,
    "gid": 1000,
    "comm": "vulnerable_app",
    "signal": 11,  # SIGSEGV
    "rip": 0x7ffff7ab4000,
    "rsp": 0x7ffffffde000,
    "rbp": 0x7ffffffde100,
    "network_events": [
        {
            "timestamp": 1696167824.5,
            "daddr": "10.0.0.50",
            "dport": 4444,
            "bytes_sent": 512
        }
    ]
}

# Process crash
crash = detector.process_crash_event(crash_event)

print(f"[+] Crash processed: {crash.process_name}")
print(f"[+] Risk level: {crash.risk_level}")
print(f"[+] Exploitable: {crash.exploitable}")
print(f"[+] Coredump: {crash.coredump_path}")

# Export report
report_path = detector.export_crash_report(crash)
print(f"[+] Report: {report_path}")

# Read report
with open(report_path) as f:
    report = json.load(f)
    print(json.dumps(report, indent=2))
```

**Output:**
```json
{
  "metadata": {
    "timestamp": "2026-10-01T14:23:45.123456",
    "process": "vulnerable_app",
    "binary": "/usr/local/bin/vulnerable_app",
    "signal": "SIGSEGV"
  },
  "risk_assessment": {
    "risk_score": 8,
    "risk_level": "HIGH",
    "exploitable": true
  },
  "forensics": {
    "cpu_context": {
      "rip": "0x7ffff7ab4000",
      "rip_location": "HEAP"
    },
    "stack_trace": [
      "#0  0x00007ffff7ab4000 in vulnerable_function () from /usr/local/bin/vulnerable_app",
      "#1  0x0000555555555555 in main () from /usr/local/bin/vulnerable_app"
    ],
    "coredump": "/var/crashes/core-vulnerable_app-12345-1696167825"
  }
}
```

---

## Fase 4: Reverse Engineering met GDB

### Stap 1: Coredump openen

```bash
# Vind het meest recente coredump
ls -lt /var/crashes/ | head -1

# Open in GDB
gdb /usr/local/bin/vulnerable_app \
    /var/crashes/core-vulnerable_app-12345-1696167825

# In GDB:
(gdb) bt
#0  0x00007ffff7ab4000 in ?? ()
#1  0x0000555555559123 in parse_input ()
#2  0x0000555555559000 in main ()

(gdb) info registers
rax            0x0
rbx            0x0
rcx            0x0
rdx            0x0
rsi            0x7ffff7ab4000   140737353805824
rdi            0x0
rbp            0x7ffffffde100   0x7ffffffde100
rsp            0x7ffffffde0f8   0x7ffffffde0f8
rip            0x7ffff7ab4000   0x7ffff7ab4000

(gdb) x/20i $rip
=> 0x7ffff7ab4000:  (bad)
   0x7ffff7ab4001:  (bad)
   0x7ffff7ab4002:  (bad)

(gdb) x/100x $rsp
0x7ffffffde0f8: 0x41414141  0x41414141  0x42424242  0x42424242
0x7ffffffde108: 0x43434343  0x43434343  0x44444444  0x44444444
# A's, B's, C's, D's = Buffer overflow pattern

(gdb) quit
```

### Interpretatie:
- **RIP = 0x7ffff7ab4000 (HEAP)** → Code execution from heap
- **Stack = A's, B's, C's, D's** → Controlled buffer overflow
- **Signal = SIGSEGV** → Crash on invalid memory access

**Conclusie: EXPLOIT DETECTED!**

---

## Fase 5: POC Creatie

### Python POC Template

```python
#!/usr/bin/env python3
"""
Zero-Day POC: Buffer Overflow in vulnerable_app

Based on crash analysis:
- Target: /usr/local/bin/vulnerable_app
- Vulnerability: Stack buffer overflow
- Exploitability: HIGH (code execution from heap)
"""

import socket
import sys
import subprocess
import time

TARGET_IP = "localhost"
TARGET_PORT = 8888
BINARY = "/usr/local/bin/vulnerable_app"

# Payload construction based on crash context
def create_payload():
    """Build exploit payload"""
    
    # Buffer size from coredump analysis
    BUFFER_SIZE = 1024
    
    # Fill buffer with controlled pattern
    payload = b"A" * BUFFER_SIZE
    
    # RIP overwrite (from crash RIP location)
    # 0x7ffff7ab4000 = attacker-controlled memory
    # We can write shellcode here
    payload += b"\\x41\\x42\\x43\\x44"  # Return address
    
    # Padding to align stack
    payload += b"\\x00" * 16
    
    return payload

def exploit():
    """Send exploit payload"""
    
    print(f"[*] Targeting: {BINARY}")
    print(f"[*] Connecting to {TARGET_IP}:{TARGET_PORT}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_IP, TARGET_PORT))
        
        payload = create_payload()
        print(f"[*] Sending payload ({len(payload)} bytes)")
        sock.sendall(payload)
        
        # Wait for crash
        time.sleep(1)
        
        # Check if crashed
        result = subprocess.run(
            ["pgrep", "-x", BINARY.split("/")[-1]],
            capture_output=True
        )
        
        if result.returncode != 0:
            print("[+] CRASH CONFIRMED!")
            print("[+] Exploit successful - process terminated")
            return True
        else:
            print("[-] Process still running - exploit failed")
            return False
        
        sock.close()
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    exploit()
```

### POC Testen

```bash
# Make executable
chmod +x exploit.py

# Run 20x to test reproducibility
for i in {1..20}; do
    python3 exploit.py
    sleep 1
done

# Expected output:
# [+] CRASH CONFIRMED! (20/20 times)
```

---

## Fase 6: Mitigation & Detection

### Detection Rule (Sigma)

```yaml
title: "Heap Buffer Overflow in vulnerable_app - Zero-Day"
status: production

detection:
  crash_event:
    process_name: "vulnerable_app"
    signal: 11  # SIGSEGV
    rip_location: "HEAP"
  
  exploitation_indicators:
    - network_activity_before: true
    - syscall_pattern: "recv|mmap"
    - controlled_buffer_pattern: true
  
  condition: crash_event and exploitation_indicators
  
level: critical
tags:
  - zero_day
  - buffer_overflow
  - heap_overflow
```

### Remediation Steps

```bash
# 1. Isolate system
systemctl stop vulnerable_app
iptables -I INPUT -j DROP

# 2. Check for lateral movement
journalctl -u vulnerable_app -n 100

# 3. Block attacker IP
iptables -I INPUT -s 10.0.0.50 -j DROP

# 4. Apply patches when available
# Contact vendor for security update

# 5. Monitor for recurrence
tail -f /var/log/syslog | grep vulnerable_app
```

---

## Workflow Summary

```
CRASH DETECTED
     ↓
AUTOMATIC TRIAGE (risk score)
     ↓
HIGH RISK? 
├─ YES → FORENSICS COLLECTION (coredump)
│         ↓
│       GDB ANALYSIS
│         ↓
│       REVERSE ENGINEERING (payload analysis)
│         ↓
│       POC CREATION (reproduce exploit)
│         ↓
│       MITIGATION (patch/block/detect)
│
└─ NO → LOG & MONITOR
```

---

## Troubleshooting

### "Cannot find coredump"
```bash
# Enable core dumps
ulimit -c unlimited

# Check status
cat /proc/sys/kernel/core_pattern

# Should output:
# /var/crashes/core-%e-%p-%t
```

### "GDB fails to attach"
```bash
# Check permissions
sudo sysctl kernel.yama.ptrace_scope=1  # Allow ptrace

# Or run as root
sudo gdb /path/to/binary /path/to/coredump
```

### "No network activity in crash context"
```bash
# Enable packet capture before crash
tcpdump -i any -nn -w capture.pcap port 4444

# Then replay crash trigger
```

---

## Next Steps

1. ✅ Crash detection enabled
2. ✅ Forensic collection working
3. ✅ Analysis and reverse engineering complete
4. ✅ POC reproduced reliably
5. ⏳ Vendor contacted for patch
6. ⏳ Detection rules deployed
7. ⏳ Monitoring in production

**Estimated Time to Mitigation:** 2-4 hours from initial crash detection

---

**Document versie:** 1.0  
**Laatst geupdate:** 2026-10-01  
**Contact:** Security Team
