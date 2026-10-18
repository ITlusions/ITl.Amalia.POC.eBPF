# Runbook: Zero-Day Crash Analysis en Reverse Engineering

**Status:** Production  
**Datum:** 2026-10-01  
**Doel:** Detecteren, analyseren, reverse engineren en reproduceerbaar maken van zero-day exploits via applicatie-crashes

## Autorisatie en operationele grens

- **Operator:** Niels Weistra, CISSP
- **RoE:** [RoE-ITlusions-Testlab-2026](../ITL.Amalia/docs/engagements/RoE-ITlusions-Testlab-2026.md)
- **Geldig:** 27 april 2026 t/m 31 december 2026, tenzij het engagement eerder wordt afgesloten
- **Toegestaan:** Uitsluitend systemen en testinstanties die in sectie 3.1 van de RoE zijn opgenomen
- **Uitgesloten:** Klantproductie, externe cloud-tenants en systemen van derden zonder afzonderlijke schriftelijke toestemming
- **Kritieke bevinding:** Test op het betreffende systeem pauzeren en vastleggen in BrainCell `incidents` en `vuln_reports`

De CISSP-certificering is professionele kwalificatie; de schriftelijke RoE vormt de autorisatie. Voor iedere analyse en reproductie moet de actuele scope vooraf worden gecontroleerd.

---

## Tabel van Inhoud

1. [Detectie & Monitoring](#1-detectie--monitoring)
2. [Triage & Classificatie](#2-triage--classificatie)
3. [Forensische Verzameling](#3-forensische-verzameling)
4. [Analyse van Crash Dump](#4-analyse-van-crash-dump)
5. [Reverse Engineering van Exploitcode](#5-reverse-engineering-van-exploitcode)
6. [Reproduceerbaarheid Testen](#6-reproduceerbaarheid-testen)
7. [Mitigation & Detection](#7-mitigation--detection)

---

## 1. Detectie & Monitoring

### 1.1 eBPF Crash Monitoring

**Doel:** Real-time detectie van applicatie-crashes met volledige context

**Stap 1: Kernel-Level Crash Hook**
```bash
# eBPF program monitort proces-signalen
# Capture: SIGSEGV (11), SIGABRT (6), SIGBUS (7), SIGILL (4)

bpf_tracepoint__signal__signal_deliver {
    sig_num = ctx->sig  # Signal number
    
    if (sig_num == 11 || sig_num == 6 || sig_num == 7 || sig_num == 4) {
        event.type = "process_crash"
        event.pid = bpf_get_current_pid_tgid() >> 32
        event.signal = sig_num
        event.process_name = bpf_get_current_comm()
        event.timestamp = bpf_ktime_get_ns()
        event.rip = ctx->rip  # Instruction pointer
        event.rsp = ctx->rsp  # Stack pointer
        
        crash_events.ringbuf_output(&event, sizeof(event), 0)
    }
}
```

**Stap 2: Signaal Mapping**
```python
SIGNAL_MAPPING = {
    4: "SIGILL (Illegal Instruction)",
    6: "SIGABRT (Abort)",
    7: "SIGBUS (Bus Error - memory alignment)",
    8: "SIGFPE (Floating Point Exception)",
    11: "SIGSEGV (Segmentation Fault)",
    14: "SIGALRM (Alarm)",
    15: "SIGTERM (Termination)",
}

# Severity scoring
SEVERITY = {
    "SIGSEGV": "CRITICAL",    # Exploitable memory access
    "SIGABRT": "HIGH",         # Intentional termination (possible exploit)
    "SIGBUS": "HIGH",          # Memory alignment issue (exploitable)
    "SIGILL": "CRITICAL",      # Illegal instruction (JIT attack)
}
```

### 1.2 Alerting Rules

**eBPF Detection Rules:**
```yaml
title: "Unexpected Process Crash - Possible Zero-Day"
detection:
  crash_event:
    signal: [4, 6, 7, 11]  # SIGILL, SIGABRT, SIGBUS, SIGSEGV
    process_name:
      - "apache*"
      - "nginx*"
      - "mysql*"
      - "postgres*"
      - "java*"
      - "python*"
      - "node*"
  
  suspicious_indicators:
    - rip_in_heap_region: "true"        # Code execution from heap
    - rip_in_stack_region: "true"       # Stack overflow
    - network_activity_before_crash: "true"  # Remote trigger
    - file_access_before_crash: "true"  # File-based trigger
  
  condition: crash_event and suspicious_indicators
  
level: critical
tags:
  - zero_day
  - exploitation
  - reverse_engineering
```

---

## 2. Triage & Classificatie

### 2.1 Crash Triage Checklist

| Criterium | Onderzoeken | Score |
|-----------|-------------|-------|
| **Applicatie Type** | Web server, database, runtime | - |
| **Signaal Type** | SIGSEGV, SIGABRT, SIGBUS | High = exploitabel |
| **Instruction Pointer** | Code segment vs heap vs stack | Heap/stack = +2 |
| **Voorafgaande Activiteit** | Netwerk input, file read, syscall | Remote input = +2 |
| **Reproduceerbaar** | Is het altijd dezelfde trigger? | Ja = +2 |
| **Willekeurig Geheugen** | Raakt ASLR, heap layout af? | Ja = +2 |

**Risico Score Berekening:**
```
Laag (1-3):       Waarschijnlijk bug, geen exploit
Gemiddeld (4-6):  Mogelijk exploitabel, onderzoek nodig
Hoog (7-9):       Waarschijnlijk exploitabel zero-day
Kritiek (10+):    Actieve exploitatie waarschijnlijk
```

### 2.2 Snelle Triage Script

```python
class CrashTriage:
    def assess_crash(self, crash_event):
        score = 0
        
        # Signaal type assessment
        signal_risk = {"SIGSEGV": 3, "SIGABRT": 2, "SIGBUS": 3, "SIGILL": 3}
        score += signal_risk.get(crash_event.signal, 1)
        
        # Memory region assessment
        if self._is_heap_address(crash_event.rip):
            score += 2  # Code execution from heap
        elif self._is_stack_address(crash_event.rip):
            score += 2  # Stack corruption/overflow
        
        # Triggering method
        if crash_event.network_activity_before:
            score += 2  # Remote triggered
        if crash_event.file_access_before:
            score += 1  # File triggered
        
        # Reproduceerder
        if crash_event.reproducible:
            score += 2
        
        # Deterministic (não-ASLR)
        if crash_event.consistent_rip:
            score += 2
        
        risk_level = self._classify_risk(score)
        return {
            "risk_score": score,
            "risk_level": risk_level,
            "priority": self._assign_priority(score),
            "recommendation": self._get_recommendation(risk_level)
        }
    
    def _is_heap_address(self, addr):
        # Check if address falls in heap region
        return self.heap_start < addr < self.heap_end
    
    def _is_stack_address(self, addr):
        # Check if address falls in stack region
        return self.stack_start > addr > self.stack_end
    
    def _classify_risk(self, score):
        if score < 4: return "LOW"
        if score < 7: return "MEDIUM"
        if score < 10: return "HIGH"
        return "CRITICAL"
    
    def _assign_priority(self, score):
        if score >= 10: return "P1 - Immediate Response"
        if score >= 7: return "P2 - Urgent Investigation"
        if score >= 4: return "P3 - Standard Investigation"
        return "P4 - Log and Monitor"
```

---

## 3. Forensische Verzameling

### 3.1 eBPF-Based Crash Capture

**Wat we verzamelen bij crash:**

```python
@dataclass
class CrashContext:
    # Proces info
    pid: int
    ppid: int
    uid: int
    gid: int
    process_name: str
    binary_path: str
    
    # Crash info
    timestamp: float
    signal: int
    signal_name: str
    exit_code: int
    
    # CPU context
    rip: int  # Instruction pointer (crash location)
    rsp: int  # Stack pointer
    rbp: int  # Base pointer
    rax: int  # Accumulator
    rbx: int  # Base register
    rcx: int  # Counter register
    rdx: int  # Data register
    rsi: int  # Source index
    rdi: int  # Destination index
    
    # Memory context
    memory_maps: Dict  # /proc/[pid]/maps
    heap_start: int
    heap_end: int
    stack_start: int
    stack_end: int
    
    # System calls leading to crash (last 20)
    syscall_trace: List[Dict]
    
    # Network activity
    network_events_before: List[Dict]
    remote_ip: Optional[str]
    remote_port: Optional[int]
    
    # File activity
    file_access_before: List[Dict]
    
    # Stack trace (unwinding)
    stack_frames: List[str]
    
    # Coredump location
    coredump_path: str
    coredump_size: int
    
    # Environment
    env_vars: Dict
    open_files: List[str]
    loaded_libraries: List[str]
```

### 3.2 Crash Capture Workflow

**Fase 1: Signal Capture (kernel)**
```python
# eBPF captures at signal delivery time
def on_crash_signal(ctx):
    # Save CPU registers
    registers = {
        'rip': ctx.rip,
        'rsp': ctx.rsp,
        'rbp': ctx.rbp,
        'rax': ctx.rax,
        # ... all registers
    }
    
    # Save process info
    process = {
        'pid': get_pid(),
        'process_name': get_comm(),
        'binary_path': get_exe_path(),
    }
    
    # Save memory maps
    memory = read_maps_file(f'/proc/{pid}/maps')
    
    return CrashEvent(registers, process, memory)
```

**Fase 2: Syscall Trace (kernel)**
```c
// eBPF tracepoint for syscall monitoring
SEC("tp/raw_syscalls/sys_enter")
int trace_syscalls(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Store syscall in buffer (last 20 only)
    struct syscall_event event = {
        .timestamp = bpf_ktime_get_ns(),
        .syscall_id = ctx->id,
        .arg0 = ctx->args[0],
        .arg1 = ctx->args[1],
        .arg2 = ctx->args[2],
    };
    
    syscall_buffer.ringbuf_output(&event, sizeof(event), 0);
}
```

**Fase 3: Core Dump Collection**
```bash
# Enable core dumps
ulimit -c unlimited

# Configure core dump pattern
echo "/var/crashes/core-%e-%p-%t" > /proc/sys/kernel/core_pattern

# Ensure directory exists
mkdir -p /var/crashes
chmod 777 /var/crashes

# When crash occurs, kernel writes core dump automatically
# File: /var/crashes/core-[process_name]-[pid]-[timestamp]
```

---

## 4. Analyse van Crash Dump

### 4.1 GDB Crash Analysis

```bash
# Laad core dump
gdb /path/to/binary /path/to/coredump

# Commando's in GDB
(gdb) bt                      # Backtrace
(gdb) info registers          # CPU registers
(gdb) x/20i $rip              # Disassembly at crash point
(gdb) x/100x $rsp             # Stack contents
(gdb) info locals              # Local variables
(gdb) info args                # Function arguments
(gdb) frame 0                  # Frame 0 (innermost)
(gdb) disassemble              # Disassemble current function
```

### 4.2 Crash Pattern Analysis

**Signaalanalyse:**
```python
class CrashAnalyzer:
    def analyze_sigsegv(self, crash):
        """Analyze segmentation fault"""
        issue = "Invalid memory access"
        
        # Check if accessing null
        if crash.rip == 0x0:
            return ("NULL_POINTER_DEREFERENCE", "High exploitability")
        
        # Check if heap corruption
        if self.is_heap_address(crash.rip) and crash.memory_was_written:
            return ("HEAP_OVERFLOW", "Very high exploitability")
        
        # Check if stack overflow
        if self.is_stack_address(crash.rsp) and crash.rsp < self.stack_limit:
            return ("STACK_OVERFLOW", "Very high exploitability - ROP/shellcode possible")
        
        # Check if use-after-free
        if self.is_freed_memory(crash.rip):
            return ("USE_AFTER_FREE", "High exploitability")
        
        return (issue, "Medium exploitability")
    
    def analyze_sigabrt(self, crash):
        """Analyze abort signal"""
        # SIGABRT triggered by:
        # 1. Intentional abort() call - might be heap corruption check
        # 2. Double free detected
        # 3. Assertion failure
        
        if self.check_double_free(crash):
            return ("DOUBLE_FREE", "High exploitability")
        
        if self.check_assertion_failure(crash):
            return ("ASSERTION_FAILURE", "Medium exploitability")
        
        return ("ABORT_SIGNAL", "Unknown cause")
    
    def analyze_sigbus(self, crash):
        """Analyze bus error"""
        # Usually memory alignment issue or invalid memory access
        return ("BUS_ERROR_ALIGNMENT", "Medium exploitability - alignment issues")
    
    def analyze_sigill(self, crash):
        """Analyze illegal instruction"""
        # JIT attack, code corruption, or invalid instruction
        return ("ILLEGAL_INSTRUCTION", "Very high exploitability - possible JIT attack")
```

### 4.3 RIP Analysis (Crash Location)

```python
def analyze_rip_location(crash):
    """Determine where crash happened"""
    
    rip = crash.rip
    
    # Check against memory map
    for mem_region in crash.memory_maps:
        if mem_region.start <= rip <= mem_region.end:
            region_type = mem_region.type  # heap, stack, code, etc
            region_perms = mem_region.perms  # r,w,x
            
            if region_type == "heap":
                return {
                    "location": "HEAP",
                    "severity": "CRITICAL",
                    "implication": "Code execution from heap - likely exploit"
                }
            elif region_type == "stack":
                return {
                    "location": "STACK",
                    "severity": "CRITICAL",
                    "implication": "Code execution from stack - buffer overflow"
                }
            elif region_type == "code" and "x" not in region_perms:
                return {
                    "location": "DATA_SECTION",
                    "severity": "CRITICAL",
                    "implication": "Executing non-executable memory"
                }
            elif region_type == "code" and "x" in region_perms:
                return {
                    "location": "CODE_SECTION",
                    "severity": "MEDIUM",
                    "implication": "Crash in legitimate code - might be legitimate bug"
                }
    
    return {
        "location": "UNKNOWN",
        "severity": "MEDIUM",
        "implication": "Could not map crash location"
    }
```

---

## 5. Reverse Engineering van Exploitcode

### 5.1 Syscall Trace Analyse

**Doel:** Begrijpen hoe de exploit de crash veroorzaakt

```python
class ExploitTraceAnalyzer:
    def analyze_syscall_sequence(self, syscall_trace):
        """Analyze sequence of syscalls leading to crash"""
        
        exploit_pattern = []
        
        for syscall in syscall_trace:
            syscall_name = self.syscall_names[syscall.id]
            
            # Pattern detection
            if syscall_name in ["read", "recv", "recvfrom"]:
                exploit_pattern.append({
                    "phase": "INPUT",
                    "syscall": syscall_name,
                    "arg0": syscall.arg0,  # file descriptor / socket
                    "arg1": syscall.arg1,  # buffer pointer (target)
                    "arg2": syscall.arg2,  # length
                    "implication": "Attacker input being read into buffer"
                })
            
            elif syscall_name == "mmap":
                exploit_pattern.append({
                    "phase": "MEMORY_SETUP",
                    "syscall": "mmap",
                    "addr": syscall.arg0,
                    "length": syscall.arg1,
                    "prot": syscall.arg2,  # r/w/x flags
                    "implication": "Memory mapping for exploit setup"
                })
            
            elif syscall_name == "mprotect":
                exploit_pattern.append({
                    "phase": "MEMORY_CHANGE",
                    "syscall": "mprotect",
                    "addr": syscall.arg0,
                    "prot_old": "r/w/x (was)",
                    "prot_new": syscall.arg2,  # New permissions
                    "implication": "Making memory executable or writable"
                })
            
            elif syscall_name in ["write", "writev"]:
                exploit_pattern.append({
                    "phase": "PAYLOAD_WRITE",
                    "syscall": syscall_name,
                    "implication": "Writing shellcode or payload"
                })
        
        # Pattern classification
        return self.classify_exploit_pattern(exploit_pattern)
    
    def classify_exploit_pattern(self, pattern):
        """Classify exploit type based on syscall sequence"""
        
        phases = [p["phase"] for p in pattern]
        
        if "INPUT" in phases and "MEMORY_SETUP" in phases:
            return "BUFFER_OVERFLOW_EXPLOIT"
        
        if "MEMORY_CHANGE" in phases and phases[-1] == "PAYLOAD_WRITE":
            return "CODE_INJECTION_EXPLOIT"
        
        if "mmap" in str(pattern) and "mprotect" in str(pattern):
            return "JIT_SPRAYING_EXPLOIT"
        
        return "UNKNOWN_EXPLOIT_TYPE"
```

### 5.2 Stack Trace Unwinding

**Doel:** Begrijpen call stack op crash moment**

```python
def unwind_stack(crash):
    """Unwind stack to see call chain"""
    
    stack_frames = []
    rbp = crash.rbp  # Base pointer
    rsp = crash.rsp  # Stack pointer
    
    # Read stack memory
    stack_memory = read_memory(rsp, 4096)
    
    frame_no = 0
    while frame_no < 20:  # Max 20 frames
        # Read return address
        return_addr = read_pointer(stack_memory, frame_no * 8)
        
        if return_addr == 0:
            break
        
        # Resolve symbol
        symbol = resolve_symbol(return_addr)
        
        stack_frames.append({
            "frame": frame_no,
            "address": hex(return_addr),
            "symbol": symbol,
            "binary": get_binary_from_address(return_addr)
        })
        
        frame_no += 1
    
    return stack_frames
```

### 5.3 Disassembly Analysis

```bash
# Extract disassembly around crash point
objdump -d /path/to/binary | grep -A20 -B20 crash_function

# Use radare2 for advanced analysis
r2 /path/to/binary
> aa          # Analyze all
> sf crash_function  # Seek to function
> pdf         # Print function disassembly
> px 256      # Hex dump at current position
```

---

## 6. Reproduceerbaarheid Testen

### 6.1 Crash Reproduction Script

**Doel:** Maken van reproduceerbare test case

```python
class CrashReproducer:
    def create_poc(self, crash_context, exploit_analysis):
        """Create proof-of-concept to reproduce crash"""
        
        # Determine trigger method
        trigger_method = exploit_analysis.get("trigger_method")
        
        if trigger_method == "network":
            poc = self.create_network_poc(crash_context)
        elif trigger_method == "file":
            poc = self.create_file_poc(crash_context)
        elif trigger_method == "command_line":
            poc = self.create_cmdline_poc(crash_context)
        else:
            poc = self.create_generic_poc(crash_context)
        
        return poc
    
    def create_network_poc(self, context):
        """Create network-based POC"""
        
        poc_code = f"""
#!/usr/bin/env python3
import socket
import sys

# Target application
TARGET_IP = "{context.remote_ip}"
TARGET_PORT = {context.remote_port}
BINARY = "{context.binary_path}"

# Crash trigger payload
# Based on syscall analysis: {context.exploit_pattern}
PAYLOAD = b""

# Build payload based on crash context
if "{context.signal}" == "SIGSEGV":
    # Buffer overflow pattern
    PAYLOAD = b"A" * {context.buffer_size}
    PAYLOAD += b"\\x41\\x42\\x43\\x44"  # RIP overwrite
elif "{context.signal}" == "SIGABRT":
    # Heap corruption pattern
    PAYLOAD = b"\\x00" * 1000  # Heap spray
    PAYLOAD += b"EXPLOIT_DATA"

# Send payload
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((TARGET_IP, TARGET_PORT))
sock.sendall(PAYLOAD)
sock.recv(1024)
sock.close()

print("[+] Payload sent - {context.binary_path} should crash")
print(f"[+] Expected signal: {context.signal}")
"""
        
        return poc_code
    
    def create_file_poc(self, context):
        """Create file-based POC"""
        
        poc_code = f"""
#!/usr/bin/env python3
import subprocess
import os

BINARY = "{context.binary_path}"

# Malicious file content
PAYLOAD = b""  # Filled based on analysis

# Write malicious file
with open("crash.dat", "wb") as f:
    f.write(PAYLOAD)

# Execute binary with malicious file
result = subprocess.run(
    [BINARY, "crash.dat"],
    capture_output=True,
    timeout=5
)

print(f"[+] Executed: {BINARY} crash.dat")
print(f"[+] Return code: {result.returncode}")
if result.returncode < 0:
    print(f"[+] Killed by signal: {-result.returncode}")
"""
        
        return poc_code
```

### 6.2 Reproduceerbaar Test Checklist

```
[ ] POC beschrijving geschreven
[ ] POC code gebuild/compiled
[ ] POC op test machine getest
[ ] Crash consistent reproductie (>10x)
[ ] Signal type matchend (SIGSEGV/SIGABRT/etc)
[ ] RIP register op dezelfde waarde
[ ] Stack trace identiek
[ ] Coredump gegenereerd
[ ] Coredump bevestigt exploit
[ ] Versie van applicatie gedocumenteerd
[ ] Kernel versie gedocumenteerd
[ ] ASLR status gedocumenteerd
[ ] Payload size consistent
[ ] Timing stabiel (niet race-condition)
[ ] Proof of exploitabiliteit aangetoond
```

### 6.3 Test Automation

```python
class CrashReproductionTester:
    def test_reproducibility(self, poc, iterations=20):
        """Test if POC reliably crashes the binary"""
        
        successful_crashes = 0
        failed_attempts = 0
        
        for i in range(iterations):
            try:
                result = subprocess.run(
                    poc.split(),
                    timeout=5,
                    capture_output=True
                )
                
                # Check for crash
                if result.returncode < 0:  # Killed by signal
                    signal_num = abs(result.returncode)
                    successful_crashes += 1
                    print(f"[+] Crash #{i+1}: Signal {signal_num}")
                else:
                    failed_attempts += 1
                    print(f"[-] Attempt #{i+1}: No crash (exit code {result.returncode})")
            
            except subprocess.TimeoutExpired:
                failed_attempts += 1
                print(f"[-] Attempt #{i+1}: Timeout")
        
        reproducibility_rate = successful_crashes / iterations * 100
        
        print(f"\n=== REPRODUCIBILITY RESULTS ===")
        print(f"Success rate: {reproducibility_rate}%")
        print(f"Crashes: {successful_crashes}/{iterations}")
        
        if reproducibility_rate >= 90:
            print("[+] POC is HIGHLY reproducible")
            return True
        elif reproducibility_rate >= 70:
            print("[!] POC is MODERATELY reproducible (might be race condition)")
            return True
        else:
            print("[-] POC is NOT reliably reproducible")
            return False
```

---

## 7. Mitigation & Detection

### 7.1 Detection Rules

**Voor BrainCell/Sigma Detection:**

```yaml
title: "Zero-Day Crash Pattern - Heap Overflow Detection"
status: production

detection:
  crash_pattern:
    signal: [6, 11]  # SIGABRT, SIGSEGV
    rip_location: "heap"
    memory_written_before: "true"
  
  exploitation_indicators:
    - syscall_pattern: "read|mmap|mprotect"
    - network_input_before_crash: "true"
    - memory_page_permission_changed: "true"
  
  condition: crash_pattern and exploitation_indicators
  
level: critical
tags:
  - zero_day
  - heap_overflow
  - exploitation
```

### 7.2 Monitoring & Alerting

```python
class ZeroDayMonitor:
    def setup_monitoring(self):
        """Setup continuous zero-day crash monitoring"""
        
        # Monitor these signals
        self.monitored_signals = [4, 6, 7, 11]  # SIGILL, SIGABRT, SIGBUS, SIGSEGV
        
        # Monitor these processes
        self.monitored_processes = [
            "apache*", "nginx*", "mysql*", "postgres*",
            "java*", "python*", "node*", "php*"
        ]
        
        # Alert thresholds
        self.thresholds = {
            "crashes_per_minute": 3,
            "unique_processes": 2,
            "exploitable_crashes": 1
        }
    
    def on_crash_detected(self, crash_event):
        """Handle crash event"""
        
        # Triage
        risk_score = self.triage(crash_event)
        
        # If high risk
        if risk_score >= 8:
            # Alert SOC
            self.alert_soc(crash_event, risk_score)
            
            # Collect forensics automatically
            forensics = self.collect_forensics(crash_event)
            
            # Begin analysis workflow
            self.start_analysis_workflow(forensics)
            
            # Export to SOAR
            self.export_to_soar(crash_event, forensics)
    
    def alert_soc(self, crash, score):
        """Send alert to Security Operations Center"""
        
        alert = f"""
CRITICAL: Zero-Day Crash Detected
Risk Score: {score}/10
Binary: {crash.binary_path}
Signal: {crash.signal_name}
RIP: 0x{crash.rip:x} (in {crash.rip_location})
Timestamp: {crash.timestamp}

IMMEDIATE ACTIONS:
1. Isolate affected system if in production
2. Pull coredump: {crash.coredump_path}
3. Start reverse engineering
4. Check for similar crashes on other systems
5. Review network logs for attacker IP: {crash.remote_ip}
"""
        
        # Send via email, Slack, PagerDuty, etc
        self.send_alert(alert)
```

### 7.3 Patch & Mitigation

**Na Zero-Day identificatie:**

```bash
# 1. Immediate containment
systemctl stop vulnerable_service
iptables -I INPUT -s 0.0.0.0/0 -p tcp --dport 8080 -j DROP

# 2. Workaround if available
# Example: Disable vulnerable feature
sed -i 's/enable_feature=1/enable_feature=0/' /etc/app.conf

# 3. Request vendor patch
# File CVE if not already reported
# https://cve.mitre.org/

# 4. Monitor for exploitation
tcpdump -i any -nn "host attacker_ip" -w exploitation.pcap

# 5. Timeline: vendor response → patch testing → deployment
```

---

## Workflow Diagram

```
CRASH DETECTED
       |
       v
[1] MONITORING & ALERTING
    ├─ eBPF captures signal
    ├─ Risk scoring
    └─ Alert if P1/P2
       |
       v
[2] TRIAGE
    ├─ Signal type analysis
    ├─ Memory location check
    ├─ Reproducibility test
    └─ Risk classification
       |
       v
[3] FORENSICS COLLECTION
    ├─ Coredump capture
    ├─ Syscall trace
    ├─ Memory maps
    ├─ Network events
    └─ Stack unwinding
       |
       v
[4] CRASH ANALYSIS
    ├─ GDB analysis
    ├─ RIP location mapping
    ├─ Signal interpretation
    └─ Exploitability assessment
       |
       v
[5] REVERSE ENGINEERING
    ├─ Syscall sequence analysis
    ├─ Exploit pattern detection
    ├─ Stack trace interpretation
    └─ Disassembly review
       |
       v
[6] POC CREATION & TESTING
    ├─ Build proof-of-concept
    ├─ Test reproducibility
    ├─ Confirm exploitability
    └─ Document payload
       |
       v
[7] MITIGATION
    ├─ Isolate/patch system
    ├─ Create detection rules
    ├─ File CVE/advisory
    └─ Deploy fixes
```

---

## Bijlage: Commands Reference

```bash
# Core dump analysis
gdb binary coredump
objdump -d binary > disassembly.txt
readelf -l binary  # Memory layout

# System call tracing
strace -e trace=memory,mmap,mprotect process
ltrace -e '*' process  # Library calls

# Memory analysis
checksec binary  # Security features
file binary
ldd binary  # Dependencies

# Network analysis
netstat -tlnp  # Listening ports
tcpdump -i any -nn "port 8080" -w traffic.pcap

# Process analysis
ps aux | grep process_name
lsof -p PID  # Open files
cat /proc/PID/maps  # Memory map
cat /proc/PID/status  # Process status

# eBPF monitoring
bpftool prog list
bpftool prog show id NUM
cat /sys/kernel/debug/tracing/trace_pipe
```

---

## Document Control

| Versie | Datum | Auteur | Wijzigingen |
|--------|-------|--------|------------|
| 1.0 | 2026-10-01 | Security Team | Initiale runbook |

**Laatst geupdate:** 2026-10-01  
**Volgende review:** 2026-12-01
