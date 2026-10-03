"""
Crash Detection Module - Zero-Day Exploitation Monitoring

Monitors process crashes (SIGSEGV, SIGABRT, SIGBUS, SIGILL) using eBPF
and collects forensic context for reverse engineering.

Integrates with crash analysis runbook for automated triage and analysis.
"""

import time
import json
import subprocess
import os
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SignalType(Enum):
    """Process crash signals"""
    SIGILL = 4      # Illegal instruction
    SIGABRT = 6     # Abort signal
    SIGBUS = 7      # Bus error
    SIGSEGV = 11    # Segmentation fault


class RiskLevel(Enum):
    """Crash risk classification"""
    LOW = "LOW"           # < 4 points
    MEDIUM = "MEDIUM"     # 4-6 points
    HIGH = "HIGH"         # 7-9 points
    CRITICAL = "CRITICAL" # 10+ points


@dataclass
class CrashEvent:
    """Crash event captured by eBPF"""
    timestamp: float
    timestamp_iso: str
    pid: int
    ppid: int
    uid: int
    gid: int
    process_name: str
    binary_path: str
    signal: int
    signal_name: str
    
    # CPU context at crash
    rip: int  # Instruction pointer (crash location)
    rsp: int  # Stack pointer
    rbp: int  # Base pointer
    rax: int
    rbx: int
    rcx: int
    rdx: int
    rsi: int
    rdi: int
    
    # Memory context
    memory_maps: Dict[str, Any] = field(default_factory=dict)
    heap_start: int = 0
    heap_end: int = 0
    stack_start: int = 0
    stack_end: int = 0
    
    # Execution context
    syscall_trace: List[Dict] = field(default_factory=list)
    network_events_before: List[Dict] = field(default_factory=list)
    file_access_before: List[Dict] = field(default_factory=list)
    
    # Analysis
    rip_location: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "MEDIUM"
    exploitable: bool = False
    
    # Artifacts
    coredump_path: Optional[str] = None
    coredump_size: int = 0


@dataclass
class CrashTriage:
    """Crash triage assessment"""
    crash: CrashEvent
    risk_score: int
    risk_level: RiskLevel
    priority: str
    recommendation: str
    indicators: List[str] = field(default_factory=list)


class CrashDetector:
    """Detects and analyzes process crashes for zero-day exploitation"""
    
    SIGNAL_NAMES = {
        4: "SIGILL",
        6: "SIGABRT",
        7: "SIGBUS",
        11: "SIGSEGV",
    }
    
    MONITORED_SIGNALS = [4, 6, 7, 11]
    
    def __init__(self):
        """Initialize crash detector"""
        self.crash_events = []
        self.triages = []
        self.enable_coredumps()
    
    def enable_coredumps(self):
        """Enable core dump generation for analysis"""
        try:
            # Set unlimited core dump size
            os.system("ulimit -c unlimited")
            
            # Configure core dump location
            os.makedirs("/var/crashes", exist_ok=True)
            os.chmod("/var/crashes", 0o777)
            
            # Set core pattern
            with open("/proc/sys/kernel/core_pattern", "w") as f:
                f.write("/var/crashes/core-%e-%p-%t")
            
            logger.info("[+] Core dumps enabled at /var/crashes/")
        except PermissionError:
            logger.warning("[!] Cannot enable core dumps (requires root)")
    
    def process_crash_event(self, ebpf_event: Dict) -> CrashEvent:
        """Process crash event from eBPF kernel program"""
        
        crash = CrashEvent(
            timestamp=ebpf_event.get("timestamp", time.time()),
            timestamp_iso=datetime.fromtimestamp(ebpf_event.get("timestamp", time.time())).isoformat(),
            pid=ebpf_event.get("pid"),
            ppid=ebpf_event.get("ppid"),
            uid=ebpf_event.get("uid"),
            gid=ebpf_event.get("gid"),
            process_name=ebpf_event.get("comm"),
            binary_path=self._get_binary_path(ebpf_event.get("pid")),
            signal=ebpf_event.get("signal"),
            signal_name=self.SIGNAL_NAMES.get(ebpf_event.get("signal"), "UNKNOWN"),
            rip=ebpf_event.get("rip"),
            rsp=ebpf_event.get("rsp"),
            rbp=ebpf_event.get("rbp"),
            rax=ebpf_event.get("rax"),
            rbx=ebpf_event.get("rbx"),
            rcx=ebpf_event.get("rcx"),
            rdx=ebpf_event.get("rdx"),
            rsi=ebpf_event.get("rsi"),
            rdi=ebpf_event.get("rdi"),
        )
        
        # Collect additional context
        crash.memory_maps = self._read_memory_maps(crash.pid)
        crash.heap_start, crash.heap_end = self._get_heap_range(crash.pid)
        crash.stack_start, crash.stack_end = self._get_stack_range(crash.pid)
        
        # Map RIP to memory region
        crash.rip_location = self._map_rip_location(crash)
        
        # Collect syscall trace
        crash.syscall_trace = self._get_syscall_trace(crash.pid)
        
        # Collect network events
        crash.network_events_before = ebpf_event.get("network_events", [])
        
        # Collect file access
        crash.file_access_before = ebpf_event.get("file_events", [])
        
        # Perform triage
        triage = self.triage_crash(crash)
        crash.risk_score = triage.risk_score
        crash.risk_level = triage.risk_level.value
        crash.exploitable = triage.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        
        # Collect coredump
        crash.coredump_path = self._find_coredump(crash)
        if crash.coredump_path:
            crash.coredump_size = os.path.getsize(crash.coredump_path)
        
        self.crash_events.append(crash)
        logger.warning(f"[!] Crash detected: {crash.process_name} (PID {crash.pid}) - {crash.signal_name}")
        
        return crash
    
    def triage_crash(self, crash: CrashEvent) -> CrashTriage:
        """Assess crash exploitability (runbook phase 2)"""
        
        score = 0
        indicators = []
        
        # 1. Signal type assessment
        signal_risk = {
            11: 3,  # SIGSEGV - highest risk
            7: 3,   # SIGBUS
            4: 3,   # SIGILL
            6: 2,   # SIGABRT
        }
        signal_points = signal_risk.get(crash.signal, 1)
        score += signal_points
        indicators.append(f"Signal type: {crash.signal_name} (+{signal_points})")
        
        # 2. Memory region assessment
        if crash.rip_location == "HEAP":
            score += 2
            indicators.append("Code execution from heap (+2)")
        elif crash.rip_location == "STACK":
            score += 2
            indicators.append("Code execution from stack (+2)")
        elif crash.rip_location == "DATA":
            score += 1
            indicators.append("Executing non-executable memory (+1)")
        
        # 3. Triggering method
        if crash.network_events_before:
            score += 2
            indicators.append(f"Remote triggered ({len(crash.network_events_before)} events) (+2)")
        elif crash.file_access_before:
            score += 1
            indicators.append("File triggered (+1)")
        
        # 4. Reproducibility (check syscall consistency)
        if len(crash.syscall_trace) > 0:
            score += 1
            indicators.append(f"Syscall trace available ({len(crash.syscall_trace)} calls) (+1)")
        
        # 5. Coredump available
        if crash.coredump_path:
            score += 1
            indicators.append("Coredump available (+1)")
        
        # Classify risk level
        if score < 4:
            risk_level = RiskLevel.LOW
            priority = "P4 - Log and Monitor"
            recommendation = "Likely legitimate bug, add to known issues"
        elif score < 7:
            risk_level = RiskLevel.MEDIUM
            priority = "P3 - Standard Investigation"
            recommendation = "Investigate but not immediately critical"
        elif score < 10:
            risk_level = RiskLevel.HIGH
            priority = "P2 - Urgent Investigation"
            recommendation = "Begin reverse engineering and POC creation"
        else:
            risk_level = RiskLevel.CRITICAL
            priority = "P1 - Immediate Response"
            recommendation = "Treat as active zero-day exploitation"
        
        triage = CrashTriage(
            crash=crash,
            risk_score=score,
            risk_level=risk_level,
            priority=priority,
            recommendation=recommendation,
            indicators=indicators
        )
        
        self.triages.append(triage)
        return triage
    
    def analyze_crash(self, crash: CrashEvent) -> Dict[str, Any]:
        """Analyze crash for reverse engineering (runbook phase 4-5)"""
        
        analysis = {
            "timestamp": crash.timestamp_iso,
            "binary": crash.binary_path,
            "process": crash.process_name,
            "pid": crash.pid,
            "signal": crash.signal_name,
            "risk_level": crash.risk_level,
            "rip_location": crash.rip_location,
            "coredump": crash.coredump_path,
        }
        
        # Signal-specific analysis
        if crash.signal == SignalType.SIGSEGV.value:
            analysis["signal_analysis"] = self._analyze_sigsegv(crash)
        elif crash.signal == SignalType.SIGABRT.value:
            analysis["signal_analysis"] = self._analyze_sigabrt(crash)
        elif crash.signal == SignalType.SIGBUS.value:
            analysis["signal_analysis"] = self._analyze_sigbus(crash)
        elif crash.signal == SignalType.SIGILL.value:
            analysis["signal_analysis"] = self._analyze_sigill(crash)
        
        # Syscall pattern analysis
        if crash.syscall_trace:
            analysis["exploit_pattern"] = self._analyze_syscall_pattern(crash.syscall_trace)
        
        # Stack unwinding
        analysis["stack_trace"] = self._unwind_stack(crash)
        
        # Memory analysis
        analysis["memory_summary"] = {
            "heap": f"0x{crash.heap_start:x} - 0x{crash.heap_end:x}",
            "stack": f"0x{crash.stack_start:x} - 0x{crash.stack_end:x}",
            "rip_in_heap": crash.heap_start <= crash.rip <= crash.heap_end,
            "rip_in_stack": crash.stack_start >= crash.rip >= crash.stack_end,
        }
        
        return analysis
    
    def _analyze_sigsegv(self, crash: CrashEvent) -> Dict[str, str]:
        """Analyze segmentation fault"""
        
        if crash.rip == 0x0:
            return {
                "type": "NULL_POINTER_DEREFERENCE",
                "severity": "HIGH",
                "implication": "Invalid memory access - potential exploitation"
            }
        
        if crash.rip_location == "HEAP":
            return {
                "type": "HEAP_OVERFLOW",
                "severity": "CRITICAL",
                "implication": "Code execution from heap - very likely exploit"
            }
        
        if crash.rip_location == "STACK":
            return {
                "type": "STACK_OVERFLOW",
                "severity": "CRITICAL",
                "implication": "Stack overflow - ROP/shellcode execution possible"
            }
        
        if self._is_freed_memory(crash):
            return {
                "type": "USE_AFTER_FREE",
                "severity": "HIGH",
                "implication": "UAF vulnerability - highly exploitable"
            }
        
        return {
            "type": "SEGMENTATION_FAULT",
            "severity": "MEDIUM",
            "implication": "Generic segfault - analyze further"
        }
    
    def _analyze_sigabrt(self, crash: CrashEvent) -> Dict[str, str]:
        """Analyze abort signal"""
        
        if self._check_double_free(crash):
            return {
                "type": "DOUBLE_FREE",
                "severity": "HIGH",
                "implication": "Heap corruption - potential exploitation"
            }
        
        if self._check_heap_corruption(crash):
            return {
                "type": "HEAP_CORRUPTION",
                "severity": "HIGH",
                "implication": "Heap checks failed - likely exploit triggered abort"
            }
        
        return {
            "type": "ABORT_SIGNAL",
            "severity": "MEDIUM",
            "implication": "Intentional abort or assertion failure"
        }
    
    def _analyze_sigbus(self, crash: CrashEvent) -> Dict[str, str]:
        """Analyze bus error"""
        
        return {
            "type": "BUS_ERROR",
            "severity": "MEDIUM",
            "implication": "Memory alignment issue - potential alignment bypass exploit"
        }
    
    def _analyze_sigill(self, crash: CrashEvent) -> Dict[str, str]:
        """Analyze illegal instruction"""
        
        return {
            "type": "ILLEGAL_INSTRUCTION",
            "severity": "CRITICAL",
            "implication": "Possible JIT attack or code corruption - very likely exploited"
        }
    
    def _analyze_syscall_pattern(self, syscall_trace: List[Dict]) -> Dict[str, str]:
        """Analyze syscall sequence for exploit patterns"""
        
        pattern = []
        for syscall in syscall_trace:
            syscall_name = syscall.get("name", "unknown")
            
            if syscall_name in ["read", "recv", "recvfrom"]:
                pattern.append("INPUT")
            elif syscall_name in ["mmap", "mmap2"]:
                pattern.append("MEMORY_SETUP")
            elif syscall_name == "mprotect":
                pattern.append("MEMORY_CHANGE")
            elif syscall_name in ["write", "writev"]:
                pattern.append("PAYLOAD_WRITE")
        
        if "INPUT" in pattern and "MEMORY_SETUP" in pattern:
            return {
                "type": "BUFFER_OVERFLOW_EXPLOIT",
                "likelihood": "HIGH"
            }
        
        if "MEMORY_CHANGE" in pattern and "PAYLOAD_WRITE" in pattern:
            return {
                "type": "CODE_INJECTION_EXPLOIT",
                "likelihood": "HIGH"
            }
        
        return {
            "type": "UNKNOWN",
            "likelihood": "MEDIUM"
        }
    
    def _unwind_stack(self, crash: CrashEvent) -> List[Dict]:
        """Unwind stack for debugging"""
        
        if not crash.coredump_path:
            return []
        
        try:
            # Use gdb to unwind stack
            result = subprocess.run(
                ["gdb", "--batch", crash.binary_path, crash.coredump_path, "-ex", "bt"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse backtrace
            frames = []
            for line in result.stdout.split("\n"):
                if "#" in line:
                    frames.append(line.strip())
            
            return frames
        
        except Exception as e:
            logger.error(f"Failed to unwind stack: {e}")
            return []
    
    def _get_binary_path(self, pid: int) -> str:
        """Get binary path from /proc/[pid]/exe"""
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except:
            return "unknown"
    
    def _read_memory_maps(self, pid: int) -> Dict:
        """Read memory map from /proc/[pid]/maps"""
        maps = {}
        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    parts = line.split()
                    addr_range = parts[0]
                    perms = parts[1]
                    name = parts[-1] if len(parts) > 5 else "unknown"
                    maps[name] = {"range": addr_range, "perms": perms}
        except:
            pass
        return maps
    
    def _get_heap_range(self, pid: int) -> tuple:
        """Extract heap start and end from memory map"""
        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    if "[heap]" in line:
                        addr_range = line.split()[0]
                        start, end = addr_range.split("-")
                        return int(start, 16), int(end, 16)
        except:
            pass
        return 0, 0
    
    def _get_stack_range(self, pid: int) -> tuple:
        """Extract stack start and end from memory map"""
        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    if "[stack]" in line:
                        addr_range = line.split()[0]
                        start, end = addr_range.split("-")
                        return int(start, 16), int(end, 16)
        except:
            pass
        return 0, 0
    
    def _map_rip_location(self, crash: CrashEvent) -> str:
        """Map RIP to memory region type"""
        
        if crash.heap_start <= crash.rip <= crash.heap_end:
            return "HEAP"
        elif crash.stack_end <= crash.rip <= crash.stack_start:
            return "STACK"
        elif crash.rip_location in crash.memory_maps:
            perms = crash.memory_maps[crash.rip_location].get("perms", "")
            if "x" not in perms:
                return "DATA"
            else:
                return "CODE"
        
        return "UNKNOWN"
    
    def _get_syscall_trace(self, pid: int) -> List[Dict]:
        """Get recent syscall trace (simplified)"""
        # In production, would use strace or auditd
        return []
    
    def _find_coredump(self, crash: CrashEvent) -> Optional[str]:
        """Find coredump file for crashed process"""
        try:
            import glob
            pattern = f"/var/crashes/core-{crash.process_name}-{crash.pid}-*"
            dumps = glob.glob(pattern)
            if dumps:
                return max(dumps, key=os.path.getctime)  # Most recent
        except:
            pass
        return None
    
    def _is_freed_memory(self, crash: CrashEvent) -> bool:
        """Check if RIP points to previously freed memory"""
        # Simplified check - would need heap state
        return False
    
    def _check_double_free(self, crash: CrashEvent) -> bool:
        """Check for double-free pattern"""
        # Would check coredump for double-free signature
        return False
    
    def _check_heap_corruption(self, crash: CrashEvent) -> bool:
        """Check for heap corruption pattern"""
        # Would check coredump for heap metadata corruption
        return False
    
    def export_crash_report(self, crash: CrashEvent, filepath: str = None) -> str:
        """Export crash for runbook analysis"""
        
        if not filepath:
            filepath = f"/tmp/crash-{crash.pid}-{int(crash.timestamp)}.json"
        
        # Analyze crash
        analysis = self.analyze_crash(crash)
        
        # Build report
        report = {
            "metadata": {
                "timestamp": crash.timestamp_iso,
                "process": crash.process_name,
                "pid": crash.pid,
                "binary": crash.binary_path,
                "signal": crash.signal_name,
            },
            "risk_assessment": {
                "risk_score": crash.risk_score,
                "risk_level": crash.risk_level,
                "exploitable": crash.exploitable,
            },
            "forensics": {
                "cpu_context": {
                    "rip": hex(crash.rip),
                    "rsp": hex(crash.rsp),
                    "rip_location": crash.rip_location,
                },
                "memory": analysis.get("memory_summary", {}),
                "stack_trace": analysis.get("stack_trace", []),
                "coredump": crash.coredump_path,
            },
            "analysis": analysis,
        }
        
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"[+] Crash report exported: {filepath}")
        return filepath


# Singleton instance
_detector = None

def get_crash_detector() -> CrashDetector:
    """Get or create crash detector instance"""
    global _detector
    if _detector is None:
        _detector = CrashDetector()
    return _detector
