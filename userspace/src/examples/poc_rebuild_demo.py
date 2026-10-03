#!/usr/bin/env python3
"""
POC Rebuild Workflow - Complete pipeline from crash to exploit

Demonstrates the full cycle:
1. Load crash report (from crash_detection/detector.py export)
2. Classify exploit type automatically
3. Build POC code from templates
4. Test reproducibility
5. Export final exploit
"""

import json
import sys
import os
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from detection.crash_detection import CrashDetector, CrashEvent
from examples.poc_builder import POCBuilder, rebuild_poc_from_crash


def demo_crash_to_poc():
    """End-to-end crash analysis → POC rebuild workflow"""
    
    print("=" * 70)
    print("ZERO-DAY CRASH ANALYSIS → POC REBUILD PIPELINE")
    print("=" * 70)
    print()
    
    # ========================================================================
    # PHASE 1: Simulated crash detection (in real scenario, from eBPF)
    # ========================================================================
    
    print("[PHASE 1] CRASH DETECTION")
    print("-" * 70)
    
    # Simulate eBPF crash event
    crash_event = {
        "timestamp": time.time(),
        "pid": 12345,
        "ppid": 1234,
        "uid": 1000,
        "gid": 1000,
        "comm": "vulnerable_app",
        "signal": 11,  # SIGSEGV
        "rip": 0x7ffff7ab4000,      # Code execution from heap
        "rsp": 0x7ffffffde0f8,
        "rbp": 0x7ffffffde100,
        "rax": 0x41414141,
        "rbx": 0x42424242,
        "rcx": 0x43434343,
        "rdx": 0x44444444,
        "rsi": 0x45454545,
        "rdi": 0x46464646,
        "network_events": [
            {
                "timestamp": time.time() - 1,
                "daddr": "10.0.0.50",
                "dport": 4444,
                "bytes_sent": 512
            }
        ]
    }
    
    # Process crash
    detector = CrashDetector()
    crash = detector.process_crash_event(crash_event)
    
    print(f"[+] Crash detected: {crash.process_name} (PID {crash.pid})")
    print(f"    Signal: {crash.signal_name}")
    print(f"    RIP Location: {crash.rip_location}")
    print(f"    Risk Level: {crash.risk_level}")
    print(f"    Exploitable: {crash.exploitable}")
    print()
    
    # ========================================================================
    # PHASE 2: Export crash report
    # ========================================================================
    
    print("[PHASE 2] FORENSIC EXPORT")
    print("-" * 70)
    
    output_dir = "/tmp/zero_day_analysis"
    os.makedirs(output_dir, exist_ok=True)
    
    crash_report_path = detector.export_crash_report(crash, f"{output_dir}/crash_report.json")
    
    with open(crash_report_path) as f:
        crash_report = json.load(f)
    
    print(f"[+] Crash report exported: {crash_report_path}")
    print(f"    Risk Score: {crash_report['risk_assessment']['risk_score']}")
    print(f"    Exploitable: {crash_report['risk_assessment']['exploitable']}")
    print()
    
    # ========================================================================
    # PHASE 3: Build POC from crash analysis
    # ========================================================================
    
    print("[PHASE 3] POC GENERATION")
    print("-" * 70)
    
    builder = POCBuilder(crash_report)
    
    print(f"[*] Exploit type detected: {builder.exploit_type.value}")
    print(f"[*] RIP location: {builder.context.rip_location}")
    print(f"[*] Buffer size: {builder.context.buffer_size}")
    print(f"[*] Network triggered: {builder.context.network_triggered}")
    print()
    
    # Build exploit code
    print("[*] Generating POC code...")
    exploit_code = builder.build_exploit()
    
    # Export POC
    poc_path = builder.export_poc(f"{output_dir}/exploit.py")
    print(f"[+] POC exported: {poc_path}")
    print()
    
    # Show first 30 lines of POC
    with open(poc_path) as f:
        lines = f.readlines()[:30]
        print("[*] POC preview (first 30 lines):")
        for i, line in enumerate(lines, 1):
            print(f"    {i:2d}: {line.rstrip()}")
    print()
    
    # ========================================================================
    # PHASE 4: Test POC reliability
    # ========================================================================
    
    print("[PHASE 4] REPRODUCIBILITY TESTING")
    print("-" * 70)
    
    print("[*] Testing POC reliability (10 iterations)...")
    print()
    
    results = {
        "total_runs": 10,
        "successful": 0,
        "failed": 0,
    }
    
    for i in range(10):
        # Simulate testing (in real scenario, would run actual exploit)
        # This is a mock test showing success rate calculation
        
        success = (i % 8) < 7  # 7/10 success rate (70%)
        
        if success:
            results["successful"] += 1
            status = "[+] CRASH CONFIRMED"
        else:
            results["failed"] += 1
            status = "[-] No crash"
        
        print(f"    Iteration {i+1:2d}/10: {status}")
        time.sleep(0.2)
    
    success_rate = results["successful"] / results["total_runs"]
    print()
    print(f"[+] Results: {results['successful']}/{results['total_runs']} successful")
    print(f"[+] Success Rate: {success_rate*100:.1f}%")
    print(f"[+] Reliable: {'YES' if success_rate >= 0.8 else 'NO'}")
    print()
    
    # ========================================================================
    # PHASE 5: Multi-stage payload building
    # ========================================================================
    
    print("[PHASE 5] MULTI-STAGE PAYLOAD STRATEGY")
    print("-" * 70)
    
    stages = [
        {
            "name": "Trigger Stage",
            "description": "Send initial payload to reach vulnerable code path",
            "bytes": 512,
            "technique": "Heap spray + buffer overflow"
        },
        {
            "name": "Setup Stage",
            "description": "Execute mmap/mprotect to create executable memory",
            "bytes": 256,
            "technique": "ROP chain + syscall"
        },
        {
            "name": "Payload Stage",
            "description": "Write and execute shellcode",
            "bytes": 128,
            "technique": "Direct memory write"
        }
    ]
    
    for stage in stages:
        print(f"[*] Stage: {stage['name']}")
        print(f"    Description: {stage['description']}")
        print(f"    Size: {stage['bytes']} bytes")
        print(f"    Technique: {stage['technique']}")
        print()
    
    # ========================================================================
    # PHASE 6: Export analysis summary
    # ========================================================================
    
    print("[PHASE 6] ANALYSIS SUMMARY")
    print("-" * 70)
    
    summary = {
        "timestamp": time.time(),
        "process": crash.process_name,
        "binary": crash.binary_path,
        "exploit_type": builder.exploit_type.value,
        "risk_level": crash.risk_level,
        "rip_location": crash.rip_location,
        "success_rate": success_rate,
        "reliable": success_rate >= 0.8,
        "poc_path": poc_path,
        "crash_report": crash_report_path,
        "next_steps": [
            "1. Refine payload based on test results",
            "2. Add anti-detection techniques if needed",
            "3. Deploy detection rules to prevent exploitation",
            "4. Contact vendor for security patch",
            "5. Document CVE details"
        ]
    }
    
    summary_path = f"{output_dir}/analysis_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    print("[+] Analysis Summary:")
    print(f"    Process: {summary['process']}")
    print(f"    Exploit Type: {summary['exploit_type']}")
    print(f"    Risk Level: {summary['risk_level']}")
    print(f"    POC Reliable: {summary['reliable']}")
    print(f"    Success Rate: {summary['success_rate']*100:.1f}%")
    print()
    print(f"[+] Files generated:")
    print(f"    - {crash_report_path}")
    print(f"    - {poc_path}")
    print(f"    - {summary_path}")
    print()
    
    # ========================================================================
    # PHASE 7: Payload variations for different scenarios
    # ========================================================================
    
    print("[PHASE 7] PAYLOAD VARIATIONS")
    print("-" * 70)
    
    variations = [
        {"name": "Crash Verification", "goal": "Confirm exploitability"},
        {"name": "Shell Execution", "goal": "Reverse shell"},
        {"name": "Data Exfiltration", "goal": "Extract sensitive data"},
        {"name": "Persistence", "goal": "Maintain access"},
        {"name": "Lateral Movement", "goal": "Spread to other systems"},
    ]
    
    for i, var in enumerate(variations, 1):
        print(f"{i}. {var['name']}")
        print(f"   Goal: {var['goal']}")
    print()
    
    # ========================================================================
    # Completion
    # ========================================================================
    
    print("=" * 70)
    print("POC REBUILD COMPLETE")
    print("=" * 70)
    print()
    print("Next Steps:")
    for step in summary['next_steps']:
        print(f"  {step}")
    print()


if __name__ == "__main__":
    try:
        demo_crash_to_poc()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
