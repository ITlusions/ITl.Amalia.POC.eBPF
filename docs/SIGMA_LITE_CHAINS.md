# Sigma-Lite: Behavioral Attack Chain Detection

Sigma-Lite is a lightweight behavioral detection engine that correlates network events within a time window to detect multi-stage attack patterns. It complements YARA signature detection with temporal and behavioral analysis.

## What It Detects

### 1. DNS Exfiltration Chain
**Pattern**: High DNS volume (>50 queries) followed by large outbound transfer (>1MB)
```
Process A: 60 DNS queries (attempting to hide data channel)
           ↓ (within 60s)
Process A: 5MB outbound transfer (data exfiltration)
Result: CRITICAL - Suspected DNS tunneling/exfiltration
```
**MITRE**: T1020-AutomatedExfiltration, T1071.004-ProtocolTunneling

### 2. Lateral Movement Chain
**Pattern**: Port scanning (>20 unique ports) followed by RDP/SSH/SMB attempts
```
Process A: Connects to ports 22,80,443,445,3389,8080... (reconnaissance)
           ↓ (within 60s)
Process A: Multiple connections to port 3389 (RDP exploitation)
Result: HIGH - Suspected lateral movement reconnaissance
```
**MITRE**: T1595.002-ActiveScanning, T1021-RemoteServices

### 3. Privilege Escalation + Persistence
**Pattern**: UID transition (normal user → root) + system file access
```
Process A: UID 1000 (normal user)
           ↓
Process A: UID 0 (root/system privilege escalation)
           ↓
Process A: Accesses /etc/cron, /etc/systemd, /root/.ssh
Result: CRITICAL - Privilege escalation followed by persistence setup
```
**MITRE**: T1548-PrivilegeEscalation, T1547-Persistence

### 4. Credential Access Chain
**Pattern**: Multiple failed auth attempts + successful login + privileged access
```
Process A: 10 failed connections to port 22 (SSH brute force)
           ↓
Process A: Successful connection to port 22 (compromise)
           ↓
Process A: Accesses /root, /etc/passwd
Result: HIGH - Credential compromise via brute force
```
**MITRE**: T1110-BruteForce, T1021-RemoteServices

### 5. Reconnaissance Chain
**Pattern**: Multiple hosts scanned + multiple ports + DNS queries
```
Process A: Connects to 10 different hosts (network mapping)
           ↓
Process A: Probes 25+ different ports (service discovery)
           ↓
Process A: 50+ DNS queries (host enumeration)
Result: MEDIUM - Active reconnaissance detected
```
**MITRE**: T1595-ActiveScanning, T1046-NetworkServiceScanning

### 6. Process Injection Chain
**Pattern**: Multiple process spawning + memory access patterns
```
Process A: Spawns Process B (child process)
           ↓
Process B: Spawns Process C (grandchild)
           ↓
Process A/B/C: Access /proc/self, ptrace, memory areas
Result: HIGH - Suspected code injection/hollowing
```
**MITRE**: T1055-ProcessInjection, T1106-NativeAPI

## Installation

The module is created as `userspace/src/sigma_lite_detector.py`.

No additional dependencies required (uses only stdlib).

## Integration with Implant Agent

### 1. Update `implant_agent.py` imports:

```python
from sigma_lite_detector import SigmaLiteDetector
```

### 2. Initialize in `__init__`:

```python
class EBPFImplantAgent:
    def __init__(self, config: Dict[str, Any]):
        # ... existing code ...
        
        # Initialize Sigma-Lite
        sigma_config = self.config.get('sigma_lite', {})
        if sigma_config.get('enabled', False):
            self.sigma_lite = SigmaLiteDetector(sigma_config)
            logger.info("Sigma-Lite behavioral detection enabled")
        else:
            self.sigma_lite = None
```

### 3. In network callback, add chain detection:

```python
def network_callback(self, cpu, data, size):
    event = self.parse_network_event(data)
    
    # ... existing YARA detection ...
    
    # Sigma-Lite chain detection
    if self.sigma_lite:
        sigma_matches = self.sigma_lite.add_event(event)
        for match in sigma_matches:
            logger.critical(f"[CHAIN] {match.chain_name} - {match.description}")
            logger.critical(f"  Severity: {match.severity} | Confidence: {match.confidence:.1%}")
            logger.critical(f"  MITRE: {', '.join(match.mitre_techniques)}")
```

### 4. In export functions:

```python
def export_telemetry(self):
    # ... existing exports ...
    
    # Sigma-Lite chains
    if self.sigma_lite and self.sigma_lite.get_detected_chains():
        chains_json = os.path.join(self.telemetry_dir, f'sigma-lite-chains-{int(time.time())}.json')
        self.sigma_lite.export_to_json(chains_json)
        
        chains_report = os.path.join(self.telemetry_dir, f'sigma-lite-report-{int(time.time())}.txt')
        self.sigma_lite.export_to_report(chains_report)
```

## Configuration

Add to `config.json`:

```json
{
  "sigma_lite": {
    "enabled": true,
    "time_window_sec": 60,
    "detection_rules": [
      "dns_exfil_chain",
      "lateral_movement_chain",
      "priv_esc_persistence",
      "credential_access_chain",
      "reconnaissance_chain",
      "injection_chain"
    ],
    "export_chains": true
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Enable Sigma-Lite detection |
| `time_window_sec` | int | 60 | Time window for event correlation (seconds) |
| `detection_rules` | list | All 6 | Which chains to detect |
| `export_chains` | bool | true | Export detected chains to JSON |

## Command-Line Usage

```bash
# Enable Sigma-Lite with YARA
sudo python3 implant_agent.py \
  --load \
  --collect 3600 \
  --yara-rules \
  --sigma-lite \
  --ip-analysis \
  --braincell \
  --export
```

## Output Files

When Sigma-Lite is enabled, generates:

| File | Contents |
|------|----------|
| `sigma-lite-chains-<ts>.json` | Detected attack chains in JSON format |
| `sigma-lite-report-<ts>.txt` | Human-readable chain report |

### Example Output

**sigma-lite-chains-1234567890.json:**
```json
{
  "detected_chains": [
    {
      "timestamp": 1234567890.123,
      "chain_name": "DNS_EXFIL_CHAIN",
      "severity": "CRITICAL",
      "process": "curl",
      "confidence": 0.92,
      "description": "High DNS volume (60 queries, 60KB) followed by large transfer (5MB)",
      "mitre_techniques": [
        "T1020-AutomatedExfiltration",
        "T1071.004-ProtocolTunneling-DNS"
      ],
      "events": [...]
    }
  ],
  "summary": {
    "total_detections": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

**sigma-lite-report-1234567890.txt:**
```
SIGMA-LITE ATTACK CHAIN DETECTION REPORT
================================================================================

Total Detections: 1
  - CRITICAL: 1
  - HIGH:     0
  - MEDIUM:   0
  - LOW:      0

================================================================================
DETECTED CHAINS
================================================================================

1. [CRITICAL] DNS_EXFIL_CHAIN
   Process: curl
   Time: 1234567890.123456
   Confidence: 92.0%
   Description: High DNS volume (60 queries, 60KB) followed by large transfer (5.0MB)
   MITRE Techniques:
     - T1020-AutomatedExfiltration
     - T1071.004-ProtocolTunneling-DNS
   Events Correlated: 61
```

## Three-Layer Detection Strategy

### Layer 1: YARA (Fast, Local)
- Known signatures on individual events
- 25+ patterns in 6 categories
- <1ms per event
- Output: High-confidence instant alerts

### Layer 2: Sigma-Lite (Behavioral, Local)
- Event sequences within 60s window
- 6 attack chain patterns
- <10ms per detection
- Output: Attack chain detection (possible zero-day)

### Layer 3: Full Sigma (Centralized, Optional)
- Cross-implant correlation in BrainCell
- Enterprise-grade analysis
- Real-time multi-stage campaign tracking
- Output: APT campaign fingerprints

## Performance

**Overhead per event:**
- Memory: ~200 bytes per buffered event
- CPU: <5ms to detect chains
- Latency: None (asynchronous)

**With 60-second time window:**
- Max buffered events: ~100-200 (typical)
- Memory: ~20-40KB per process
- Detection latency: <10ms

**Typical deployment:**
- CPU overhead: <1% additional
- Memory overhead: ~10MB (all buffers + detections)
- Scalability: Handles 1000s of processes simultaneously

## Use Cases

### Red Team Exercise Monitoring
```
1. Collect telemetry during attack simulation
2. Sigma-Lite detects staged attack chains in real-time
3. Export chains for after-action review
4. Compare detected chains against known TTPs
```

### Incident Response
```
1. Implant deployed post-breach
2. Sigma-Lite correlates attacker's attack chain
3. Generates MITRE technique mapping
4. Enables faster incident reconstruction
```

### Security Research
```
1. Analyze malware behavior patterns
2. Verify effectiveness of detection rules
3. Build datasets for ML-based detection
4. Share findings with security community
```

## Extending Detection Rules

Add new attack chains by implementing detection methods:

```python
class SigmaLiteDetector:
    def _detect_custom_chain(self, process_key: str) -> Optional[SigmaMatch]:
        """Detect your custom attack pattern"""
        events = self.event_buffer[process_key]
        
        # Your detection logic here
        if detected:
            return SigmaMatch(
                timestamp=time.time(),
                chain_name='CUSTOM_CHAIN',
                severity='HIGH',
                events=events,
                process=process_key,
                mitre_techniques=['T1234-SomeTechnique'],
                description='Your description',
                confidence=0.85
            )
        return None
```

Then enable in config:
```json
{
  "sigma_lite": {
    "detection_rules": ["dns_exfil_chain", "custom_chain"]
  }
}
```

## Threat Detection Stack Summary

| Component | Purpose | Speed | Scope | Integration |
|-----------|---------|-------|-------|-------------|
| **IP Analysis** | Behavioral profiling | Per-event | Single IP | Optional |
| **YARA** | Known signatures | Per-event | Single event | Embedded |
| **Sigma-Lite** | Attack chains | Per-60s | Time window | Local implant |
| **Full Sigma** | Enterprise patterns | Real-time | Multi-host | BrainCell |

All components work together for comprehensive threat detection.

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Sigma Rules: https://github.com/SigmaHQ/sigma
- Behavioral Analysis: https://mitre-engenuity.org/news/ttps-behaviors-and-techniques-oh-my/
- Attack Chain Analysis: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
