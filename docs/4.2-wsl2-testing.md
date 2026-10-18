# Testing eBPF Implant in WSL 2

Guide to compile, deploy, and test network collection in WSL 2.

## [WARN] IMPORTANT: Your Current Environment

You're currently running in **MSYS2** (Windows UNIX emulation), which:
- ❌ **Cannot** run eBPF programs (no Linux kernel)
- ❌ **Cannot** load kernel modules or hooks
- ✅ **Can** run the Python code logic (as shown in demo)

**To test actual network collection, you need WSL 2 or Linux.**

## Setup WSL 2

### 1. Install WSL 2 (If Not Already Installed)

**PowerShell (as Administrator):**
```powershell
# Enable WSL 2 feature
wsl --install

# Or update existing WSL 1 to WSL 2
wsl --set-default-version 2

# List installed distributions
wsl --list --verbose

# Install Ubuntu (if needed)
wsl --install -d Ubuntu-22.04
```

### 2. Verify WSL 2 Setup

```bash
# Open WSL 2 terminal
wsl

# Check kernel version (should be 5.8+)
uname -r
# Output should be: 5.10.16.3-microsoft-standard or higher

# Check if running as WSL 2
cat /proc/version
# Should show "WSL 2" or Microsoft kernel
```

## Install Dependencies

Inside WSL 2 terminal:

```bash
# Update package manager
sudo apt update && sudo apt upgrade -y

# Install required tools
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libz-dev \
    pkg-config \
    python3 \
    python3-pip \
    linux-headers-$(uname -r)

# Verify installations
clang --version
python3 --version
bpftool version  # May need: sudo apt install linux-tools-generic
```

## Copy Project to WSL 2

**From Windows PowerShell:**
```powershell
# Navigate to project
cd D:\repos\ITL.Amalia.Poc.eBpf

# Copy to WSL 2 Ubuntu home
wsl cp -r . ~/ebpf-implant/
```

**Or within WSL 2:**
```bash
# Create directory
mkdir -p ~/ebpf-implant
cd ~/ebpf-implant

# If you cloned from Git
git clone https://github.com/your-org/ITL.Amalia.Poc.eBpf.git .
```

## Compile eBPF Program

Inside WSL 2:

```bash
cd ~/ebpf-implant

# Compile with clang
clang -O2 -target bpf -c kernel/programs/sensor.bpf.c -o kernel/programs/sensor.o

# Verify compilation
ls -la kernel/programs/sensor.o
file kernel/programs/sensor.o
# Should show: ELF 64-bit LSB relocatable, eBPF, version 1
```

## Test Network Collection (5 minutes)

### Step 1: Verify Capabilities

```bash
cd ~/ebpf-implant

# Run system capability check
sudo bash build/test_setup.sh

# Expected output:
# [PASS] Kernel version 5.8+
# [PASS] clang installed
# [PASS] eBPF programs can load
```

### Step 2: Install Python Dependencies

```bash
# Install BCC (eBPF loader library)
sudo apt install -y python3-bcc

# Or use pip
pip3 install bcc
```

### Step 3: Test Network Collection (60 seconds)

```bash
# Test collection with network events only
sudo python3 userspace/src/implant_agent.py \
    --config config.json \
    --load \
    --collect 60 \
    --export

# Expected output:
# [*] Configuration Summary:
#     Implant ID: ebpf-sensor-poc-01
#     Events to collect:
#       - network_events: [OK] ENABLED
#       - process_events: [DISABLED] disabled
#       - file_events: [DISABLED] disabled
#
# [*] Loading eBPF program into kernel...
# [+] eBPF program loaded successfully
# [*] Collecting events for 60 seconds...
#
# [While collecting, generate traffic in another terminal]
```

### Step 4: Generate Network Traffic (in another WSL 2 terminal)

While collection is running:

```bash
# In another terminal while collection runs:

# HTTPS request
curl https://example.com

# SSH connection attempt (will fail if no SSH running, but generates network event)
ssh -vvv user@10.0.0.1 2>&1 || true

# DNS lookup
nslookup example.com

# HTTP server interaction
nc -zv example.com 80
```

### Step 5: View Collected Telemetry

```bash
# After collection finishes
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 -m json.tool

# Expected output:
{
  "implant_id": "ebpf-sensor-poc-01",
  "events": {
    "network": [
      {
        "type": "network",
        "timestamp": 1691234568.90,
        "pid": 1234,
        "comm": "curl",
        "protocol": "TCP",
        "sport": 54821,
        "dport": 443,
        "saddr": "192.168.1.100",
        "daddr": "93.184.216.34",
        "direction": "outbound"
      }
    ]
  },
  "summary": {
    "network_events": 12,
    "total_events": 12
  }
}
```

## Configuration Options for Testing

### Network Only (Default - Recommended for Testing)

```bash
# Verify config
python3 userspace/src/implant_agent.py --config-show | grep -A5 network_events

# Should show: "enabled": true
```

### Filter Specific Ports

After collection, filter results:

```bash
# HTTPS (443) connections only
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 << 'EOF'
import json, sys
data = json.load(sys.stdin)
for evt in data['events']['network']:
    if evt['dport'] in [443, 80]:
        print(f"{evt['comm']}({evt['pid']}) -> {evt['daddr']}:{evt['dport']}"
EOF
```

### SSH Connections

```bash
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 << 'EOF'
import json, sys
data = json.load(sys.stdin)
for evt in data['events']['network']:
    if evt['dport'] == 22 or 'ssh' in evt['comm']:
        print(f"SSH: {evt['comm']} -> {evt['daddr']}:{evt['dport']} ({evt['direction']})"
EOF
```

## Troubleshooting

### "Permission denied"

```bash
# Must run with sudo
sudo python3 userspace/src/implant_agent.py --load --collect 60

# Or with sudo bash to stay in elevated mode
sudo bash
python3 userspace/src/implant_agent.py --load --collect 60
```

### "No such file or directory: /sys/kernel/debug/tracing"

```bash
# Mount debugfs
sudo mount -t debugfs none /sys/kernel/debug

# Make permanent in /etc/fstab
echo "none /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a /etc/fstab
```

### "Cannot load BPF object"

```bash
# Recompile eBPF
cd ~/ebpf-implant
clang -O2 -target bpf -c kernel/programs/sensor.bpf.c -o kernel/programs/sensor.o

# Check kernel module support
cat /boot/config-$(uname -r) | grep CONFIG_BPF
# Should show: CONFIG_BPF=y

cat /boot/config-$(uname -r) | grep CONFIG_HAVE_EBPF_JIT
# Should show: CONFIG_HAVE_EBPF_JIT=y
```

### No Events Collected

```bash
# 1. Verify eBPF loaded
sudo bpftool prog list | grep -E "tracepoint|kprobe"

# 2. Generate more traffic
for i in {1..10}; do curl https://example.com 2>&1 | head -1; done

# 3. Check if tracepoints available
cat /sys/kernel/debug/tracing/available_events | grep tcp

# 4. Test with simpler command
sudo /bin/bash -c 'sleep 0 & wait $!'
```

## Full Deployment in WSL 2

Once testing works, install systemd service:

```bash
# Install to /opt/ebpf-implant
sudo bash ~/ebpf-implant/build/install.sh

# Enable persistent monitoring
sudo systemctl enable ebpf-implant.service
sudo systemctl start ebpf-implant.service

# Monitor logs
sudo journalctl -u ebpf-implant.service -f

# Check status
sudo systemctl status ebpf-implant.service
```

## Comparison: Windows Demo vs WSL 2 Real Test

| Feature | Windows Demo | WSL 2 Real |
|---------|--------------|-----------|
| Environment | MSYS2 (emulation) | Linux kernel |
| eBPF loading | ❌ No (no kernel) | ✅ Yes |
| Network hooking | ❌ No | ✅ Yes (kprobe) |
| Ring buffers | ❌ Simulated | ✅ Real |
| Event capture | ❌ Mock data | ✅ Real kernel events |
| Performance | N/A | ~1-3% CPU overhead |
| Persistence | N/A | ✅ systemd service |

## Next Steps

1. **Setup WSL 2** with Linux kernel 5.8+
2. **Copy project** to WSL 2 home directory
3. **Install dependencies** (clang, llvm, python3-bcc)
4. **Compile** eBPF program with clang
5. **Test** with 60-second collection
6. **Deploy** systemd service for continuous monitoring

## References

- [WSL 2 Documentation](https://learn.microsoft.com/en-us/windows/wsl/install)
- [eBPF Requirements](https://ebpf.io/what-is-ebpf/#requirements)
- [Linux Kernel BPF](https://www.kernel.org/doc/html/latest/bpf/)
