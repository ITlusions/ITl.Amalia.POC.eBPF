# Configuration Guide

The eBPF implant is configured via `config.json`. Enable/disable specific event types without recompiling.

## Quick Config Changes

### Show Current Configuration
```bash
python3 implant_agent.py --config-show
```

### Enable/Disable Event Types

**Network connections only (default)**
```bash
python3 implant_agent.py --config-set collection.network_events.enabled true
python3 implant_agent.py --config-set collection.process_events.enabled false
python3 implant_agent.py --config-set collection.file_events.enabled false
```

**Process execution only**
```bash
python3 implant_agent.py --config-set collection.process_events.enabled true
python3 implant_agent.py --config-set collection.network_events.enabled false
python3 implant_agent.py --config-set collection.file_events.enabled false
```

**File access only**
```bash
python3 implant_agent.py --config-set collection.file_events.enabled true
python3 implant_agent.py --config-set collection.network_events.enabled false
python3 implant_agent.py --config-set collection.process_events.enabled false
```

**All event types**
```bash
python3 implant_agent.py --config-set collection.process_events.enabled true
python3 implant_agent.py --config-set collection.network_events.enabled true
python3 implant_agent.py --config-set collection.file_events.enabled true
```

## Configuration File Structure

```json
{
  "implant": {
    "id": "ebpf-sensor-poc-01",
    "sensor_type": "ebpf-kernel-level",
    "description": "Kernel-level telemetry implant"
  },
  "collection": {
    "process_events": {
      "enabled": false,
      "description": "Monitor process execution (exec, fork)",
      "hooks": [
        "tp/sched/sched_process_exec",
        "tp/sched/sched_process_fork"
      ]
    },
    "network_events": {
      "enabled": true,
      "description": "Monitor network connections (TCP)",
      "hooks": [
        "kprobe/tcp_v4_connect",
        "kprobe/tcp_v4_syn_recv_sock"
      ]
    },
    "file_events": {
      "enabled": false,
      "description": "Monitor file access (open, read, write)",
      "hooks": [
        "tp/syscalls/sys_enter_openat",
        "tp/syscalls/sys_enter_read",
        "tp/syscalls/sys_enter_write"
      ]
    }
  },
  "output": {
    "directory": "/tmp/ebpf-telemetry",
    "format": "json",
    "export_enabled": true
  },
  "amalia": {
    "enabled": false,
    "url": "http://localhost:8000/api/ingest",
    "token": null,
    "timeout_seconds": 10
  },
  "performance": {
    "ringbuffer_size_kb": 256,
    "poll_interval_ms": 100,
    "max_event_loss_percent": 2
  },
  "debugging": {
    "verbose": false,
    "print_events": true,
    "log_level": "INFO"
  }
}
```

## Configuration Options

### Implant Settings

**implant.id**
- Unique identifier for this implant instance
- Used in telemetry export
- Default: `ebpf-sensor-poc-01`

**implant.sensor_type**
- Type of sensor (e.g., `ebpf-kernel-level`)
- Used for Amalia integration
- Default: `ebpf-kernel-level`

### Collection Settings

**collection.{event_type}.enabled**
- Boolean: enable/disable specific event type
- Options: `process_events`, `network_events`, `file_events`
- Default: `network_events=true`, others=`false`

**Process Events**
- Captures process execution (exec) and forking
- Includes: PID, PPID, UID/GID, command, argv
- Overhead: ~0.5% CPU per 100 processes/sec

**Network Events**
- Captures TCP connections (inbound/outbound)
- Includes: 5-tuple, direction, process context
- Overhead: ~0.2% CPU per 100 connections/sec

**File Events**
- Captures file access operations
- Includes: path, operation type, flags, process context
- Overhead: ~1-2% CPU per 1000 opens/sec

### Output Settings

**output.directory**
- Where to write telemetry JSON files
- Default: `/tmp/ebpf-telemetry`

**output.format**
- Export format (currently only `json` supported)
- Default: `json`

**output.export_enabled**
- Enable/disable writing to disk
- Default: `true`

### Amalia Integration

**amalia.enabled**
- Enable/disable direct export to Amalia platform
- Default: `false`

**amalia.url**
- Amalia API endpoint for telemetry ingest
- Default: `http://localhost:8000/api/ingest`
- Example: `http://amalia.local:8000/api/ingest`

**amalia.token**
- API authentication token
- Default: `null` (no auth)
- Set to Bearer token for authenticated requests

**amalia.timeout_seconds**
- HTTP request timeout
- Default: `10` seconds

### Performance Tuning

**performance.ringbuffer_size_kb**
- Ring buffer size in KB
- Default: `256` (256KB)
- Increase for high-volume environments
- Options: `64`, `128`, `256`, `512`, `1024`

**performance.poll_interval_ms**
- How often to poll ring buffers
- Default: `100` (100ms)
- Lower = more responsive, higher CPU
- Higher = less responsive, lower CPU

**performance.max_event_loss_percent**
- Acceptable event loss percentage
- Default: `2` (2%)
- Adjust ringbuffer size if exceeding

### Debugging

**debugging.verbose**
- Enable verbose logging
- Default: `false`

**debugging.print_events**
- Print each event to console as received
- Default: `true`
- Set to `false` for silent operation

**debugging.log_level**
- Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`
- Default: `INFO`

## Common Configuration Scenarios

### Scenario 1: Network Monitoring Only (Red Team Honeypot)

```bash
# Disable all except network
python3 implant_agent.py \
  --config-set collection.process_events.enabled false \
  --config-set collection.network_events.enabled true \
  --config-set collection.file_events.enabled false

# Verify
python3 implant_agent.py --config-show

# Deploy
sudo /opt/ebpf-implant/implant_agent.py --load --collect 3600 --export
```

### Scenario 2: Full Monitoring (Comprehensive Audit)

```bash
# Enable all event types
python3 implant_agent.py \
  --config-set collection.process_events.enabled true \
  --config-set collection.network_events.enabled true \
  --config-set collection.file_events.enabled true

# Disable verbose output
python3 implant_agent.py \
  --config-set debugging.print_events false

# Deploy
sudo /opt/ebpf-implant/implant_agent.py --load --collect 3600 --export
```

### Scenario 3: Amalia Integration

```bash
# Configure Amalia endpoint and token
python3 implant_agent.py \
  --config-set amalia.enabled true \
  --config-set amalia.url "http://amalia.local:8000/api/ingest" \
  --config-set amalia.token "YOUR_API_TOKEN"

# Deploy and send
sudo /opt/ebpf-implant/implant_agent.py --load --collect 3600 --amalia
```

### Scenario 4: Low-Impact Monitoring

```bash
# Network only (lowest impact)
python3 implant_agent.py \
  --config-set collection.network_events.enabled true \
  --config-set collection.process_events.enabled false \
  --config-set collection.file_events.enabled false

# Silent operation
python3 implant_agent.py \
  --config-set debugging.print_events false

# Smaller ring buffer
python3 implant_agent.py \
  --config-set performance.ringbuffer_size_kb 128

# Deploy
sudo systemctl start ebpf-implant.service
```

## Using Multiple Configs

Create different config files for different deployments:

```bash
# Network monitoring config
cp config.json config-network.json
python3 implant_agent.py --config config-network.json --config-set collection.network_events.enabled true

# Process monitoring config
cp config.json config-process.json
python3 implant_agent.py --config config-process.json --config-set collection.process_events.enabled true

# Deploy with specific config
sudo /opt/ebpf-implant/implant_agent.py --config config-network.json --load --collect 60
```

## Resetting Configuration

```bash
# Delete config.json to use hardcoded defaults
rm config.json

# Or create fresh config
python3 implant_agent.py --config-show > /tmp/default-config.json
cp /tmp/default-config.json config.json
```

## Validating Configuration

```bash
# Show full config
python3 implant_agent.py --config-show | python3 -m json.tool

# Check specific setting
python3 implant_agent.py --config-show | grep -A2 network_events

# Dry run collection
python3 implant_agent.py --config-show
sudo /opt/ebpf-implant/implant_agent.py --load --collect 10 --export
cat /tmp/ebpf-telemetry/telemetry-*.json | python3 -m json.tool
```
