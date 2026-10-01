# userspace/src — eBPF Implant Source Code (DDD Architecture)

Welcome to the eBPF implant userspace agent. This directory contains all Python code organized using **Domain-Driven Design (DDD)**.

## Quick Start

### Running the Implant

```bash
# Basic collection (collect events for 60 seconds)
python -m application.implant_agent --collect 60

# With stealth mode enabled
python -m application.implant_agent --stealth --collect 60

# Export to specific location
python -m application.implant_agent --export /tmp/my-telemetry.json
```

### Running Examples

```bash
# Example 1: Basic event collection
python examples/basic_collection.py

# Example 2: Full threat analysis
python examples/full_analysis.py

# Example 3: BrainCell integration
python examples/braincell_streaming.py
```

## Architecture Overview

**8 Domain Layers:**
- `application/` — Main orchestrator
- `detection/` — Threat analysis (4-layer: IP, YARA, Sigma-Lite, Correlation)
- `collection/` — Event models
- `anti_forensics/` — Stealth (7 modules)
- `c2/` — Command & control (6 modules)
- `integrations/` — External systems
- `core/` — Infrastructure
- `examples/` — Usage demonstrations

**42 Python modules organized with single responsibility principle.**

## Key Features

### 4-Layer Threat Detection

1. **IP Analysis** — Behavioral profiling (45→100 threat score)
2. **YARA Detection** — Signature matching (25+ rules)
3. **Sigma-Lite** — Attack chain detection (6 behavioral patterns)
4. **Threat Correlator** — Unified verdict with confidence

### 7-Module Stealth Layer

- Audit suppression, process hiding, memory encryption, artifact cleaning, kernel obfuscation, detection evasion, orchestration

### Dual C2 Channels

- **Primary:** HTTPS with certificate pinning
- **Fallback:** DNS TXT tunneling
- **Rate Limiting:** Adaptive jitter (±30%)

## Directory Structure

See `STRUCTURE.md` for the complete module guide.

Quick reference:
```
src/
├── core/              # Infrastructure (config, logging, ABCs)
├── collection/        # Event models
├── detection/         # Threat analysis
├── anti_forensics/    # Stealth (7 modules)
├── c2/                # C2 communication (6 modules)
├── integrations/      # External systems
├── application/       # Main orchestrator
├── examples/          # Usage demos
├── STRUCTURE.md       # Architecture guide
└── verify_imports.py  # Validation script
```

## Documentation

| Document | Purpose |
|----------|--------|
| `STRUCTURE.md` | Complete DDD architecture guide |
| `ARCHITECTURE.md` | Platform design and threat detection |
| `CLAUDE.md` | Project mission and deployment |
| `SIGMA_LITE_CHAINS.md` | Behavioral attack patterns |
| `QUICKSTART.md` | 5-minute deployment |

## Common Tasks

### Import the Implant

```python
from application import EBPFImplantAgent

implant = EBPFImplantAgent(config_file="config.json")
implant.start_collection(duration_sec=60)
implant.export_telemetry()
implant.stop()
```

### Add a Detection Method

1. Create `detection/my_detector/`
2. Implement `ThreatDetector` ABC
3. Export via `__init__.py`
4. Wire in `application/services.py`
5. Update threat correlator

### Configure the Implant

Edit `config.json` or set environment variables:
```bash
export IMPLANT_ID="my-sensor"
export ENABLE_STEALTH="true"
export C2_SERVER_URL="http://c2.attacker.com"
```

## Deployment Modes

### Mode 1: Manual Collection
```bash
python -m application.implant_agent --collect 30
```

### Mode 2: Continuous Service
```bash
sudo systemctl enable ebpf-implant
sudo systemctl start ebpf-implant
```

### Mode 3: Amalia Integration
```bash
export ENABLE_AMALIA_EXPORT="true"
python -m application.implant_agent --collect 3600
```

## Verification

```bash
# Check all imports and module structure
python verify_imports.py

# Run examples
python examples/basic_collection.py
python examples/full_analysis.py
```

## Troubleshooting

### Import Errors
```python
# Old (will fail)
from ip_analysis import IPAnalyzer

# New (correct)
from detection.ip_analysis import IPAnalyzer
from detection import IPAnalyzer  # Via public API
```

### Configuration Issues
```bash
python -c "from core import ConfigManager; print(ConfigManager().settings)"
```

## Migration Notes

This is the refactored DDD architecture (2.0).

Old files → New locations:
- `implant_agent.py` → `application/implant_agent.py` (550→150 lines)
- `ip_analysis.py` → `detection/ip_analysis/`
- `yara_*.py` → `detection/yara/`
- `sigma_lite_detector.py` → `detection/sigma_lite/`
- `anti_forensics.py` → 7 modules in `anti_forensics/`
- `c2_client.py` → 6 modules in `c2/`
- `braincell_websocket.py` → `integrations/braincell/`

**Benefits:** Single responsibility, easier testing, clear dependencies, no circular imports.

## Next Steps

1. Read `STRUCTURE.md` for module details
2. Review `examples/` for working code
3. See `ARCHITECTURE.md` for platform design
4. Deploy with `build/install.sh`

---

**Version:** 2.0 DDD Architecture  
**Status:** Production-Ready
