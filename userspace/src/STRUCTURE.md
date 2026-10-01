# eBPF Implant - New DDD Module Structure

## Overview

The eBPF implant has been refactored from a flat 10-file structure into a **Domain-Driven Design (DDD)** architecture with 8 main domains and 40+ focused modules.

**Benefits:**
- Single Responsibility Principle: Each module has one clear purpose
- Easier Testing: Domains can be tested in isolation
- Clear Dependencies: Domains are organized by layer
- Maintainability: Related code grouped logically
- Extensibility: Add new features without modifying core layers

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  application/                                        │   │
│  │  ├── implant_agent.py (150 lines - thin orchestrator)│   │
│  │  └── services.py (DI composition root)               │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    DETECTION LAYER                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  detection/                                          │   │
│  │  ├── ip_analysis/     (threat profiling + scoring)   │   │
│  │  ├── yara/            (signature matching)           │   │
│  │  ├── sigma_lite/      (behavioral detection)         │   │
│  │  └── correlation/     (unified verdict)              │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                   COLLECTION LAYER                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  collection/                                         │   │
│  │  ├── models.py (event data structures)               │   │
│  │  └── (ringbuf parsing - future)                      │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│              INFRASTRUCTURE LAYERS                           │
│  ┌──────────────┐ ┌────────────┐ ┌──────────────────────┐  │
│  │   anti_     │ │     c2     │ │  integrations        │  │
│  │ forensics   │ │ (C2 comms) │ │ (external systems)   │  │
│  │ (stealth)   │ │            │ │                      │  │
│  └──────────────┘ └────────────┘ └──────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    CORE LAYER                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  core/                                               │   │
│  │  ├── config.py     (configuration management)        │   │
│  │  ├── logger.py     (logging with stealth mode)       │   │
│  │  └── base_classes.py (ABCs, Protocols, Exceptions)   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Domain Organization

### 1. **core/** — Infrastructure Foundation
Provides shared utilities for all other domains.

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `config.py` | Configuration loading from JSON/env | `ConfigManager`, `ConfigurationSettings` |
| `logger.py` | Logging with stealth mode support | `ImplantLogger` |
| `base_classes.py` | Abstract base classes, protocols, exceptions | `EventCollector`, `ThreatDetector`, `StealthMechanism`, etc. |

**Imports:** Standard library only (no circular dependencies)

### 2. **collection/** — Event Capture & Models
Data structures and parsing for eBPF telemetry.

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `models.py` | Event dataclasses | `ProcessEvent`, `NetworkEvent`, `FileEvent`, `TelemetryCollection` |
| (future) `ringbuf.py` | Ring buffer polling | `RingBufferManager` |
| (future) `parser.py` | Event deserialization | `EventParser` |

**Imports:** From `core/`

### 3. **detection/** — Threat Analysis
Four-layer threat detection system.

#### 3a. **detection/ip_analysis/** — Network Behavioral Profiling
Analyzes network patterns for anomalies.

| Module | Purpose |
|--------|---------|
| `analyzer.py` | Threat scoring algorithm |
| `models.py` | `IPProfile`, `calculate_threat_score()` |

#### 3b. **detection/yara/** — Signature Matching
YARA rules for known malware patterns.

| Module | Purpose |
|--------|---------|
| `detector.py` | Pattern matching engine (25+ rules) |
| `rules_manager.py` | Load rules from file/Git/API |
| `models.py` | `YARARuleMatch`, `ThreatCategory` |

#### 3c. **detection/sigma_lite/** — Behavioral Detection
Correlates events into attack chains (60-sec windows).

| Module | Purpose |
|--------|---------|
| `detector.py` | 6 attack patterns: DNS exfil, lateral movement, etc. |
| `models.py` | `SigmaMatch`, `AttackChain` |

#### 3d. **detection/correlation/** — Threat Verdict
Combines all three detection methods with weighted confidence.

| Module | Purpose |
|--------|---------|
| `threat_correlator.py` | Synthesizes IP + YARA + Sigma-Lite verdicts |
| (exports) | `ThreatLevel`, `ThreatVerdict` |

**Imports:** From `core/`, `collection/`

### 4. **anti_forensics/** — ⚠️ MOVED TO EXTERNAL PACKAGE

**Status**: Moved to separate optional package `itl-ebpf-stealth`

For advanced threat simulation testing only. Install separately:
```bash
pip install itl-ebpf-stealth
```

### 5. **c2/** — ⚠️ MOVED TO EXTERNAL PACKAGE  

**Status**: Moved to separate optional package `itl-ebpf-stealth`

For advanced C2 communication testing only. Install separately:
```bash
pip install itl-ebpf-stealth
```

### 6. **integrations/** — External Systems
Real-time streaming and threat platform exports.

#### 6a. **integrations/braincell/** — BrainCell Persistent Memory
WebSocket streaming to BrainCell platform.

| Module | Purpose |
|--------|---------|
| `client.py` | Batch event streaming, tagging |

#### 6b. **integrations/amalia/** — Amalia Platform
Threat verdict export to Amalia red team platform.

| Module | Purpose |
|--------|---------|
| `exporter.py` | POST verdicts to Amalia API |

**Imports:** From `core/`, `detection/`, `collection/`

### 6. **application/** — Main Orchestrator
Thin orchestrator and DI composition root for core threat detection.

| Module | Purpose | Responsibility |
|--------|---------|-----------------|
| `implant_agent.py` | Main orchestrator | Wire services, handle CLI args, optional stealth support |
| `services.py` | Dependency injection factory | Create/wire all services (stealth optional) |

**Imports:** Core domains + optional stealth

**Optional Stealth Integration**:
- Auto-detects `itl-ebpf-stealth` package if installed
- Gracefully handles missing stealth (continues without it)
- No hard dependency on stealth modules

### 8. **examples/** — Usage Demonstrations
Three executable examples showing different capabilities.

| Example | Purpose |
|---------|---------|
| `basic_collection.py` | Collect events only |
| `full_analysis.py` | YARA + IP + Sigma-Lite detection |
| `braincell_streaming.py` | BrainCell integration demo |

## Import Patterns

### Pattern 1: Import from Domain

```python
# Correct: Import from new domain structure
from detection.ip_analysis import IPAnalyzer
from detection.yara import YARADetector
from detection.correlation import ThreatCorrelator

# Also valid: Re-exported via domain __init__.py
from detection import IPAnalyzer, ThreatCorrelator
```

### Pattern 2: Dependency Injection (DI)

```python
from application.services import get_services

# In application code:
services = get_services()
threat_detector = services.create_threat_detection_stack()
c2_client = services.create_c2_client()
```

### Pattern 3: Circular Dependency Avoidance

**Never do this:**
```python
# BAD: anti_forensics imports c2 imports detection
from anti_forensics import something
from c2 import something_else
from detection import something_third
```

**Good: Use DI or application layer:**
```python
# GOOD: Only application layer wires everything
from application import EBPFImplantAgent
implant = EBPFImplantAgent()  # DI happens inside
```

## Dependency Graph

```
Imports flow DOWNWARD ONLY (never upward):

application/
    ↓
├─ detection/      ← Used by application
├─ anti_forensics/ ← Used by application
├─ c2/             ← Used by application
├─ integrations/   ← Used by application
├─ collection/     ← Used by application
└─ core/           ← Used by all

NO circular dependencies (verified)
```

## Migration Path from Old Structure

| Old File | New Location | Status |
|----------|--------------|--------|
| `implant_agent.py` | `application/implant_agent.py` | Refactored (550→150 lines) |
| `ip_analysis.py` | `detection/ip_analysis/analyzer.py` | Moved |
| `yara_detection.py` | `detection/yara/detector.py` | Moved |
| `yara_rules_manager.py` | `detection/yara/rules_manager.py` | Moved |
| `sigma_lite_detector.py` | `detection/sigma_lite/detector.py` | Moved |
| `braincell_websocket.py` | `integrations/braincell/client.py` | Moved |
| `anti_forensics.py` | `anti_forensics/` (7 modules) | Split |
| `c2_client.py` | `c2/` (6 modules) | Split |
| **New:** threat_correlator.py | `detection/correlation/threat_correlator.py` | Created |
| **New:** config.py | `core/config.py` | Created |
| **New:** logger.py | `core/logger.py` | Created |
| **New:** base_classes.py | `core/base_classes.py` | Created |

## File Count by Domain

| Domain | Files | Purpose |
|--------|-------|---------|
| `core/` | 4 | Infrastructure |
| `collection/` | 2 | Event models |
| `detection/` | 12 | Threat analysis |
| `integrations/` | 4 | External integrations |
| `application/` | 2 | Main orchestrator |
| `examples/` | 4 | Usage examples |
| **Total** | **28** | - |
| **Optional**: `itl_ebpf_stealth` | 14 | Stealth & C2 (separate package) |

## Quick Start for Developers

### To use the implant:

```python
from application import EBPFImplantAgent

implant = EBPFImplantAgent(config_file="config.json", stealth_mode=True)
implant.start_collection(duration_sec=60)
implant.export_telemetry(output_file="/tmp/telemetry.json")
implant.stop()
```

### To add a new detection method:

1. Create `detection/my_detector/`
2. Add `detector.py` (implement `ThreatDetector` ABC)
3. Add `models.py` (data structures)
4. Add `__init__.py` (export public API)
5. Update `detection/correlation/threat_correlator.py` to include results
6. Update `application/services.py` to wire the service

### To add a new integration:

1. Create `integrations/my_platform/`
2. Add `client.py` (implement `ExternalIntegration` ABC)
3. Add `__init__.py` (export public API)
4. Wire in `application/services.py`

## Anti-Patterns to Avoid

1. **Importing from `application/` in domains** → Creates circular dependency
2. **Direct instantiation of services** → Use DI container instead
3. **Global singletons for stateful objects** → Use constructor injection
4. **Mixing concerns** → One module, one responsibility
5. **Cross-domain imports** → Use public API from `__init__.py`
6. **Hard-coding stealth dependencies** → Check if package available, gracefully degrade

## Performance Characteristics

| Component | Overhead | Notes |
|-----------|----------|-------|
| IP Analysis | <1ms per event | In-memory scoring |
| YARA Detection | 5-10ms per batch | Depends on rule count |
| Sigma-Lite | 2-5ms per 60s window | Behavioral correlation |
| Threat Correlation | <1ms | Weighted confidence calc |
| C2 Channel Switch | <100ms | HTTPS→DNS fallback |
| BrainCell Streaming | Async background | 50-event batches |

## Testing Strategy

Each domain can be tested independently:

```bash
# Test just IP analysis
python -m pytest detection/ip_analysis/

# Test just C2
python -m pytest c2/

# Test application with mocks
python -m pytest application/ --mock-external
```

## Documentation References

- `ARCHITECTURE.md` — High-level platform design
- `CLAUDE.md` — Project mission and deployment modes
- `SIGMA_LITE_CHAINS.md` — Behavioral pattern documentation
- `QUICKSTART.md` — 5-minute deployment guide
