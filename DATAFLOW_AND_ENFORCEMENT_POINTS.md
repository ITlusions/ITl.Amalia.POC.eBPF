# Dataflow: Crash Detection → POC Rebuild

Dit diagram toont de huidige workflow en waar scope-validatie/audit-logging ontbreekt.

---

## Huidig Dataflow (Onvolledig)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   PHASE 1: CRASH DETECTION                          │
└─────────────────────────────────────────────────────────────────────┘

  eBPF Kernel
  ┌──────────────────────────────────────────┐
  │ [tp/sched/sched_process_exec]            │
  │ ┌────────────────────────────────────┐   │
  │ │ Capture SIGSEGV, SIGABRT, SIGBUS   │   │
  │ └────────────────────────────────────┘   │
  └──────────────────┬───────────────────────┘
                     │
                     │ Ring Buffer
                     ↓
  ┌──────────────────────────────────────────────┐
  │  detection/crash_detection/detector.py       │
  │  ┌──────────────────────────────────────┐    │
  │  │ CrashDetector.process_crash_event()  │    │
  │  │                                      │    │
  │  │ ✓ Extract: PID, signal, RIP, RIP   │    │
  │  │ ✓ Map RIP to HEAP/STACK/CODE       │    │
  │  │ ✓ Risk classification              │    │
  │  │ ✓ Try to collect coredump (Linux)  │    │
  │  │                                      │    │
  │  │ ✗ NO: Operator verification        │    │
  │  │ ✗ NO: RoE scope check              │    │
  │  │ ✗ NO: Audit log                    │    │
  │  └──────────────────────────────────────┘    │
  │                                              │
  │  ┌──────────────────────────────────────┐    │
  │  │ CrashDetector.export_crash_report()  │    │
  │  │                                      │    │
  │  │ → JSON file with forensics          │    │
  │  │ ✗ NO RoE reference                 │    │
  │  │ ✗ NO audit trail                   │    │
  │  └──────────────────────────────────────┘    │
  └──────────────────┬───────────────────────────┘
                     │
                     │ crash_report.json
                     ↓

┌─────────────────────────────────────────────────────────────────────┐
│                   PHASE 2: POC GENERATION                           │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────┐
  │  examples/poc_builder.py                     │
  │  ┌──────────────────────────────────────┐    │
  │  │ POCBuilder.__init__(crash_report)    │    │
  │  │                                      │    │
  │  │ ✓ Extract context                   │    │
  │  │ ✓ Classify exploit type             │    │
  │  │                                      │    │
  │  │ ✗ NO: Target IP validation          │    │
  │  │ ✗ NO: RoE scope binding             │    │
  │  │ ✗ NO: Operator ID capture           │    │
  │  └──────────────────────────────────────┘    │
  │                                              │
  │  ┌──────────────────────────────────────┐    │
  │  │ POCBuilder.build_exploit()           │    │
  │  │  → _build_buffer_overflow()          │    │
  │  │  → _build_heap_overflow()            │    │
  │  │  → _build_stack_pivot()              │    │
  │  │                                      │    │
  │  │ Template includes socket + subproc  │    │
  │  │ ✓ Correct exploit logic             │    │
  │  │ ✗ NO: Scope hardening               │    │
  │  └──────────────────────────────────────┘    │
  │                                              │
  │  ┌──────────────────────────────────────┐    │
  │  │ POCBuilder.export_poc(filepath)      │    │
  │  │                                      │    │
  │  │ ✓ Write Python file                 │    │
  │  │ ✓ Make executable (chmod +x)        │    │
  │  │                                      │    │
  │  │ ✗ NO: Audit log                     │    │
  │  │ ✗ NO: Scope tag in generated code   │    │
  │  └──────────────────────────────────────┘    │
  └──────────────────┬───────────────────────────┘
                     │
                     │ exploit.py (executable)
                     ↓

┌─────────────────────────────────────────────────────────────────────┐
│                   PHASE 3: POC TESTING                              │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────┐
  │  POCBuilder.test_poc(poc_path, iterations)   │
  │  ┌──────────────────────────────────────┐    │
  │  │ For i in range(iterations):          │    │
  │  │   subprocess.run(["python3", poc])   │    │
  │  │   → Sends socket to target_ip:port   │    │
  │  │                                      │    │
  │  │ ✓ Loops N times                     │    │
  │  │ ✓ Counts successes                  │    │
  │  │ ✓ Returns success_rate              │    │
  │  │                                      │    │
  │  │ ✗ NO: Target validation             │    │
  │  │ ✗ NO: Audit log per iteration       │    │
  │  │ ✗ NO: Early exit on out-of-scope    │    │
  │  └──────────────────────────────────────┘    │
  └──────────────────┬───────────────────────────┘
                     │
                     │ test_results.json
                     │ (success_rate, etc)
                     ↓
                 [END]
```

---

## KRITIEKE PATHS (Waar Scope-Validatie Ontbreekt)

### Path A: Operator → POCBuilder (ONBESCHERMD)

```
┌─────────────────────────────┐
│ Operator runs:              │
│ POCBuilder(crash_report)    │
└────────┬────────────────────┘
         │
         ↓ NO CHECKS ✗
┌──────────────────────────────────────────┐
│ builder = POCBuilder(report)             │
│ # Operator kan nu:                       │
│ builder.context.target_ip = "1.2.3.4"   │  ← OUT OF SCOPE
│ builder.context.target_port = 80        │  ← EXTERNAL SERVICE
│ poc = builder.build_exploit()           │  ← GENERATES CODE
│ poc_path = builder.export_poc("/tmp/")   │  ← WRITES FILE
└─────────────────────────────────────────┘

❌ PROBLEEM: Geen doelvalidatie
❌ PROBLEEM: Geen autorisatiecheck
❌ PROBLEEM: Geen audit trail
```

### Path B: POC Execution (ONBESCHERMD)

```
┌─────────────────────────────┐
│ Operator runs:              │
│ python3 exploit.py          │
└────────┬────────────────────┘
         │
         ↓ HARDCODED TARGET
┌──────────────────────────────────────────┐
│ sock = socket.socket()                   │
│ sock.connect(("192.168.1.100", 8888))    │  ← COULD BE CUSTOMER!
│ sock.sendall(payload)                    │  ← OUT OF SCOPE ATTACK
│ sock.close()                             │
└─────────────────────────────────────────┘

❌ PROBLEEM: Socket target ongevalideerd
❌ PROBLEEM: Geen scope check
❌ PROBLEEM: Geen logging
❌ CONSEQUENTIE: Operator kan per ongeluk klant testen
```

---

## VERSTERKTE DATAFLOW (Met Mitigatie)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   PHASE 2: POC GENERATION (VERSTERKT)               │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  POCBuilder.__init__(crash_report, operator_id, roe_path)    │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │ ✓ Extract context                                     │  │
  │  │ ✓ Classify exploit type                              │  │
  │  │                                                        │  │
  │  │ ✓✓ LOAD & VALIDATE RoE                               │  │
  │  │    - Check roe_expiry >= now()                        │  │
  │  │    - Bind engagement_id                               │  │
  │  │    - Load allowed_scope CIDR's                        │  │
  │  │                                                        │  │
  │  │ ✓✓ BIND OPERATOR                                      │  │
  │  │    - Store operator_id (audit trail)                  │  │
  │  │    - Log: "POCBuilder created by {op} for {eng}"      │  │
  │  │                                                        │  │
  │  │ ✓✓ VALIDATE TARGET                                    │  │
  │  │    - Check target_ip in allowed_scope                 │  │
  │  │    - Reject if out-of-scope                           │  │
  │  │    - Error: "Target X.X.X.X NOT in scope"             │  │
  │  └────────────────────────────────────────────────────────┘  │
  │                                                              │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │ POCBuilder.build_exploit()                             │  │
  │  │  [Same as before — logic unchanged]                   │  │
  │  └────────────────────────────────────────────────────────┘  │
  │                                                              │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │ POCBuilder.export_poc(filepath)                        │  │
  │  │                                                        │  │
  │  │ ✓ Write Python file                                   │  │
  │  │                                                        │  │
  │  │ ✓✓ LOG TO AUDIT TRAIL                                 │  │
  │  │    - Append /tmp/poc-audit-trail.jsonl:               │  │
  │  │    {                                                   │  │
  │  │      "event": "poc_generated",                         │  │
  │  │      "timestamp": "2026-10-01T...",                   │  │
  │  │      "operator": "niels.weistra",                      │  │
  │  │      "engagement": "RoE-Testlab-2026",                │  │
  │  │      "process": "vulnerable_app",                      │  │
  │  │      "target": "127.0.0.1:8888",                      │  │
  │  │      "exploit_type": "buffer_overflow",                │  │
  │  │      "poc_path": "/tmp/exploit.py"                     │  │
  │  │    }                                                   │  │
  │  │                                                        │  │
  │  │ ✓✓ ADD SCOPE TAG TO GENERATED CODE                    │  │
  │  │    # Generated code template includes:                 │  │
  │  │    """                                                 │  │
  │  │    # Authorization: RoE-Testlab-2026                  │  │
  │  │    # Operator: niels.weistra                           │  │
  │  │    # Scope: 127.0.0.1, 10.0.0.0/8, 192.168.0.0/16    │  │
  │  │    # Permitted targets ONLY                            │  │
  │  │    """                                                 │  │
  │  └────────────────────────────────────────────────────────┘  │
  └───────────────────────┬──────────────────────────────────────┘
                          │
                          │ exploit.py (WITH SCOPE TAGS)
                          ↓

┌─────────────────────────────────────────────────────────────────────┐
│                   PHASE 3: POC TESTING (VERSTERKT)                  │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  POCBuilder.test_poc(poc_path, iterations)                   │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │ ✓✓ VALIDATE TARGET BEFORE EACH ITERATION              │  │
  │  │    if not context.validate_target(target_ip):         │  │
  │  │      raise ValueError("OUT OF SCOPE")                 │  │
  │  │                                                        │  │
  │  │ For i in range(iterations):                           │  │
  │  │   ✓✓ LOG BEFORE TEST                                  │  │
  │  │      audit.log("poc_test_start", iteration=i)         │  │
  │  │                                                        │  │
  │  │   subprocess.run(["python3", poc])                     │  │
  │  │   → Sends socket to target_ip:port                    │  │
  │  │                                                        │  │
  │  │   ✓✓ LOG AFTER TEST                                   │  │
  │  │      audit.log("poc_test_result", success=bool)       │  │
  │  │                                                        │  │
  │  │ ✓✓ FINAL AUDIT LOG                                    │  │
  │  │    {                                                   │  │
  │  │      "event": "poc_test_complete",                     │  │
  │  │      "operator": "niels.weistra",                      │  │
  │  │      "engagement": "RoE-Testlab-2026",                │  │
  │  │      "target": "127.0.0.1:8888",                      │  │
  │  │      "iterations": 5,                                  │  │
  │  │      "successful": 4,                                  │  │
  │  │      "success_rate": 0.8,                              │  │
  │  │      "timestamp": "2026-10-01T..."                    │  │
  │  │    }                                                   │  │
  │  └────────────────────────────────────────────────────────┘  │
  └──────────────────────┬───────────────────────────────────────┘
                         │
                         │ test_results.json + audit trail
                         ↓
        BrainCell.incidents (POTENTIAL FUTURE)
        /tmp/poc-audit-trail.jsonl (IMMEDIATE)
                     [END]
```

---

## Scope Enforcement Points

| Stap | Huidig | Mitigatie | Status |
|------|--------|-----------|--------|
| POCBuilder init | ✗ | Load RoE + validate expiry | TODO Tier 1 |
| Target IP set | ✗ | validate_target() CIDR check | TODO Tier 1 |
| Export POC | ✗ | Audit log + scope tag in code | TODO Tier 1 |
| Test POC (iteration) | ✗ | Validate target + log each run | TODO Tier 1 |
| Socket connect | ✗ | Guard clause + fail-safe | TODO Tier 2 |
| Operator verify | ✗ | Bind to operator_id | TODO Tier 2 |

---

## Implementatie Volgorde

1. **Eerst:** CIDR-validatie in `CrashContext.validate_target()`
2. **Dan:** RoE-laden in `POCBuilder.__init__()`
3. **Dan:** Audit-loggen in `export_poc()` en `test_poc()`
4. **Laatste:** Scope-tag in gegenereerde code-template

**Verwachte impact:** Geen logica-verandering; zuiver toevoegingen.

---

Generated: 1 oktober 2026
