# ITL.Amalia.Poc.eBpf — Implementatie Audit

**Datum:** 1 oktober 2026  
**Operateur:** Niels Weistra, CISSP  
**Autorisatie:** RoE-ITlusions-Testlab-2026 (27 apr – 31 dec 2026)  
**Scope audit:** Crashdetectie, POC-bouw, reproductie workflow

---

## Executive Summary

De implementatie van crashdetectie en POC-bouw is **technisch robuust** maar **autorisatiecontroles ontbreken volledig**. Geen enkele codepat valideert:

- Doelsystemen tegen RoE-scope
- Operatoridentiteit en permissies
- Starttijd van engagement
- Audit logging van exploitpogingen

**Risicoclassificatie:** MEDIUM (technisch sterk, procedureel zwak)

---

## Bevindingen

### 1. KRITIEK: Geen Scope-Validatie in POCBuilder

| Bevinding | Sterkte | CVSS | Impact |
|-----------|---------|------|--------|
| POCBuilder accepteert willekeurige target_ip/port | High | 6.5 | Kan buiten labscope testen |
| Geen RoE-binding in CrashContext | High | 6.5 | Geen audit trail |
| Hardcoded localhost:8888 als default | Low | 2.5 | Verzekerdt labzetting maar niet afdwingend |
| Geen autorisatieverificatie vóór exploitatie | High | 6.5 | Operator kan zonder toestemming handelen |

**Bewijslocatie:** [poc_builder.py](userspace/src/examples/poc_builder.py#L71-L100)

```python
@dataclass
class CrashContext:
    target_ip: str      # ← Geen validatie tegen CIDR's
    target_port: int    # ← Geen poort-whitelist
    # Geen: engagement_id, operator_id, roe_reference, authorized_scope
```

**Aanval:** Operator laadt crash report en wijzigt target_ip naar "192.168.1.100" (klantnetwerk) zonder waarschuwing:

```python
builder = POCBuilder(crash_report)
builder.context.target_ip = "192.168.1.100"  # ← Geen blokkering
poc_code = builder.build_exploit()
builder.export_poc("/tmp/attack_customer.py")
```

---

### 2. KRITIEK: Geen Audit Logging van Exploitpogingen

| Bevinding | Sterkte | Impact |
|-----------|---------|--------|
| subprocess.run() exploitverificatie loggen niet | High | Geen bewijspad voor incidenten |
| POCBuilder.test_poc() heeft geen centraal logboek | High | Reproduceerbaarheid onbekend |
| CrashDetector.process_crash_event() logt alleen naar applicatie | Medium | Audit trail incompleet |

**Bewijslocatie:** [poc_builder.py#L554-L585](userspace/src/examples/poc_builder.py#L554)

```python
def test_poc(self, poc_path: str, iterations: int = 5) -> Dict[str, Any]:
    results = {
        "total_runs": iterations,
        "successful": 0,  # ← Succes niet ondertekend
        "failed": 0
    }
    for i in range(iterations):
        try:
            result = subprocess.run(...)  # ← Geen logging van exploitpoging
```

**Consequentie:** Crashlog toont "crash detected" maar niet "exploitcode genereerd en getest".

---

### 3. HOOG: CrashDetector Coredump-Operaties op Linux Alleen

| Bevinding | Sterkte | Scope | Impact |
|-----------|---------|-------|--------|
| `enable_coredumps()` probeert `/proc/sys/kernel/core_pattern` te schrijven | High | Linux/Unix | root-bevoegdheden vereist; Windows niet ondersteund |
| `analyze_crash()` voert gdb uit zonder error handling | High | Debugging | Kan falen op systemen zonder gdb |
| `_find_coredump()` leest `/var/crashes/` — hardcoded pad | Medium | Linux | Niet portabel naar Windows/macOS |

**Bewijslocatie:** [detector.py#L116-L130](userspace/src/detection/crash_detection/detector.py#L116)

```python
def enable_coredumps(self):
    try:
        os.system("ulimit -c unlimited")  # ← Shell-command, Linux-only
        with open("/proc/sys/kernel/core_pattern", "w") as f:  # ← /proc, Linux-only
            f.write("/var/crashes/core-%e-%p-%t")
    except PermissionError:
        logger.warning("[!] Cannot enable core dumps (requires root)")
```

**Aanval:** Op Windows/macOS blijft coredump deactiveren stil (warning alleen); operator denkt dat context is verzameld maar het is leeg.

---

### 4. HOOG: Geen Verificatie van Doelproces in Exploit-Verificatie

| Bevinding | Sterkte | Impact |
|-----------|---------|--------|
| `verify_crash()` gebruikt `pgrep -x <process_name>` | Medium | Kan procesnamen botsen |
| Geen verificatie dat het juiste PID is gecrasht | High | Valse positieven mogelijk |
| Geen netwerk-connectiviteitstest vóór exploitpoging | Medium | Stille falures zonder foutmelding |

**Bewijslocatie:** [poc_builder.py#L254-L264](userspace/src/examples/poc_builder.py#L254)

```python
def verify_crash(self):
    time.sleep(0.5)
    result = subprocess.run(
        ["pgrep", "-x", "{self.context.process_name}"],  # ← Kan vals negatief geven
        capture_output=True
    )
    if result.returncode == 0:
        return False  # Still running
    else:
        return True   # ← Aangenomen dat PID gecrasht, maar onbevestigd
```

---

### 5. MEDIUM: Geen Scope-Communicatie in POC-Generatie

| Bevinding | Sterkte | Impact |
|-----------|---------|--------|
| Gegenereerde POC bevat geen RoE-referentie | Medium | Onbekend of POC binnen scope mag draaien |
| Geen waarschuwing bij bouw buiten testlab-uren | Low | Uit-scope exploitatie mogelijk |
| Template hardcoded "localhost" als failsafe, niet als verplichting | Low | Vertrouwt operator om poort niet te wijzigen |

**Bewijslocatie:** [poc_builder.py#L200-L250](userspace/src/examples/poc_builder.py#L200)

---

## Bedreigingsmodel

### Offensieve Scenario's

| Scenario | Waarschijnlijkheid | Detectie |
|----------|-------------------|----------|
| Operator wijzigt target_ip naar klantnetwerk | Hoog | Geen (RoE-validatie ontbreekt) |
| POC buiten RoE-uren wordt getest | Medium | Geen (tijdstempel-validatie ontbreekt) |
| Crash van niet-autoriseerd proces wordt verwerkt | Medium | Risicoklassificatie gebeurt; geen scope-check |
| Exploitverificatie als eigenstandig script wordt gekopieerd | Hoog | Geen audit trail; onbekend wie/wanneer |

### Verdedigings Prioriteiten

1. **RoE-binding** in POCBuilder
2. **Audit logging** naar BrainCell
3. **Scope-validatie** vóór socket-verbinding
4. **Operator-authenticatie** in crashdetectie

---

## Aanbevelingen

### Tier 1: Kritiek (implementeer voor end-to-date deployment)

#### 1a. Voeg RoE-Context aan POCBuilder toe

```python
@dataclass
class CrashContext:
    # Bestaande velden...
    engagement_id: str          # Gekoppelde RoE
    engagement_scope: List[str] # Toegestane CIDR's / domeinen
    operator_id: str            # CISSP cert holder
    roe_expiry: datetime        # RoE geldigheid
    
    def validate_target(self, target_ip: str, target_port: int) -> bool:
        """Controleer of target in scope valt"""
        # Controleer tegen self.engagement_scope CIDR's
        # Controleer roe_expiry >= now()
        # Log poging in BrainCell
        pass
```

#### 1b. Audit Logging naar BrainCell

```python
class POCBuilder:
    def test_poc(self, poc_path: str, iterations: int) -> Dict:
        # Elk testresultaat naar BrainCell:
        braincell_log = {
            "cell": "incidents",
            "title": f"POC Test: {self.context.process_name} (PID {self.context.pid})",
            "engagement_id": self.context.engagement_id,
            "operator": self.context.operator_id,
            "target": f"{self.context.target_ip}:{self.context.target_port}",
            "success_rate": results["success_rate"],
            "timestamp": datetime.now().isoformat()
        }
        # POST naar BrainCell API
```

---

### Tier 2: Hoog (implementeer vóór productiedeployment)

#### 2a. Operator-Verificatie in CrashDetector

```python
class CrashDetector:
    def __init__(self, operator_id: str, roe_path: str):
        """Bind detector aan operator en RoE"""
        self.operator_id = operator_id
        self.roe = self._load_roe(roe_path)  # Valideer ondertekening
        self.roe_expiry = self.roe.get("end_date")
        
    def process_crash_event(self, ebpf_event: Dict) -> CrashEvent:
        # Valideer RoE geldigheid
        if datetime.now() > self.roe_expiry:
            raise ValueError(f"RoE verlopen op {self.roe_expiry}")
```

#### 2b. Doelvalidatie Vóór Exploitpoging

```python
def send_payload(self, payload):
    """Valideer target vóór verbinding"""
    if not self.context.validate_target(self.target_ip, self.target_port):
        raise ValueError(
            f"Target {self.target_ip}:{self.target_port} is OUT OF SCOPE. "
            f"Engagement scope: {self.context.engagement_scope}"
        )
    # Pas dan socket-verbinding tot
    sock = socket.socket(...)
```

---

### Tier 3: Gemiddeld (implementeer vóór volgende sprint)

#### 3a. Cross-Platform Coredump-Ondersteuning

```python
def enable_coredumps(self):
    """Platform-agnostische coredump-activering"""
    if sys.platform.startswith("linux"):
        self._enable_coredumps_linux()
    elif sys.platform == "win32":
        self._enable_coredumps_windows()  # Crash dumps via WER
    elif sys.platform == "darwin":
        self._enable_coredumps_macos()    # crashreporter
```

#### 3b. Verbeterde Procesbewaking in verify_crash()

```python
def verify_crash(self):
    """Verificatie met PID-binding"""
    # Controleer specifieke PID, niet procesnaam
    if self.original_pid and not self._pid_exists(self.original_pid):
        return True  # Dit PID is weg
    
    # Secundaire: controleer coredump
    if self.coredump_path and os.path.exists(self.coredump_path):
        return True  # Bewijs dat process gecrasht
    
    return False
```

---

## Implementatietijdlijn

| Fase | Duur | Prioriteit | Artefacten |
|------|------|-----------|-----------|
| Tier 1 (RoE-binding, audit logging) | 2-3 dagen | Kritiek | braincell_integration.py |
| Tier 2 (Operator-verificatie, doelvalidatie) | 2-3 dagen | Hoog | roe_validator.py |
| Tier 3 (Cross-platform, PID-tracking) | 2-3 dagen | Gemiddeld | platform_adapter.py |
| QA en testing | 2-3 dagen | — | test_scope_validation.py |
| **Totaal** | **1-2 weken** | — | — |

---

## Conclusie

De code is **architecturaal robuust** maar **procedureel onvolledig**. De afwezigheid van scope-afdwinging is geen technisch problema maar een governance-risico.

Met Tier 1-implementatie (RoE-binding + audit) wordt deze codebase productiefit voor geautoriseerde labdoeleinden.

---

**Operator:** Niels Weistra, CISSP  
**Datum:** 1 oktober 2026  
**Status:** Geldige RoE; implementatie nodig vóór productiegebruik
