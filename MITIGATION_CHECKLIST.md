# Mitigatie Checklist — Directe Maatregelen

**Status:** Lab-RoE geldig; dit plan adresseert governance-risico's vóór productiegebruik

---

## Onmiddellijk (< 1 dag)

- [x] RoE-referentie vastleggen in projectdocumentatie (README, RUNBOOK, GUIDE)
  - **Gedaan:** [IMPLEMENTATION_REVIEW.md](./IMPLEMENTATION_REVIEW.md)

- [ ] Code-review checklist toevoegen: "Scope-validatie?"
  - **Locatie:** Voeg toe aan [CLAUDE.md](./CLAUDE.md) pull-request template

- [ ] Documenteer "Permitted targets" en "Forbidden targets" expliciet
  ```markdown
  ✓ Permitted: 127.0.0.1, localhost, 10.0.0.0/8 (labnetwerken)
  ✗ Forbidden: Alle externe IP's, klantnetwerken, publieke services
  ```
  - **Locatie:** [POC_REBUILD_GUIDE.md](./POC_REBUILD_GUIDE.md) sectie 1

- [ ] Operator-identiteit opvragen in POCBuilder.__init__()
  ```python
  builder = POCBuilder(crash_report, operator_id="niels.weistra")
  ```
  - **Locatie:** [poc_builder.py](./userspace/src/examples/poc_builder.py) lijn 71

- [ ] Noodstop-woord toevoegen aan demo
  ```python
  # Signal handler for "STOP" command
  signal.signal(signal.SIGINT, cleanup)  # Ctrl+C → schoon afsluiten
  ```
  - **Locatie:** [poc_rebuild_demo.py](./userspace/src/examples/poc_rebuild_demo.py)

---

## Korte termijn (1-3 dagen)

- [ ] **Tier 1a: RoE-Context toevoegen**
  
  **File:** [userspace/src/examples/poc_builder.py](userspace/src/examples/poc_builder.py)
  
  ```python
  @dataclass
  class CrashContext:
      # Bestaande velden...
      process_name: str
      binary_path: str
      
      # NIEUWE VELDEN VOOR AUTORISATIE:
      engagement_id: str = "RoE-ITlusions-Testlab-2026"
      engagement_scope: List[str] = field(default_factory=lambda: ["127.0.0.1/32", "10.0.0.0/8", "192.168.0.0/16"])
      operator_id: str = "niels.weistra"
      roe_expiry: str = "2026-12-31"
      
      def validate_target(self, target_ip: str) -> bool:
          """Reject out-of-scope targets"""
          import ipaddress
          target = ipaddress.ip_address(target_ip)
          for cidr in self.engagement_scope:
              if target in ipaddress.ip_network(cidr):
                  return True
          raise ValueError(f"Target {target_ip} OUT OF SCOPE. Allowed: {self.engagement_scope}")
  ```

- [ ] **Tier 1b: Audit-log toevoegen**
  
  **File:** [userspace/src/examples/poc_builder.py](userspace/src/examples/poc_builder.py) klasse POCBuilder
  
  ```python
  def export_poc(self, filepath: str) -> str:
      """Export POC en log naar audit trail"""
      exploit_code = self.build_exploit()
      
      with open(filepath, "w") as f:
          f.write(exploit_code)
      
      # LOG NAAR BRAINCELL
      braincell_log = {
          "timestamp": datetime.now().isoformat(),
          "event": "poc_generated",
          "engagement_id": self.context.engagement_id,
          "operator": self.context.operator_id,
          "process": self.context.process_name,
          "target": f"{self.context.target_ip}:{self.context.target_port}",
          "exploit_type": self.exploit_type.value,
          "poc_path": filepath
      }
      
      # Write to local audit log (tot BrainCell API beschikbaar)
      with open("/tmp/poc-audit-trail.jsonl", "a") as f:
          f.write(json.dumps(braincell_log) + "\n")
      
      logger.info(f"[+] POC exported + audited: {filepath}")
      return filepath
  ```

- [ ] **Scope-validatie invoegen vóór socket-verbinding**
  
  **File:** [userspace/src/examples/poc_builder.py](userspace/src/examples/poc_builder.py) klasse BufferOverflowExploit
  
  ```python
  def send_payload(self, payload):
      """Send payload to vulnerable service"""
      # SCOPE-VALIDATIE
      try:
          if not self.context.validate_target(self.target_ip):
              raise ValueError(f"Target {self.target_ip} is out of scope")
      except AttributeError:
          # Geen scope-context; fail-safe naar localhost
          if self.target_ip != "127.0.0.1" and self.target_ip != "localhost":
              print(f"[!] WARNING: No scope validation context; using localhost fallback")
              self.target_ip = "127.0.0.1"
      
      try:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.connect((self.target_ip, self.target_port))
          sock.sendall(payload)
          sock.close()
          return True
      except Exception as e:
          print(f"[-] Connection failed: {e}")
          return False
  ```

---

## Middellange termijn (1-2 weken)

- [ ] **Tier 2: Operator-verificatie integreert in CrashDetector**
  
  **File:** [userspace/src/detection/crash_detection/detector.py](userspace/src/detection/crash_detection/detector.py)
  
  ```python
  class CrashDetector:
      def __init__(self, operator_id: str = None, roe_path: str = None):
          self.crash_events = []
          self.triages = []
          self.operator_id = operator_id or "unknown"
          self.roe_path = roe_path
          
          # Valideer RoE als verstrekt
          if roe_path and os.path.exists(roe_path):
              with open(roe_path) as f:
                  self.roe = json.load(f)
          else:
              self.roe = {"end_date": "2026-12-31"}  # Fallback
          
          # Controleer expiry
          roe_end = datetime.fromisoformat(self.roe["end_date"])
          if datetime.now() > roe_end:
              raise ValueError(f"RoE expired on {roe_end}")
          
          self.enable_coredumps()
  ```

- [ ] **Tier 2: Operator-verificatie in POCBuilder.test_poc()**
  
  **File:** [userspace/src/examples/poc_builder.py](userspace/src/examples/poc_builder.py)
  
  ```python
  def test_poc(self, poc_path: str, iterations: int = 5) -> Dict[str, Any]:
      """Test POC reliability with audit logging"""
      
      results = {
          "total_runs": iterations,
          "successful": 0,
          "failed": 0,
      }
      
      # Audit log start
      audit_log_start = {
          "event": "poc_test_start",
          "poc_path": poc_path,
          "operator": self.context.operator_id,
          "target": f"{self.context.target_ip}:{self.context.target_port}",
          "timestamp": datetime.now().isoformat(),
          "iterations": iterations
      }
      
      for i in range(iterations):
          try:
              result = subprocess.run([...], timeout=5)
              if result.returncode == 0:
                  results["successful"] += 1
          except subprocess.TimeoutExpired:
              results["failed"] += 1
      
      # Audit log end
      audit_log_end = audit_log_start.copy()
      audit_log_end["event"] = "poc_test_complete"
      audit_log_end["success_rate"] = results["success_rate"]
      
      # Write audit trail
      with open("/tmp/poc-audit-trail.jsonl", "a") as f:
          f.write(json.dumps(audit_log_end) + "\n")
      
      return results
  ```

---

## Kwaliteitscontrole

Voordat je code committed, controleer:

```bash
# 1. Unicode fout fixed?
python examples/poc_rebuild_demo.py 2>&1 | head -20

# 2. Scope-validatie aanwezig?
grep -n "validate_target\|engagement_scope" userspace/src/examples/poc_builder.py

# 3. Audit logging aanwezig?
grep -n "braincell\|audit_log" userspace/src/examples/poc_builder.py

# 4. Operator-verificatie aanwezig?
grep -n "operator_id\|roe_expiry" userspace/src/detection/crash_detection/detector.py

# 5. Syntax valide?
python -m py_compile userspace/src/examples/poc_builder.py
python -m py_compile userspace/src/detection/crash_detection/detector.py
```

---

## Signoff

Wanneer alle stappen voltooid:

```
[ ] Mitigatie voltooid — Alle Tier 1 items gesloten
[ ] QA gevalideerd — Tests groepsgroen
[ ] RoE-referentie in 3+ projectbestanden
[ ] Operator-verificatie geïmplementeerd
[ ] Audit-trail naar /tmp/poc-audit-trail.jsonl

Handtekening: Niels Weistra, CISSP
Datum: _____________
```

---

**Volgende stap:** Controleer Unicode-fout; implementeer Tier 1 mitigaties; test volledige workflow.
