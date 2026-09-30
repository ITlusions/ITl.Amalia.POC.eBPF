# External YARA Rules Management

Load threat detection rules from multiple sources instead of hardcoding them. Enables centralized rule management, rapid updates, and team collaboration.

## Overview

The YARA Rules Manager supports loading rules from:

| Source | Use Case | Update Speed | Complexity |
|--------|----------|--------------|-----------|
| **Embedded** | Standalone deployments, no internet | Static | Simple |
| **Local File** | Custom rules, testing, offline | Manual | Easy |
| **Git Repository** | Team collaboration, version control | Pull updates | Medium |
| **BrainCell API** | Centralized threat intelligence | Real-time | Advanced |

## Quick Start

### 1. Using Local File

Create `yara-rules.json`:
```json
{
  "c2_beacon": {
    "description": "C2 patterns",
    "patterns": [
      {"port": 4444, "severity": "high"}
    ]
  }
}
```

Configure in `config.json`:
```json
{
  "yara_analysis": {
    "enabled": true,
    "rules": {
      "source": "file",
      "file": "/path/to/yara-rules.json"
    }
  }
}
```

Run:
```bash
sudo python3 implant_agent.py --load --collect 60 --yara-rules --export
```

### 2. Using Git Repository

Store rules in GitHub:
```
https://raw.githubusercontent.com/yourorg/threat-rules/main/yara-rules.json
```

Configure:
```json
{
  "yara_analysis": {
    "enabled": true,
    "rules": {
      "source": "git",
      "git_url": "https://raw.githubusercontent.com/yourorg/threat-rules/main/yara-rules.json"
    }
  }
}
```

### 3. Using BrainCell

Store rules as BrainCell notes tagged with `yara-rule`:

Configure:
```json
{
  "yara_analysis": {
    "enabled": true,
    "rules": {
      "source": "braincell",
      "braincell_url": "http://braincell:8000",
      "braincell_token": "your-api-token"
    }
  }
}
```

### 4. Using Embedded (Default)

No configuration needed - uses built-in rules:
```json
{
  "yara_analysis": {
    "enabled": true,
    "rules": {
      "source": "embedded"
    }
  }
}
```

## Configuration Reference

### Rules Configuration

```json
{
  "yara_analysis": {
    "rules": {
      "source": "embedded|file|git|braincell",
      "file": "/path/to/rules.json",
      "git_url": "https://raw.../yara-rules.json",
      "braincell_url": "http://braincell:8000",
      "braincell_token": "api-token-here",
      "cache_rules": true
    }
  }
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `source` | string | "embedded" | Where to load rules from |
| `file` | string | null | Path to JSON rules file |
| `git_url` | string | null | Git raw URL to rules JSON |
| `braincell_url` | string | null | BrainCell API base URL |
| `braincell_token` | string | null | BrainCell API authentication token |
| `cache_rules` | bool | true | Cache loaded rules in memory |

## Rule File Format

Rules are JSON with threat categories:

```json
{
  "category_name": {
    "description": "What this detects",
    "patterns": [
      {
        "port": 4444,
        "severity": "high",
        "description": "Known C2 port"
      },
      {
        "name": "pattern_name",
        "condition": "detection_condition",
        "severity": "medium"
      }
    ]
  }
}
```

### Pattern Types

**Port-based:**
```json
{"port": 4444, "severity": "high"}
```

**Condition-based:**
```json
{
  "name": "dns_tunneling",
  "condition": "dns_queries > 100 and bytes_sent > 10000",
  "severity": "high"
}
```

### Severity Levels

- `critical` - Immediate threat, take action now
- `high` - Strong evidence of malicious activity
- `medium` - Suspicious but could be legitimate
- `low` - Minimal risk, informational

## Usage Examples

### Example 1: Local File (Testing Custom Rules)

```bash
# Create test rules
cat > /tmp/test-rules.json << 'EOF'
{
  "test_threat": {
    "description": "Test threat pattern",
    "patterns": [
      {"port": 9999, "severity": "high"}
    ]
  }
}
EOF

# Configure to use local file
python3 -c "
import json
config = json.load(open('config.json'))
config['yara_analysis']['rules'] = {
    'source': 'file',
    'file': '/tmp/test-rules.json'
}
json.dump(config, open('config.json', 'w'), indent=2)
"

# Run with custom rules
sudo python3 implant_agent.py --load --collect 60 --yara-rules --export
```

### Example 2: Git Repository (Team Rules)

```bash
# Store rules in GitHub
# https://github.com/yourorg/threat-rules/blob/main/yara-rules.json

# Configure to use git
python3 -c "
import json
config = json.load(open('config.json'))
config['yara_analysis']['rules'] = {
    'source': 'git',
    'git_url': 'https://raw.githubusercontent.com/yourorg/threat-rules/main/yara-rules.json'
}
json.dump(config, open('config.json', 'w'), indent=2)
"

# Implant will automatically fetch latest rules from git
sudo python3 implant_agent.py --load --collect 60 --yara-rules --export
```

### Example 3: BrainCell (Central Rules)

```bash
# 1. Create rules in BrainCell as notes with 'yara-rule' tag:
#    Title: c2_beacon
#    Content: {"description": "...", "patterns": [...]}
#    Tags: ["yara-rule", "c2"]

# 2. Configure to use BrainCell
python3 -c "
import json
config = json.load(open('config.json'))
config['yara_analysis']['rules'] = {
    'source': 'braincell',
    'braincell_url': 'http://braincell:8000',
    'braincell_token': 'your-token'
}
json.dump(config, open('config.json', 'w'), indent=2)
"

# 3. Run - rules loaded from BrainCell
sudo python3 implant_agent.py --load --collect 60 --yara-rules --export
```

## Programmatic Usage

### Load Rules Directly

```python
from yara_rules_manager import YARARulesManager

# Load from file
manager = YARARulesManager({
    "source": "file",
    "file": "/path/to/yara-rules.json"
})
rules = manager.load_rules()

# Or from git
manager = YARARulesManager({
    "source": "git",
    "git_url": "https://raw.../yara-rules.json"
})
rules = manager.load_rules()

# Get summary
print(manager.get_summary())
# Output: {'total_categories': 6, 'total_patterns': 25, ...}

# Export to file
manager.save_rules_to_file(rules, "output-rules.json")
```

### Use with YARADetector

```python
from yara_detection import YARADetector

# Create detector with custom rules config
rules_config = {
    "source": "git",
    "git_url": "https://raw.../yara-rules.json"
}
detector = YARADetector(rules_config)

# Scan profiles
for ip, profile in analyzer.ip_profiles.items():
    matches = detector.scan_profile(ip, profile)
```

## Fallback Behavior

If loading fails, the system automatically falls back to embedded rules:

```
1. Try to load from configured source
   ↓
2. If load fails → Use embedded defaults
   ↓
3. All detection continues with embedded rules
```

**Load failures trigger:**
- Console error message
- Entry in `manager.load_errors`
- Automatic fallback (no crash)

## Git Repository Setup

### Create Rules Repository

```bash
# Create repo
mkdir threat-rules
cd threat-rules
git init

# Create rules
cat > yara-rules.json << 'EOF'
{
  "organization_threats": {
    "description": "Your org's threat patterns",
    "patterns": [...]
  }
}
EOF

git add yara-rules.json
git commit -m "Initial YARA rules"
git push origin main
```

### Use in Implant

```bash
# Get raw URL from GitHub
# https://github.com/yourorg/threat-rules/blob/main/yara-rules.json
# becomes
# https://raw.githubusercontent.com/yourorg/threat-rules/main/yara-rules.json

# Configure
python3 implant_agent.py --config-set yara_analysis.rules.source git
python3 implant_agent.py --config-set yara_analysis.rules.git_url https://raw.../yara-rules.json
```

## BrainCell Integration

### Store Rules as Notes

1. Open BrainCell
2. Create note:
   - **Title**: `c2_beacon` (category name)
   - **Content**: JSON with patterns
   - **Tags**: `yara-rule`, `threat`, `c2`

Example content:
```json
{
  "description": "C2 communication patterns",
  "patterns": [
    {"port": 4444, "severity": "high"},
    {"port": 8888, "severity": "high"}
  ]
}
```

3. Configure implant:
```json
{
  "yara_analysis": {
    "rules": {
      "source": "braincell",
      "braincell_url": "http://braincell:8000",
      "braincell_token": "your-token"
    }
  }
}
```

4. Implant automatically queries BrainCell for notes with `yara-rule` tag

## Troubleshooting

### Rules not loading from file

```bash
# Check file exists
ls -la /path/to/yara-rules.json

# Validate JSON
python3 -m json.tool < /path/to/yara-rules.json

# Check config
grep -A 5 'yara_analysis' config.json
```

### Git URL not working

```bash
# Test URL directly
curl -s https://raw.../yara-rules.json | python3 -m json.tool

# Check network connectivity
curl -v https://github.com
```

### BrainCell connection failed

```bash
# Test BrainCell API
curl -H "Authorization: Bearer TOKEN" \
  http://braincell:8000/api/notes?tags=yara-rule

# Verify token
echo "Token: $YOUR_TOKEN"

# Check URL
grep braincell_url config.json
```

### Falls back to embedded rules

This is **not an error** - it's intentional fallback behavior. Check:

```python
from yara_detection import YARADetector
detector = YARADetector({"source": "git", ...})
if detector.rules == detector.YARA_RULES:
    print("Using embedded (fallback)")
```

## Best Practices

### 1. Version Control Rules
```bash
# Store rules in git repo
git log yara-rules.json  # See changes
git diff HEAD~1 yara-rules.json  # Review updates
```

### 2. Test Before Deploying
```bash
# Test locally first
cp yara-rules.json /tmp/test-rules.json
# Modify and test

# Push to git when validated
git commit -am "Update C2 port detection"
git push
```

### 3. Organize Rules by Threat
```json
{
  "mitre_attack_execution": {...},
  "mitre_attack_persistence": {...},
  "customer_specific_threats": {...},
  "vendor_malware_samples": {...}
}
```

### 4. Document Rule Purpose
```json
{
  "c2_beacon": {
    "description": "Command & Control communication patterns",
    "source": "https://attack.mitre.org/techniques/T1071/",
    "last_updated": "2024-09-30",
    "author": "Security Team",
    "patterns": [...]
  }
}
```

### 5. Monitor Load Errors
```python
from yara_detection import YARADetector
detector = YARADetector(config)
if detector.rules_manager.load_errors:
    for error in detector.rules_manager.load_errors:
        log.warning(f"Rule load error: {error}")
```

## Advanced Topics

### Custom Rule Categories

Add new categories to match your threat model:

```json
{
  "internal_policy_violations": {
    "description": "Internal policy violations",
    "patterns": [
      {"port": 6667, "severity": "high", "description": "IRC (banned)"}
    ]
  }
}
```

### Rule Inheritance

Create base rules, then override:

```bash
# base-rules.json
{
  "c2_beacon": {"patterns": [{"port": 4444, ...}]},
  "dns_tunneling": {"patterns": [...]}
}

# org-rules.json
{
  "c2_beacon": {"patterns": [{"port": 8888, ...}]},
  "custom_threat": {"patterns": [...]}
}
```

### Dynamic Rule Updates

Periodically refresh from source:

```python
# Reload rules every hour
import threading
def refresh_rules():
    global detector
    detector = YARADetector(rules_config)
    threading.Timer(3600, refresh_rules).start()

refresh_rules()
```

## References

- [YARA Rules Manager Documentation](yara_rules_manager.py)
- [YARA Integration Guide](YARA_INTEGRATION.md)
- [eBPF Implant Configuration](README.md)
- [BrainCell API Documentation](../../../BrainCell/docs/)

---

## Summary

External rules enable:
✅ Centralized threat intelligence management  
✅ Rapid rule updates without redeployment  
✅ Team collaboration on threat detection  
✅ Version-controlled rule evolution  
✅ Easy integration with threat intelligence platforms  
✅ Fallback to embedded rules for reliability  

Choose the source that fits your infrastructure and update frequency needs.
