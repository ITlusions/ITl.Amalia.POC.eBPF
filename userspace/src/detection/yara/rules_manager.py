"""
YARA Rules Manager - Load and manage threat detection rules from multiple sources.

Supports loading rules from:
- Local JSON/YAML files
- Git repositories (raw files)
- BrainCell API (as notes with tags)
- Fallback to embedded defaults
"""

import json
import sys
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError


# Default embedded rules (fallback if external source unavailable)
DEFAULT_EMBEDDED_RULES = {
    "c2_beacon": {
        "description": "Known C2 beacon patterns",
        "patterns": [
            {"port": 4444, "severity": "high"},
            {"port": 5555, "severity": "high"},
            {"port": 6666, "severity": "high"},
            {"port": 7777, "severity": "high"},
            {"port": 8888, "severity": "high"},
            {"port": 9999, "severity": "high"},
            {"port": 10000, "severity": "high"},
            {"port": 6129, "severity": "medium"},
            {"port": 12345, "severity": "high"},
            {"port": 27374, "severity": "high"},
            {"port": 31337, "severity": "high"},
        ]
    },
    "dns_tunneling": {
        "description": "DNS-based data exfiltration",
        "patterns": [
            {"name": "high_volume_dns", "condition": "dns_queries > 100 and bytes_sent > 10000", "severity": "high"},
            {"name": "suspicious_dns_subdomains", "condition": "domain contains unusual characters", "severity": "medium"},
            {"name": "dns_to_suspicious_resolver", "condition": "dns_port == 53 and bytes_sent > bytes_received", "severity": "medium"}
        ]
    },
    "data_exfiltration": {
        "description": "Large data transfers to external IPs",
        "patterns": [
            {"name": "large_outbound_transfer", "condition": "bytes_sent > 1000000 and is_public_ip", "severity": "high"},
            {"name": "sftp_ssh_transfer", "condition": "protocol == TCP and (port == 22 or port == 115) and bytes_sent > 100000", "severity": "medium"},
            {"name": "ftp_transfer", "condition": "protocol == TCP and port == 21 and bytes_sent > 100000", "severity": "medium"}
        ]
    },
    "lateral_movement": {
        "description": "Internal network scanning and movement",
        "patterns": [
            {"name": "port_scanning", "condition": "tcp_state == SYN_SENT and unique_ports > 20", "severity": "medium"},
            {"name": "rdp_sweep", "condition": "port == 3389 and connections > 10", "severity": "medium"},
            {"name": "ssh_brute_force", "condition": "port == 22 and failed_connections > 5", "severity": "medium"}
        ]
    },
    "credential_access": {
        "description": "Credential harvesting and access attempts",
        "patterns": [
            {"name": "ldap_query", "condition": "port == 389 and bytes_sent > 1000", "severity": "medium"},
            {"name": "kerberos_activity", "condition": "port == 88 and connections > 5", "severity": "low"},
            {"name": "smb_access", "condition": "port in [445, 139, 135]", "severity": "medium"}
        ]
    },
    "persistence": {
        "description": "Persistence mechanisms",
        "patterns": [
            {"name": "dns_hijacking", "condition": "dns_queries to_internal_resolver from_external_ip", "severity": "high"},
            {"name": "scheduled_task", "condition": "process == schtasks.exe or taskkill.exe", "severity": "medium"}
        ]
    }
}


class YARARulesManager:
    """Manages loading and caching YARA rules from multiple sources."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize rules manager.

        Args:
            config: Configuration dict with:
                - rules_source: "embedded" (default), "file", "git", or "braincell"
                - rules_file: Path to local rules JSON file
                - rules_git_url: Git raw URL to rules file
                - rules_braincell_url: BrainCell API URL
                - rules_braincell_token: BrainCell API token
                - cache_rules: Cache loaded rules in memory (default: True)
        """
        self.config = config or {}
        self.loaded_rules = None
        self.load_errors = []

    def load_rules(self) -> Dict[str, Any]:
        """
        Load rules from configured source.

        Returns priority:
        1. Cached rules (if cache enabled)
        2. External source (file/git/braincell)
        3. Embedded defaults (fallback)
        """
        # Return cached if available
        if self.loaded_rules:
            return self.loaded_rules

        source = self.config.get("rules_source", "embedded")

        print(f"[*] Loading YARA rules from: {source}")

        # Try loading from source
        if source == "file":
            rules = self._load_from_file()
        elif source == "git":
            rules = self._load_from_git()
        elif source == "braincell":
            rules = self._load_from_braincell()
        else:  # embedded
            rules = DEFAULT_EMBEDDED_RULES.copy()

        # Fallback to embedded if loading failed
        if not rules:
            print("[!] Failed to load external rules, falling back to embedded defaults")
            rules = DEFAULT_EMBEDDED_RULES.copy()

        # Cache if enabled
        if self.config.get("cache_rules", True):
            self.loaded_rules = rules

        return rules

    def _load_from_file(self) -> Optional[Dict[str, Any]]:
        """Load rules from local JSON file."""
        rules_file = self.config.get("rules_file")
        if not rules_file:
            print("[!] rules_file not configured")
            return None

        try:
            path = Path(rules_file)
            if not path.exists():
                print(f"[!] Rules file not found: {rules_file}")
                return None

            with open(path, 'r') as f:
                rules = json.load(f)

            print(f"[+] Loaded {len(rules)} rule categories from {rules_file}")
            return rules
        except Exception as e:
            error = f"Failed to load rules from file: {e}"
            print(f"[!] {error}")
            self.load_errors.append(error)
            return None

    def _load_from_git(self) -> Optional[Dict[str, Any]]:
        """Load rules from git repository (raw GitHub URL)."""
        git_url = self.config.get("rules_git_url")
        if not git_url:
            print("[!] rules_git_url not configured")
            return None

        try:
            print(f"[*] Fetching rules from git: {git_url}")
            with urlopen(git_url, timeout=10) as response:
                data = response.read().decode('utf-8')
                rules = json.loads(data)

            print(f"[+] Loaded {len(rules)} rule categories from git repository")
            return rules
        except URLError as e:
            error = f"Failed to fetch rules from git: {e}"
            print(f"[!] {error}")
            self.load_errors.append(error)
            return None
        except json.JSONDecodeError as e:
            error = f"Invalid JSON in git rules: {e}"
            print(f"[!] {error}")
            self.load_errors.append(error)
            return None
        except Exception as e:
            error = f"Error loading rules from git: {e}"
            print(f"[!] {error}")
            self.load_errors.append(error)
            return None

    def _load_from_braincell(self) -> Optional[Dict[str, Any]]:
        """Load rules from BrainCell API (as notes with 'yara-rule' tag)."""
        try:
            import requests
        except ImportError:
            error = "requests library required for BrainCell loading"
            print(f"[!] {error}")
            self.load_errors.append(error)
            return None

        braincell_url = self.config.get("rules_braincell_url")
        token = self.config.get("rules_braincell_token")

        if not braincell_url or not token:
            print("[!] braincell_url or token not configured")
            return None

        try:
            print(f"[*] Fetching rules from BrainCell: {braincell_url}")

            # Query notes with 'yara-rule' tag
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(
                f"{braincell_url}/api/notes?tags=yara-rule",
                headers=headers,
                timeout=10
            )

            if response.status_code != 200:
                error = f"BrainCell returned {response.status_code}"
                print(f"[!] {error}")
                self.load_errors.append(error)
                return None

            # Parse notes into rules
            notes = response.json().get("items", [])
            rules = self._parse_braincell_notes(notes)

            print(f"[+] Loaded {len(rules)} rule categories from BrainCell")
            return rules
        except Exception as e:
            error = f"Failed to load rules from BrainCell: {e}"
            print(f"[!] {error}")
            self.load_errors.append(error)
            return None

    def _parse_braincell_notes(self, notes: List[Dict]) -> Dict[str, Any]:
        """
        Parse BrainCell notes into YARA rules.

        Expected note format:
        {
            "title": "Rule Category Name",
            "content": "JSON of rule patterns",
            "tags": ["yara-rule", "c2", ...]
        }
        """
        rules = {}
        for note in notes:
            title = note.get("title", "").lower().replace(" ", "_")
            content = note.get("content", "")

            try:
                # Try parsing content as JSON
                if content.startswith("{"):
                    rule_data = json.loads(content)
                else:
                    # If not JSON, create basic rule
                    rule_data = {
                        "description": note.get("title", ""),
                        "patterns": []
                    }

                if title and rule_data:
                    rules[title] = rule_data
            except json.JSONDecodeError:
                print(f"[!] Could not parse BrainCell note as JSON: {title}")

        return rules

    def save_rules_to_file(self, rules: Dict[str, Any], filepath: str) -> bool:
        """Export loaded rules to JSON file."""
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(rules, f, indent=2)

            print(f"[+] Rules exported to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Failed to export rules: {e}")
            return False

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of loaded rules."""
        rules = self.loaded_rules or DEFAULT_EMBEDDED_RULES
        summary = {
            "total_categories": len(rules),
            "total_patterns": sum(len(r.get("patterns", [])) for r in rules.values()),
            "categories": list(rules.keys()),
            "load_errors": self.load_errors
        }
        return summary


def create_example_rules_file(filepath: str = "yara-rules.json"):
    """Create example rules file template."""
    example_rules = {
        "c2_beacon": {
            "description": "Known C2 beacon patterns",
            "patterns": [
                {"port": 4444, "severity": "high", "description": "Common C2 port"},
                {"port": 8888, "severity": "high", "description": "Alternative C2 port"}
            ]
        },
        "custom_threat": {
            "description": "Your custom threat pattern",
            "patterns": [
                {"port": 9999, "severity": "high", "description": "Your custom port"}
            ]
        }
    }

    path = Path(filepath)
    with open(path, 'w') as f:
        json.dump(example_rules, f, indent=2)

    print(f"[+] Created example rules file: {filepath}")


if __name__ == "__main__":
    # Example usage
    print("=== YARA Rules Manager Example ===\n")

    # Load from embedded (default)
    print("1. Loading from embedded defaults:")
    manager = YARARulesManager()
    rules = manager.load_rules()
    print(json.dumps(manager.get_summary(), indent=2))

    # Create example file
    print("\n2. Creating example rules file:")
    create_example_rules_file("example-rules.json")

    # Load from file
    print("\n3. Loading from file:")
    manager_file = YARARulesManager({
        "rules_source": "file",
        "rules_file": "example-rules.json"
    })
    rules_file = manager_file.load_rules()
    print(json.dumps(manager_file.get_summary(), indent=2))

    # Export rules
    print("\n4. Exporting rules:")
    manager.save_rules_to_file(rules, "exported-rules.json")
