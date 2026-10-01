"""Amalia platform integration: threat telemetry export"""

import requests
import json
from typing import Dict, Any, Optional
from datetime import datetime


class AmaliaExporter:
    """Export threat telemetry to Amalia platform"""

    def __init__(self, amalia_url: str, api_key: Optional[str] = None):
        self.amalia_url = amalia_url
        self.api_key = api_key

    def export_telemetry(self, telemetry_data: Dict[str, Any]) -> bool:
        """Export collected telemetry to Amalia"""
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            response = requests.post(
                f"{self.amalia_url}/api/ingest",
                json=telemetry_data,
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False

    def export_threat_verdict(self, verdict: Dict[str, Any]) -> bool:
        """Export threat verdict to Amalia"""
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            payload = {
                "timestamp": datetime.now().isoformat(),
                "verdict": verdict,
            }

            response = requests.post(
                f"{self.amalia_url}/api/verdicts",
                json=payload,
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False
