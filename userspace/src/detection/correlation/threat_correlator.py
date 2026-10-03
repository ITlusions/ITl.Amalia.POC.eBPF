"""Threat correlation: combines IP analysis, YARA, and Sigma-Lite results"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


@dataclass
class ThreatVerdict:
    """Combined threat assessment from all detection methods"""
    timestamp: float
    ip: str
    threat_level: ThreatLevel
    ip_analysis_score: float  # 0-100
    yara_matches: List[Dict[str, Any]]
    sigma_chains: List[Dict[str, Any]]
    
    ip_threat_description: str = ""
    yara_threat_description: str = ""
    sigma_threat_description: str = ""
    
    mitre_techniques: List[str] = None
    confidence: float = 0.0
    
    def __post_init__(self):
        if self.mitre_techniques is None:
            self.mitre_techniques = []
    
    @property
    def agreement_level(self) -> str:
        """How many detection methods agree"""
        methods_triggered = 0
        if self.ip_analysis_score > 30:
            methods_triggered += 1
        if self.yara_matches:
            methods_triggered += 1
        if self.sigma_chains:
            methods_triggered += 1
        
        if methods_triggered >= 3:
            return "UNANIMOUS"
        elif methods_triggered == 2:
            return "MAJORITY"
        elif methods_triggered == 1:
            return "SINGLE"
        else:
            return "NONE"


class ThreatCorrelator:
    """Correlates threat detection results from multiple engines"""
    
    def __init__(self):
        """Initialize correlator"""
        self.verdicts: List[ThreatVerdict] = []
    
    def correlate(
        self,
        ip: str,
        ip_profile: Optional[Dict[str, Any]] = None,
        yara_matches: Optional[List[Dict[str, Any]]] = None,
        sigma_chains: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatVerdict:
        """
        Correlate threat detection results into unified verdict.
        
        Args:
            ip: Target IP address
            ip_profile: IP behavioral profile with threat_score
            yara_matches: List of YARA rule matches
            sigma_chains: List of Sigma-Lite chain detections
        
        Returns:
            ThreatVerdict with combined assessment
        """
        import time
        
        ip_score = 0.0
        if ip_profile:
            ip_score = ip_profile.get('threat_score', 0.0)
        
        yara_matches = yara_matches or []
        sigma_chains = sigma_chains or []
        
        # Calculate confidence and threat level
        threat_level = self._calculate_threat_level(ip_score, yara_matches, sigma_chains)
        confidence = self._calculate_confidence(ip_score, yara_matches, sigma_chains)
        mitre_techniques = self._extract_mitre_techniques(yara_matches, sigma_chains)
        
        verdict = ThreatVerdict(
            timestamp=time.time(),
            ip=ip,
            threat_level=threat_level,
            ip_analysis_score=ip_score,
            yara_matches=yara_matches,
            sigma_chains=sigma_chains,
            ip_threat_description=self._describe_ip_threat(ip_profile),
            yara_threat_description=self._describe_yara_threat(yara_matches),
            sigma_threat_description=self._describe_sigma_threat(sigma_chains),
            mitre_techniques=mitre_techniques,
            confidence=confidence,
        )
        
        self.verdicts.append(verdict)
        return verdict
    
    def _calculate_threat_level(
        self,
        ip_score: float,
        yara_matches: List[Dict[str, Any]],
        sigma_chains: List[Dict[str, Any]],
    ) -> ThreatLevel:
        """Calculate threat level based on agreement"""
        methods_triggered = 0
        severity_count = {"critical": 0, "high": 0}
        
        if ip_score > 30:
            methods_triggered += 1
        
        if yara_matches:
            methods_triggered += 1
            severity_count["critical"] += len([m for m in yara_matches if m.get('severity') == 'critical'])
            severity_count["high"] += len([m for m in yara_matches if m.get('severity') == 'high'])
        
        if sigma_chains:
            methods_triggered += 1
            severity_count["critical"] += len([c for c in sigma_chains if c.get('severity') == 'CRITICAL'])
            severity_count["high"] += len([c for c in sigma_chains if c.get('severity') == 'HIGH'])
        
        # All methods agree = CRITICAL
        if methods_triggered >= 3 or severity_count["critical"] > 0:
            return ThreatLevel.CRITICAL
        
        # Multiple methods = HIGH
        if methods_triggered >= 2 or severity_count["high"] > 1:
            return ThreatLevel.HIGH
        
        # Single method = MEDIUM
        if methods_triggered == 1:
            if ip_score > 50 or severity_count["high"] > 0:
                return ThreatLevel.HIGH
            return ThreatLevel.MEDIUM
        
        return ThreatLevel.CLEAN
    
    def _calculate_confidence(
        self,
        ip_score: float,
        yara_matches: List[Dict[str, Any]],
        sigma_chains: List[Dict[str, Any]],
    ) -> float:
        """Calculate overall confidence (0.0 - 1.0)"""
        confidence = 0.0
        
        # IP analysis contribution
        if ip_score > 30:
            confidence += (min(ip_score / 100, 1.0) * 0.33)
        
        # YARA contribution
        if yara_matches:
            avg_yara_conf = sum(m.get('confidence', 0.5) for m in yara_matches) / len(yara_matches)
            confidence += (avg_yara_conf * 0.33)
        
        # Sigma-Lite contribution
        if sigma_chains:
            avg_sigma_conf = sum(c.get('confidence', 0.7) for c in sigma_chains) / len(sigma_chains)
            confidence += (avg_sigma_conf * 0.34)
        
        return min(confidence, 1.0)
    
    def _extract_mitre_techniques(
        self,
        yara_matches: List[Dict[str, Any]],
        sigma_chains: List[Dict[str, Any]],
    ) -> List[str]:
        """Extract unique MITRE ATT&CK techniques"""
        techniques = set()
        
        for match in yara_matches:
            for technique in match.get('mitre_techniques', []):
                techniques.add(technique)
        
        for chain in sigma_chains:
            for technique in chain.get('mitre_techniques', []):
                techniques.add(technique)
        
        return sorted(list(techniques))
    
    def _describe_ip_threat(self, ip_profile: Optional[Dict[str, Any]]) -> str:
        """Describe threat from IP analysis"""
        if not ip_profile:
            return ""
        
        score = ip_profile.get('threat_score', 0.0)
        if score < 20:
            return "IP profile shows normal behavior"
        elif score < 40:
            return "IP profile shows moderate suspicion"
        elif score < 70:
            return "IP profile shows elevated threat indicators"
        else:
            return "IP profile shows critical threat indicators"
    
    def _describe_yara_threat(self, yara_matches: List[Dict[str, Any]]) -> str:
        """Describe threat from YARA matches"""
        if not yara_matches:
            return "No known threat signatures detected"
        
        critical = len([m for m in yara_matches if m.get('severity') == 'critical'])
        high = len([m for m in yara_matches if m.get('severity') == 'high'])
        
        if critical > 0:
            return f"Known malware signatures detected ({critical} critical, {high} high)"
        elif high > 0:
            return f"Suspicious patterns detected ({high} high severity)"
        else:
            return f"Minor threat signatures detected ({len(yara_matches)} matches)"
    
    def _describe_sigma_threat(self, sigma_chains: List[Dict[str, Any]]) -> str:
        """Describe threat from Sigma-Lite chains"""
        if not sigma_chains:
            return "No attack chains detected"
        
        critical = len([c for c in sigma_chains if c.get('severity') == 'CRITICAL'])
        high = len([c for c in sigma_chains if c.get('severity') == 'HIGH'])
        
        chains = [c.get('chain_name', 'Unknown') for c in sigma_chains[:2]]
        
        if critical > 0:
            return f"Multi-stage attack chain detected: {', '.join(chains)}"
        elif high > 0:
            return f"Behavioral attack pattern identified: {', '.join(chains)}"
        else:
            return f"Potential attack behavior: {', '.join(chains)}"
    
    def get_critical_verdicts(self) -> List[ThreatVerdict]:
        """Get all CRITICAL threat verdicts"""
        return [v for v in self.verdicts if v.threat_level == ThreatLevel.CRITICAL]
    
    def get_unanimous_verdicts(self) -> List[ThreatVerdict]:
        """Get verdicts where all methods agree"""
        return [v for v in self.verdicts if v.agreement_level == "UNANIMOUS"]
