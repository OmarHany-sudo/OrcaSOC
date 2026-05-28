"""
Severity Analyzer - Analyzes and adjusts severity scores
"""
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class SeverityAnalyzer:
    """
    Analyzes threat severity and adjusts scores based on
    multiple factors including exploitability, impact, and context.
    """

    # CVSS-like scoring factors
    ATTACK_VECTORS = {
        "network": 0.85,
        "adjacent": 0.62,
        "local": 0.55,
        "physical": 0.2,
    }

    # Keywords that indicate high exploitability
    EXPLOITABILITY_KEYWORDS = [
        "public exploit", "exploit available", "poc released", "weaponized",
        "actively exploited", "in the wild", "no patch", "unpatched",
        "trivial exploitation", "easy to exploit", "metasploit"
    ]

    # Keywords that indicate high impact
    IMPACT_KEYWORDS = [
        "remote code execution", "rce", "command injection",
        "authentication bypass", "privilege escalation", "data exfiltration",
        "lateral movement", "domain compromise", "complete system access"
    ]

    # Scope keywords
    SCOPE_KEYWORDS = {
        "internet-facing": 1.5,
        "publicly accessible": 1.4,
        "widely deployed": 1.3,
        "enterprise": 1.2,
        "cloud": 1.2,
        "critical infrastructure": 1.5,
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.min_severity = self.config.get("min_severity", 0.0)

    def analyze(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze and adjust severity for an alert.
        Returns the alert with adjusted severity.
        """
        current_severity = alert.get("severity", 5.0)

        # Calculate adjustment factors
        exploitability = self._assess_exploitability(alert)
        impact = self._assess_impact(alert)
        scope = self._assess_scope(alert)
        maturity = self._assess_exploit_maturity(alert)

        # Calculate adjusted severity
        adjusted = self._calculate_adjusted_severity(
            current_severity, exploitability, impact, scope, maturity
        )

        # Update alert
        alert["severity"] = round(adjusted, 1)
        alert["severity_label"] = self._get_severity_label(adjusted)
        alert["severity_analysis"] = {
            "base_score": current_severity,
            "exploitability_factor": exploitability,
            "impact_factor": impact,
            "scope_factor": scope,
            "maturity_factor": maturity,
            "adjusted_score": adjusted,
        }

        return alert

    def analyze_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze severity for a batch of alerts."""
        return [self.analyze(alert) for alert in alerts]

    def _assess_exploitability(self, alert: Dict[str, Any]) -> float:
        """Assess how exploitable the threat is."""
        text = f"{alert.get('title', '')} {alert.get('summary', '')} {alert.get('raw_content', '')}"
        text_lower = text.lower()

        score = 0.5  # Base

        for keyword in self.EXPLOITABILITY_KEYWORDS:
            if keyword in text_lower:
                score += 0.15

        # Check if PoC is available
        if alert.get("download_links"):
            for link in alert["download_links"]:
                if any(kw in link.lower() for kw in ["poc", "exploit", "github"]):
                    score += 0.1

        return min(score, 1.0)

    def _assess_impact(self, alert: Dict[str, Any]) -> float:
        """Assess potential impact."""
        text = f"{alert.get('title', '')} {alert.get('summary', '')} {alert.get('raw_content', '')}"
        text_lower = text.lower()

        score = 0.5

        for keyword in self.IMPACT_KEYWORDS:
            if keyword in text_lower:
                score += 0.2

        # Category-based adjustments
        category = alert.get("category", "")
        if category == "ransomware":
            score += 0.2
        elif category == "cve" and alert.get("severity", 0) >= 9:
            score += 0.3
        elif category == "data_breach":
            score += 0.15

        return min(score, 1.0)

    def _assess_scope(self, alert: Dict[str, Any]) -> float:
        """Assess the scope of affected systems."""
        text = f"{alert.get('title', '')} {alert.get('summary', '')}"
        text_lower = text.lower()

        score = 0.5

        for keyword, multiplier in self.SCOPE_KEYWORDS.items():
            if keyword in text_lower:
                score = max(score, 0.5 * multiplier)

        # Popular/widespread products
        widespread_products = [
            "windows", "linux", "apache", "nginx", "microsoft",
            "cisco", "vmware", "oracle", "adobe", "chrome"
        ]
        for product in widespread_products:
            if product in text_lower:
                score += 0.1

        return min(score, 1.5)

    def _assess_exploit_maturity(self, alert: Dict[str, Any]) -> float:
        """Assess exploit maturity level."""
        text = f"{alert.get('title', '')} {alert.get('summary', '')}"
        text_lower = text.lower()

        if "weaponized" in text_lower or "in the wild" in text_lower:
            return 1.0
        elif "public exploit" in text_lower or "poc released" in text_lower:
            return 0.8
        elif "proof of concept" in text_lower:
            return 0.6
        elif "theoretical" in text_lower:
            return 0.3

        return 0.5

    def _calculate_adjusted_severity(self, base: float, exploitability: float,
                                     impact: float, scope: float, maturity: float) -> float:
        """Calculate adjusted severity score."""
        # Weight the factors
        adjusted = base * 0.4 + \
                   (exploitability * 10) * 0.2 + \
                   (impact * 10) * 0.2 + \
                   min(scope * 5, 5) * 0.1 + \
                   (maturity * 5) * 0.1

        # Ensure within bounds
        return max(0.0, min(adjusted, 10.0))

    def _get_severity_label(self, severity: float) -> str:
        """Convert severity to label."""
        if severity >= 9.0:
            return "CRITICAL"
        elif severity >= 7.0:
            return "HIGH"
        elif severity >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def is_critical(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is critical."""
        return alert.get("severity", 0) >= 9.0

    def is_high(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is high severity."""
        return alert.get("severity", 0) >= 7.0

    def should_alert_immediately(self, alert: Dict[str, Any]) -> bool:
        """Check if alert should be sent immediately."""
        if self.is_critical(alert):
            return True

        # High severity with public exploit
        if self.is_high(alert) and alert.get("download_links"):
            text = f"{alert.get('title', '')} {alert.get('summary', '')}".lower()
            if any(kw in text for kw in ["exploit", "poc", "weaponized"]):
                return True

        return False
