"""
Threat Scorer - Calculates a 0-100 CTI priority score.
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ThreatScorer:
    """Score threats using exploitability, KEV status, ransomware usage, and product impact."""

    POPULAR_PRODUCTS = [
        "windows", "microsoft", "office", "exchange", "sharepoint", "azure",
        "linux", "ubuntu", "debian", "red hat", "rhel", "centos",
        "apache", "nginx", "tomcat", "wordpress", "drupal", "joomla",
        "chrome", "firefox", "safari", "edge",
        "cisco", "fortinet", "palo alto", "checkpoint", "sonicwall",
        "vmware", "citrix", "ivanti", "atlassian", "confluence", "jira",
        "oracle", "sap", "servicenow", "salesforce",
        "kubernetes", "docker", "jenkins", "gitlab", "github",
    ]

    EXPLOIT_KEYWORDS = [
        "exploit", "weaponized", "metasploit", "in the wild", "actively exploited",
        "public exploit", "exploit available",
    ]

    POC_KEYWORDS = [
        "poc", "proof of concept", "github.com", "nuclei template", "template released",
    ]

    RANSOMWARE_KEYWORDS = [
        "ransomware", "ransomware campaign", "ransomware usage", "known to be used in ransomware",
    ]

    def score(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Add threat_score and scoring factors to an alert."""
        text = self._alert_text(alert)
        severity = float(alert.get("severity", 0) or 0)

        cvss_points = min(severity, 10.0) * 4.0
        exploit_points = 18 if self._has_exploit(alert, text) else 0
        poc_points = 14 if self._has_poc(alert, text) else 0
        kev_points = 18 if alert.get("is_kev") or "known exploited" in text else 0
        ransomware_points = 12 if self._has_ransomware_usage(alert, text) else 0
        product_points = self._product_popularity_points(text)

        score = int(round(min(
            cvss_points + exploit_points + poc_points + kev_points + ransomware_points + product_points,
            100,
        )))

        alert["threat_score"] = score
        alert["threat_score_factors"] = {
            "cvss": round(cvss_points, 1),
            "exploit": exploit_points,
            "poc": poc_points,
            "kev": kev_points,
            "ransomware": ransomware_points,
            "product_popularity": product_points,
        }
        return alert

    def score_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score a batch of alerts."""
        for alert in alerts:
            try:
                self.score(alert)
            except Exception as e:
                logger.error("Threat scoring failed for %s: %s", alert.get("title", "N/A"), e)
                alert["threat_score"] = int(float(alert.get("severity", 0) or 0) * 10)
        return alerts

    def _alert_text(self, alert: Dict[str, Any]) -> str:
        parts = [
            alert.get("title", ""),
            alert.get("summary", ""),
            alert.get("raw_content", ""),
            " ".join(str(tag) for tag in alert.get("tags", [])),
            " ".join(str(link) for link in alert.get("download_links", [])),
        ]
        return " ".join(parts).lower()

    def _has_exploit(self, alert: Dict[str, Any], text: str) -> bool:
        if alert.get("category") in {"exploit", "github_poc"}:
            return True
        return any(keyword in text for keyword in self.EXPLOIT_KEYWORDS)

    def _has_poc(self, alert: Dict[str, Any], text: str) -> bool:
        if alert.get("github_urls") or alert.get("release_urls"):
            return True
        return any(keyword in text for keyword in self.POC_KEYWORDS)

    def _has_ransomware_usage(self, alert: Dict[str, Any], text: str) -> bool:
        if alert.get("ransomware_usage") or alert.get("category") == "ransomware":
            return True
        return any(keyword in text for keyword in self.RANSOMWARE_KEYWORDS)

    def _product_popularity_points(self, text: str) -> int:
        matches = sum(1 for product in self.POPULAR_PRODUCTS if product in text)
        if matches >= 3:
            return 10
        if matches == 2:
            return 8
        if matches == 1:
            return 5
        return 0
