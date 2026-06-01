"""
Bug bounty disclosure collector for public HackerOne and Bugcrowd activity.
"""
import logging
from datetime import datetime
from typing import List, Dict, Any

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class BugBountyDisclosureCollector(BaseCollector):
    """Collects public vulnerability disclosure activity from bug bounty platforms."""

    HACKERONE_API = "https://api.hackerone.com/v1/hackers/hacktivity"
    BUGCROWD_CROWDSTREAM = "https://bugcrowd.com/crowdstream.json"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("BugBounty", config)
        self.max_items = self.config.get("max_items", 10)

    def collect(self) -> List[Dict[str, Any]]:
        alerts = []
        alerts.extend(self._collect_hackerone())
        alerts.extend(self._collect_bugcrowd())
        logger.info("[BugBounty] Collected %s disclosures", len(alerts))
        return alerts[:self.max_items]

    def _collect_hackerone(self) -> List[Dict[str, Any]]:
        params = {
            "sort_type": "latest_disclosable_activity_at",
            "queryString": "disclosed:true",
            "page[size]": self.max_items,
        }
        response = self.fetch(self.HACKERONE_API, params=params)
        if not response:
            return []

        try:
            data = response.json()
        except Exception as e:
            logger.error("[BugBounty] Error parsing HackerOne response: %s", e)
            return []

        alerts = []
        for item in data.get("data", []):
            attributes = item.get("attributes", {})
            relationships = item.get("relationships", {})
            report = relationships.get("report", {}).get("data", {}).get("attributes", {})
            title = report.get("title") or attributes.get("title") or "HackerOne Disclosure"
            url = report.get("url") or attributes.get("url") or "https://hackerone.com/hacktivity"
            summary = attributes.get("hacktivity_summary") or report.get("title") or title
            severity = self._severity_from_text(str(attributes.get("severity_rating", "")) + " " + title)
            alerts.append(self.standardize_alert(
                title=f"HackerOne: {title}",
                url=url,
                source="HackerOne",
                category="security_research",
                severity=severity,
                summary=self.truncate_text(summary, 700),
                raw_content=str(attributes),
                published_at=attributes.get("latest_disclosable_activity_at") or datetime.utcnow().isoformat(),
                download_links=[url],
                tags=["hackerone", "disclosure"],
            ))
        return alerts

    def _collect_bugcrowd(self) -> List[Dict[str, Any]]:
        response = self.fetch(self.BUGCROWD_CROWDSTREAM, params={"page": 1})
        if not response:
            return []

        try:
            data = response.json()
        except Exception as e:
            logger.error("[BugBounty] Error parsing Bugcrowd response: %s", e)
            return []

        items = data.get("results") or data.get("activities") or data.get("data") or []
        alerts = []
        for item in items[: self.max_items]:
            title = item.get("title") or item.get("submission_title") or "Bugcrowd Disclosure"
            url = item.get("url") or item.get("submission_url") or "https://bugcrowd.com/crowdstream"
            summary = item.get("summary") or item.get("description") or title
            severity = self._severity_from_text(str(item.get("priority", "")) + " " + title)
            alerts.append(self.standardize_alert(
                title=f"Bugcrowd: {title}",
                url=url,
                source="Bugcrowd",
                category="security_research",
                severity=severity,
                summary=self.truncate_text(summary, 700),
                raw_content=str(item),
                published_at=item.get("created_at") or item.get("published_at") or datetime.utcnow().isoformat(),
                download_links=[url],
                tags=["bugcrowd", "disclosure"],
            ))
        return alerts

    def _severity_from_text(self, text: str) -> float:
        text_lower = text.lower()
        if any(term in text_lower for term in ["critical", "p1", "rce", "remote code execution"]):
            return 9.0
        if any(term in text_lower for term in ["high", "p2", "auth bypass", "sqli"]):
            return 7.5
        if any(term in text_lower for term in ["medium", "p3", "xss"]):
            return 5.5
        return 5.0
