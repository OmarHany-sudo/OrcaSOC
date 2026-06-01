"""
CISA KEV Collector - Known Exploited Vulnerabilities catalog.
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class CISAKEVCollector(BaseCollector):
    """Collects recent entries from CISA's Known Exploited Vulnerabilities catalog."""

    KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("CISA KEV", config)
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_items = self.config.get("max_items", 20)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect recent KEV catalog additions."""
        response = self.fetch(self.KEV_JSON_URL)
        if not response:
            return []

        try:
            data = response.json()
        except Exception as e:
            logger.error("[CISA KEV] Error parsing catalog JSON: %s", e)
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        cutoff = datetime.utcnow() - timedelta(hours=self.lookback_hours)
        alerts = []

        for item in vulnerabilities:
            try:
                date_added = item.get("dateAdded", "")
                if date_added:
                    added_dt = datetime.strptime(date_added, "%Y-%m-%d")
                    if added_dt < cutoff:
                        continue

                alert = self._process_item(item)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error("[CISA KEV] Error processing item: %s", e)

        logger.info("[CISA KEV] Collected %s KEV items", len(alerts))
        return alerts[:self.max_items]

    def _process_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = item.get("cveID", "UNKNOWN")
        vendor = item.get("vendorProject", "")
        product = item.get("product", "")
        vulnerability_name = item.get("vulnerabilityName", cve_id)
        notes = item.get("notes", "")
        action = item.get("requiredAction", "")
        due_date = item.get("dueDate", "")
        ransomware = item.get("knownRansomwareCampaignUse", "Unknown")

        summary = (
            f"{vulnerability_name}\n\n"
            f"Vendor/Product: {vendor} {product}\n"
            f"Required Action: {action}\n"
            f"Due Date: {due_date}\n"
            f"Known Ransomware Use: {ransomware}"
        )
        if notes:
            summary += f"\nNotes: {notes}"

        ransomware_usage = str(ransomware).lower() == "known"
        severity = 9.5 if ransomware_usage else 8.5

        alert = self.standardize_alert(
            title=f"CISA KEV: {cve_id} - {vulnerability_name}",
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            source="CISA KEV",
            category="cve",
            severity=severity,
            summary=summary,
            raw_content=summary,
            published_at=item.get("dateAdded") or datetime.utcnow().isoformat(),
            download_links=[],
            tags=["kev", cve_id, vendor, product],
        )
        alert["is_kev"] = True
        alert["ransomware_usage"] = ransomware_usage
        alert["affected_product"] = " ".join(part for part in [vendor, product] if part)
        return alert
