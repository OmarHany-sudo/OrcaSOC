"""
Leak Monitor - Monitors public data breach notifications
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class LeakMonitor(BaseCollector):
    """Monitors public data breach notifications and leak trackers."""

    HIBP_API = "https://haveibeenpwned.com/api/v3/breaches"
    HIBP_HEADERS = {
        "User-Agent": "CyberThreatIntelligence-Bot",
        "Accept": "application/json"
    }

    # Public leak tracking RSS feeds and APIs
    LEAK_SOURCES = [
        "https://www.bleepingcomputer.com/feed/",
    ]

    BREACH_KEYWORDS = [
        "breach", "leaked", "exposed", "compromised",
        "data dump", "database leak", "credentials exposed",
        "personal information", "pii exposed"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("LeakMonitor", config)
        self.hibp_api_key = self.config.get("hibp_api_key")
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_items = self.config.get("max_items", 10)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect data breach information."""
        alerts = []

        try:
            hibp_alerts = self._collect_from_hibp()
            alerts.extend(hibp_alerts)
        except Exception as e:
            logger.error(f"[LeakMonitor] Error collecting from HIBP: {e}")

        logger.info(f"[LeakMonitor] Collected {len(alerts)} breach alerts")
        return alerts

    def _collect_from_hibp(self) -> List[Dict[str, Any]]:
        """Collect recent breaches from Have I Been Pwned."""
        alerts = []

        headers = self.HIBP_HEADERS.copy()
        if self.hibp_api_key:
            headers["hibp-api-key"] = self.hibp_api_key

        response = self.fetch(self.HIBP_API, headers=headers)
        if not response:
            return []

        try:
            breaches = response.json()
        except Exception as e:
            logger.error(f"[LeakMonitor] Error parsing HIBP response: {e}")
            return []

        # Calculate cutoff time
        cutoff = datetime.utcnow() - timedelta(hours=self.lookback_hours)

        for breach in breaches[:self.max_items * 2]:
            try:
                breach_date_str = breach.get("BreachDate", "")
                if breach_date_str:
                    breach_date = datetime.strptime(breach_date_str, "%Y-%m-%d")
                else:
                    added_date_str = breach.get("AddedDate", "")
                    if added_date_str:
                        breach_date = datetime.fromisoformat(added_date_str.replace("Z", "+00:00"))
                    else:
                        continue

                if breach_date.tzinfo is not None:
                    breach_date = breach_date.replace(tzinfo=None)

                if breach_date < cutoff:
                    continue

                alert = self._process_breach(breach)
                if alert:
                    alerts.append(alert)

            except Exception as e:
                logger.error(f"[LeakMonitor] Error processing breach: {e}")

        return alerts[:self.max_items]

    def _process_breach(self, breach: Dict) -> Dict[str, Any]:
        """Process a breach into an alert."""
        name = breach.get("Name", "Unknown")
        title = breach.get("Title", name)
        domain = breach.get("Domain", "")
        breach_date = breach.get("BreachDate", "")
        added_date = breach.get("AddedDate", "")
        modified_date = breach.get("ModifiedDate", "")
        pwn_count = breach.get("PwnCount", 0)
        description = breach.get("Description", "")
        data_classes = breach.get("DataClasses", [])
        is_verified = breach.get("IsVerified", False)
        is_fabricated = breach.get("IsFabricated", False)
        is_sensitive = breach.get("IsSensitive", False)
        logo_path = breach.get("LogoPath", "")

        # Clean HTML from description
        description = self.clean_html(description)

        # Calculate severity based on pwn count
        severity = self._calculate_severity(pwn_count, is_verified, is_sensitive)

        # Build URL
        url = f"https://haveibeenpwned.com/PwnedWebsites#{name}"

        # Build summary
        summary = f"Breach: {title}\n\n"
        if description:
            summary += f"{description[:400]}\n\n"
        summary += f"Compromised Accounts: {pwn_count:,}\n"
        summary += f"Breached Data: {', '.join(data_classes[:10])}\n"
        summary += f"Verified: {'Yes' if is_verified else 'No'}\n"
        if domain:
            summary += f"Domain: {domain}\n"
        if breach_date:
            summary += f"Breach Date: {breach_date}"

        # Published date
        published = added_date if added_date else datetime.utcnow().isoformat()

        # Tags
        tags = ["data-breach", "leak"]
        if is_verified:
            tags.append("verified")
        if is_sensitive:
            tags.append("sensitive")
        tags.extend(data_classes[:5])

        return self.standardize_alert(
            title=f"Data Breach: {title}",
            url=url,
            source="HaveIBeenPwned",
            category="data_breach",
            severity=severity,
            summary=summary,
            raw_content=description,
            published_at=published,
            download_links=[],
            tags=tags,
        )

    def _calculate_severity(self, pwn_count: int, is_verified: bool, is_sensitive: bool) -> float:
        """Calculate severity score based on breach characteristics."""
        severity = 5.0

        # Scale based on affected accounts
        if pwn_count > 100_000_000:
            severity += 2.5
        elif pwn_count > 10_000_000:
            severity += 2.0
        elif pwn_count > 1_000_000:
            severity += 1.5
        elif pwn_count > 100_000:
            severity += 1.0
        elif pwn_count > 10_000:
            severity += 0.5

        # Verified breaches are more severe
        if is_verified:
            severity += 0.5

        # Sensitive breaches are more severe
        if is_sensitive:
            severity += 0.5

        return min(severity, 10.0)
