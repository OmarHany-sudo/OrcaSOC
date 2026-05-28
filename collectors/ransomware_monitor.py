"""
Ransomware Monitor - Monitors ransomware activity
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class RansomwareMonitor(BaseCollector):
    """Monitors ransomware activity via public feeds."""

    RANSOMWARE_LIVE_API = "https://ransomware.live/api/v2/recent"
    RANSOMWARE_LIVE_VICTIMS = "https://ransomware.live/api/v2/recentvictims"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("Ransomware", config)
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_items = self.config.get("max_items", 10)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect recent ransomware activity."""
        alerts = []

        try:
            recent_alerts = self._collect_recent_victims()
            alerts.extend(recent_alerts)
        except Exception as e:
            logger.error(f"[Ransomware] Error collecting victims: {e}")

        logger.info(f"[Ransomware] Collected {len(alerts)} ransomware alerts")
        return alerts

    def _collect_recent_victims(self) -> List[Dict[str, Any]]:
        """Collect recent ransomware victims."""
        alerts = []

        response = self.fetch(self.RANSOMWARE_LIVE_VICTIMS)
        if not response:
            return []

        try:
            victims = response.json()
            if not isinstance(victims, list):
                victims = [victims] if isinstance(victims, dict) else []
        except Exception as e:
            logger.error(f"[Ransomware] Error parsing victims: {e}")
            return []

        # Calculate cutoff
        cutoff = datetime.utcnow() - timedelta(hours=self.lookback_hours)

        for victim in victims[:self.max_items * 2]:
            try:
                discovered = victim.get("discovered", "")
                if discovered:
                    try:
                        victim_date = datetime.strptime(discovered, "%Y-%m-%d %H:%M:%S.%f")
                    except ValueError:
                        try:
                            victim_date = datetime.strptime(discovered, "%Y-%m-%d")
                        except ValueError:
                            victim_date = datetime.utcnow()
                else:
                    victim_date = datetime.utcnow()

                if victim_date < cutoff:
                    continue

                alert = self._process_victim(victim, victim_date)
                if alert:
                    alerts.append(alert)

            except Exception as e:
                logger.error(f"[Ransomware] Error processing victim: {e}")

        return alerts[:self.max_items]

    def _process_victim(self, victim: Dict, victim_date: datetime) -> Dict[str, Any]:
        """Process a ransomware victim into an alert."""
        victim_name = victim.get("victim", "Unknown")
        group = victim.get("group", "Unknown Group")
        country = victim.get("country", "")
        description = victim.get("description", "")
        activity = victim.get("activity", "")
        url = victim.get("url", "")

        # Build post URL
        post_url = url if url else f"https://ransomware.live/group/{group}"

        # Calculate severity
        severity = self._calculate_severity(victim)

        # Build summary
        summary = f"Ransomware Victim: {victim_name}\n\n"
        summary += f"Threat Actor: {group}\n"
        if country:
            summary += f"Country: {country}\n"
        if activity:
            summary += f"Activity: {activity}\n"
        if description:
            summary += f"\n{description[:400]}"

        tags = ["ransomware", group.lower().replace(" ", "-")]
        if country:
            tags.append(country.lower())

        return self.standardize_alert(
            title=f"Ransomware: {victim_name}",
            url=post_url,
            source="Ransomware.live",
            category="ransomware",
            severity=severity,
            summary=summary,
            raw_content=description,
            published_at=victim_date.isoformat(),
            download_links=[],
            tags=tags,
        )

    def _calculate_severity(self, victim: Dict) -> float:
        """Calculate severity based on victim characteristics."""
        severity = 6.0

        # Increase severity for critical infrastructure keywords
        critical_sectors = [
            "healthcare", "hospital", "medical", "energy", "power",
            "water", "government", "municipal", "school", "education",
            "bank", "financial", "insurance"
        ]

        victim_name = victim.get("victim", "").lower()
        activity = victim.get("activity", "").lower()

        for sector in critical_sectors:
            if sector in victim_name or sector in activity:
                severity += 1.5
                break

        # Known severe groups
        severe_groups = ["lockbit", "blackcat", "clop", "play", "8base"]
        group = victim.get("group", "").lower()
        if any(g in group for g in severe_groups):
            severity += 1.0

        return min(severity, 10.0)
