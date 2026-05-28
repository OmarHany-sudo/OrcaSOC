"""
Discord Sender - Sends alerts via Discord Webhooks
"""
import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

import requests

logger = logging.getLogger(__name__)


class DiscordSender:
    """
    Sends threat intelligence alerts to Discord via webhooks.
    Uses rich embeds for better formatting.
    """

    # Color mapping for severity
    SEVERITY_COLORS = {
        "CRITICAL": 0xFF0000,    # Red
        "HIGH": 0xFFA500,        # Orange
        "MEDIUM": 0xFFFF00,      # Yellow
        "LOW": 0x00FF00,         # Green
    }

    # Category emojis
    CATEGORY_EMOJIS = {
        "cve": "🛡️",
        "exploit": "💥",
        "github_poc": "⚙️",
        "ai_tool": "🤖",
        "red_team_tool": "🔴",
        "malware_analysis": "🦠",
        "threat_report": "📊",
        "data_breach": "💔",
        "ransomware": "🔒",
        "osint_tool": "🔍",
        "dfir_tool": "🔬",
        "ai_model": "🧠",
        "prompt_injection": "💉",
        "jailbreak": "🔓",
    }

    def __init__(self, webhook_url: str, config: Dict[str, Any] = None):
        self.webhook_url = webhook_url
        self.config = config or {}
        self.max_retries = self.config.get("max_retries", 3)
        self.rate_limit_delay = self.config.get("rate_limit_delay", 1.0)

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send a single alert to Discord."""
        embed = self._create_embed(alert)
        payload = {"embeds": [embed]}

        return self._send_webhook(payload)

    def send_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        """Send multiple alerts to Discord."""
        success = 0
        for alert in alerts:
            if self.send_alert(alert):
                success += 1
        return success

    def send_summary(self, stats: Dict[str, Any]) -> bool:
        """Send a summary embed."""
        embed = {
            "title": "📊 CTI Bot Daily Summary",
            "color": 0x3498db,
            "fields": [
                {"name": "Total Alerts", "value": str(stats.get("total_alerts", 0)), "inline": True},
                {"name": "Critical", "value": str(stats.get("critical_count", 0)), "inline": True},
                {"name": "High", "value": str(stats.get("high_count", 0)), "inline": True},
                {"name": "CVEs", "value": str(stats.get("cve_count", 0)), "inline": True},
                {"name": "Exploits", "value": str(stats.get("exploit_count", 0)), "inline": True},
                {"name": "Breaches", "value": str(stats.get("breach_count", 0)), "inline": True},
            ],
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "Cyber Threat Intelligence Bot"}
        }

        return self._send_webhook({"embeds": [embed]})

    def _create_embed(self, alert: Dict[str, Any]) -> Dict:
        """Create a Discord embed from an alert."""
        severity = alert.get("severity_label", "MEDIUM")
        category = alert.get("category", "general")
        title = alert.get("title", "Unknown Alert")
        url = alert.get("url", "")
        summary = alert.get("summary", "No summary available")
        source = alert.get("source", "Unknown")

        # Truncate summary
        if len(summary) > 1000:
            summary = summary[:997] + "..."

        color = self.SEVERITY_COLORS.get(severity, 0x808080)
        cat_emoji = self.CATEGORY_EMOJIS.get(category, "📌")

        embed = {
            "title": f"{cat_emoji} {title[:256]}",
            "url": url,
            "color": color,
            "description": summary[:4096],
            "timestamp": alert.get("published_at", datetime.utcnow().isoformat()),
            "footer": {
                "text": f"Source: {source} | Severity: {severity}"
            },
            "fields": []
        }

        # Add severity field
        severity_score = alert.get("severity", 5.0)
        embed["fields"].append({
            "name": "Severity",
            "value": f"{severity_score}/10 - {severity}",
            "inline": True
        })

        # Add category field
        embed["fields"].append({
            "name": "Category",
            "value": category.replace("_", " ").title(),
            "inline": True
        })

        # Add AI analysis if available
        if alert.get("ai_analysis"):
            ai_text = alert["ai_analysis"][:1000]
            embed["fields"].append({
                "name": "🤖 AI Analysis",
                "value": ai_text,
                "inline": False
            })

        # Add download links
        if alert.get("download_links"):
            links_text = "\n".join(alert["download_links"][:5])
            if len(links_text) > 1000:
                links_text = links_text[:997] + "..."
            embed["fields"].append({
                "name": "📥 Downloads",
                "value": links_text,
                "inline": False
            })

        # Add tags
        if alert.get("tags"):
            tags_text = ", ".join(alert["tags"][:10])
            embed["fields"].append({
                "name": "Tags",
                "value": tags_text,
                "inline": False
            })

        return embed

    def _send_webhook(self, payload: Dict) -> bool:
        """Send payload to Discord webhook."""
        import time

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30
                )

                if response.status_code == 204:
                    time.sleep(self.rate_limit_delay)
                    return True
                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    logger.warning(f"Discord rate limited. Waiting {retry_after}s")
                    time.sleep(retry_after)
                else:
                    logger.error(f"Discord webhook error: {response.status_code} - {response.text}")
                    if attempt < self.max_retries - 1:
                        time.sleep(2 ** attempt)

            except requests.exceptions.RequestException as e:
                logger.error(f"Discord webhook request error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        return False

    def test_webhook(self) -> bool:
        """Test if the webhook is working."""
        payload = {
            "content": "🤖 CTI Bot webhook test successful!",
            "username": "CTI Bot"
        }
        return self._send_webhook(payload)
