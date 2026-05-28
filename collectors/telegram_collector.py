"""
Telegram Collector - Monitors security Telegram channels
"""
import logging
from datetime import datetime
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class TelegramCollector(BaseCollector):
    """Collects updates from security-focused Telegram channels."""

    TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"

    # List of public Telegram channels to monitor
    # These should be public channels that can be accessed via web preview
    SECURITY_CHANNELS = [
        "@vxug",
        "@malwarevware",
        "@threatintel",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("Telegram", config)
        self.bot_token = self.config.get("bot_token")
        self.max_messages = self.config.get("max_messages", 10)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect messages from monitored Telegram channels."""
        alerts = []

        if not self.bot_token:
            logger.warning("[Telegram] No bot token configured, skipping Telegram collection")
            return []

        # Get updates via bot API
        try:
            updates = self._get_updates()
            for update in updates:
                alert = self._process_update(update)
                if alert:
                    alerts.append(alert)
        except Exception as e:
            logger.error(f"[Telegram] Error collecting updates: {e}")

        logger.info(f"[Telegram] Collected {len(alerts)} messages")
        return alerts

    def _get_updates(self) -> List[Dict]:
        """Get updates from Telegram Bot API."""
        url = self.TELEGRAM_API.format(token=self.bot_token, method="getUpdates")
        params = {
            "limit": self.max_messages,
            "allowed_updates": ["channel_post"]
        }

        response = self.fetch(url, params=params)
        if not response:
            return []

        try:
            data = response.json()
            if data.get("ok"):
                return [u for u in data.get("result", []) if "channel_post" in u]
            return []
        except Exception as e:
            logger.error(f"[Telegram] Error parsing updates: {e}")
            return []

    def _process_update(self, update: Dict) -> Dict[str, Any]:
        """Process a Telegram channel post into an alert."""
        channel_post = update.get("channel_post", {})

        message_id = channel_post.get("message_id", 0)
        chat = channel_post.get("chat", {})
        channel_title = chat.get("title", "Unknown Channel")
        channel_username = chat.get("username", "")
        date = channel_post.get("date", 0)
        text = channel_post.get("text", "")
        caption = channel_post.get("caption", "")
        entities = channel_post.get("entities", [])

        # Combine text and caption
        content = text or caption
        if not content:
            return None

        # Build URL
        if channel_username:
            url = f"https://t.me/{channel_username}/{message_id}"
        else:
            url = f"https://t.me/c/{chat.get('id', '')}/{message_id}"

        # Convert date
        published = datetime.fromtimestamp(date).isoformat() if date else None

        # Extract URLs from entities
        urls = []
        for entity in entities:
            if entity.get("type") in ["url", "text_link"]:
                if "url" in entity:
                    urls.append(entity["url"])

        # Also extract any URLs from text
        urls.extend(self.extract_urls(content))
        urls = list(set(urls))

        # Classify category
        category = self._classify_content(content, channel_title)

        # Estimate severity
        severity = self._estimate_severity(content)

        # Truncate content for summary
        summary = self.truncate_text(content, 500)

        return self.standardize_alert(
            title=f"Telegram: {channel_title}",
            url=url,
            source=f"Telegram/{channel_title}",
            category=category,
            severity=severity,
            summary=summary,
            raw_content=content,
            published_at=published,
            download_links=urls[:5],
            tags=[channel_username or channel_title],
        )

    def _classify_content(self, text: str, channel_title: str) -> str:
        """Classify content based on text and channel."""
        text_lower = text.lower()

        categories = {
            "malware_analysis": ["malware", "sample", "trojan", "virus", "ransomware"],
            "cve": ["cve-", "vulnerability", "patch"],
            "exploit": ["exploit", "poc", "0day", "zero-day"],
            "ai_tool": ["ai ", "llm", "gpt", "model"],
            "data_breach": ["breach", "leak", "exposed", "dump"],
            "threat_report": ["apt", "campaign", "threat actor"],
        }

        for category, keywords in categories.items():
            if any(kw in text_lower for kw in keywords):
                return category

        return "threat_report"

    def _estimate_severity(self, text: str) -> float:
        """Estimate severity based on content."""
        text_lower = text.lower()

        if any(kw in text_lower for kw in ["critical", "cve-202", "0day", "ransomware"]):
            return 8.5
        elif any(kw in text_lower for kw in ["exploit", "vulnerability", "apt", "breach"]):
            return 7.0

        return 5.5
