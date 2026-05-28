"""
Telegram Sender - Sends alerts via Telegram Bot API
"""
import logging
import time
from typing import Dict, Any, List, Optional

import requests

logger = logging.getLogger(__name__)


class TelegramSender:
    """
    Sends threat intelligence alerts to Telegram users.
    Supports HTML formatting, retry logic, and rate limiting.
    """

    TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"

    # Severity emojis
    SEVERITY_EMOJIS = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
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
        "security_research": "📄",
        "ai_model": "🧠",
        "prompt_injection": "💉",
        "jailbreak": "🔓",
        "dataset": "📦",
    }

    def __init__(self, bot_token: str, config: Dict[str, Any] = None):
        self.bot_token = bot_token
        self.config = config or {}
        self.rate_limit_delay = self.config.get("rate_limit_delay", 1.0)
        self.max_retries = self.config.get("max_retries", 3)
        self.parse_mode = self.config.get("parse_mode", "HTML")

    def _api_call(self, method: str, data: Dict[str, Any]) -> Optional[Dict]:
        """Make an API call to Telegram."""
        url = self.TELEGRAM_API.format(token=self.bot_token, method=method)

        for attempt in range(self.max_retries):
            try:
                response = requests.post(url, data=data, timeout=30)
                result = response.json()

                if result.get("ok"):
                    return result.get("result")
                else:
                    error = result.get("description", "Unknown error")
                    if "Too Many Requests" in error:
                        retry_after = result.get("parameters", {}).get("retry_after", 5)
                        logger.warning(f"Rate limited. Waiting {retry_after}s")
                        time.sleep(retry_after)
                    else:
                        logger.error(f"Telegram API error: {error}")
                        if attempt < self.max_retries - 1:
                            time.sleep(2 ** attempt)

            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        return None

    def send_alert(self, chat_id: int, alert: Dict[str, Any]) -> bool:
        """Send a single alert to a Telegram chat."""
        message = self._format_alert(alert)

        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": self.parse_mode,
            "disable_web_page_preview": False,
        }

        result = self._api_call("sendMessage", data)

        if result:
            logger.info(f"Alert sent to {chat_id}: {alert.get('title', 'Unknown')[:50]}")
            time.sleep(self.rate_limit_delay)
            return True
        else:
            logger.error(f"Failed to send alert to {chat_id}")
            return False

    def send_alerts(self, chat_id: int, alerts: List[Dict[str, Any]]) -> int:
        """Send multiple alerts to a chat. Returns count of successful sends."""
        success = 0
        for alert in alerts:
            if self.send_alert(chat_id, alert):
                success += 1
        return success

    def broadcast(self, alerts: List[Dict[str, Any]], subscribers: List[Dict[str, Any]]) -> Dict[int, int]:
        """
        Broadcast alerts to all subscribers.
        Returns dict mapping chat_id to successful send count.
        """
        results = {}

        for subscriber in subscribers:
            chat_id = subscriber.get("chat_id")
            if not chat_id:
                continue

            sent = self.send_alerts(chat_id, alerts)
            results[chat_id] = sent

        return results

    def send_welcome_message(self, chat_id: int, username: str = None) -> bool:
        """Send welcome message to new subscriber."""
        name = username or "there"
        message = f"""👋 <b>Welcome to the Cyber Threat Intelligence Bot!</b>

Hello {name},

You'll now receive real-time threat intelligence alerts including:
• 🛡️ CVE disclosures and vulnerability alerts
• 💥 Exploit releases and PoC tools
• 🦠 Malware and ransomware tracking
• 💔 Data breach notifications
• 🤖 AI security tools and research
• 📊 Threat reports and analysis

<b>Commands:</b>
/stop - Unsubscribe from alerts
/status - View bot statistics
/help - Show all commands

Stay secure! 🔒"""

        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": self.parse_mode,
        }

        result = self._api_call("sendMessage", data)
        return result is not None

    def send_goodbye_message(self, chat_id: int) -> bool:
        """Send goodbye message to unsubscribing user."""
        message = """You've been unsubscribed from threat intelligence alerts.

To resubscribe, send /start anytime.

Stay safe! 🛡️"""

        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": self.parse_mode,
        }

        result = self._api_call("sendMessage", data)
        return result is not None

    def send_status(self, chat_id: int, stats: Dict[str, Any]) -> bool:
        """Send bot status to a user."""
        message = f"""📊 <b>Bot Status</b>

<b>Subscribers:</b> {stats.get('total_subscribers', 0)}
<b>Alerts sent (24h):</b> {stats.get('alerts_24h', 0)}
<b>Total alerts sent:</b> {stats.get('total_alerts', 0)}
<b>Sources monitored:</b> {stats.get('sources_count', 0)}
<b>Last run:</b> {stats.get('last_run', 'N/A')}

<b>Recent Activity:</b>
• CVEs: {stats.get('cves_24h', 0)}
• Exploits: {stats.get('exploits_24h', 0)}
• Breaches: {stats.get('breaches_24h', 0)}
• Ransomware: {stats.get('ransomware_24h', 0)}

AI Analysis: {'✅ Enabled' if stats.get('ai_enabled') else '❌ Disabled'}
Duplicate Detection: {'✅ Active' if stats.get('embeddings_active') else '❌ Inactive'}

Version: {stats.get('version', '1.0.0')}"""

        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": self.parse_mode,
        }

        result = self._api_call("sendMessage", data)
        return result is not None

    def send_admin_stats(self, chat_id: int, stats: Dict[str, Any]) -> bool:
        """Send detailed stats to admin."""
        message = f"""🔐 <b>Admin Dashboard</b>

<b>Users:</b>
• Active: {stats.get('active_users', 0)}
• Total (ever): {stats.get('total_users_ever', 0)}
• Admins: {stats.get('admin_count', 0)}

<b>Alerts (24h):</b>
• Total collected: {stats.get('alerts_24h', 0)}
• Critical: {stats.get('critical_24h', 0)}
• High: {stats.get('high_24h', 0)}
• Sent: {stats.get('sent_24h', 0)}

<b>Storage:</b>
• DB Size: {stats.get('db_size_mb', 0):.1f} MB
• Embeddings: {stats.get('embeddings_count', 0)}
• Processed URLs: {stats.get('processed_urls', 0)}

<b>Performance:</b>
• Avg run time: {stats.get('avg_run_time', 'N/A')}s
• Success rate: {stats.get('success_rate', 0):.1f}%
• Runs today: {stats.get('runs_today', 0)}

<b>Sources:</b>
{chr(10).join(f"• {s}: {c}" for s, c in stats.get('source_counts', {}).items())}"""

        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": self.parse_mode,
        }

        result = self._api_call("sendMessage", data)
        return result is not None

    def _format_alert(self, alert: Dict[str, Any]) -> str:
        """Format an alert into HTML message."""
        severity = alert.get("severity_label", "MEDIUM")
        severity_emoji = self.SEVERITY_EMOJIS.get(severity, "🟡")
        category = alert.get("category", "general")
        cat_emoji = self.CATEGORY_EMOJIS.get(category, "📌")

        # Build header
        header = f"{severity_emoji} <b>{severity} {cat_emoji} {category.replace('_', ' ').upper()}</b>"

        # Title
        title = alert.get("title", "Unknown Alert")
        title_section = f"\n\n<b>{self._escape_html(title)}</b>"

        # URL
        url = alert.get("url", "")
        url_section = f"\n🔗 <a href='{url}'>View Source</a>" if url else ""

        # Affected
        affected = ""
        if alert.get("tags"):
            affected = f"\n\n<b>Affected:</b> {', '.join(alert['tags'][:5])}"

        # Severity detail
        severity_score = alert.get("severity", 5.0)
        severity_section = f"\n<b>Severity:</b> {severity_score}/10 {severity}"

        # Summary
        summary = alert.get("summary", "")
        summary_section = ""
        if summary:
            clean_summary = self._escape_html(summary[:800])
            summary_section = f"\n\n<b>Summary:</b>\n{clean_summary}"

        # Download links
        downloads = ""
        if alert.get("download_links"):
            download_links = alert["download_links"][:5]
            download_texts = []
            for link in download_links:
                # Truncate long URLs for display
                display = link[:50] + "..." if len(link) > 50 else link
                download_texts.append(f"• <a href='{link}'>{self._escape_html(display)}</a>")
            downloads = "\n\n<b>Downloads:</b>\n" + "\n".join(download_texts)

        # AI Analysis
        ai_analysis = ""
        if alert.get("ai_analysis"):
            clean_analysis = self._escape_html(alert["ai_analysis"][:500])
            ai_analysis = f"\n\n🤖 <b>AI Analysis:</b>\n{clean_analysis}"

        # Why it matters
        why_section = ""
        if alert.get("why_it_matters"):
            clean_why = self._escape_html(alert["why_it_matters"][:400])
            why_section = f"\n\n⚠️ <b>Why this matters:</b>\n{clean_why}"

        # Source
        source = alert.get("source", "Unknown")
        source_section = f"\n\n— <i>Source: {self._escape_html(source)}</i>"

        # Combine all parts
        message = (
            f"{header}"
            f"{title_section}"
            f"{url_section}"
            f"{affected}"
            f"{severity_section}"
            f"{summary_section}"
            f"{downloads}"
            f"{ai_analysis}"
            f"{why_section}"
            f"{source_section}"
        )

        # Ensure message is within Telegram limits
        if len(message) > 4096:
            # Truncate summary
            excess = len(message) - 4000
            if summary_section and len(summary_section) > excess:
                summary_section = summary_section[:-(excess + 3)] + "..."
                message = (
                    f"{header}"
                    f"{title_section}"
                    f"{url_section}"
                    f"{affected}"
                    f"{severity_section}"
                    f"{summary_section}"
                    f"{downloads}"
                    f"{ai_analysis}"
                    f"{why_section}"
                    f"{source_section}"
                )

        return message

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    def get_updates(self, offset: int = 0, limit: int = 100) -> List[Dict]:
        """Get updates from Telegram (for user management)."""
        url = self.TELEGRAM_API.format(token=self.bot_token, method="getUpdates")
        params = {
            "offset": offset,
            "limit": limit,
            "timeout": 10,
        }

        try:
            response = requests.get(url, params=params, timeout=30)
            result = response.json()
            if result.get("ok"):
                return result.get("result", [])
        except Exception as e:
            logger.error(f"Error getting updates: {e}")

        return []

    def set_webhook(self, webhook_url: str) -> bool:
        """Set webhook for the bot."""
        url = self.TELEGRAM_API.format(token=self.bot_token, method="setWebhook")
        data = {"url": webhook_url}

        try:
            response = requests.post(url, data=data, timeout=30)
            result = response.json()
            return result.get("ok", False)
        except Exception as e:
            logger.error(f"Error setting webhook: {e}")
            return False

    def delete_webhook(self) -> bool:
        """Delete webhook."""
        url = self.TELEGRAM_API.format(token=self.bot_token, method="deleteWebhook")

        try:
            response = requests.post(url, timeout=30)
            result = response.json()
            return result.get("ok", False)
        except Exception as e:
            logger.error(f"Error deleting webhook: {e}")
            return False
