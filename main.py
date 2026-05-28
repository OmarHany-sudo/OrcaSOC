#!/usr/bin/env python3
"""
AI-Powered Cyber Threat Intelligence Telegram Bot
Main entry point - runs as a GitHub Actions workflow
"""
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

import config
from storage.database import DatabaseManager
from storage.persistence import PersistenceManager
from storage.state_manager import StateManager
from storage.embeddings import EmbeddingsManager

from collectors.rss_collector import RSSCollector
from collectors.github_collector import GitHubCollector
from collectors.cve_collector import CVECollector
from collectors.exploitdb_collector import ExploitDBCollector
from collectors.huggingface_collector import HuggingFaceCollector
from collectors.reddit_collector import RedditCollector
from collectors.telegram_collector import TelegramCollector
from collectors.leak_monitor import LeakMonitor
from collectors.ransomware_monitor import RansomwareMonitor
from collectors.darkweb_monitor import DarkWebMonitor

from ai.classifier import ThreatClassifier
from ai.summarizer import ThreatSummarizer
from ai.relevance_engine import RelevanceEngine
from ai.severity_analyzer import SeverityAnalyzer
from ai.duplicate_detector import DuplicateDetector
from ai.download_extractor import DownloadExtractor
from ai.threat_ranker import ThreatRanker
from ai.ai_threat_analyst import AIThreatAnalyst

from notifier.telegram_sender import TelegramSender

# Setup logging
def setup_logging():
    """Configure logging."""
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format=config.LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()


class CTIBot:
    """
    Main Cyber Threat Intelligence Bot class.
    Orchestrates collection, analysis, and notification of threat intelligence.
    """

    def __init__(self):
        logger.info("=" * 60)
        logger.info("🛡️ AI-Powered Cyber Threat Intelligence Bot Starting")
        logger.info("=" * 60)

        # Initialize storage
        self.db = DatabaseManager(config.USERS_DB, config.NEWS_DB)
        self.persistence = PersistenceManager(config.DATA_DIR)
        self.state = StateManager(config.STATE_FILE)
        self.embeddings = EmbeddingsManager(config.EMBEDDINGS_DB, config.EMBEDDING_MODEL)

        # Initialize collectors
        self.collectors = self._init_collectors()

        # Initialize AI components
        self.ai_components = self._init_ai_components()

        # Initialize notifiers
        self.notifiers = self._init_notifiers()

        # Track execution
        self.start_time = time.time()
        self.alerts_collected = 0
        self.alerts_sent = 0

    def _init_collectors(self):
        """Initialize all data collectors."""
    

        collectors = {
            "rss": RSSCollector(
    feeds=config.SOURCES.get("rss", {}).get("feeds", []),
    config={
        "lookback_hours": config.LOOKBACK_HOURS,
        "max_items_per_feed": config.MAX_ITEMS_PER_SOURCE,
    }
),
            "github": GitHubCollector(config={
                "github_token": os.getenv("GITHUB_TOKEN"),
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
                "queries": config.SOURCES.get("github", {}).get("security_repos", []),
            }),
            "cve": CVECollector(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
                "min_cvss_score": config.MIN_SEVERITY_TO_ALERT,
                "nvd_api_key": os.getenv("NVD_API_KEY"),
            }),
            "exploitdb": ExploitDBCollector(config={
                "max_items": config.MAX_ITEMS_PER_SOURCE,
            }),
            "huggingface": HuggingFaceCollector(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
            }),
            "reddit": RedditCollector(config={
                "subreddits": config.SOURCES.get("reddit", {}).get("subreddits", []),
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_posts_per_subreddit": 5,
            }),
            "telegram": TelegramCollector(config={
                "bot_token": config.TELEGRAM_BOT_TOKEN,
                "max_messages": 10,
            }),
            "leak": LeakMonitor(config={
                "hibp_api_key": os.getenv("HIBP_API_KEY"),
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_items": config.MAX_ITEMS_PER_SOURCE,
            }),
            "ransomware": RansomwareMonitor(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_items": config.MAX_ITEMS_PER_SOURCE,
            }),
            "darkweb": DarkWebMonitor(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_items": 5,
            }),
        }

        logger.info(f"Initialized {len(collectors)} collectors")
        return collectors

    def _init_ai_components(self):
        """Initialize AI processing components."""
        ai_config = {
    "gemini_api_key": config.GEMINI_API_KEY,
    "model": config.GEMINI_MODEL,
    "ai_enabled": config.AI_ENABLED,
}

        components = {
            "classifier": ThreatClassifier(config=ai_config),
            "summarizer": ThreatSummarizer(config=ai_config),
            "relevance": RelevanceEngine(config={
                "min_relevance": 0.3,
                "ai_enabled": config.AI_ENABLED,
            }),
            "severity": SeverityAnalyzer(config={
                "min_severity": config.MIN_SEVERITY_TO_ALERT,
            }),
            "duplicate": DuplicateDetector(
                embeddings_manager=self.embeddings,
                config={
                    "similarity_threshold": config.DUPLICATE_SIMILARITY_THRESHOLD,
                }
            ),
            "downloads": DownloadExtractor(),
            "ranker": ThreatRanker(config={
                "max_alerts_per_run": config.MAX_ALERTS_PER_RUN,
            }),
            "analyst": AIThreatAnalyst(config=ai_config),
        }

        logger.info(f"Initialized {len(components)} AI components (AI enabled: {config.AI_ENABLED})")
        return components

    def _init_notifiers(self):
        """Initialize notification senders."""
        notifiers = {}

        # Telegram notifier
        if config.TELEGRAM_BOT_TOKEN:
            notifiers["telegram"] = TelegramSender(
                config.TELEGRAM_BOT_TOKEN,
                config={
                    "rate_limit_delay": 1.0,
                    "max_retries": 3,
                }
            )
            logger.info("Telegram notifier initialized")

        return notifiers

    def run(self):
        """Execute one complete bot cycle."""
        logger.info("Starting bot run cycle...")

        try:
            # Step 1: Process Telegram updates (user management)
            self._process_telegram_updates()

            # Step 2: Collect threat intelligence
            raw_alerts = self._collect_data()

            # Step 3: Process and filter alerts
            processed_alerts = self._process_alerts(raw_alerts)

            # Step 4: Send alerts to subscribers
            if processed_alerts:
                self._send_alerts(processed_alerts)

            # Step 5: Save state and persist data
            self._save_state()

            # Step 6: Git commit if in GitHub Actions
            self._git_commit()

            # Log summary
            duration = time.time() - self.start_time
            logger.info("=" * 60)
            logger.info(f"✅ Bot cycle completed in {duration:.1f}s")
            logger.info(f"   Collected: {self.alerts_collected}")
            logger.info(f"   Processed: {len(processed_alerts)}")
            logger.info(f"   Sent: {self.alerts_sent}")
            logger.info("=" * 60)

        except Exception as e:
            logger.exception(f"Bot run failed: {e}")
            raise

    def _process_telegram_updates(self):
        """Process Telegram bot commands and user management."""
        if "telegram" not in self.notifiers:
            return

        logger.info("Processing Telegram updates...")
        sender = self.notifiers["telegram"]

        # Get updates
        last_update_id = self.state.get_last_update_id()
        updates = sender.get_updates(offset=last_update_id + 1)

        new_users = 0
        removed_users = 0

        for update in updates:
            try:
                update_id = update.get("update_id", 0)
                self.state.set_last_update_id(update_id)

                # Handle messages
                message = update.get("message", {})
                if not message:
                    message = update.get("callback_query", {}).get("message", {})

                chat = message.get("chat", {})
                chat_id = chat.get("id")
                text = message.get("text", "")

                if not chat_id or not text:
                    continue

                username = message.get("from", {}).get("username", "")
                first_name = message.get("from", {}).get("first_name", "")
                last_name = message.get("from", {}).get("last_name", "")

                # Process commands
                if text == "/start":
                    added = self.db.add_user(
                        chat_id=chat_id,
                        username=username,
                        first_name=first_name,
                        last_name=last_name,
                        is_admin=(chat_id in config.TELEGRAM_ADMIN_IDS)
                    )
                    if added:
                        new_users += 1
                        self.persistence.save_json(f"user_{chat_id}.json", {
                            "joined": datetime.utcnow().isoformat(),
                            "username": username,
                        })
                    sender.send_welcome_message(chat_id, username or first_name)

                elif text == "/stop":
                    self.db.remove_user(chat_id)
                    removed_users += 1
                    sender.send_goodbye_message(chat_id)

                elif text == "/status":
                    stats = self._get_bot_stats()
                    sender.send_status(chat_id, stats)

                elif text == "/stats" or text == "/admin":
                    if self.db.is_admin(chat_id):
                        stats = self._get_admin_stats()
                        sender.send_admin_stats(chat_id, stats)
                    else:
                        sender._api_call("sendMessage", {
                            "chat_id": chat_id,
                            "text": "⛔ Admin access required.",
                            "parse_mode": "HTML",
                        })

                elif text == "/help":
                    help_text = self._get_help_text()
                    sender._api_call("sendMessage", {
                        "chat_id": chat_id,
                        "text": help_text,
                        "parse_mode": "HTML",
                    })

            except Exception as e:
                logger.error(f"Error processing update: {e}")

        if new_users > 0 or removed_users > 0:
            logger.info(f"User changes: +{new_users} new, -{removed_users} removed")

    def _collect_data(self) -> list:
        """Collect data from all sources."""
        all_alerts = []

        collectors_to_run = [
            ("CVE", "cve"),
            ("ExploitDB", "exploitdb"),
            ("GitHub", "github"),
            ("RSS", "rss"),
            ("HuggingFace", "huggingface"),
            ("Reddit", "reddit"),
            ("Ransomware", "ransomware"),
            ("Leak Monitor", "leak"),
            ("DarkWeb", "darkweb"),
        ]

        for name, key in collectors_to_run:
            try:
                logger.info(f"Collecting from {name}...")
                collector = self.collectors.get(key)
                if collector:
                    alerts = collector.collect()
                    logger.info(f"  {name}: {len(alerts)} alerts")
                    all_alerts.extend(alerts)
                    self.state.set_last_check_time(key.lower())
            except Exception as e:
                logger.error(f"Collector {name} failed: {e}")

        self.alerts_collected = len(all_alerts)
        logger.info(f"Total raw alerts collected: {len(all_alerts)}")
        return all_alerts

    def _process_alerts(self, alerts: list) -> list:
        """Process and filter collected alerts."""
        if not alerts:
            return []

        logger.info("Processing alerts...")

        # Step 1: Classify
        logger.info("  Classifying alerts...")
        alerts = self.ai_components["classifier"].classify_batch(alerts)

        # Step 2: Filter noise
        alerts = [a for a in alerts if self.ai_components["classifier"].is_valuable(a)]
        logger.info(f"  After noise filter: {len(alerts)}")

        # Step 3: Extract downloads
        logger.info("  Extracting downloads...")
        alerts = self.ai_components["downloads"].extract_batch(alerts)

        # Step 4: Filter duplicates
        logger.info("  Filtering duplicates...")
        alerts = self.ai_components["duplicate"].filter_duplicates(alerts)
        logger.info(f"  After dedup: {len(alerts)}")

        # Step 5: Analyze severity
        logger.info("  Analyzing severity...")
        alerts = self.ai_components["severity"].analyze_batch(alerts)

        # Step 6: Filter by minimum severity
        alerts = [a for a in alerts if a.get("severity", 0) >= config.MIN_SEVERITY_TO_ALERT]
        logger.info(f"  After severity filter: {len(alerts)}")

        # Step 7: Score relevance
        logger.info("  Scoring relevance...")
        alerts = self.ai_components["relevance"].filter_alerts(alerts)
        logger.info(f"  After relevance filter: {len(alerts)}")

        # Step 8: Generate summaries
        logger.info("  Generating summaries...")
        alerts = self.ai_components["summarizer"].summarize_batch(alerts)

        # Step 9: AI analysis
        if config.AI_ENABLED:
            logger.info("  Running AI analysis...")
            for alert in alerts[:5]:  # Only analyze top alerts
                try:
                    self.ai_components["analyst"].analyze(alert)
                    alert["why_it_matters"] = self.ai_components["analyst"].generate_why_it_matters(alert)
                except Exception as e:
                    logger.error(f"AI analysis failed for alert: {e}")

        # Step 10: Rank alerts
        logger.info("  Ranking alerts...")
        alerts = self.ai_components["ranker"].get_top_alerts(alerts, config.MAX_ALERTS_PER_RUN)

        # Step 11: Save to database
        for alert in alerts:
            try:
                self.db.save_alert(alert)
                self.state.add_processed_hash(alert["hash_id"])
            except Exception as e:
                logger.error(f"Error saving alert: {e}")

        logger.info(f"Final alerts to send: {len(alerts)}")
        return alerts

    def _send_alerts(self, alerts: list):
        """Send alerts to all subscribers."""
        if not alerts:
            return

        # Get active subscribers
        subscribers = self.db.get_active_users()
        if not subscribers:
            logger.warning("No subscribers to send alerts to")
            return

        logger.info(f"Sending {len(alerts)} alerts to {len(subscribers)} subscribers...")

        if "telegram" in self.notifiers:
            sender = self.notifiers["telegram"]
            results = sender.broadcast(alerts, subscribers)

            total_sent = sum(results.values())
            self.alerts_sent = total_sent
            self.state.increment_alert_count(total_sent)

            logger.info(f"Sent {total_sent} alert messages via Telegram")

    def _save_state(self):
        """Save bot state."""
        self.state.increment_run_count()

        # Save stats
        stats = self._get_bot_stats()
        self.persistence.save_json("last_run_stats.json", stats)

        # Save state
        self.state.save()

        logger.info("State saved")

    def _git_commit(self):
        """Commit state to git if in GitHub Actions."""
        if self.persistence.should_git_push():
            logger.info("Committing state to git...")
            commit_msg = (
                f"Update: {self.alerts_collected} collected, "
                f"{self.alerts_sent} sent - "
                f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"
            )
            self.persistence.git_commit_and_push(commit_msg)
        else:
            logger.info("Not in GitHub Actions, skipping git commit")

    def _get_bot_stats(self) -> dict:
        """Get bot statistics for status command."""
        db_stats = self.db.get_alert_stats(hours=24)

        return {
            "total_subscribers": self.db.get_user_count(),
            "alerts_24h": db_stats.get("total", 0),
            "total_alerts": self.state.get("total_alerts_sent", 0),
            "sources_count": len(self.collectors),
            "last_run": self.state.get("last_run", "N/A"),
            "cves_24h": db_stats.get("by_category", {}).get("cve", 0),
            "exploits_24h": db_stats.get("by_category", {}).get("exploit", 0),
            "breaches_24h": db_stats.get("by_category", {}).get("data_breach", 0),
            "ransomware_24h": db_stats.get("by_category", {}).get("ransomware", 0),
            "ai_enabled": config.AI_ENABLED,
            "embeddings_active": self.embeddings.model is not None,
            "version": config.STATE_FILE.parent.parent.name,
        }

    def _get_admin_stats(self) -> dict:
        """Get detailed stats for admin dashboard."""
        alert_stats = self.db.get_alert_stats(hours=24)
        embedding_stats = self.embeddings.get_stats()

        return {
            "active_users": self.db.get_user_count(),
            "total_users_ever": self.state.get("total_users_ever", 0),
            "admin_count": len(self.db.get_admin_users()),
            "alerts_24h": alert_stats.get("total", 0),
            "critical_24h": alert_stats.get("by_severity", {}).get("CRITICAL", 0),
            "high_24h": alert_stats.get("by_severity", {}).get("HIGH", 0),
            "sent_24h": self.alerts_sent,
            "db_size_mb": self._get_db_size(),
            "embeddings_count": embedding_stats.get("total_embeddings", 0),
            "processed_urls": len(self.state.get("processed_urls", [])),
            "avg_run_time": f"{(time.time() - self.start_time):.1f}",
            "success_rate": 100.0,
            "runs_today": self.state.get_run_count_today(),
            "source_counts": alert_stats.get("by_category", {}),
        }

    def _get_db_size(self) -> float:
        """Get database file size in MB."""
        total_size = 0
        for db_file in [config.USERS_DB, config.NEWS_DB, config.EMBEDDINGS_DB]:
            if db_file.exists():
                total_size += db_file.stat().st_size
        return total_size / (1024 * 1024)

    @staticmethod
    def _get_help_text() -> str:
        """Get help text for bot commands."""
        return """🛡️ <b>Cyber Threat Intelligence Bot</b>

<b>Available Commands:</b>

/start - Subscribe to threat intelligence alerts
/stop - Unsubscribe from alerts
/status - View bot statistics and status
/help - Show this help message

<b>Admin Commands:</b>
/stats or /admin - View admin dashboard

<b>What you'll receive:</b>
• CVE disclosures and vulnerability alerts
• Exploit releases and PoC tools
• Malware and ransomware tracking
• Data breach notifications
• AI security tools and research
• Threat intelligence reports

Stay secure! 🔒"""


def main():
    """Main entry point."""
    bot = CTIBot()
    bot.run()


if __name__ == "__main__":
    main()
