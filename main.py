#!/usr/bin/env python3
"""
AI-Powered Cyber Threat Intelligence Telegram Bot
Main entry point - runs as a GitHub Actions workflow
"""
import logging
import os
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests

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
from collectors.cisa_kev_collector import CISAKEVCollector
from collectors.projectdiscovery_collector import ProjectDiscoveryCollector
from collectors.bugbounty_collector import BugBountyDisclosureCollector
from collectors.security_papers_collector import SecurityPapersCollector

from ai.classifier import ThreatClassifier
from ai.summarizer import ThreatSummarizer
from ai.relevance_engine import RelevanceEngine
from ai.severity_analyzer import SeverityAnalyzer
from ai.duplicate_detector import DuplicateDetector
from ai.download_extractor import DownloadExtractor
from ai.threat_ranker import ThreatRanker
from ai.ai_threat_analyst import AIThreatAnalyst
from ai.threat_scorer import ThreatScorer

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


SOURCE_ALIASES = {
    "all": None,
    "run": None,
    "cves": ["cve", "cisa"],
    "cve": ["cve", "cisa"],
    "exploits": ["exploitdb", "github_poc", "projectdiscovery"],
    "exploit": ["exploitdb", "github_poc", "projectdiscovery"],
    "leaks": ["leak", "bugbounty"],
    "ransomware": ["ransomware"],
    "ai": ["huggingface", "papers"],
    "darkweb": ["darkweb"],
    "github": ["github", "github_poc"],
    "osint": ["osint"],
    "redteam": ["redteam"],
    "red_team": ["redteam"],
    "papers": ["papers"],
    "projectdiscovery": ["projectdiscovery"],
    "bugbounty": ["bugbounty"],
}

MANUAL_COMMAND_SOURCES = {
    "/run": "all",
    "/cves": "cves",
    "/exploits": "exploits",
    "/leaks": "leaks",
    "/ransomware": "ransomware",
    "/ai": "ai",
    "/darkweb": "darkweb",
    "/github": "github",
    "/osint": "osint",
    "/redteam": "redteam",
}


class CTIBot:
    """
    Main Cyber Threat Intelligence Bot class.
    Orchestrates collection, analysis, and notification of threat intelligence.
    """

    def __init__(self, source: str = None, process_updates: bool = None):
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
        self.source = (source or config.SOURCE or "all").lower()
        self.process_updates = (
            not config.SKIP_TELEGRAM_UPDATES if process_updates is None else process_updates
        )

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
            "github_poc": GitHubCollector(config={
                "github_token": os.getenv("GITHUB_TOKEN"),
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
                "queries": [
                    "CVE RCE PoC",
                    "CVE exploit proof of concept",
                    "0day exploit PoC",
                    "auth bypass CVE PoC",
                    "SQLi exploit PoC",
                    "XSS exploit PoC",
                    "deserialization exploit PoC",
                ],
            }),
            "osint": GitHubCollector(config={
                "github_token": os.getenv("GITHUB_TOKEN"),
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
                "queries": config.SOURCES.get("github", {}).get("osint_queries", []),
            }),
            "redteam": GitHubCollector(config={
                "github_token": os.getenv("GITHUB_TOKEN"),
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
                "queries": config.SOURCES.get("github", {}).get("redteam_queries", []),
            }),
            "cve": CVECollector(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
                "min_cvss_score": config.MIN_SEVERITY_TO_ALERT,
                "nvd_api_key": os.getenv("NVD_API_KEY"),
            }),
            "cisa": CISAKEVCollector(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_items": config.MAX_ITEMS_PER_SOURCE,
            }),
            "exploitdb": ExploitDBCollector(config={
                "max_items": config.MAX_ITEMS_PER_SOURCE,
            }),
            "projectdiscovery": ProjectDiscoveryCollector(config={
                "github_token": os.getenv("GITHUB_TOKEN"),
                "max_items": config.MAX_ITEMS_PER_SOURCE,
            }),
            "huggingface": HuggingFaceCollector(config={
                "lookback_hours": config.LOOKBACK_HOURS,
                "max_results": config.MAX_ITEMS_PER_SOURCE,
            }),
            "papers": SecurityPapersCollector(config={
                "max_items": config.MAX_ITEMS_PER_SOURCE,
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
            "bugbounty": BugBountyDisclosureCollector(config={
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
            "scorer": ThreatScorer(),
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
        logger.info("Starting bot run cycle for source='%s'...", self.source)

        try:
            # Step 1: Process Telegram updates (user management)
            if self.process_updates:
                self._process_telegram_updates()
            else:
                logger.info("Skipping Telegram update processing for this run")

            # Step 2: Collect threat intelligence
            raw_alerts = self._collect_data(self.source)

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

                callback_query = update.get("callback_query", {})
                callback_id = callback_query.get("id")
                callback_data = callback_query.get("data", "")

                message = update.get("message", {})
                if not message:
                    message = callback_query.get("message", {})

                chat = message.get("chat", {})
                chat_id = chat.get("id")
                text = message.get("text", "")

                if callback_data:
                    source = callback_data.replace("run:", "", 1)
                    if source == "top":
                        sender.answer_callback_query(callback_id, "Loading top alerts...")
                        self._send_saved_alerts_to_chat(
                            chat_id,
                            self.db.get_top_alerts(hours=24, limit=10),
                            "Top Alerts",
                        )
                    else:
                        self._handle_manual_scan_request(chat_id, source, sender, callback_id)
                    continue

                if not chat_id or not text:
                    continue

                username = message.get("from", {}).get("username", "")
                first_name = message.get("from", {}).get("first_name", "")
                last_name = message.get("from", {}).get("last_name", "")

                command = text.split()[0].split("@")[0].lower()

                # Process commands
                if command == "/start":
                    added = self.db.add_user(
                        chat_id=chat_id,
                        username=username,
                        first_name=first_name,
                        last_name=last_name,
                        is_admin=(chat_id in config.TELEGRAM_ADMIN_IDS)
                    )
                    if added:
                        new_users += 1
                        self.state.set(
                            "total_users_ever",
                            self.state.get("total_users_ever", 0) + 1,
                        )
                        self.persistence.save_json(f"user_{chat_id}.json", {
                            "joined": datetime.utcnow().isoformat(),
                            "username": username,
                        })
                    sender.send_welcome_message(chat_id, username or first_name)

                elif command == "/stop":
                    self.db.remove_user(chat_id)
                    removed_users += 1
                    self.db.update_daily_stats(unsubscribed_users=1)
                    sender.send_goodbye_message(chat_id)

                elif command == "/status":
                    stats = self._get_bot_stats()
                    sender.send_status(chat_id, stats)

                elif command == "/dashboard":
                    sender.send_dashboard(chat_id, self._get_dashboard_stats())

                elif command == "/latest":
                    self._send_saved_alerts_to_chat(chat_id, self.db.get_latest_alerts(limit=10), "Latest Alerts")

                elif command == "/top":
                    self._send_saved_alerts_to_chat(chat_id, self.db.get_top_alerts(hours=24, limit=10), "Top Alerts")

                elif command in MANUAL_COMMAND_SOURCES:
                    self._handle_manual_scan_request(
                        chat_id,
                        MANUAL_COMMAND_SOURCES[command],
                        sender,
                    )

                elif command in {"/stats", "/admin"}:
                    if self.db.is_admin(chat_id):
                        stats = self._get_admin_stats()
                        sender.send_admin_stats(chat_id, stats)
                    else:
                        sender._api_call("sendMessage", {
                            "chat_id": chat_id,
                            "text": "⛔ Admin access required.",
                            "parse_mode": "HTML",
                        })

                elif command == "/help":
                    help_text = self._get_help_text()
                    sender._api_call("sendMessage", {
                        "chat_id": chat_id,
                        "text": help_text,
                        "parse_mode": "HTML",
                        "reply_markup": sender.build_command_keyboard(),
                    })

            except Exception as e:
                logger.error(f"Error processing update: {e}")

        if new_users > 0 or removed_users > 0:
            if new_users:
                self.db.update_daily_stats(new_users=new_users)
            logger.info(f"User changes: +{new_users} new, -{removed_users} removed")

    def _handle_manual_scan_request(self, chat_id: int, source: str, sender, callback_id: str = None):
        """Dispatch a manual GitHub Actions run for a requested source."""
        source = (source or "all").lower()
        if source not in SOURCE_ALIASES:
            sender.send_text(chat_id, f"Unknown source: <code>{source}</code>")
            return
        if callback_id:
            sender.answer_callback_query(callback_id, f"Starting {source} scan...")

        if not self._can_run_manual_command(chat_id):
            sender.send_text(chat_id, "⛔ Manual scans require admin access.")
            return

        ok, message = self._dispatch_manual_workflow(source, chat_id)
        if ok:
            sender.send_text(
                chat_id,
                f"✅ Manual OrcaSOC scan queued.\n\nSource: <b>{source}</b>\nWorkflow: <code>{config.GITHUB_WORKFLOW_FILE}</code>",
                reply_markup=sender.build_command_keyboard(),
            )
        else:
            sender.send_text(chat_id, f"❌ Could not queue manual scan.\n\n{message}")

    def _can_run_manual_command(self, chat_id: int) -> bool:
        """Allow manual scan commands for admins, or everyone when no admin list is configured."""
        if not config.TELEGRAM_MANUAL_COMMANDS_ADMIN_ONLY:
            return True
        if not config.TELEGRAM_ADMIN_IDS:
            return True
        return chat_id in config.TELEGRAM_ADMIN_IDS or self.db.is_admin(chat_id)

    def _dispatch_manual_workflow(self, source: str, chat_id: int) -> tuple:
        """Trigger the manual_run.yml workflow through GitHub Actions Workflow Dispatch API."""
        token = os.getenv("GITHUB_TOKEN", "")
        repository = config.GITHUB_REPOSITORY or os.getenv("GITHUB_REPOSITORY", "")
        if not token or not repository:
            return False, "GITHUB_TOKEN/GITHUB_REPOSITORY are not available in this runtime."

        url = f"https://api.github.com/repos/{repository}/actions/workflows/{config.GITHUB_WORKFLOW_FILE}/dispatches"
        payload = {
            "ref": config.GITHUB_REF_NAME,
            "inputs": {
                "source": source,
                "requested_by": str(chat_id),
            },
        }
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=20)
            if response.status_code in {200, 201, 204}:
                logger.info("Dispatched manual workflow for source=%s chat_id=%s", source, chat_id)
                return True, "queued"
            return False, f"GitHub API returned {response.status_code}: {response.text[:300]}"
        except Exception as e:
            logger.error("Manual workflow dispatch failed: %s", e)
            return False, str(e)

    def _send_saved_alerts_to_chat(self, chat_id: int, alerts: list, title: str):
        """Send saved alerts from the database to one Telegram chat."""
        if "telegram" not in self.notifiers:
            return
        sender = self.notifiers["telegram"]
        if not alerts:
            sender.send_text(chat_id, f"No saved alerts found for <b>{title}</b>.")
            return
        sender.send_text(chat_id, f"📌 <b>{title}</b>\nSending {len(alerts)} saved alerts...")
        sender.send_alerts(chat_id, alerts)

    def _get_dashboard_stats(self) -> dict:
        """Build dashboard statistics for Telegram."""
        stats = self.db.get_alert_stats(hours=24)
        categories = stats.get("by_category", {})
        return {
            "alerts_24h": stats.get("total", 0),
            "cves": categories.get("cve", 0),
            "exploits": categories.get("exploit", 0) + categories.get("github_poc", 0),
            "leaks": categories.get("data_breach", 0),
            "ai_models": categories.get("ai_model", 0) + categories.get("ai_tool", 0),
            "github_pocs": categories.get("github_poc", 0),
            "ransomware": categories.get("ransomware", 0),
            "subscribers": self.db.get_user_count(),
            "sources_count": len(self.collectors),
        }

    def _resolve_collector_names(self, source: str) -> list:
        """Resolve a source alias to collector names."""
        normalized = (source or "all").lower()
        selected = SOURCE_ALIASES.get(normalized)
        if selected is None:
            return list(self.collectors.keys())
        return [name for name in selected if name in self.collectors]

    def _collect_data(self, source: str = None) -> list:
        """Collect threat intelligence from all configured collectors."""
        selected_names = self._resolve_collector_names(source or self.source)
        logger.info("Collecting threat intelligence from %s collectors: %s", len(selected_names), ", ".join(selected_names))
        all_alerts = []
        source_counts = {}

        def run_collector(name: str):
            collector = self.collectors[name]
            try:
                logger.info(f"  Collector '{name}' starting...")
                alerts = collector.collect()

                if alerts is None:
                    alerts = []
                if not isinstance(alerts, list):
                    logger.warning(
                        "  Collector '%s' returned %s instead of list; skipping",
                        name,
                        type(alerts).__name__,
                    )
                    alerts = []

                valid_alerts = [alert for alert in alerts if isinstance(alert, dict)]
                invalid_count = len(alerts) - len(valid_alerts)
                if invalid_count:
                    logger.warning(
                        "  Collector '%s' returned %s invalid items; skipped",
                        name,
                        invalid_count,
                    )

                source_counts[name] = len(valid_alerts)
                self.state.set_last_check_time(name)
                logger.info(f"  Collector '{name}' collected {len(valid_alerts)} items")
                return name, valid_alerts

            except Exception as e:
                source_counts[name] = 0
                logger.exception(f"  Collector '{name}' failed: {e}")
                return name, []

        workers = min(max(config.COLLECTOR_WORKERS, 1), max(len(selected_names), 1))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(run_collector, name): name for name in selected_names}
            for future in as_completed(futures):
                name, alerts = future.result()
                source_counts[name] = len(alerts)
                all_alerts.extend(alerts)

        self.alerts_collected = len(all_alerts)
        logger.info("Collection complete: %s total items", self.alerts_collected)
        for name, count in source_counts.items():
            logger.info("  Collection count - %s: %s", name, count)

        return all_alerts

    def _filter_previously_processed(self, alerts: list) -> list:
        """Remove alerts already processed in prior runs."""
        unique_alerts = []
        seen_hashes = set()
        duplicates_removed = 0

        for alert in alerts:
            hash_id = alert.get("hash_id")
            url = alert.get("url")

            if not hash_id:
                logger.warning("Skipping alert without hash_id: %s", alert.get("title", "N/A"))
                duplicates_removed += 1
                continue

            already_seen = (
                hash_id in seen_hashes
                or self.state.is_hash_processed(hash_id)
                or self.db.alert_exists(hash_id)
                or (url and (self.state.is_url_processed(url) or self.db.is_url_collected(url)))
            )

            if already_seen:
                duplicates_removed += 1
                continue

            seen_hashes.add(hash_id)
            unique_alerts.append(alert)

        if duplicates_removed:
            logger.info("  Previously processed duplicates removed: %s", duplicates_removed)

        return unique_alerts

    def _process_alerts(self, alerts: list) -> list:
        """Process and filter collected alerts."""
        if not alerts:
            return []

        logger.info("Processing alerts...")
        logger.info(f"  Raw collected alerts: {len(alerts)}")

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
        alerts = self._filter_previously_processed(alerts)
        alerts = self.ai_components["duplicate"].filter_duplicates(alerts)
        logger.info(f"  After duplicate filter: {len(alerts)}")

        # Step 5: Analyze severity
        logger.info("  Analyzing severity...")
        alerts = self.ai_components["severity"].analyze_batch(alerts)

        # Step 6: Filter by minimum severity
        alerts = [a for a in alerts if a.get("severity", 0) >= config.MIN_SEVERITY_TO_ALERT]
        logger.info(f"  After severity filter: {len(alerts)}")

        # Step 7: Calculate CTI threat score
        logger.info("  Calculating threat scores...")
        alerts = self.ai_components["scorer"].score_batch(alerts)

        # Step 8: Score relevance
        logger.info("  Scoring relevance...")
        alerts = self.ai_components["relevance"].filter_alerts(alerts)
        logger.info(f"  After relevance filter: {len(alerts)}")

        # Step 9: Generate summaries
        logger.info("  Generating summaries...")
        alerts = self.ai_components["summarizer"].summarize_batch(alerts)

        # Step 10: AI analysis
        if config.AI_ENABLED:
            logger.info("  Running AI analysis...")
            for alert in alerts[:5]:  # Only analyze top alerts
                try:
                    self.ai_components["analyst"].analyze(alert)
                    alert["why_it_matters"] = self.ai_components["analyst"].generate_why_it_matters(alert)
                except Exception as e:
                    logger.error(f"AI analysis failed for alert: {e}")

        # Step 11: Rank alerts
        logger.info("  Ranking alerts...")
        alerts = self.ai_components["ranker"].get_top_alerts(alerts, config.MAX_ALERTS_PER_RUN)

        # Step 12: Save to database
        for alert in alerts:
            try:
                saved = self.db.save_alert(alert)
                self.state.add_processed_hash(alert["hash_id"])
                if alert.get("url"):
                    self.state.add_processed_url(alert["url"])
                    self.db.add_collected_url(alert["url"], alert["hash_id"])
                if saved:
                    self.state.increment_daily_count()
                    alert_text = " ".join([
                        alert.get("title", ""),
                        alert.get("summary", ""),
                        alert.get("raw_content", "")[:500],
                    ])
                    self.embeddings.store_embedding(alert["hash_id"], alert_text)
            except Exception as e:
                logger.error(f"Error saving alert: {e}")

        logger.info(f"  Final alerts to send: {len(alerts)}")
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
            cve_count = sum(1 for a in alerts if a.get("category") == "cve")
            exploit_count = sum(1 for a in alerts if a.get("category") in {"exploit", "github_poc"})
            github_count = sum(1 for a in alerts if a.get("source") == "GitHub" or a.get("category") == "github_poc")
            ai_count = sum(1 for a in alerts if a.get("category") in {"ai_tool", "ai_model", "prompt_injection", "jailbreak"})
            self.db.update_daily_stats(
                total_alerts=len(alerts),
                critical_count=sum(1 for a in alerts if a.get("severity_label") == "CRITICAL"),
                high_count=sum(1 for a in alerts if a.get("severity_label") == "HIGH"),
                medium_count=sum(1 for a in alerts if a.get("severity_label") == "MEDIUM"),
                low_count=sum(1 for a in alerts if a.get("severity_label") == "LOW"),
                cve_count=cve_count,
                exploit_count=exploit_count,
                github_count=github_count,
                ai_count=ai_count,
                other_count=max(len(alerts) - cve_count - exploit_count - ai_count, 0),
                notifications_sent=total_sent,
            )

            logger.info(f"Final alerts sent: {len(alerts)} alerts, {total_sent} Telegram messages")

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
        return """🛡️ <b>OrcaSOC v2 Cyber Threat Intelligence</b>

<b>Available Commands:</b>

/start - Subscribe to threat intelligence alerts
/stop - Unsubscribe from alerts
/status - View bot statistics and status
/dashboard - View CTI dashboard
/latest - Send latest 10 saved alerts
/top - Send top 10 alerts from the last 24h
/help - Show this help message

<b>Manual Scans:</b>
/run - Run all collectors now
/cves - Run CVE and CISA KEV intelligence
/exploits - Run ExploitDB, GitHub PoCs, and ProjectDiscovery
/leaks - Run breach and bug bounty disclosures
/ransomware - Run ransomware intelligence
/ai - Run AI security and paper intelligence
/darkweb - Run dark web intelligence
/github - Run GitHub intelligence
/osint - Run OSINT tool intelligence
/redteam - Run Red Team tool intelligence

<b>Admin:</b>
/stats or /admin - View admin dashboard

<b>What you'll receive:</b>
• CVE disclosures and vulnerability alerts
• CISA KEV exploited vulnerabilities
• Exploit releases and PoC tools
• Malware and ransomware tracking
• Data breach notifications
• AI security tools and research
• Threat intelligence reports

Stay secure! 🔒"""


def parse_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Run OrcaSOC CTI bot")
    parser.add_argument("--source", default=os.getenv("SOURCE", "all"), help="Source alias to collect")
    parser.add_argument(
        "--skip-updates",
        action="store_true",
        default=config.SKIP_TELEGRAM_UPDATES,
        help="Skip Telegram update processing",
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    bot = CTIBot(source=args.source, process_updates=not args.skip_updates)
    bot.run()


if __name__ == "__main__":
    main()
