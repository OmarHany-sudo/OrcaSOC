"""
State Manager - Tracks execution state between GitHub Actions runs
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class StateManager:
    """
    Manages the state of the bot between executions.
    Since the bot runs statelessly in GitHub Actions,
    state is persisted through JSON files committed to the repo.
    """

    def __init__(self, state_file: Path):
        self.state_file = state_file
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Load state from file or initialize defaults."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading state: {e}")

        return self._default_state()

    def _default_state(self) -> Dict[str, Any]:
        """Create default state structure."""
        return {
            "last_run": None,
            "last_update_id": 0,
            "processed_urls": [],
            "processed_hashes": [],
            "last_cve_check": None,
            "last_exploit_check": None,
            "last_github_check": None,
            "last_huggingface_check": None,
            "last_reddit_check": None,
            "last_rss_check": None,
            "last_ransomware_check": None,
            "last_leak_check": None,
            "daily_counts": {},
            "total_alerts_sent": 0,
            "total_users_ever": 0,
            "version": "1.0.0",
            "runs_today": 0,
            "last_run_date": None,
        }

    def save(self) -> bool:
        """Save current state to file."""
        try:
            self.state["last_run"] = datetime.utcnow().isoformat()
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, ensure_ascii=False, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Error saving state: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get a state value."""
        return self.state.get(key, default)

    def set(self, key: str, value: Any):
        """Set a state value."""
        self.state[key] = value

    def update(self, updates: Dict[str, Any]):
        """Update multiple state values."""
        self.state.update(updates)

    def get_last_update_id(self) -> int:
        """Get last processed Telegram update ID."""
        return self.state.get("last_update_id", 0)

    def set_last_update_id(self, update_id: int):
        """Set last processed Telegram update ID."""
        self.state["last_update_id"] = update_id

    def is_url_processed(self, url: str) -> bool:
        """Check if a URL has already been processed."""
        processed = self.state.get("processed_urls", [])
        return url in processed

    def add_processed_url(self, url: str, max_urls: int = 5000):
        """Add a URL to the processed list."""
        processed = self.state.get("processed_urls", [])
        if url not in processed:
            processed.append(url)
            if len(processed) > max_urls:
                processed = processed[-max_urls:]
            self.state["processed_urls"] = processed

    def is_hash_processed(self, hash_id: str) -> bool:
        """Check if a hash has already been processed."""
        processed = self.state.get("processed_hashes", [])
        return hash_id in processed

    def add_processed_hash(self, hash_id: str, max_hashes: int = 5000):
        """Add a hash to the processed list."""
        processed = self.state.get("processed_hashes", [])
        if hash_id not in processed:
            processed.append(hash_id)
            if len(processed) > max_hashes:
                processed = processed[-max_hashes:]
            self.state["processed_hashes"] = processed

    def get_last_check_time(self, source: str) -> Optional[str]:
        """Get the last check time for a data source."""
        key = f"last_{source}_check"
        return self.state.get(key)

    def set_last_check_time(self, source: str, timestamp: str = None):
        """Set the last check time for a data source."""
        key = f"last_{source}_check"
        self.state[key] = timestamp or datetime.utcnow().isoformat()

    def increment_run_count(self):
        """Increment the daily run counter."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        last_date = self.state.get("last_run_date")

        if last_date != today:
            self.state["runs_today"] = 1
            self.state["last_run_date"] = today
        else:
            self.state["runs_today"] = self.state.get("runs_today", 0) + 1

    def get_run_count_today(self) -> int:
        """Get number of runs today."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        if self.state.get("last_run_date") == today:
            return self.state.get("runs_today", 0)
        return 0

    def increment_alert_count(self, count: int = 1):
        """Increment total alerts sent counter."""
        self.state["total_alerts_sent"] = self.state.get("total_alerts_sent", 0) + count

    def get_daily_count(self, date: str = None) -> int:
        """Get alert count for a specific date."""
        if date is None:
            date = datetime.utcnow().strftime("%Y-%m-%d")
        return self.state.get("daily_counts", {}).get(date, 0)

    def increment_daily_count(self, date: str = None):
        """Increment alert count for today."""
        if date is None:
            date = datetime.utcnow().strftime("%Y-%m-%d")
        daily_counts = self.state.get("daily_counts", {})
        daily_counts[date] = daily_counts.get(date, 0) + 1
        self.state["daily_counts"] = daily_counts

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the current state."""
        return {
            "last_run": self.state.get("last_run"),
            "total_alerts_sent": self.state.get("total_alerts_sent", 0),
            "total_users_ever": self.state.get("total_users_ever", 0),
            "processed_urls_count": len(self.state.get("processed_urls", [])),
            "processed_hashes_count": len(self.state.get("processed_hashes", [])),
            "runs_today": self.get_run_count_today(),
            "version": self.state.get("version", "1.0.0"),
        }
