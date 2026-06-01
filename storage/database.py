"""
SQLite Database Manager for Threat Intelligence Storage
"""
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite databases for users and threat intelligence data."""

    def __init__(self, users_db_path: Path, news_db_path: Path):
        self.users_db_path = users_db_path
        self.news_db_path = news_db_path
        self._init_databases()

    @contextmanager
    def _get_connection(self, db_path: Path):
        """Context manager for database connections."""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_databases(self):
        """Initialize all database tables."""
        self._init_users_db()
        self._init_news_db()

    def _init_users_db(self):
        """Create users table."""
        with self._get_connection(self.users_db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    chat_id INTEGER UNIQUE NOT NULL,
                    subscribed INTEGER DEFAULT 1,
                    is_admin INTEGER DEFAULT 0,
                    joined_at TEXT NOT NULL,
                    last_activity TEXT
                )
            """)

    def _init_news_db(self):
        """Create news/alerts table."""
        with self._get_connection(self.news_db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    url TEXT,
                    source TEXT NOT NULL,
                    category TEXT,
                    severity REAL,
                    severity_label TEXT,
                    summary TEXT,
                    ai_analysis TEXT,
                    download_links TEXT,
                    raw_content TEXT,
                    hash_id TEXT UNIQUE NOT NULL,
                    embedding_id INTEGER,
                    published_at TEXT,
                    collected_at TEXT NOT NULL,
                    notified INTEGER DEFAULT 0,
                    relevance_score REAL,
                    threat_score INTEGER DEFAULT 0
                )
            """)

            self._ensure_column(conn, "alerts", "threat_score", "INTEGER DEFAULT 0")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS collected_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    hash_id TEXT,
                    collected_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS daily_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE NOT NULL,
                    total_alerts INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    cve_count INTEGER DEFAULT 0,
                    exploit_count INTEGER DEFAULT 0,
                    github_count INTEGER DEFAULT 0,
                    ai_count INTEGER DEFAULT 0,
                    other_count INTEGER DEFAULT 0,
                    notifications_sent INTEGER DEFAULT 0,
                    new_users INTEGER DEFAULT 0,
                    unsubscribed_users INTEGER DEFAULT 0
                )
            """)

    def _ensure_column(self, conn, table: str, column: str, definition: str):
        """Add a column to an existing SQLite table if it is missing."""
        cursor = conn.execute(f"PRAGMA table_info({table})")
        columns = {row[1] for row in cursor.fetchall()}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # === Users Management ===

    def add_user(self, chat_id: int, username: str = None, first_name: str = None,
                 last_name: str = None, is_admin: bool = False) -> bool:
        """Add a new subscriber."""
        try:
            with self._get_connection(self.users_db_path) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO users
                    (chat_id, username, first_name, last_name, is_admin, joined_at, last_activity)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (chat_id, username, first_name, last_name, int(is_admin),
                      datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
                if conn.total_changes > 0:
                    logger.info(f"New user added: {chat_id} (@{username})")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error adding user {chat_id}: {e}")
            return False

    def remove_user(self, chat_id: int) -> bool:
        """Unsubscribe a user."""
        try:
            with self._get_connection(self.users_db_path) as conn:
                conn.execute("UPDATE users SET subscribed = 0 WHERE chat_id = ?", (chat_id,))
                return conn.total_changes > 0
        except Exception as e:
            logger.error(f"Error removing user {chat_id}: {e}")
            return False

    def get_active_users(self) -> List[Dict]:
        """Get all subscribed users."""
        with self._get_connection(self.users_db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE subscribed = 1")
            return [dict(row) for row in cursor.fetchall()]

    def get_admin_users(self) -> List[Dict]:
        """Get all admin users."""
        with self._get_connection(self.users_db_path) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE is_admin = 1 AND subscribed = 1")
            return [dict(row) for row in cursor.fetchall()]

    def get_user_count(self) -> int:
        """Get total subscriber count."""
        with self._get_connection(self.users_db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM users WHERE subscribed = 1")
            return cursor.fetchone()[0]

    def is_admin(self, chat_id: int) -> bool:
        """Check if user is admin."""
        with self._get_connection(self.users_db_path) as conn:
            cursor = conn.execute(
                "SELECT is_admin FROM users WHERE chat_id = ?", (chat_id,)
            )
            row = cursor.fetchone()
            return row and row["is_admin"] == 1

    # === Alerts Management ===

    def save_alert(self, alert: Dict[str, Any]) -> bool:
        """Save a new threat alert."""
        try:
            with self._get_connection(self.news_db_path) as conn:
                download_links = json.dumps(alert.get("download_links", [])) if isinstance(alert.get("download_links"), list) else alert.get("download_links", "")
                conn.execute("""
                    INSERT OR IGNORE INTO alerts
                    (title, url, source, category, severity, severity_label, summary,
                     ai_analysis, download_links, raw_content, hash_id, published_at,
                     collected_at, relevance_score, threat_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get("title", ""),
                    alert.get("url", ""),
                    alert.get("source", ""),
                    alert.get("category", "general"),
                    alert.get("severity", 0.0),
                    alert.get("severity_label", "LOW"),
                    alert.get("summary", ""),
                    alert.get("ai_analysis", ""),
                    download_links,
                    alert.get("raw_content", ""),
                    alert["hash_id"],
                    alert.get("published_at"),
                    datetime.utcnow().isoformat(),
                    alert.get("relevance_score", 0.0),
                    int(alert.get("threat_score", 0) or 0),
                ))
                return conn.total_changes > 0
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
            return False

    def alert_exists(self, hash_id: str) -> bool:
        """Check if alert already exists."""
        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute("SELECT 1 FROM alerts WHERE hash_id = ?", (hash_id,))
            return cursor.fetchone() is not None

    def get_recent_alerts(self, hours: int = 24, category: str = None,
                         min_severity: float = 0) -> List[Dict]:
        """Get recent alerts with optional filtering."""
        cutoff = datetime.utcnow().timestamp() - (hours * 3600)
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat()

        query = "SELECT * FROM alerts WHERE collected_at > ?"
        params = [cutoff_iso]

        if category:
            query += " AND category = ?"
            params.append(category)
        if min_severity > 0:
            query += " AND severity >= ?"
            params.append(min_severity)

        query += " ORDER BY collected_at DESC"

        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute(query, params)
            return [self._decode_alert_row(row) for row in cursor.fetchall()]

    def get_latest_alerts(self, limit: int = 10) -> List[Dict]:
        """Get the latest saved alerts."""
        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM alerts ORDER BY collected_at DESC LIMIT ?",
                (limit,)
            )
            return [self._decode_alert_row(row) for row in cursor.fetchall()]

    def get_top_alerts(self, hours: int = 24, limit: int = 10) -> List[Dict]:
        """Get highest-priority alerts for a time window."""
        cutoff = datetime.utcnow().timestamp() - (hours * 3600)
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat()
        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute(
                """
                SELECT * FROM alerts
                WHERE collected_at > ?
                ORDER BY threat_score DESC, severity DESC, relevance_score DESC, collected_at DESC
                LIMIT ?
                """,
                (cutoff_iso, limit)
            )
            return [self._decode_alert_row(row) for row in cursor.fetchall()]

    def mark_alert_notified(self, alert_id: int):
        """Mark an alert as notified."""
        with self._get_connection(self.news_db_path) as conn:
            conn.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,))

    def get_unnotified_alerts(self, limit: int = 10) -> List[Dict]:
        """Get alerts that haven't been notified yet."""
        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE notified = 0 ORDER BY severity DESC, collected_at DESC LIMIT ?",
                (limit,)
            )
            return [self._decode_alert_row(row) for row in cursor.fetchall()]

    def get_alert_stats(self, hours: int = 24) -> Dict:
        """Get alert statistics."""
        cutoff = datetime.utcnow().timestamp() - (hours * 3600)
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat()

        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE collected_at > ?", (cutoff_iso,)
            )
            total = cursor.fetchone()[0]

            cursor = conn.execute(
                "SELECT severity_label, COUNT(*) FROM alerts WHERE collected_at > ? GROUP BY severity_label",
                (cutoff_iso,)
            )
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor = conn.execute(
                "SELECT category, COUNT(*) FROM alerts WHERE collected_at > ? GROUP BY category",
                (cutoff_iso,)
            )
            category_counts = {row[0]: row[1] for row in cursor.fetchall()}

            return {
                "total": total,
                "by_severity": severity_counts,
                "by_category": category_counts,
                "hours": hours
            }

    def _decode_alert_row(self, row) -> Dict[str, Any]:
        """Convert a SQLite row into an alert dict with decoded JSON fields."""
        alert = dict(row)
        links = alert.get("download_links")
        if isinstance(links, str):
            try:
                alert["download_links"] = json.loads(links) if links else []
            except Exception:
                alert["download_links"] = [links] if links else []
        return alert

    # === URL Tracking ===

    def is_url_collected(self, url: str) -> bool:
        """Check if URL was already collected."""
        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute("SELECT 1 FROM collected_urls WHERE url = ?", (url,))
            return cursor.fetchone() is not None

    def add_collected_url(self, url: str, hash_id: str = None):
        """Mark URL as collected."""
        try:
            with self._get_connection(self.news_db_path) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO collected_urls (url, hash_id, collected_at) VALUES (?, ?, ?)",
                    (url, hash_id, datetime.utcnow().isoformat())
                )
        except Exception as e:
            logger.error(f"Error adding collected URL: {e}")

    # === Daily Stats ===

    def update_daily_stats(self, **kwargs):
        """Update daily statistics."""
        today = datetime.utcnow().strftime("%Y-%m-%d")

        try:
            with self._get_connection(self.news_db_path) as conn:
                conn.execute("""
                    INSERT INTO daily_stats (date) VALUES (?)
                    ON CONFLICT(date) DO NOTHING
                """, (today,))

                updates = []
                params = []
                for key, value in kwargs.items():
                    if key in [
                        "total_alerts", "critical_count", "high_count", "medium_count",
                        "low_count", "cve_count", "exploit_count", "github_count",
                        "ai_count", "other_count", "notifications_sent",
                        "new_users", "unsubscribed_users"
                    ]:
                        updates.append(f"{key} = {key} + ?")
                        params.append(value)

                if updates:
                    query = f"UPDATE daily_stats SET {', '.join(updates)} WHERE date = ?"
                    params.append(today)
                    conn.execute(query, params)
        except Exception as e:
            logger.error(f"Error updating daily stats: {e}")

    def get_daily_stats(self, days: int = 7) -> List[Dict]:
        """Get daily statistics for the last N days."""
        with self._get_connection(self.news_db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM daily_stats ORDER BY date DESC LIMIT ?",
                (days,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_data(self, days: int = 30):
        """Remove old collected URLs to prevent database bloat."""
        cutoff = datetime.utcnow().timestamp() - (days * 86400)
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat()

        with self._get_connection(self.news_db_path) as conn:
            conn.execute("DELETE FROM collected_urls WHERE collected_at < ?", (cutoff_iso,))
            deleted = conn.total_changes
            logger.info(f"Cleaned up {deleted} old collected URLs")
