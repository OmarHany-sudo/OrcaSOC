"""
DarkWeb Monitor - Monitors publicly indexed dark web feeds
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class DarkWebMonitor(BaseCollector):
    """
    Monitors publicly available dark web indexing feeds.
    Only uses publicly accessible, legal threat intelligence feeds.
    """

    # Public threat intelligence feeds that may contain dark web references
    INTEL_FEEDS = [
        "https://www.reddit.com/r/darknet/rising.json",
    ]

    THREAT_KEYWORDS = [
        "ransomware", "data sale", "database dump", "credentials",
        "exploit market", "0day for sale", "stealer logs",
        "initial access", "access broker", "botnet"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("DarkWeb", config)
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_items = self.config.get("max_items", 5)
        self.min_score = self.config.get("min_reddit_score", 10)

        self.session.headers.update({
            "User-Agent": "CyberThreatBot/1.0 (by /u/cti-bot)"
        })

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect dark web intelligence from public feeds.
        Only uses publicly accessible sources.
        """
        alerts = []

        try:
            reddit_alerts = self._collect_from_reddit()
            alerts.extend(reddit_alerts)
        except Exception as e:
            logger.error(f"[DarkWeb] Error collecting from Reddit: {e}")

        logger.info(f"[DarkWeb] Collected {len(alerts)} alerts")
        return alerts

    def _collect_from_reddit(self) -> List[Dict[str, Any]]:
        """Collect from Reddit darknet monitoring discussions."""
        alerts = []
        url = "https://www.reddit.com/r/darknet/hot.json"

        params = {
            "limit": self.max_items * 2,
            "t": "day"
        }

        response = self.fetch(url, params=params)
        if not response:
            return []

        try:
            data = response.json()
            posts = data.get("data", {}).get("children", [])
        except Exception as e:
            logger.error(f"[DarkWeb] Error parsing Reddit response: {e}")
            return []

        cutoff = datetime.utcnow() - timedelta(hours=self.lookback_hours)

        for post_data in posts:
            try:
                post = post_data.get("data", {})
                score = post.get("score", 0)
                created_utc = post.get("created_utc", 0)

                if score < self.min_score:
                    continue

                post_date = datetime.fromtimestamp(created_utc)
                if post_date < cutoff:
                    continue

                alert = self._process_reddit_post(post)
                if alert:
                    alerts.append(alert)

            except Exception as e:
                logger.error(f"[DarkWeb] Error processing Reddit post: {e}")

        return alerts[:self.max_items]

    def _process_reddit_post(self, post: Dict) -> Dict[str, Any]:
        """Process a Reddit post into a dark web intelligence alert."""
        title = post.get("title", "No Title")
        permalink = f"https://reddit.com{post.get('permalink', '')}"
        selftext = post.get("selftext", "")
        score = post.get("score", 0)
        num_comments = post.get("num_comments", 0)
        author = post.get("author", "unknown")
        url = post.get("url", permalink)

        # Only include posts with relevant threat keywords
        content = (title + " " + selftext).lower()
        found_keywords = [kw for kw in self.THREAT_KEYWORDS if kw in content]

        if not found_keywords:
            return None

        published = datetime.fromtimestamp(post.get("created_utc", 0)).isoformat()

        # Extract URLs
        urls = []
        if url != permalink and "reddit.com" not in url:
            urls.append(url)
        urls.extend(self.extract_urls(selftext)[:3])

        # Estimate severity
        severity = min(5.0 + (score / 100), 8.0)
        if any(kw in content for kw in ["ransomware", "data sale", "credentials"]):
            severity += 1.0

        summary = f"Dark Web Intelligence (Reddit r/darknet)\n\n"
        summary += f"Posted by u/{author}\n"
        summary += f"Score: {score} | Comments: {num_comments}\n\n"
        if selftext:
            summary += self.truncate_text(selftext, 400)

        tags = ["dark-web-intel"] + found_keywords[:5]

        return self.standardize_alert(
            title=f"DarkWeb Intel: {title}",
            url=permalink,
            source="Reddit/r/darknet",
            category="threat_report",
            severity=min(severity, 10.0),
            summary=summary,
            raw_content=selftext,
            published_at=published,
            download_links=list(set(urls)),
            tags=tags,
            author=author
        )

    def _extract_threat_indicators(self, text: str) -> List[str]:
        """Extract potential threat indicators from text."""
        indicators = []

        # Look for cryptocurrency addresses
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        btc_matches = re.findall(btc_pattern, text)
        indicators.extend([f"BTC: {m}" for m in btc_matches])

        # Look for onion domains (just as indicators, not accessing them)
        onion_pattern = r'\b[a-z2-7]{16,56}\.onion\b'
        onion_matches = re.findall(onion_pattern, text)
        indicators.extend([f"Onion: {m}" for m in onion_matches])

        return indicators[:10]
