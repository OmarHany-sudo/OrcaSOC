"""
RSS Collector - Aggregates security news from RSS feeds
"""
import logging
import re
from datetime import datetime
from typing import List, Dict, Any

import feedparser

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class RSSCollector(BaseCollector):
    """Collects threat intelligence from security RSS feeds."""

    DEFAULT_FEEDS = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://threatpost.com/feed/",
        "https://www.darkreading.com/rss.xml",
        "https://krebsonsecurity.com/feed/",
        "https://www.schneier.com/blog/atom.xml",
        "https://blog.talosintelligence.com/feeds/posts/default",
        "https://research.checkpoint.com/feed/",
        "https://www.wired.com/category/security/feed/",
        "https://www.securityweek.com/feed/",
        "https://thehackernews.com/news-sitemap.xml",
    ]

    def __init__(self, feeds: List[str] = None, config: Dict[str, Any] = None):
        super().__init__("RSS", config)
        self.feeds = feeds or self.DEFAULT_FEEDS
        self.max_items = self.config.get("max_items_per_feed", 10)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect articles from all RSS feeds."""
        alerts = []

        for feed_url in self.feeds:
            try:
                feed_alerts = self._parse_feed(feed_url)
                alerts.extend(feed_alerts)
                logger.info(f"[RSS] Collected {len(feed_alerts)} items from {feed_url}")
            except Exception as e:
                logger.error(f"[RSS] Error parsing feed {feed_url}: {e}")

        return alerts

    def _parse_feed(self, feed_url: str) -> List[Dict[str, Any]]:
        """Parse a single RSS feed."""
        alerts = []

        try:
            parsed = feedparser.parse(feed_url)
        except Exception as e:
            logger.error(f"[RSS] Failed to parse {feed_url}: {e}")
            return []

        if not parsed.entries:
            return []

        for entry in parsed.entries[:self.max_items]:
            try:
                alert = self._process_entry(entry, feed_url)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"[RSS] Error processing entry from {feed_url}: {e}")

        return alerts

    def _process_entry(self, entry, feed_url: str) -> Dict[str, Any]:
        """Process a single RSS entry into a standardized alert."""
        title = entry.get("title", "No Title").strip()
        link = entry.get("link", "")

        if not link:
            return None

        # Extract summary
        summary = ""
        if "summary" in entry:
            summary = self.clean_html(entry.summary)
        elif "description" in entry:
            summary = self.clean_html(entry.description)

        # Truncate summary
        summary = self.truncate_text(summary, 500)

        # Get published date
        published = None
        if "published_parsed" in entry and entry.published_parsed:
            published = datetime(*entry.published_parsed[:6]).isoformat()
        elif "updated_parsed" in entry and entry.updated_parsed:
            published = datetime(*entry.updated_parsed[:6]).isoformat()

        # Extract tags/categories
        tags = []
        if "tags" in entry:
            tags = [tag.term for tag in entry.tags if hasattr(tag, "term")]

        # Determine category based on content
        category = self._classify_category(title + " " + summary, tags)

        # Estimate severity based on keywords
        severity = self._estimate_severity(title + " " + summary)

        # Extract download links from content
        download_links = self._extract_download_links(summary)

        return self.standardize_alert(
            title=title,
            url=link,
            source=self.get_domain(feed_url),
            category=category,
            severity=severity,
            summary=summary,
            raw_content=summary,
            published_at=published,
            download_links=download_links,
            tags=tags
        )

    def _classify_category(self, text: str, tags: List[str]) -> str:
        """Classify the article category based on content."""
        text_lower = text.lower()
        tags_lower = [t.lower() for t in tags]

        categories = {
            "cve": ["cve-", "vulnerability", "cve ", "patch", "security update"],
            "exploit": ["exploit", "proof of concept", "poc", "zero-day", "0day"],
            "ransomware": ["ransomware", "ransom", "encryption attack"],
            "ai_tool": ["ai tool", "artificial intelligence", "machine learning", "ml model"],
            "data_breach": ["data breach", "leaked", "breach", "exposed data", "compromised"],
            "threat_report": ["threat report", "apt", "threat actor", "campaign", "attack"],
            "malware_analysis": ["malware", "trojan", "ransomware", "backdoor", "spyware"],
        }

        for category, keywords in categories.items():
            if any(kw in text_lower for kw in keywords) or any(kw in tags_lower for kw in keywords):
                return category

        return "threat_report"

    def _estimate_severity(self, text: str) -> float:
        """Estimate severity based on keywords in text."""
        text_lower = text.lower()

        critical_keywords = ["critical", "cve-202", "zero-day", "0day", "rce",
                             "remote code execution", "wormable", "actively exploited"]
        high_keywords = ["high severity", "important", "exploit available", "poc",
                         "privilege escalation", "authentication bypass"]

        if any(kw in text_lower for kw in critical_keywords):
            return 9.5
        elif any(kw in text_lower for kw in high_keywords):
            return 7.5
        elif "medium" in text_lower:
            return 5.5

        return 5.0

    def _extract_download_links(self, text: str) -> List[str]:
        """Extract potential download links from text."""
        links = []
        github_urls = re.findall(r'https?://github\.com/[^\s<>"\')]+', text)
        links.extend(github_urls)
        return links[:5]
