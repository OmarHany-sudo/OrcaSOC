"""
ProjectDiscovery Collector - Nuclei templates releases and ProjectDiscovery blog.
"""
import logging
from datetime import datetime
from typing import List, Dict, Any

import feedparser

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class ProjectDiscoveryCollector(BaseCollector):
    """Collects ProjectDiscovery Nuclei template releases and security research posts."""

    RELEASES_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases"
    BLOG_FEEDS = [
        "https://projectdiscovery.io/blog/rss.xml",
        "https://projectdiscovery.io/blog/category/nuclei-templates/rss.xml",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("ProjectDiscovery", config)
        self.max_items = self.config.get("max_items", 10)
        self.github_token = self.config.get("github_token")
        if self.github_token:
            self.session.headers.update({"Authorization": f"Bearer {self.github_token}"})

    def collect(self) -> List[Dict[str, Any]]:
        alerts = []
        alerts.extend(self._collect_releases())
        alerts.extend(self._collect_blog())
        logger.info("[ProjectDiscovery] Collected %s items", len(alerts))
        return alerts[:self.max_items]

    def _collect_releases(self) -> List[Dict[str, Any]]:
        response = self.fetch(self.RELEASES_API, params={"per_page": self.max_items})
        if not response:
            return []
        try:
            releases = response.json()
        except Exception as e:
            logger.error("[ProjectDiscovery] Error parsing releases: %s", e)
            return []

        alerts = []
        for release in releases:
            title = release.get("name") or release.get("tag_name", "Nuclei Templates Release")
            body = release.get("body", "")
            url = release.get("html_url", "")
            published = release.get("published_at") or release.get("created_at")
            severity = self._estimate_severity(title + " " + body)
            tags = ["nuclei", "templates", "projectdiscovery"]
            if "kev" in body.lower():
                tags.append("kev")

            alert = self.standardize_alert(
                title=f"ProjectDiscovery: {title}",
                url=url,
                source="ProjectDiscovery",
                category="exploit",
                severity=severity,
                summary=self.truncate_text(body, 800) or title,
                raw_content=body,
                published_at=published,
                download_links=[url] if url else [],
                tags=tags,
            )
            if "kev" in body.lower():
                alert["is_kev"] = True
            alerts.append(alert)
        return alerts

    def _collect_blog(self) -> List[Dict[str, Any]]:
        alerts = []
        for feed_url in self.BLOG_FEEDS:
            try:
                parsed = feedparser.parse(feed_url)
                for entry in parsed.entries[: self.max_items]:
                    title = entry.get("title", "ProjectDiscovery Blog")
                    link = entry.get("link", "")
                    summary = self.clean_html(entry.get("summary", ""))
                    published = None
                    if entry.get("published_parsed"):
                        published = datetime(*entry.published_parsed[:6]).isoformat()
                    alert = self.standardize_alert(
                        title=f"ProjectDiscovery Blog: {title}",
                        url=link,
                        source="ProjectDiscovery Blog",
                        category="security_research",
                        severity=self._estimate_severity(title + " " + summary),
                        summary=self.truncate_text(summary, 700),
                        raw_content=summary,
                        published_at=published,
                        download_links=[link] if link else [],
                        tags=["projectdiscovery", "research"],
                    )
                    alerts.append(alert)
            except Exception as e:
                logger.error("[ProjectDiscovery] Error parsing blog feed %s: %s", feed_url, e)
        return alerts

    def _estimate_severity(self, text: str) -> float:
        text_lower = text.lower()
        if any(word in text_lower for word in ["critical", "rce", "remote code execution", "kev", "0day"]):
            return 9.0
        if any(word in text_lower for word in ["cve-", "auth bypass", "sqli", "deserialization", "xss"]):
            return 7.5
        return 6.0
