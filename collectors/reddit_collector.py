"""
Reddit Collector - Monitors cybersecurity subreddits
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class RedditCollector(BaseCollector):
    """Collects posts from cybersecurity subreddits."""

    REDDIT_API_URL = "https://www.reddit.com/r/{subreddit}/new.json"

    DEFAULT_SUBREDDITS = [
        "cybersecurity",
        "netsec",
        "Malware",
        "ThreatIntelligence",
        "redteamsec",
        "blueteamsec",
        "ComputerForensics",
        "osint",
        "hacking",
        "LocalLLaMA",
        "MachineLearning",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("Reddit", config)
        self.subreddits = self.config.get("subreddits", self.DEFAULT_SUBREDDITS)
        self.max_posts = self.config.get("max_posts_per_subreddit", 5)
        self.lookback_hours = self.config.get("lookback_hours", 24)

        # Reddit requires a custom User-Agent
        self.session.headers.update({
            "User-Agent": "CyberThreatBot/1.0 (by /u/cti-bot)"
        })

        # Reddit OAuth credentials (optional, for higher rate limits)
        self.client_id = self.config.get("reddit_client_id")
        self.client_secret = self.config.get("reddit_client_secret")

    def collect(self) -> List[Dict[str, Any]]:
        """Collect posts from configured subreddits."""
        alerts = []

        for subreddit in self.subreddits:
            try:
                posts = self._fetch_subreddit_posts(subreddit)
                for post in posts:
                    alert = self._process_post(post, subreddit)
                    if alert:
                        alerts.append(alert)
            except Exception as e:
                logger.error(f"[Reddit] Error fetching r/{subreddit}: {e}")

        logger.info(f"[Reddit] Collected {len(alerts)} posts")
        return alerts

    def _fetch_subreddit_posts(self, subreddit: str) -> List[Dict]:
        """Fetch recent posts from a subreddit."""
        url = self.REDDIT_API_URL.format(subreddit=subreddit)
        params = {
            "limit": self.max_posts,
            "t": "day"
        }

        response = self.fetch(url, params=params)
        if not response:
            return []

        try:
            data = response.json()
            posts = data.get("data", {}).get("children", [])
            return [post["data"] for post in posts]
        except Exception as e:
            logger.error(f"[Reddit] Error parsing r/{subreddit} response: {e}")
            return []

    def _process_post(self, post: Dict, subreddit: str) -> Dict[str, Any]:
        """Process a Reddit post into an alert."""
        title = post.get("title", "No Title")
        url = post.get("url", "")
        permalink = f"https://reddit.com{post.get('permalink', '')}"
        selftext = post.get("selftext", "")
        score = post.get("score", 0)
        created_utc = post.get("created_utc", 0)
        author = post.get("author", "unknown")
        num_comments = post.get("num_comments", 0)
        is_self = post.get("is_self", False)
        flair = post.get("link_flair_text", "")

        # Convert timestamp
        published = datetime.fromtimestamp(created_utc).isoformat() if created_utc else None

        # Use permalink as main URL for self-posts, external URL otherwise
        main_url = permalink if is_self else url

        # Build content
        content = selftext if selftext else title
        content = self.truncate_text(content, 1000)

        # Classify category
        category = self._classify_post(title, selftext, subreddit)

        # Estimate severity based on engagement and content
        severity = self._estimate_severity(title, score, num_comments)

        # Extract download links
        download_links = []
        if not is_self and "reddit.com" not in url:
            download_links.append(url)
        github_links = self.extract_urls(selftext)
        download_links.extend([l for l in github_links if "github.com" in l][:3])

        tags = [subreddit]
        if flair:
            tags.append(flair)

        summary = f"Posted by u/{author} in r/{subreddit}\n\n"
        if selftext:
            summary += f"{content[:400]}\n\n"
        summary += f"Score: {score} | Comments: {num_comments}"

        return self.standardize_alert(
            title=f"Reddit: {title}",
            url=main_url,
            source=f"Reddit/r/{subreddit}",
            category=category,
            severity=severity,
            summary=summary,
            raw_content=content,
            published_at=published,
            download_links=list(set(download_links)),
            tags=tags,
            author=author
        )

    def _classify_post(self, title: str, selftext: str, subreddit: str) -> str:
        """Classify post category."""
        text = (title + " " + selftext).lower()

        if subreddit in ["Malware"]:
            return "malware_analysis"
        elif subreddit in ["redteamsec", "hacking"]:
            return "red_team_tool"
        elif subreddit in ["blueteamsec", "ComputerForensics"]:
            return "dfir_tool"
        elif subreddit in ["osint"]:
            return "osint_tool"
        elif subreddit in ["LocalLLaMA", "MachineLearning"]:
            return "ai_tool"

        categories = {
            "cve": ["cve-", "vulnerability", "disclosure"],
            "exploit": ["exploit", "poc", "proof of concept"],
            "ai_tool": ["ai model", "llm", "machine learning"],
            "data_breach": ["breach", "leaked", "exposed"],
        }

        for category, keywords in categories.items():
            if any(kw in text for kw in keywords):
                return category

        return "threat_report"

    def _estimate_severity(self, title: str, score: int, num_comments: int) -> float:
        """Estimate severity based on engagement and keywords."""
        base = 5.0

        # Boost based on engagement
        if score > 1000:
            base += 1.5
        elif score > 500:
            base += 1.0
        elif score > 100:
            base += 0.5

        # Boost based on comments
        if num_comments > 100:
            base += 0.5

        # Check for critical keywords
        title_lower = title.lower()
        if any(kw in title_lower for kw in ["critical", "cve-202", "0day", "zero-day", "rce"]):
            base += 1.5

        return min(base, 10.0)
