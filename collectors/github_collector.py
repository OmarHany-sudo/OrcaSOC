"""
GitHub Collector - Monitors GitHub for security PoCs and tools
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class GitHubCollector(BaseCollector):
    """Collects security-related repositories from GitHub."""

    GITHUB_API_URL = "https://api.github.com"

    SECURITY_QUERIES = [
        "CVE-2026",
        "exploit POC",
        "proof of concept",
        "red team tool",
        "malware analysis",
        "threat intelligence",
        "OSINT tool",
        "forensic tool",
        "vulnerability scanner",
        "pentesting tool",
        "AI security",
        "prompt injection",
    ]

    SECURITY_KEYWORDS = [
        "security", "exploit", "vulnerability", "cve",
        "malware", "forensic", "osint", "threat",
        "pentest", "redteam", "blueteam", "dfir",
        "ai security", "prompt injection", "jailbreak"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("GitHub", config)
        self.token = self.config.get("github_token")
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_results = self.config.get("max_results", 20)
        self.queries = self.config.get("queries", self.SECURITY_QUERIES)

        if self.token:
            self.session.headers.update({"Authorization": f"token {self.token}"})

    def collect(self) -> List[Dict[str, Any]]:
        """Collect security repositories from GitHub."""
        alerts = []

        for query in self.queries:
            try:
                repos = self._search_repositories(query)
                for repo in repos:
                    alert = self._process_repository(repo)
                    if alert and alert["hash_id"] not in [a["hash_id"] for a in alerts]:
                        alerts.append(alert)
            except Exception as e:
                logger.error(f"[GitHub] Error searching for '{query}': {e}")

        logger.info(f"[GitHub] Collected {len(alerts)} repositories")
        return alerts[:self.max_results]

    def _search_repositories(self, query: str) -> List[Dict]:
        """Search GitHub repositories."""
        since_date = (datetime.utcnow() - timedelta(hours=self.lookback_hours)).strftime("%Y-%m-%d")
        search_query = f"{query} created:>{since_date} sort:updated"

        url = f"{self.GITHUB_API_URL}/search/repositories"
        params = {
            "q": search_query,
            "sort": "updated",
            "order": "desc",
            "per_page": 10
        }

        response = self.fetch(url, params=params)
        if not response:
            return []

        try:
            data = response.json()
            return data.get("items", [])
        except Exception as e:
            logger.error(f"[GitHub] Error parsing search results: {e}")
            return []

    def _process_repository(self, repo: Dict) -> Dict[str, Any]:
        """Process a GitHub repository into an alert."""
        name = repo.get("full_name", "Unknown")
        url = repo.get("html_url", "")
        description = repo.get("description", "No description") or "No description"
        language = repo.get("language", "")
        stars = repo.get("stargazers_count", 0)
        created_at = repo.get("created_at", datetime.utcnow().isoformat())
        topics = repo.get("topics", [])

        # Classify category
        category = self._classify_repo(description, topics, name)

        # Estimate severity based on keywords
        severity = self._estimate_severity(description + " " + " ".join(topics))

        # Boost severity for high-star repos
        if stars > 100:
            severity = min(severity * 1.1, 10.0)

        # Build summary
        summary = f"{description}\n\n"
        summary += f"Language: {language}\n"
        summary += f"Stars: {stars}\n"
        if topics:
            summary += f"Topics: {', '.join(topics[:8])}\n"

        # Download links
        download_links = [url]
        if repo.get("homepage"):
            download_links.append(repo["homepage"])

        # Add releases URL
        releases_url = f"{url}/releases"
        download_links.append(releases_url)

        return self.standardize_alert(
            title=f"GitHub: {name}",
            url=url,
            source="GitHub",
            category=category,
            severity=severity,
            summary=summary,
            raw_content=description,
            published_at=created_at,
            download_links=download_links,
            tags=topics + [language] if language else topics,
            author=repo.get("owner", {}).get("login", "")
        )

    def _classify_repo(self, description: str, topics: List[str], name: str) -> str:
        """Classify repository category."""
        text = (description + " " + " ".join(topics) + " " + name).lower()

        categories = {
            "github_poc": ["poc", "proof of concept", "cve-20", "exploit", "vulnerability"],
            "ai_tool": ["ai ", "artificial intelligence", "llm", "gpt", "machine learning", "ml"],
            "red_team_tool": ["red team", "redteam", "pentest", "penetration test", "offensive"],
            "malware_analysis": ["malware", "reverse engineering", "sandbox", "yara"],
            "osint_tool": ["osint", "intelligence", "recon", "reconnaissance"],
            "dfir_tool": ["forensic", "dfir", "incident response", "blue team"],
            "threat_report": ["threat", "apt", "campaign", "malware"],
        }

        for category, keywords in categories.items():
            if any(kw in text for kw in keywords):
                return category

        return "github_poc"

    def _estimate_severity(self, text: str) -> float:
        """Estimate severity based on repository content."""
        text_lower = text.lower()

        critical_keywords = ["0day", "zero-day", "critical vulnerability", "rce", "remote code"]
        high_keywords = ["exploit", "cve-20", "vulnerability", "malware", "backdoor"]

        if any(kw in text_lower for kw in critical_keywords):
            return 8.5
        elif any(kw in text_lower for kw in high_keywords):
            return 7.0

        return 5.5
