"""
Base Collector - Abstract base class for all data collectors
"""
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Base class for all threat intelligence collectors."""

    def __init__(self, name: str, config: Dict[str, Any] = None):
        self.name = name
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })

    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect threat intelligence data.
        Must return a list of standardized alert dictionaries.
        """
        pass

    def fetch(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with error handling."""
        try:
            timeout = kwargs.pop("timeout", 30)
            if method.upper() == "GET":
                response = self.session.get(url, timeout=timeout, **kwargs)
            elif method.upper() == "POST":
                response = self.session.post(url, timeout=timeout, **kwargs)
            else:
                response = self.session.request(method, url, timeout=timeout, **kwargs)

            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"[{self.name}] Request failed for {url}: {e}")
            return None

    def standardize_alert(self, title: str, url: str, source: str, category: str = "general",
                          severity: float = 5.0, summary: str = "", raw_content: str = "",
                          published_at: str = None, download_links: List[str] = None,
                          tags: List[str] = None, author: str = None) -> Dict[str, Any]:
        """
        Create a standardized alert dictionary.
        All collectors should use this format.
        """
        hash_input = f"{title}:{url}:{source}"
        hash_id = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        severity_label = self._get_severity_label(severity)

        return {
            "title": title,
            "url": url,
            "source": source,
            "category": category,
            "severity": float(severity),
            "severity_label": severity_label,
            "summary": summary,
            "raw_content": raw_content[:5000] if raw_content else "",
            "hash_id": hash_id,
            "published_at": published_at or datetime.utcnow().isoformat(),
            "collected_at": datetime.utcnow().isoformat(),
            "download_links": download_links or [],
            "tags": tags or [],
            "author": author,
            "relevance_score": 0.0,
            "ai_analysis": "",
        }

    def _get_severity_label(self, severity: float) -> str:
        """Convert numeric severity to label."""
        if severity >= 9.0:
            return "CRITICAL"
        elif severity >= 7.0:
            return "HIGH"
        elif severity >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        return url_pattern.findall(text)

    def is_recent(self, date_str: str, hours: int = 24) -> bool:
        """Check if a date is within the lookback window."""
        try:
            date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            return date >= cutoff
        except Exception:
            return True  # If we can't parse, assume it's recent

    def truncate_text(self, text: str, max_length: int = 1000) -> str:
        """Truncate text to maximum length."""
        if not text:
            return ""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."

    def clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        clean = re.compile("<.*?>")
        return clean.sub("", text)

    def get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

    def rate_limit_delay(self, min_delay: float = 1.0):
        """Sleep to respect rate limits."""
        import time
        time.sleep(min_delay)
