"""
Relevance Engine - Filters and ranks content by relevance using Gemini API
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class RelevanceEngine:
    """
    Analyzes and scores threat intelligence content for relevance.
    Helps filter noise and prioritize important alerts.
    """

    # High-value keywords that boost relevance
    HIGH_VALUE_KEYWORDS = [
        # Critical vulnerabilities
        "remote code execution", "rce", "command injection", "sql injection",
        "authentication bypass", "privilege escalation", "0day", "zero-day",
        "wormable", "actively exploited", "in the wild",

        # High-impact breaches
        "data breach", "millions affected", "pii exposed", "credentials leaked",
        "ransomware attack", "critical infrastructure",

        # AI security
        "prompt injection", "jailbreak", "ai safety", "model bypass",
        "adversarial attack", "llm vulnerability",

        # Important tools
        "exploit released", "poc published", "cve-2026",

        # Threat actors
        "apt", "state-sponsored", "ransomware group",
    ]

    # Low-value indicators
    LOW_VALUE_INDICATORS = [
        "sponsored", "advertisement", "webinar", "join us",
        "register now", "free ebook", "whitepaper download",
        "marketing", "promotional",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.min_relevance = self.config.get("min_relevance", 0.3)
        self.gemini_api_key = self.config.get("gemini_api_key")
        self.model_name = self.config.get("model", "gemini-2.0-flash")
        self.use_ai = bool(self.gemini_api_key)

    def score(self, alert: Dict[str, Any]) -> float:
        """
        Calculate a relevance score for an alert.
        """
        # If AI is enabled, we could potentially use Gemini for scoring, 
        # but the rule-based approach is faster for initial scoring.
        scores = []

        # Content relevance
        content_score = self._score_content(alert)
        scores.append(content_score * 0.3)

        # Source credibility
        source_score = self._score_source(alert)
        scores.append(source_score * 0.2)

        # Severity weight
        severity_score = self._score_severity(alert)
        scores.append(severity_score * 0.25)

        # Timeliness
        timeliness_score = self._score_timeliness(alert)
        scores.append(timeliness_score * 0.15)

        # Actionability
        action_score = self._score_actionability(alert)
        scores.append(action_score * 0.1)

        total_score = sum(scores)
        return min(total_score, 1.0)

    def filter_alerts(self, alerts: List[Dict[str, Any]], threshold: float = None) -> List[Dict[str, Any]]:
        """Filter alerts by relevance threshold."""
        threshold = threshold or self.min_relevance

        scored_alerts = []
        for alert in alerts:
            score = self.score(alert)
            alert["relevance_score"] = score
            if score >= threshold:
                scored_alerts.append(alert)

        # Sort by relevance score
        scored_alerts.sort(key=lambda x: x["relevance_score"], reverse=True)
        return scored_alerts

    def rank_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank alerts by combined relevance and severity."""
        for alert in alerts:
            relevance = alert.get("relevance_score", self.score(alert))
            severity = alert.get("severity", 5.0) / 10.0
            alert["rank_score"] = (relevance * 0.6) + (severity * 0.4)
        return sorted(alerts, key=lambda x: x["rank_score"], reverse=True)

    def _score_content(self, alert: Dict[str, Any]) -> float:
        """Score based on content quality and keywords."""
        text = f"{alert.get('title', '')} {alert.get('summary', '')} {alert.get('raw_content', '')}"
        text_lower = text.lower()
        score = 0.5
        high_value_matches = sum(1 for kw in self.HIGH_VALUE_KEYWORDS if kw in text_lower)
        score += min(high_value_matches * 0.08, 0.4)
        low_value_matches = sum(1 for ind in self.LOW_VALUE_INDICATORS if ind in text_lower)
        score -= min(low_value_matches * 0.1, 0.3)
        if 200 <= len(text) <= 4000:
            score += 0.1
        return max(score, 0.0)

    def _score_source(self, alert: Dict[str, Any]) -> float:
        """Score based on source credibility."""
        source_scores = {"NVD": 1.0, "Exploit-DB": 0.95, "GitHub": 0.85, "HaveIBeenPwned": 0.95, "Ransomware.live": 0.9, "HuggingFace": 0.8, "Reddit": 0.6, "Telegram": 0.7}
        return source_scores.get(alert.get("source", ""), 0.5)

    def _score_severity(self, alert: Dict[str, Any]) -> float:
        """Score based on severity."""
        return alert.get("severity", 5.0) / 10.0

    def _score_timeliness(self, alert: Dict[str, Any]) -> float:
        """Score based on how recent the alert is."""
        from datetime import datetime, timezone
        published = alert.get("published_at")
        if not published:
            return 0.5
        try:
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            hours_old = (datetime.now(timezone.utc) - pub_date).total_seconds() / 3600
            if hours_old < 1: return 1.0
            elif hours_old < 6: return 0.9
            elif hours_old < 24: return 0.8
            elif hours_old < 72: return 0.6
            else: return 0.4
        except:
            return 0.5

    def _score_actionability(self, alert: Dict[str, Any]) -> float:
        """Score based on how actionable the alert is."""
        score = 0.5
        if alert.get("download_links"): score += 0.2
        title = alert.get("title", "").lower()
        if "cve-" in title: score += 0.15
        if any(kw in title for kw in ["exploit", "poc", "tool"]): score += 0.1
        if alert.get("severity", 0) >= 8: score += 0.15
        return min(score, 1.0)
