"""
Threat Ranker - Ranks and prioritizes threats
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ThreatRanker:
    """
    Ranks and prioritizes threat intelligence alerts
    based on multiple weighted factors.
    """

    # Category priority weights (higher = more important)
    CATEGORY_WEIGHTS = {
        "cve": 0.9,
        "exploit": 1.0,
        "github_poc": 0.8,
        "ransomware": 0.95,
        "data_breach": 0.85,
        "ai_tool": 0.6,
        "red_team_tool": 0.7,
        "malware_analysis": 0.8,
        "threat_report": 0.75,
        "osint_tool": 0.5,
        "dfir_tool": 0.5,
        "security_research": 0.6,
        "ai_model": 0.5,
        "prompt_injection": 0.85,
        "jailbreak": 0.8,
        "dataset": 0.4,
    }

    # Source credibility weights
    SOURCE_WEIGHTS = {
        "NVD": 1.0,
        "Exploit-DB": 0.95,
        "HaveIBeenPwned": 0.95,
        "Ransomware.live": 0.9,
        "GitHub": 0.85,
        "HuggingFace": 0.7,
        "Reddit": 0.5,
        "Telegram": 0.6,
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_alerts = self.config.get("max_alerts_per_run", 10)

    def rank(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Rank alerts by priority.
        Returns alerts sorted by rank score (highest first).
        """
        for alert in alerts:
            score = self._calculate_rank_score(alert)
            alert["rank_score"] = score

        # Sort by rank score descending
        ranked = sorted(
            alerts,
            key=lambda x: (x.get("threat_score", 0), x.get("rank_score", 0)),
            reverse=True,
        )

        # Log ranking summary
        if ranked:
            logger.info(
                "Top ranked alert: %s (threat_score: %s, rank_score: %.2f)",
                ranked[0].get("title", "N/A"),
                ranked[0].get("threat_score", 0),
                ranked[0].get("rank_score", 0),
            )

        return ranked

    def get_top_alerts(self, alerts: List[Dict[str, Any]], n: int = None) -> List[Dict[str, Any]]:
        """Get top N alerts by rank."""
        n = n or self.max_alerts
        ranked = self.rank(alerts)
        return ranked[:n]

    def _calculate_rank_score(self, alert: Dict[str, Any]) -> float:
        """Calculate a composite rank score for an alert."""
        scores = []

        if alert.get("threat_score") is not None:
            scores.append((float(alert.get("threat_score", 0)) / 100.0) * 0.35)

        # Severity score (0-10, normalized to 0-1)
        severity = alert.get("severity", 5.0)
        scores.append((severity / 10.0) * 0.20)

        # Category weight
        category = alert.get("category", "general")
        cat_weight = self.CATEGORY_WEIGHTS.get(category, 0.5)
        scores.append(cat_weight * 0.15)

        # Source credibility
        source = alert.get("source", "")
        src_weight = self.SOURCE_WEIGHTS.get(source, 0.5)
        scores.append(src_weight * 0.10)

        # Relevance score (already 0-1)
        relevance = alert.get("relevance_score", 0.5)
        scores.append(relevance * 0.10)

        # Has exploit/PoC available
        has_poc = bool(alert.get("download_links"))
        scores.append(0.05 if has_poc else 0.0)

        # Timeliness bonus
        timeliness = self._calculate_timeliness(alert)
        scores.append(timeliness * 0.05)

        total_score = sum(scores)
        return round(total_score, 3)

    def _calculate_timeliness(self, alert: Dict[str, Any]) -> float:
        """Calculate timeliness score."""
        from datetime import datetime, timezone

        published = alert.get("published_at")
        if not published:
            return 0.5

        try:
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if pub_date.tzinfo is None:
                pub_date = pub_date.replace(tzinfo=timezone.utc)
            hours_old = (datetime.now(timezone.utc) - pub_date).total_seconds() / 3600

            if hours_old < 1:
                return 1.0
            elif hours_old < 6:
                return 0.9
            elif hours_old < 24:
                return 0.8
            elif hours_old < 72:
                return 0.6
            elif hours_old < 168:  # 1 week
                return 0.4
            else:
                return 0.2
        except Exception:
            return 0.5

    def get_priority_label(self, alert: Dict[str, Any]) -> str:
        """Get a priority label for an alert."""
        score = alert.get("rank_score", 0)

        if score >= 0.8:
            return "🔴 CRITICAL PRIORITY"
        elif score >= 0.6:
            return "🟠 HIGH PRIORITY"
        elif score >= 0.4:
            return "🟡 MEDIUM PRIORITY"
        else:
            return "🟢 LOW PRIORITY"

    def generate_ranking_report(self, alerts: List[Dict[str, Any]]) -> str:
        """Generate a text report of ranked alerts."""
        if not alerts:
            return "No alerts to rank."

        ranked = self.rank(alerts)
        report = f"📊 <b>Threat Ranking Report</b>\n"
        report += f"Total Alerts: {len(ranked)}\n\n"

        for i, alert in enumerate(ranked[:10], 1):
            priority = self.get_priority_label(alert)
            title = alert.get("title", "Unknown")[:60]
            score = alert.get("rank_score", 0)
            category = alert.get("category", "?")

            report += f"{i}. {priority}\n"
            report += f"   {title}\n"
            report += f"   Score: {score:.2f} | Category: {category}\n\n"

        return report
