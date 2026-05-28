"""
AI Summarizer - Generates human-readable summaries using Gemini API
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ThreatSummarizer:
    """
    Summarizes threat intelligence content into concise,
    human-readable summaries using Gemini API or rule-based methods.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.gemini_api_key = self.config.get("gemini_api_key")
        self.model_name = self.config.get("model", "gemini-2.0-flash")
        self.max_length = self.config.get("max_summary_length", 300)
        self.use_ai = bool(self.gemini_api_key)

    def summarize(self, alert: Dict[str, Any]) -> str:
        """
        Generate a summary for an alert.
        Uses Gemini if available, falls back to rule-based summarization.
        """
        content = self._prepare_content(alert)

        if self.use_ai:
            try:
                return self._ai_summarize(content, alert)
            except Exception as e:
                logger.error(f"Gemini summarization failed: {e}, falling back to rule-based")

        return self._rule_based_summarize(alert, content)

    def summarize_batch(self, alerts: list) -> list:
        """Summarize multiple alerts."""
        for alert in alerts:
            if not alert.get("summary") or len(alert["summary"]) < 50:
                alert["summary"] = self.summarize(alert)
        return alerts

    def _prepare_content(self, alert: Dict[str, Any]) -> str:
        """Prepare content for summarization."""
        parts = []

        if alert.get("title"):
            parts.append(f"Title: {alert['title']}")

        if alert.get("category"):
            parts.append(f"Category: {alert['category']}")

        if alert.get("severity"):
            parts.append(f"Severity: {alert['severity']}/10")

        if alert.get("raw_content"):
            content = alert["raw_content"][:4000]  # Gemini supports larger context
            parts.append(f"Content: {content}")
        elif alert.get("summary"):
            parts.append(f"Description: {alert['summary'][:2000]}")

        return "\n".join(parts)

    def _ai_summarize(self, content: str, alert: Dict[str, Any]) -> str:
        """Use Gemini to generate a summary."""
        import google.generativeai as genai

        genai.configure(api_key=self.gemini_api_key)
        model = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction="You are a cybersecurity threat intelligence analyst. Summarize threats concisely and accurately."
        )

        prompt = f"""As a cybersecurity analyst, provide a concise summary (max 3 sentences) of this threat intelligence item.

{content}

Focus on:
1. What the threat/vulnerability is
2. Who/what is affected
3. What action should be taken

Summary:"""

        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=200,
                temperature=0.3,
            )
        )

        summary = response.text.strip()
        return summary[:self.max_length]

    def _rule_based_summarize(self, alert: Dict[str, Any], content: str) -> str:
        """Generate a summary using rule-based extraction."""
        title = alert.get("title", "Unknown Threat")
        category = alert.get("category", "threat")
        severity = alert.get("severity", 5.0)

        summary_parts = []

        # Build a structured summary
        if category == "cve":
            summary_parts.append(f"Vulnerability alert: {title}")
        elif category == "exploit":
            summary_parts.append(f"Exploit available: {title}")
        elif category == "github_poc":
            summary_parts.append(f"New PoC tool: {title}")
        elif category == "data_breach":
            summary_parts.append(f"Data breach reported: {title}")
        elif category == "ransomware":
            summary_parts.append(f"Ransomware activity: {title}")
        else:
            summary_parts.append(f"{category.replace('_', ' ').title()}: {title}")

        # Add key details from content
        raw = alert.get("raw_content", "") or alert.get("summary", "")
        if raw:
            # Extract first meaningful sentence
            sentences = raw.split(".")
            for sentence in sentences[:2]:
                clean = sentence.strip()
                if len(clean) > 20:
                    summary_parts.append(clean)
                    break

        # Add severity context
        if severity >= 9:
            summary_parts.append("CRITICAL severity - immediate attention required.")
        elif severity >= 7:
            summary_parts.append("HIGH severity - assess impact promptly.")

        result = " ".join(summary_parts)
        return result[:self.max_length]

    def generate_executive_summary(self, alerts: list) -> str:
        """Generate an executive summary of multiple alerts."""
        if not alerts:
            return "No new threats detected."

        critical = [a for a in alerts if a.get("severity", 0) >= 9]
        high = [a for a in alerts if 7 <= a.get("severity", 0) < 9]
        medium = [a for a in alerts if 4 <= a.get("severity", 0) < 7]

        summary = f"""Executive Summary:

Total Alerts: {len(alerts)}
Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}

Key Items:
"""

        for alert in sorted(alerts, key=lambda x: x.get("severity", 0), reverse=True)[:5]:
            title = alert.get("title", "Unknown")
            sev = alert.get("severity_label", "MEDIUM")
            cat = alert.get("category", "general")
            summary += f"\n- [{sev}] {title} ({cat})"

        return summary
