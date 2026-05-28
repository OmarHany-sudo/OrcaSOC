"""
AI Threat Analyst - Generates AI-powered threat analysis using Gemini API
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class AIThreatAnalyst:
    """
    Uses Gemini API to generate human-readable threat analysis,
    impact assessments, and actionable recommendations.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.gemini_api_key = self.config.get("gemini_api_key")
        self.model_name = self.config.get("model", "gemini-2.0-flash")
        self.use_ai = bool(self.gemini_api_key)

    def analyze(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Gemini analysis for an alert.
        Returns updated alert with AI analysis.
        """
        if self.use_ai:
            try:
                analysis = self._ai_analyze(alert)
                alert["ai_analysis"] = analysis
                return alert
            except Exception as e:
                logger.error(f"Gemini analysis failed: {e}")

        # Fallback to rule-based analysis
        analysis = self._rule_based_analysis(alert)
        alert["ai_analysis"] = analysis
        return alert

    def analyze_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze a batch of alerts."""
        for alert in alerts:
            self.analyze(alert)
        return alerts

    def _ai_analyze(self, alert: Dict[str, Any]) -> str:
        """Use Gemini to generate threat analysis."""
        import google.generativeai as genai

        genai.configure(api_key=self.gemini_api_key)
        model = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction="You are a senior cybersecurity threat analyst. Provide concise, actionable threat assessments."
        )

        # Build context
        context = self._build_analysis_context(alert)

        prompt = f"""As a senior cybersecurity threat analyst, analyze this threat intelligence item and explain:

1. WHY this matters (threat significance)
2. WHO should care (target audience)
3. WHAT to do about it (actionable recommendations)
4. RISK LEVEL (assessed risk)

Be concise (max 200 words). Use professional security terminology.

{context}

Analysis:"""

        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=400,
                temperature=0.3,
            )
        )

        return response.text.strip()

    def _rule_based_analysis(self, alert: Dict[str, Any]) -> str:
        """Generate analysis using rules when AI is unavailable."""
        parts = []

        category = alert.get("category", "unknown")
        severity = alert.get("severity", 5.0)
        severity_label = alert.get("severity_label", "MEDIUM")

        # Why it matters
        parts.append("<b>Why this matters:</b>")

        if category == "cve":
            parts.append("- New vulnerability disclosure may affect system security")
            if severity >= 9:
                parts.append("- Critical severity requires immediate patching")
            if "github" in str(alert.get("download_links", "")).lower():
                parts.append("- Public PoC/exploit available increases risk")
        elif category == "exploit":
            parts.append("- Public exploit code enables attacks")
            parts.append("- Threat actors may weaponize quickly")
        elif category == "github_poc":
            parts.append("- New security tool or PoC available")
            parts.append("- May be useful for defense or research")
        elif category == "ransomware":
            parts.append("- Ransomware activity indicates active threat")
            parts.append("- Organizations should verify backups and detection")
        elif category == "data_breach":
            parts.append("- Data exposure may compromise credentials")
            parts.append("- Affected users should change passwords")
        elif category == "ai_tool":
            parts.append("- AI security tool that may enhance capabilities")
        else:
            parts.append("- New threat intelligence item requires review")

        # Risk assessment
        parts.append(f"\n<b>Risk Assessment:</b> {severity_label} ({severity}/10)")

        if severity >= 9:
            parts.append("- Immediate action recommended")
        elif severity >= 7:
            parts.append("- Assess impact and plan response")
        else:
            parts.append("- Monitor and review as needed")

        return "\n".join(parts)

    def _build_analysis_context(self, alert: Dict[str, Any]) -> str:
        """Build context string for AI analysis."""
        parts = []

        if alert.get("title"):
            parts.append(f"Title: {alert['title']}")

        if alert.get("category"):
            parts.append(f"Category: {alert['category']}")

        if alert.get("severity"):
            parts.append(f"Severity: {alert['severity']}/10 ({alert.get('severity_label', '')})")

        if alert.get("source"):
            parts.append(f"Source: {alert['source']}")

        if alert.get("summary"):
            parts.append(f"Description: {alert['summary'][:1000]}")

        if alert.get("download_links"):
            parts.append(f"Resources: {len(alert['download_links'])} links available")

        return "\n".join(parts)

    def generate_why_it_matters(self, alert: Dict[str, Any]) -> str:
        """
        Generate 'Why this matters' explanation.
        """
        if self.use_ai:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_api_key)
                model = genai.GenerativeModel(
                    model_name=self.model_name,
                    system_instruction="You are a cybersecurity analyst explaining threat significance."
                )

                prompt = f"""Explain in 2-3 bullet points why this cybersecurity item matters:

Title: {alert.get('title', '')}
Category: {alert.get('category', '')}
Severity: {alert.get('severity', 5)}/10
Description: {alert.get('summary', '')[:500]}

Respond ONLY with bullet points. Be specific and actionable."""

                response = model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        max_output_tokens=200,
                        temperature=0.3,
                    )
                )

                return response.text.strip()
            except Exception as e:
                logger.error(f"Gemini 'why it matters' failed: {e}")

        # Fallback
        return self._generate_why_fallback(alert)

    def _generate_why_fallback(self, alert: Dict[str, Any]) -> str:
        """Fallback why-it-matters generator."""
        reasons = []

        category = alert.get("category", "")
        severity = alert.get("severity", 5.0)

        if category == "cve" and severity >= 9:
            reasons.append("- Critical vulnerability with potential for widespread exploitation")
        elif category == "cve":
            reasons.append("- New vulnerability that may require patching")

        if alert.get("download_links"):
            reasons.append("- Public exploit/tools available lowers barrier for attackers")

        if category == "ransomware":
            reasons.append("- Active ransomware operation threatens data availability")

        if category == "data_breach":
            reasons.append("- Exposed data may enable further attacks or identity theft")

        if severity >= 8:
            reasons.append("- High severity indicates significant potential impact")

        if not reasons:
            reasons.append("- New threat intelligence requires security team awareness")

        return "\n".join(reasons)

    def generate_action_items(self, alert: Dict[str, Any]) -> List[str]:
        """Generate recommended action items."""
        actions = []
        category = alert.get("category", "")
        severity = alert.get("severity", 5.0)

        if category == "cve":
            actions.append("Check if affected systems are in your environment")
            if severity >= 7:
                actions.append("Prioritize patching or apply mitigations")
            actions.append("Monitor vendor advisories for updates")

        elif category == "exploit":
            actions.append("Assess if the exploit affects your systems")
            actions.append("Update detection rules if applicable")
            actions.append("Consider network segmentation")

        elif category == "ransomware":
            actions.append("Verify backup integrity and availability")
            actions.append("Review detection capabilities")
            actions.append("Alert relevant stakeholders")

        elif category == "data_breach":
            actions.append("Check if your organization/accounts are affected")
            actions.append("Reset credentials if necessary")
            actions.append("Monitor for suspicious activity")

        elif severity >= 8:
            actions.append("Immediate assessment recommended")
            actions.append("Consider activating incident response procedures")

        if not actions:
            actions.append("Review and assess relevance to your environment")
            actions.append("Share with relevant security teams")

        return actions
