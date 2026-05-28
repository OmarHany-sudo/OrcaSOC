"""
AI Classifier - Classifies threat intelligence content using Gemini API
"""
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """
    Classifies threat intelligence alerts into categories.
    Uses both keyword-based and Gemini-powered classification.
    """

    # Category classification rules
    CATEGORY_RULES = {
        "cve": {
            "keywords": ["cve-", "vulnerability", "security advisory", "patch", "security update"],
            "weight": 1.0
        },
        "exploit": {
            "keywords": ["exploit", "proof of concept", "poc", "exploit code", "weaponized"],
            "weight": 1.0
        },
        "github_poc": {
            "keywords": ["github.com", "repository", "starred", "fork"],
            "secondary": ["poc", "exploit", "cve-", "security tool"],
            "weight": 0.9
        },
        "ai_tool": {
            "keywords": ["ai tool", "artificial intelligence", "machine learning", "llm", "gpt",
                         "neural network", "deep learning", "model"],
            "secondary": ["security", "cyber", "threat"],
            "weight": 0.8
        },
        "red_team_tool": {
            "keywords": ["red team", "redteam", "pentest", "penetration test", "offensive security"],
            "weight": 0.9
        },
        "malware_analysis": {
            "keywords": ["malware", "ransomware", "trojan", "virus", "backdoor", "spyware",
                         "reverse engineering", "sample analysis"],
            "weight": 1.0
        },
        "threat_report": {
            "keywords": ["threat report", "apt", "threat actor", "campaign", "attack campaign",
                         "threat landscape", "intelligence report"],
            "weight": 1.0
        },
        "data_breach": {
            "keywords": ["data breach", "breach", "leaked", "exposed data", "compromised",
                         "credentials exposed", "database leak"],
            "weight": 1.0
        },
        "ransomware": {
            "keywords": ["ransomware", "ransom", "encryption attack", "file encryptor"],
            "weight": 1.0
        },
        "osint_tool": {
            "keywords": ["osint", "open source intelligence", "reconnaissance", "recon tool"],
            "weight": 0.8
        },
        "dfir_tool": {
            "keywords": ["dfir", "digital forensics", "incident response", "forensic tool",
                         "memory forensics", "disk analysis"],
            "weight": 0.8
        },
        "security_research": {
            "keywords": ["research", "white paper", "academic", "study", "analysis"],
            "secondary": ["security", "cyber", "vulnerability"],
            "weight": 0.7
        },
        "ai_model": {
            "keywords": ["huggingface", "model release", "transformer", "llm", "foundation model"],
            "weight": 0.7
        },
        "prompt_injection": {
            "keywords": ["prompt injection", "jailbreak", "adversarial prompt", "llm attack",
                         "prompt attack", "instruction bypass"],
            "weight": 0.9
        },
        "jailbreak": {
            "keywords": ["jailbreak", "model bypass", "safety bypass", "alignment bypass"],
            "weight": 0.9
        },
        "dataset": {
            "keywords": ["dataset", "corpus", "training data", "benchmark"],
            "secondary": ["security", "cyber", "threat"],
            "weight": 0.6
        },
    }

    # Noise indicators - things that suggest low-value content
    NOISE_INDICATORS = [
        "hiring", "job opening", "career", "internship",
        "marketing", "promotion", "discount", "sale",
        "webinar registration", "conference ticket",
        "unrelated", "off-topic", "spam"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.gemini_api_key = self.config.get("gemini_api_key")
        self.model_name = self.config.get("model", "gemini-2.0-flash")
        self.use_ai = bool(self.gemini_api_key)

    def classify(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an alert into categories and assign relevance scores.
        """
        text = f"{alert.get('title', '')} {alert.get('summary', '')} {alert.get('raw_content', '')}"
        text_lower = text.lower()

        # Check for noise
        is_noise = self._is_noise(text_lower)
        if is_noise:
            alert["is_noise"] = True
            alert["relevance_score"] = 0.1
            alert["classification"] = {"category": "noise", "confidence": 0.9}
            return alert

        # Use Gemini for classification if enabled
        if self.use_ai:
            try:
                return self._ai_classify(alert)
            except Exception as e:
                logger.error(f"Gemini classification failed: {e}")

        # Fallback to rule-based classification
        category_scores = self._score_categories(text_lower)
        best_category = max(category_scores, key=category_scores.get)
        best_score = category_scores[best_category]
        relevance = self._calculate_relevance(alert, category_scores)

        alert["classification"] = {
            "category": best_category,
            "confidence": best_score,
            "all_scores": category_scores
        }
        alert["relevance_score"] = relevance
        alert["is_noise"] = False

        return alert

    def _ai_classify(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Use Gemini to classify the threat."""
        import google.generativeai as genai
        import json

        genai.configure(api_key=self.gemini_api_key)
        model = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction="You are a cybersecurity analyst. Classify the threat into one of the following categories: " + ", ".join(self.CATEGORY_RULES.keys())
        )

        content = f"Title: {alert.get('title')}\nDescription: {alert.get('summary', '')[:1000]}"
        prompt = f"""Classify this cybersecurity item. Return ONLY a JSON object with 'category' and 'confidence' (0-1).

{content}

JSON:"""

        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=100,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )

        try:
            result = json.loads(response.text.strip())
            category = result.get("category", "unknown")
            confidence = result.get("confidence", 0.5)

            if category not in self.CATEGORY_RULES:
                category = "unknown"

            alert["classification"] = {
                "category": category,
                "confidence": confidence
            }
            alert["relevance_score"] = self._calculate_relevance(alert, {category: confidence})
            alert["is_noise"] = False
            return alert
        except:
            raise Exception("Failed to parse Gemini classification output")

    def classify_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify a batch of alerts."""
        return [self.classify(alert) for alert in alerts]

    def _is_noise(self, text: str) -> bool:
        """Check if content is noise/low-value."""
        for indicator in self.NOISE_INDICATORS:
            if indicator in text:
                return True
        if text.count("hiring") + text.count("job") + text.count("career") >= 2:
            return True
        return False

    def _score_categories(self, text: str) -> Dict[str, float]:
        """Score each category based on keyword matches."""
        scores = {}
        for category, rules in self.CATEGORY_RULES.items():
            score = 0.0
            matched_keywords = 0
            for keyword in rules["keywords"]:
                if keyword in text:
                    matched_keywords += 1
                    score += rules["weight"]
            if "secondary" in rules:
                secondary_matches = sum(1 for kw in rules["secondary"] if kw in text)
                if secondary_matches > 0 and matched_keywords > 0:
                    score += secondary_matches * rules["weight"] * 0.5
            if matched_keywords > 0:
                scores[category] = min(score / len(rules["keywords"]) + matched_keywords * 0.1, 1.0)
            else:
                scores[category] = 0.0
        if not any(scores.values()):
            scores["unknown"] = 1.0
        return scores

    def _calculate_relevance(self, alert: Dict[str, Any], category_scores: Dict[str, float]) -> float:
        """Calculate overall relevance score for an alert."""
        relevance = 0.5
        best_score = max(category_scores.values()) if category_scores else 0
        relevance += best_score * 0.3
        severity = alert.get("severity", 5.0)
        relevance += (severity / 10.0) * 0.2
        source = alert.get("source", "")
        source_boosts = {"NVD": 0.15, "Exploit-DB": 0.15, "GitHub": 0.1, "HaveIBeenPwned": 0.15, "Ransomware.live": 0.1}
        relevance += source_boosts.get(source, 0.05)
        if alert.get("download_links"):
            relevance += 0.1
        return min(relevance, 1.0)

    def is_valuable(self, alert: Dict[str, Any], threshold: float = 0.4) -> bool:
        """Check if an alert is valuable enough to keep."""
        if alert.get("is_noise", False):
            return False
        relevance = alert.get("relevance_score", 0)
        severity = alert.get("severity", 0)
        if severity >= 8.0:
            return True
        return relevance >= threshold
