"""
HuggingFace Collector - Monitors for security-related AI models
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class HuggingFaceCollector(BaseCollector):
    """Collects security-related AI models from HuggingFace."""

    HF_API_URL = "https://huggingface.co/api/models"

    SECURITY_TAGS = [
        "security",
        "malware-detection",
        "vulnerability-detection",
        "threat-intelligence",
        "cybersecurity",
        "pentest",
        "ai-security",
        "prompt-injection",
        "jailbreak",
    ]

    SECURITY_KEYWORDS = [
        "security", "cyber", "threat", "vulnerability", "malware",
        "pentest", "forensic", "osint", "ai safety", "jailbreak",
        "prompt injection", "adversarial", "red team"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("HuggingFace", config)
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_results = self.config.get("max_results", 15)
        self.min_downloads = self.config.get("min_downloads", 0)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect security-related models from HuggingFace."""
        alerts = []

        for tag in self.SECURITY_TAGS:
            try:
                models = self._fetch_models_by_tag(tag)
                for model in models:
                    alert = self._process_model(model)
                    if alert and alert["hash_id"] not in [a["hash_id"] for a in alerts]:
                        alerts.append(alert)
            except Exception as e:
                logger.error(f"[HuggingFace] Error fetching tag '{tag}': {e}")

        # Also search by keyword
        try:
            keyword_models = self._search_by_keywords()
            for model in keyword_models:
                alert = self._process_model(model)
                if alert and alert["hash_id"] not in [a["hash_id"] for a in alerts]:
                    alerts.append(alert)
        except Exception as e:
            logger.error(f"[HuggingFace] Error searching by keywords: {e}")

        logger.info(f"[HuggingFace] Collected {len(alerts)} models")
        return alerts[:self.max_results]

    def _fetch_models_by_tag(self, tag: str) -> List[Dict]:
        """Fetch models filtered by tag."""
        params = {
            "filter": tag,
            "sort": "lastModified",
            "direction": -1,
            "limit": 10,
        }

        response = self.fetch(self.HF_API_URL, params=params)
        if not response:
            return []

        try:
            models = response.json()
            # Filter by recent date
            since = (datetime.utcnow() - timedelta(hours=self.lookback_hours)).isoformat()
            return [m for m in models if m.get("lastModified", "") > since]
        except Exception as e:
            logger.error(f"[HuggingFace] Error parsing models: {e}")
            return []

    def _search_by_keywords(self) -> List[Dict]:
        """Search models using security keywords."""
        all_models = []
        search_url = "https://huggingface.co/api/models"

        for keyword in ["security", "cyber", "malware"]:
            params = {
                "search": keyword,
                "sort": "lastModified",
                "direction": -1,
                "limit": 5,
            }
            response = self.fetch(search_url, params=params)
            if response:
                try:
                    models = response.json()
                    all_models.extend(models)
                except Exception:
                    pass

        return all_models

    def _process_model(self, model: Dict) -> Dict[str, Any]:
        """Process a HuggingFace model into an alert."""
        model_id = model.get("id", "")
        url = f"https://huggingface.co/{model_id}"

        # Get model info
        downloads = model.get("downloads", 0)
        likes = model.get("likes", 0)
        tags = model.get("tags", [])
        pipeline_tag = model.get("pipeline_tag", "")
        last_modified = model.get("lastModified", datetime.utcnow().isoformat())

        # Fetch README for description
        description = self._fetch_readme(model_id)

        # Classify category
        category = self._classify_model(tags, model_id, description)

        # Estimate severity/relevance
        severity = min(5.0 + (likes / 100) + (downloads / 1000), 8.0)

        # Build summary
        summary = f"Model: {model_id}\n\n"
        if description:
            summary += f"{description[:300]}\n\n"
        summary += f"Downloads: {downloads}\n"
        summary += f"Likes: {likes}\n"
        if pipeline_tag:
            summary += f"Pipeline: {pipeline_tag}\n"
        summary += f"Tags: {', '.join(tags[:8])}"

        # Download links
        download_links = [url]
        if pipeline_tag:
            download_links.append(f"{url}/tree/main")

        return self.standardize_alert(
            title=f"HuggingFace: {model_id}",
            url=url,
            source="HuggingFace",
            category=category,
            severity=severity,
            summary=summary,
            raw_content=description,
            published_at=last_modified,
            download_links=download_links,
            tags=tags,
        )

    def _fetch_readme(self, model_id: str) -> str:
        """Fetch README content for a model."""
        readme_url = f"https://huggingface.co/{model_id}/raw/main/README.md"
        try:
            response = self.fetch(readme_url)
            if response:
                return response.text[:2000]
        except Exception:
            pass
        return ""

    def _classify_model(self, tags: List[str], model_id: str, description: str) -> str:
        """Classify the model category."""
        text = (" ".join(tags) + " " + model_id + " " + description).lower()

        if any(t in text for t in ["prompt-injection", "prompt injection", "jailbreak"]):
            return "prompt_injection"
        if any(t in text for t in ["malware", "virus", "trojan"]):
            return "malware_analysis"
        if any(t in text for t in ["vulnerability", "cve", "exploit"]):
            return "cve"
        if any(t in text for t in ["security", "cyber", "threat"]):
            return "ai_tool"

        return "ai_model"
