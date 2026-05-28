"""
Duplicate Detector - Detects and filters duplicate content
"""
import hashlib
import logging
from typing import Dict, Any, List, Tuple

from rapidfuzz import fuzz

logger = logging.getLogger(__name__)


class DuplicateDetector:
    """
    Detects duplicate or near-duplicate threat intelligence alerts.
    Uses multiple techniques: exact hash matching, fuzzy text matching,
    and semantic similarity via embeddings.
    """

    def __init__(self, embeddings_manager=None, config: Dict[str, Any] = None):
        self.config = config or {}
        self.embeddings = embeddings_manager
        self.similarity_threshold = self.config.get("similarity_threshold", 0.85)
        self.fuzzy_threshold = self.config.get("fuzzy_threshold", 85)

        # In-memory cache for current batch
        self._text_cache = {}

    def is_duplicate(self, alert: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Check if an alert is a duplicate.
        Returns (is_duplicate, similarity_score).
        """
        # Check hash-based duplicate
        hash_id = alert.get("hash_id", "")
        if hash_id and self._hash_exists(hash_id):
            return True, 1.0

        # Check text similarity
        text = self._get_alert_text(alert)
        is_dup, similarity = self._check_text_similarity(text)
        if is_dup:
            return True, similarity

        # Check embedding similarity if available
        if self.embeddings:
            try:
                is_dup, emb_similarity = self.embeddings.is_duplicate(text, self.similarity_threshold)
                if is_dup:
                    return True, emb_similarity
            except Exception as e:
                logger.error(f"Embedding duplicate check failed: {e}")

        return False, 0.0

    def filter_duplicates(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out duplicates from a list of alerts.
        Keeps the highest severity version of duplicates.
        """
        unique_alerts = []
        duplicates_removed = 0

        for alert in alerts:
    is_dup, similarity = self.is_duplicate(alert)

    if is_dup:
        duplicates_removed += 1

        # Check if this is a higher-severity duplicate
        existing = self._find_existing_similar(alert)

        if existing and alert.get("severity", 0) > existing.get("severity", 0):

            # Replace with higher severity version
            matching_idx = next(
                (
                    i for i, item in enumerate(unique_alerts)
                    if item.get("hash_id") == existing.get("hash_id")
                ),
                None
            )

            if matching_idx is not None:
                unique_alerts[matching_idx] = alert

        continue

    unique_alerts.append(alert)

    # Cache the alert text
    self._cache_alert(alert)

        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate alerts")

        return unique_alerts

    def find_similar_alerts(self, alert: Dict[str, Any],
                            alert_pool: List[Dict[str, Any]],
                            threshold: float = None) -> List[Dict[str, Any]]:
        """Find similar alerts in a pool."""
        threshold = threshold or self.similarity_threshold
        text = self._get_alert_text(alert)
        similar = []

        for other in alert_pool:
            if other.get("hash_id") == alert.get("hash_id"):
                continue

            other_text = self._get_alert_text(other)
            similarity = self._calculate_similarity(text, other_text)

            if similarity >= threshold:
                similar.append({
                    "alert": other,
                    "similarity": similarity
                })

        return sorted(similar, key=lambda x: x["similarity"], reverse=True)

    def _get_alert_text(self, alert: Dict[str, Any]) -> str:
        """Extract normalized text from alert for comparison."""
        parts = [
            alert.get("title", ""),
            alert.get("summary", ""),
            alert.get("raw_content", "")[:500]
        ]
        return " ".join(parts).lower().strip()

    def _hash_exists(self, hash_id: str) -> bool:
        """Check if hash_id exists in cache."""
        return hash_id in self._text_cache

    def _cache_alert(self, alert: Dict[str, Any]):
        """Cache alert for future duplicate detection."""
        hash_id = alert.get("hash_id", "")
        if hash_id:
            self._text_cache[hash_id] = self._get_alert_text(alert)

    def _check_text_similarity(self, text: str) -> Tuple[bool, float]:
        """Check text similarity against cached alerts."""
        if not self._text_cache:
            return False, 0.0

        best_similarity = 0.0

        for cached_text in self._text_cache.values():
            # Quick token set ratio check
            similarity = fuzz.token_set_ratio(text, cached_text)
            normalized = similarity / 100.0

            if normalized > best_similarity:
                best_similarity = normalized

            if normalized >= self.similarity_threshold:
                return True, normalized

        return False, best_similarity

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts."""
        # Use multiple similarity metrics
        ratios = [
            fuzz.ratio(text1, text2) / 100.0,
            fuzz.partial_ratio(text1, text2) / 100.0,
            fuzz.token_set_ratio(text1, text2) / 100.0,
            fuzz.token_sort_ratio(text1, text2) / 100.0,
        ]

        # Weighted average
        weights = [0.2, 0.2, 0.4, 0.2]
        return sum(r * w for r, w in zip(ratios, weights))

    def _find_existing_similar(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Find an existing alert that's similar to the given one."""
        text = self._get_alert_text(alert)

        for hash_id, cached_text in self._text_cache.items():
            similarity = fuzz.token_set_ratio(text, cached_text) / 100.0
            if similarity >= self.similarity_threshold:
                # Return a minimal dict representing the existing alert
                return {"hash_id": hash_id}

        return None

    def clear_cache(self):
        """Clear the in-memory cache."""
        self._text_cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cached_items": len(self._text_cache),
            "cache_size_bytes": sum(len(v) for v in self._text_cache.values()),
        }
