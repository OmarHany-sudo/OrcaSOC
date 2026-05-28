"""
Embeddings Manager - Semantic duplicate detection using sentence transformers
"""
import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingsManager:
    """
    Manages text embeddings for semantic duplicate detection.
    Uses sentence-transformers to generate embeddings and
    FAISS for efficient similarity search.
    """

    def __init__(self, db_path: Path, model_name: str = "all-MiniLM-L6-v2"):
        self.db_path = db_path
        self.model_name = model_name
        self.model = None
        self.dimension = 384  # Default for all-MiniLM-L6-v2
        self._init_db()
        self._load_model()

    def _init_db(self):
        """Initialize the embeddings database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS embeddings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_id TEXT UNIQUE NOT NULL,
                    text_hash TEXT NOT NULL,
                    embedding BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hash_id ON embeddings(hash_id)
            """)

    def _load_model(self):
        """Load the sentence transformer model."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            self.dimension = self.model.get_sentence_embedding_dimension()
            logger.info(f"Loaded embedding model: {self.model_name} (dim={self.dimension})")
        except ImportError:
            logger.warning("sentence-transformers not available, embeddings disabled")
        except Exception as e:
            logger.error(f"Error loading embedding model: {e}")

    def generate_embedding(self, text: str) -> Optional[np.ndarray]:
        """Generate embedding for a text."""
        if self.model is None:
            return None
        try:
            embedding = self.model.encode(text, show_progress_bar=False, convert_to_numpy=True)
            return embedding
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            return None

    def store_embedding(self, hash_id: str, text: str, embedding: Optional[np.ndarray] = None):
        """Store an embedding in the database."""
        if embedding is None:
            embedding = self.generate_embedding(text)
            if embedding is None:
                return False

        text_hash = hashlib.sha256(text.encode()).hexdigest()[:32]
        embedding_bytes = embedding.astype(np.float32).tobytes()

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO embeddings (hash_id, text_hash, embedding, created_at)
                    VALUES (?, ?, ?, ?)
                """, (hash_id, text_hash, embedding_bytes, datetime.utcnow().isoformat()))
            return True
        except Exception as e:
            logger.error(f"Error storing embedding: {e}")
            return False

    def find_similar(self, text: str, threshold: float = 0.85, top_k: int = 5) -> List[Dict]:
        """
        Find similar texts using cosine similarity.
        Returns list of dicts with hash_id and similarity score.
        """
        if self.model is None:
            return []

        embedding = self.generate_embedding(text)
        if embedding is None:
            return []

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT hash_id, embedding FROM embeddings")
                rows = cursor.fetchall()

            if not rows:
                return []

            results = []
            for hash_id, emb_bytes in rows:
                stored_emb = np.frombuffer(emb_bytes, dtype=np.float32)
                if len(stored_emb) != self.dimension:
                    continue
                similarity = self._cosine_similarity(embedding, stored_emb)
                if similarity >= threshold:
                    results.append({
                        "hash_id": hash_id,
                        "similarity": float(similarity)
                    })

            results.sort(key=lambda x: x["similarity"], reverse=True)
            return results[:top_k]

        except Exception as e:
            logger.error(f"Error finding similar embeddings: {e}")
            return []

    def is_duplicate(self, text: str, threshold: float = 0.85) -> Tuple[bool, float]:
        """
        Check if text is a duplicate of previously stored content.
        Returns (is_duplicate, similarity_score).
        """
        similar = self.find_similar(text, threshold=threshold, top_k=1)
        if similar:
            return True, similar[0]["similarity"]
        return False, 0.0

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return np.dot(a, b) / (norm_a * norm_b)

    def get_stats(self) -> Dict:
        """Get embedding statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM embeddings")
                total = cursor.fetchone()[0]
                return {
                    "total_embeddings": total,
                    "model": self.model_name,
                    "dimension": self.dimension,
                    "model_loaded": self.model is not None
                }
        except Exception as e:
            logger.error(f"Error getting embedding stats: {e}")
            return {"total_embeddings": 0, "error": str(e)}

    def cleanup_old_embeddings(self, max_age_days: int = 30):
        """Remove old embeddings to save space."""
        cutoff = datetime.utcnow().timestamp() - (max_age_days * 86400)
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat()

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM embeddings WHERE created_at < ?", (cutoff_iso,))
                deleted = conn.total_changes
                logger.info(f"Cleaned up {deleted} old embeddings")
        except Exception as e:
            logger.error(f"Error cleaning up embeddings: {e}")

    def compute_text_hash(self, text: str) -> str:
        """Compute a hash for text content."""
        return hashlib.sha256(text.encode()).hexdigest()[:32]
