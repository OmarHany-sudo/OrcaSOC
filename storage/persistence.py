"""
Persistence Manager - Handles Git-based persistent storage
"""
import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class PersistenceManager:
    """
    Manages persistent state using JSON files stored in the repository.
    These files are committed back to git after each run.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, filename: str, data: Any) -> bool:
        """Save data to a JSON file."""
        try:
            filepath = self.data_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Error saving {filename}: {e}")
            return False

    def load_json(self, filename: str, default: Any = None) -> Any:
        """Load data from a JSON file."""
        filepath = self.data_dir / filename
        if not filepath.exists():
            return default if default is not None else {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
            return default if default is not None else {}

    def update_json(self, filename: str, updates: Dict[str, Any]) -> bool:
        """Update specific keys in a JSON file."""
        data = self.load_json(filename, {})
        if isinstance(data, dict):
            data.update(updates)
            return self.save_json(filename, data)
        return False

    def append_to_list(self, filename: str, item: Any, max_items: int = 10000) -> bool:
        """Append an item to a list stored in a JSON file."""
        data = self.load_json(filename, [])
        if isinstance(data, list):
            data.append(item)
            if len(data) > max_items:
                data = data[-max_items:]
            return self.save_json(filename, data)
        return False

    def save_text(self, filename: str, content: str) -> bool:
        """Save text content to a file."""
        try:
            filepath = self.data_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Error saving text {filename}: {e}")
            return False

    def load_text(self, filename: str) -> Optional[str]:
        """Load text content from a file."""
        filepath = self.data_dir / filename
        if not filepath.exists():
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error loading text {filename}: {e}")
            return None

    def file_exists(self, filename: str) -> bool:
        """Check if a file exists in the data directory."""
        return (self.data_dir / filename).exists()

    def delete_file(self, filename: str) -> bool:
        """Delete a file from the data directory."""
        try:
            filepath = self.data_dir / filename
            if filepath.exists():
                filepath.unlink()
            return True
        except Exception as e:
            logger.error(f"Error deleting {filename}: {e}")
            return False

    def list_files(self, pattern: str = "*") -> list:
        """List files in the data directory matching a pattern."""
        return [f.name for f in self.data_dir.glob(pattern) if f.is_file()]

    def get_file_size(self, filename: str) -> int:
        """Get file size in bytes."""
        filepath = self.data_dir / filename
        if filepath.exists():
            return filepath.stat().st_size
        return 0

    def git_commit_and_push(self, commit_message: str = "Update bot state") -> bool:
        """
        Commit and push data files to git.
        This is called at the end of each GitHub Actions run.
        """
        try:
            import subprocess

            # Configure git
            subprocess.run(["git", "config", "--local", "user.email", "bot@cti-bot.local"], check=True)
            subprocess.run(["git", "config", "--local", "user.name", "CTI Bot"], check=True)

            # Add data directory
            subprocess.run(["git", "add", str(self.data_dir)], check=False)

            # Check if there are changes to commit
            result = subprocess.run(
                ["git", "diff", "--cached", "--quiet"],
                capture_output=True
            )

            if result.returncode == 0:
                logger.info("No changes to commit")
                return True

            # Commit
            subprocess.run(
                ["git", "commit", "-m", commit_message],
                check=True
            )

            # Push
            subprocess.run(
                ["git", "push", "origin", os.getenv("GITHUB_REF_NAME", "main")],
                check=True
            )

            logger.info("Successfully committed and pushed state")
            return True

        except Exception as e:
            logger.error(f"Git commit/push failed: {e}")
            return False

    def should_git_push(self) -> bool:
        """Check if we're in a GitHub Actions environment where pushing is possible."""
        return bool(os.getenv("GITHUB_TOKEN")) and bool(os.getenv("GITHUB_REPOSITORY"))
