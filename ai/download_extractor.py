"""
Download Extractor - Extracts download links from content
"""
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class DownloadExtractor:
    """
    Extracts download links, repositories, and resources
    from threat intelligence content.
    """

    # URL patterns to extract
    URL_PATTERNS = {
        "github": [
            r'https?://github\.com/[\w-]+/[\w.-]+',
            r'https?://raw\.githubusercontent\.com/[\w-]+/[\w.-]+',
        ],
        "huggingface": [
            r'https?://huggingface\.co/datasets/[\w-]+/[\w.-]+',
            r'https?://huggingface\.co/(?!datasets/)[\w-]+/[\w.-]+',
        ],
        "docker": [
            r'https?://hub\.docker\.com/r/[\w-]+/[\w-]+',
        ],
        "pypi": [
            r'https?://pypi\.org/project/[\w-]+',
        ],
        "npm": [
            r'https?://www\.npmjs\.com/package/[\w-]+',
        ],
        "releases": [
            r'https?://[\w.-]+/[\w/-]+/releases/download/[\w/.-]+',
        ],
        "direct_download": [
            r'https?://[\w.-]+/[\w/._-]+\.(?:zip|tar\.gz|tar\.bz2|rar|7z|deb|rpm|exe|msi|apk|dmg)',
        ],
    }

    # File extensions indicating downloadable resources
    DOWNLOAD_EXTENSIONS = [
        ".zip", ".tar.gz", ".tar.bz2", ".tgz", ".rar", ".7z",
        ".deb", ".rpm", ".apk", ".exe", ".msi", ".dmg",
        ".py", ".sh", ".ps1", ".rb", ".go", ".rs",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    def extract(self, alert: Dict[str, Any]) -> List[str]:
        """
        Extract all download links from an alert.
        Returns a list of URLs.
        """
        all_links = []

        # Extract from various fields
        text_sources = [
            alert.get("raw_content", ""),
            alert.get("summary", ""),
            alert.get("title", ""),
        ]

        full_text = " ".join(text_sources)

        # Extract GitHub repos
        github_links = self._extract_github(full_text)
        all_links.extend(github_links)

        # Extract HuggingFace models
        hf_links = self._extract_huggingface(full_text)
        all_links.extend(hf_links)

        # Extract Docker images
        docker_links = self._extract_docker(full_text)
        all_links.extend(docker_links)

        # Extract release downloads
        release_links = self._extract_releases(full_text)
        all_links.extend(release_links)

        # Extract direct download links
        direct_links = self._extract_direct_downloads(full_text)
        all_links.extend(direct_links)

        # Extract package links
        package_links = self._extract_packages(full_text)
        all_links.extend(package_links)

        # Deduplicate while preserving order
        seen = set()
        unique_links = []
        for link in all_links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)

        # Update alert
        alert["download_links"] = unique_links
        alert["github_urls"] = [link for link in unique_links if "github.com" in link]
        alert["release_urls"] = [link for link in unique_links if "/releases" in link or "/releases/download/" in link]
        alert["model_urls"] = [link for link in unique_links if "huggingface.co/" in link and "/datasets/" not in link]
        alert["dataset_urls"] = [link for link in unique_links if "huggingface.co/datasets/" in link]
        alert["tool_urls"] = [
            link for link in unique_links
            if any(host in link for host in ["github.com", "pypi.org", "npmjs.com", "hub.docker.com"])
        ]
        alert["download_count"] = len(unique_links)

        return unique_links

    def extract_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract download links for a batch of alerts."""
        for alert in alerts:
            self.extract(alert)
        return alerts

    def _extract_github(self, text: str) -> List[str]:
        """Extract GitHub repository links."""
        links = []
        for pattern in self.URL_PATTERNS["github"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Clean up the URL
                clean = match.split("#")[0].split("?")[0].rstrip("/")
                # Remove trailing non-repo parts
                parts = clean.replace("https://github.com/", "").split("/")
                if len(parts) >= 2:
                    repo_url = f"https://github.com/{parts[0]}/{parts[1]}"
                    if repo_url not in links:
                        links.append(repo_url)

                # Also add release page if it's a tool
                release_url = f"{repo_url}/releases"
                if release_url not in links:
                    links.append(release_url)

        return links[:10]

    def _extract_huggingface(self, text: str) -> List[str]:
        """Extract HuggingFace model links."""
        links = []
        for pattern in self.URL_PATTERNS["huggingface"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            links.extend(matches)
        return links[:5]

    def _extract_docker(self, text: str) -> List[str]:
        """Extract Docker image links."""
        links = []
        for pattern in self.URL_PATTERNS["docker"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            links.extend(matches)

        # Also look for docker pull commands
        docker_pattern = r'docker\s+pull\s+([\w./-]+:[\w.-]+)'
        docker_matches = re.findall(docker_pattern, text, re.IGNORECASE)
        for match in docker_matches:
            links.append(f"https://hub.docker.com/r/{match.split(':')[0]}")

        return links[:5]

    def _extract_releases(self, text: str) -> List[str]:
        """Extract release download links."""
        links = []
        for pattern in self.URL_PATTERNS["releases"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            links.extend(matches)
        return links[:10]

    def _extract_direct_downloads(self, text: str) -> List[str]:
        """Extract direct file download links."""
        links = []
        for pattern in self.URL_PATTERNS["direct_download"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            links.extend(matches)
        return links[:10]

    def _extract_packages(self, text: str) -> List[str]:
        """Extract package manager links."""
        links = []

        # PyPI
        for pattern in self.URL_PATTERNS["pypi"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            links.extend(matches)

        # npm
        for pattern in self.URL_PATTERNS["npm"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            links.extend(matches)

        # pip install commands
        pip_pattern = r'pip\s+install\s+([\w-]+)'
        pip_matches = re.findall(pip_pattern, text, re.IGNORECASE)
        for match in pip_matches:
            links.append(f"https://pypi.org/project/{match}")

        return links[:5]

    def get_download_summary(self, alert: Dict[str, Any]) -> str:
        """Generate a human-readable download summary."""
        links = alert.get("download_links", [])
        if not links:
            return ""

        summary_parts = ["\n📥 <b>Downloads:</b>"]

        for link in links[:5]:
            # Categorize the link
            if "github.com" in link:
                icon = "🐙"
            elif "huggingface" in link:
                icon = "🤗"
            elif "docker" in link:
                icon = "🐳"
            elif any(ext in link for ext in [".zip", ".tar"]):
                icon = "📦"
            else:
                icon = "🔗"

            summary_parts.append(f'{icon} <a href="{link}">Link</a>')

        if len(links) > 5:
            summary_parts.append(f"... and {len(links) - 5} more")

        return "\n".join(summary_parts)
