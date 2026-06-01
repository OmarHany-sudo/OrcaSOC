"""
Security Papers Collector - arXiv and PapersWithCode security research.
"""
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class SecurityPapersCollector(BaseCollector):
    """Collects recent security papers from arXiv and PapersWithCode."""

    ARXIV_API = "https://export.arxiv.org/api/query"
    PAPERSWITHCODE_API = "https://paperswithcode.com/api/v1/papers/"

    KEYWORDS = [
        "security", "vulnerability", "malware", "ransomware", "prompt injection",
        "jailbreak", "llm security", "ai red teaming", "red team", "exploit",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("SecurityPapers", config)
        self.max_items = self.config.get("max_items", 10)

    def collect(self) -> List[Dict[str, Any]]:
        alerts = []
        alerts.extend(self._collect_arxiv())
        alerts.extend(self._collect_paperswithcode())
        logger.info("[SecurityPapers] Collected %s papers", len(alerts))
        return alerts[:self.max_items]

    def _collect_arxiv(self) -> List[Dict[str, Any]]:
        query = "cat:cs.CR OR all:prompt injection OR all:jailbreak OR all:LLM security"
        response = self.fetch(self.ARXIV_API, params={
            "search_query": query,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
            "max_results": self.max_items,
        })
        if not response:
            return []

        try:
            root = ET.fromstring(response.text)
        except Exception as e:
            logger.error("[SecurityPapers] Error parsing arXiv feed: %s", e)
            return []

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        alerts = []
        for entry in root.findall("atom:entry", ns):
            title = self._text(entry.find("atom:title", ns), "arXiv Security Paper")
            summary = self._text(entry.find("atom:summary", ns), "")
            link = ""
            for link_node in entry.findall("atom:link", ns):
                if link_node.attrib.get("rel") == "alternate":
                    link = link_node.attrib.get("href", "")
                    break
            published = self._text(entry.find("atom:published", ns), datetime.utcnow().isoformat())
            if not self._is_relevant(title + " " + summary):
                continue
            alerts.append(self.standardize_alert(
                title=f"arXiv Security: {title}",
                url=link,
                source="arXiv",
                category=self._category(title + " " + summary),
                severity=self._estimate_severity(title + " " + summary),
                summary=self.truncate_text(summary, 800),
                raw_content=summary,
                published_at=published,
                download_links=[link] if link else [],
                tags=["paper", "arxiv"],
            ))
        return alerts

    def _collect_paperswithcode(self) -> List[Dict[str, Any]]:
        alerts = []
        for keyword in ["security", "malware", "prompt injection", "jailbreak"]:
            response = self.fetch(self.PAPERSWITHCODE_API, params={"q": keyword, "page_size": 5})
            if not response:
                continue
            try:
                data = response.json()
            except Exception:
                continue
            for paper in data.get("results", []):
                title = paper.get("title", "PapersWithCode Security Paper")
                abstract = paper.get("abstract", "")
                url = paper.get("url_abs") or paper.get("url_pdf") or paper.get("paper_url") or ""
                if not self._is_relevant(title + " " + abstract):
                    continue
                alerts.append(self.standardize_alert(
                    title=f"PapersWithCode: {title}",
                    url=url,
                    source="PapersWithCode",
                    category=self._category(title + " " + abstract),
                    severity=self._estimate_severity(title + " " + abstract),
                    summary=self.truncate_text(abstract, 800),
                    raw_content=abstract,
                    published_at=paper.get("published") or datetime.utcnow().isoformat(),
                    download_links=[url] if url else [],
                    tags=["paper", "paperswithcode", keyword],
                ))
        return alerts[: self.max_items]

    def _text(self, node, default: str) -> str:
        return node.text.strip().replace("\n", " ") if node is not None and node.text else default

    def _is_relevant(self, text: str) -> bool:
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.KEYWORDS)

    def _category(self, text: str) -> str:
        text_lower = text.lower()
        if any(keyword in text_lower for keyword in ["prompt injection", "jailbreak", "llm"]):
            return "prompt_injection"
        if any(keyword in text_lower for keyword in ["malware", "ransomware"]):
            return "malware_analysis"
        return "security_research"

    def _estimate_severity(self, text: str) -> float:
        text_lower = text.lower()
        if any(keyword in text_lower for keyword in ["rce", "exploit", "zero-day", "0day"]):
            return 8.0
        if any(keyword in text_lower for keyword in ["prompt injection", "jailbreak", "malware"]):
            return 6.5
        return 5.0
