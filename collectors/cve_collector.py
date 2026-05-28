"""
CVE Collector - Collects CVE data from NVD and other sources
"""
import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class CVECollector(BaseCollector):
    """Collects CVE (Common Vulnerabilities and Exposures) data."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("CVE", config)
        self.lookback_hours = self.config.get("lookback_hours", 24)
        self.max_results = self.config.get("max_results", 50)
        self.min_cvss_score = self.config.get("min_cvss_score", 5.0)

    def collect(self) -> List[Dict[str, Any]]:
        """Collect recent CVEs from NVD API."""
        alerts = []

        try:
            nvd_alerts = self._collect_from_nvd()
            alerts.extend(nvd_alerts)
        except Exception as e:
            logger.error(f"[CVE] Error collecting from NVD: {e}")

        logger.info(f"[CVE] Collected {len(alerts)} CVEs")
        return alerts

    def _collect_from_nvd(self) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API."""
        alerts = []

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=self.lookback_hours)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": self.max_results,
        }

        # Add API key if available
        api_key = self.config.get("nvd_api_key")
        if api_key:
            params["apiKey"] = api_key

        response = self.fetch(self.NVD_API_URL, params=params)
        if not response:
            return []

        try:
            data = response.json()
        except Exception as e:
            logger.error(f"[CVE] Error parsing NVD response: {e}")
            return []

        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            try:
                alert = self._process_nvd_vulnerability(vuln)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"[CVE] Error processing vulnerability: {e}")

        return alerts

    def _process_nvd_vulnerability(self, vuln: Dict) -> Dict[str, Any]:
        """Process a single NVD vulnerability into an alert."""
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")

        # Get description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description:
            description = descriptions[0].get("value", "") if descriptions else "No description"

        # Get CVSS score
        severity, cvss_score = self._extract_cvss_score(cve_data)

        # Skip if below minimum threshold
        if cvss_score < self.min_cvss_score:
            return None

        # Get references
        references = cve_data.get("references", [])
        urls = [ref.get("url") for ref in references if ref.get("url")]
        main_url = urls[0] if urls else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Extract tags from description
        tags = []
        if "remote code execution" in description.lower() or "rce" in description.lower():
            tags.append("RCE")
        if "privilege escalation" in description.lower():
            tags.append("privilege-escalation")
        if "authentication" in description.lower() and "bypass" in description.lower():
            tags.append("auth-bypass")

        # Extract affected products
        configurations = cve_data.get("configurations", [])
        affected_products = self._extract_affected_products(configurations)

        # Build summary
        summary_parts = [description[:300]]
        if affected_products:
            summary_parts.append(f"\n\nAffected: {', '.join(affected_products[:5])}")

        summary = "\n".join(summary_parts)

        # Check if exploit available
        has_exploit = any("exploit" in ref.get("tags", []) for ref in references)

        # Get published date
        published = cve_data.get("published", datetime.utcnow().isoformat())

        # Build download links
        download_links = []
        github_pocs = [url for url in urls if "github.com" in url.lower()]
        download_links.extend(github_pocs[:3])

        if has_exploit:
            tags.append("exploit-available")

        # Calculate severity score
        severity_score = cvss_score if cvss_score > 0 else 5.0

        return self.standardize_alert(
            title=f"{cve_id}",
            url=main_url,
            source="NVD",
            category="cve",
            severity=severity_score,
            summary=summary,
            raw_content=description,
            published_at=published,
            download_links=download_links,
            tags=tags
        )

    def _extract_cvss_score(self, cve_data: Dict) -> tuple:
        """Extract CVSS score from CVE data."""
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0)
                severity = cvss_data.get("baseSeverity", "MEDIUM")
                return severity, float(score)

        return "MEDIUM", 5.0

    def _extract_affected_products(self, configurations: List[Dict]) -> List[str]:
        """Extract affected product names from CPE configurations."""
        products = set()

        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    criteria = match.get("criteria", "")
                    # Parse CPE string to get product name
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor and product:
                            products.add(f"{vendor}/{product}")

        return list(products)[:10]

    def _check_public_exploit(self, cve_id: str) -> bool:
        """Check if public exploit exists for CVE."""
        try:
            exploitdb_url = f"https://www.exploit-db.com/search?cve={cve_id.replace('CVE-', '')}"
            response = self.fetch(exploitdb_url)
            if response and "No results" not in response.text:
                return True
        except Exception:
            pass
        return False
