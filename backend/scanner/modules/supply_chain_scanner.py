import aiohttp
import re
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class SupplyChainScanner(BaseModule):
    """Scans for: JS Library Vulnerabilities, Known CVE detection based on versions"""

    KNOWN_VULNERABLE = {
        "jquery": {"pattern": r'jquery[/-]?([\d.]+)', "min_safe": "3.5.0", "cve": "CVE-2020-11022"},
        "angular": {"pattern": r'angular[/-]?([\d.]+)', "min_safe": "1.8.0", "cve": "Various XSS"},
        "bootstrap": {"pattern": r'bootstrap[/-]?([\d.]+)', "min_safe": "4.3.1", "cve": "CVE-2019-8331"},
        "lodash": {"pattern": r'lodash[/-]?([\d.]+)', "min_safe": "4.17.21", "cve": "CVE-2021-23337"},
        "moment": {"pattern": r'moment[/-]?([\d.]+)', "min_safe": "2.29.4", "cve": "CVE-2022-31129"},
    }

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_js_libraries(html, target_url))
        results.extend(self._check_outdated_frameworks(html, target_url))
        return results

    def _check_js_libraries(self, html, target_url) -> list:
        detected = False
        evidence_parts = []

        for lib_name, info in self.KNOWN_VULNERABLE.items():
            match = re.search(info["pattern"], html, re.IGNORECASE)
            if match:
                version = match.group(1)
                try:
                    if self._version_lt(version, info["min_safe"]):
                        detected = True
                        evidence_parts.append(
                            f"{lib_name} v{version} (vulnerable, min safe: {info['min_safe']}, {info['cve']})")
                except Exception:
                    pass

        return [self.make_result(
            bug_id="SUPPLY-161", name="JavaScript Library Vulnerability", severity=Severity.MEDIUM,
            category="Supply Chain",
            description="Deteksi library JavaScript yang outdated dan memiliki vulnerability.",
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:10]),
        )]

    def _check_outdated_frameworks(self, html, target_url) -> list:
        detected = False
        evidence_parts = []
        extra = {
            "react": {"pattern": r'react[/-]?(\d+\.\d+\.\d+)', "min_safe": "18.0.0", "cve": "Various"},
            "vue": {"pattern": r'vue[/-]?(\d+\.\d+\.\d+)', "min_safe": "3.0.0", "cve": "Various"},
            "axios": {"pattern": r'axios[/-]?(\d+\.\d+\.\d+)', "min_safe": "0.21.2", "cve": "CVE-2021-3749"},
            "handlebars": {"pattern": r'handlebars[/-]?(\d+\.\d+\.\d+)', "min_safe": "4.7.7", "cve": "CVE-2021-23369"},
            "underscore": {"pattern": r'underscore[/-]?(\d+\.\d+\.\d+)', "min_safe": "1.13.6", "cve": "CVE-2021-23358"},
        }
        for lib_name, info in extra.items():
            match = re.search(info["pattern"], html, re.IGNORECASE)
            if match:
                version = match.group(1)
                try:
                    if self._version_lt(version, info["min_safe"]):
                        detected = True
                        evidence_parts.append(f"{lib_name} v{version} (vulnerable, min safe: {info['min_safe']}, {info['cve']})")
                except Exception:
                    pass

        return [self.make_result(
            bug_id="SUPPLY-162", name="Outdated Frontend Framework", severity=Severity.MEDIUM,
            category="Supply Chain",
            description="Deteksi framework frontend yang outdated (React, Vue, Axios, dll).",
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:10]),
        )]

    def _version_lt(self, v1: str, v2: str) -> bool:
        parts1 = [int(x) for x in v1.split(".")[:3]]
        parts2 = [int(x) for x in v2.split(".")[:3]]
        while len(parts1) < 3:
            parts1.append(0)
        while len(parts2) < 3:
            parts2.append(0)
        return parts1 < parts2
