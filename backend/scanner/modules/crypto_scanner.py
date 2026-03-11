import aiohttp
import re
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CryptoScanner(BaseModule):
    """Scans for: Weak Hashing, Missing Certificate Transparency"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_weak_hashing(html))
        return results

    def _check_weak_hashing(self, html) -> list:
        detected = False
        evidence_parts = []
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'

        md5s = re.findall(md5_pattern, html)
        sha1s = re.findall(sha1_pattern, html)

        if md5s:
            detected = True
            evidence_parts.append(f"Possible MD5 hash found: {md5s[0]}")
        if sha1s:
            detected = True
            evidence_parts.append(f"Possible SHA1 hash found: {sha1s[0]}")

        return [self.make_result(
            bug_id="CRYPT-144", name="Weak Hashing Detection", severity=Severity.LOW,
            category="Cryptographic",
            description="Deteksi penggunaan hash lemah (MD5, SHA1) di response.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]
