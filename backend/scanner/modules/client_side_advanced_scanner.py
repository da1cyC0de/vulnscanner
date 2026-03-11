import aiohttp
import re
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ClientSideAdvancedScanner(BaseModule):
    """Scans for: PostMessage Vulnerability, CSS Injection, Reverse Tabnabbing"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_postmessage(html))
        results.extend(self._check_tabnabbing(html))
        results.extend(self._check_sri(html))
        return results

    def _check_postmessage(self, html) -> list:
        detected = False
        evidence = ""
        if "postMessage" in html and "addEventListener" in html:
            if not re.search(r'origin\s*[!=]==', html):
                detected = True
                evidence = "postMessage used without origin validation"

        return [self.make_result(
            bug_id="CLIADV-123", name="PostMessage Vulnerability", severity=Severity.MEDIUM,
            category="Client-Side Advanced",
            description="Cek penggunaan postMessage tanpa validasi origin.",
            detected=detected, evidence=evidence,
        )]

    def _check_tabnabbing(self, html) -> list:
        detected = False
        evidence_parts = []
        soup = self.parse_html(html)
        for a in soup.find_all("a", target="_blank"):
            rel = (a.get("rel") or [])
            if isinstance(rel, str):
                rel = [rel]
            if "noopener" not in rel and "noreferrer" not in rel:
                detected = True
                href = a.get("href", "unknown")
                evidence_parts.append(f"Link target='_blank' without noopener: {href[:100]}")

        return [self.make_result(
            bug_id="CLIADV-126", name="Reverse Tabnabbing", severity=Severity.LOW,
            category="Client-Side Advanced",
            description="Deteksi link target='_blank' tanpa rel='noopener noreferrer'.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_sri(self, html) -> list:
        detected = False
        evidence_parts = []
        soup = self.parse_html(html)

        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith("http") and "integrity" not in str(tag):
                detected = True
                evidence_parts.append(f"External resource without SRI: {src[:100]}")

        return [self.make_result(
            bug_id="COMP-106", name="Subresource Integrity (SRI) Missing", severity=Severity.LOW,
            category="Client-Side Advanced",
            description="Cek external resources yang tidak memiliki SRI attribute.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]
