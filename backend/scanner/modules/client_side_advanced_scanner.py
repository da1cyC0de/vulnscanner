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

        results.extend(self._check_postmessage(html, target_url))
        results.extend(self._check_tabnabbing(html, target_url))
        results.extend(self._check_sri(html, target_url))
        results.extend(self._check_css_injection(html, target_url))
        results.extend(self._check_mixed_content(html, target_url))
        return results

    def _check_postmessage(self, html, target_url) -> list:
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
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    def _check_tabnabbing(self, html, target_url) -> list:
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
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_sri(self, html, target_url) -> list:
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
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_css_injection(self, html, target_url) -> list:
        detected = False
        evidence = ""
        patterns = [
            r'style\s*=\s*["\'][^"]*expression\s*\(',
            r'style\s*=\s*["\'][^"]*url\s*\(\s*["\']?javascript:',
            r'style\s*=\s*["\'][^"]*-moz-binding',
            r'@import\s+url\s*\(["\']https?://',
        ]
        for p in patterns:
            match = re.search(p, html, re.IGNORECASE)
            if match:
                detected = True
                evidence = f"CSS injection pattern found: {match.group()[:100]}"
                break

        return [self.make_result(
            bug_id="CLIADV-124", name="CSS Injection", severity=Severity.MEDIUM,
            category="Client-Side Advanced",
            description="Deteksi pola CSS injection (expression, moz-binding).",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    def _check_mixed_content(self, html, target_url) -> list:
        if not target_url.startswith("https://"):
            return []
        detected = False
        evidence_parts = []
        soup = self.parse_html(html)
        for tag in soup.find_all(["script", "iframe", "form", "object"]):
            src = tag.get("src") or tag.get("action") or tag.get("data") or ""
            if src.startswith("http://"):
                detected = True
                evidence_parts.append(f"Active mixed content: <{tag.name}> loads {src[:80]}")

        return [self.make_result(
            bug_id="CLIADV-125", name="Mixed Content (Active)", severity=Severity.MEDIUM,
            category="Client-Side Advanced",
            description="Deteksi active mixed content (HTTP resource di HTTPS page).",
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:5]),
        )]
