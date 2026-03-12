import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CsrfScanner(BaseModule):
    """Scans for: CSRF Token Missing/Weak Detection"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return []

        soup = self.parse_html(html)
        detected = False
        evidence_parts = []

        csrf_names = ["csrf", "_token", "csrfmiddlewaretoken", "csrf_token",
                      "authenticity_token", "__requestverificationtoken", "antiforgery"]

        for form in soup.find_all("form"):
            if form.get("method", "get").upper() != "POST":
                continue
            form_inputs = form.find_all("input")
            has_csrf = False
            for inp in form_inputs:
                name = (inp.get("name") or "").lower()
                if any(c in name for c in csrf_names):
                    has_csrf = True
                    break
            if not has_csrf:
                detected = True
                action = form.get("action", "current page")
                evidence_parts.append(f"POST form to '{action}' missing CSRF token")

        samesite_ok = False
        cookies = (resp.headers.getall("Set-Cookie", []) if resp else [])
        for cookie in cookies:
            if "samesite=strict" in cookie.lower() or "samesite=lax" in cookie.lower():
                samesite_ok = True
                break

        return [self.make_result(
            bug_id="CSRF-050", name="CSRF Token Missing/Weak", severity=Severity.HIGH,
            category="CSRF",
            description="Cek apakah form POST memiliki CSRF token.",
            detected=detected and not samesite_ok,
            endpoint=target_url,
            evidence="\n".join(evidence_parts[:10]),
        )]
