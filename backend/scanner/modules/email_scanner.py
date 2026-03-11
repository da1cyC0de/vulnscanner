import aiohttp
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class EmailScanner(BaseModule):
    """Scans for: Email Header Injection"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_email_forms(html))
        return results

    def _check_email_forms(self, html) -> list:
        detected = False
        evidence = ""
        soup = self.parse_html(html)
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            has_email = any(i.get("type") == "email" or "email" in (i.get("name") or "").lower() for i in inputs)
            has_message = any("message" in (i.get("name") or "").lower() or "body" in (i.get("name") or "").lower()
                              for i in inputs + form.find_all("textarea"))
            if has_email and has_message:
                detected = True
                evidence = "Contact/email form found - may be vulnerable to email header injection"

        return [self.make_result(
            bug_id="EMAIL-114", name="Email Header Injection", severity=Severity.MEDIUM,
            category="Email Vulnerabilities",
            description="Deteksi form email/kontak yang mungkin rentan email header injection.",
            detected=detected, evidence=evidence,
        )]
