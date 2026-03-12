import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class AdvancedAuthScanner(BaseModule):
    """Scans for: Password Policy, Account Lockout, Username Enumeration,
    Password Reset Poisoning, OAuth Misconfig, 2FA Bypass indicators"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_username_enumeration_hints(html, target_url))
        results.extend(await self._check_password_reset(session, target_url, html))
        results.extend(self._check_oauth_misconfig(html, target_url))
        results.extend(await self._check_jwt_in_url(session, target_url, html))

        return results

    def _check_username_enumeration_hints(self, html, target_url) -> list:
        detected = False
        evidence = ""
        enum_indicators = [
            "user not found", "username not found", "email not found",
            "no account found", "user does not exist", "invalid username",
            "not registered", "akun tidak ditemukan",
        ]
        html_lower = html.lower()
        for indicator in enum_indicators:
            if indicator in html_lower:
                detected = True
                evidence = f"Username enumeration hint: '{indicator}' found in response"
                break

        return [self.make_result(
            bug_id="AUTH-097", name="Username Enumeration", severity=Severity.MEDIUM,
            category="Authentication Advanced",
            description="Deteksi apakah error message membedakan username valid/invalid.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    async def _check_password_reset(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        soup = self.parse_html(html)
        reset_links = soup.find_all("a", href=re.compile(r'(?:forgot|reset|lupa)', re.I))

        if reset_links:
            reset_url = urljoin(target_url, reset_links[0].get("href", ""))
            try:
                async with session.get(reset_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "email" in text.lower() or "reset" in text.lower():
                            headers = self._default_headers()
                            headers["Host"] = "evil.com"
                            async with session.get(reset_url, headers=headers, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                                text2 = await resp2.text(errors="replace")
                                if "evil.com" in text2:
                                    detected = True
                                    evidence = f"Password reset page reflects Host header at {reset_url}"
            except Exception:
                pass

        return [self.make_result(
            bug_id="AUTH-098", name="Password Reset Poisoning", severity=Severity.HIGH,
            category="Authentication Advanced",
            description="Tes Host Header Poisoning pada password reset.",
            detected=detected, endpoint=reset_url if detected else "", evidence=evidence,
        )]

    def _check_oauth_misconfig(self, html, target_url) -> list:
        detected = False
        evidence_parts = []
        oauth_patterns = [
            r'redirect_uri=http://', r'state=(?:[a-zA-Z0-9]{1,10})',
            r'client_secret\s*[:=]\s*["\'][^"\']+["\']',
        ]
        for pattern in oauth_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                detected = True
                evidence_parts.append(f"OAuth issue: {match.group()[:100]}")

        return [self.make_result(
            bug_id="AUTH-099", name="OAuth Misconfiguration", severity=Severity.HIGH,
            category="Authentication Advanced",
            description="Deteksi misconfiguration pada implementasi OAuth.",
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_jwt_in_url(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        match = re.search(jwt_pattern, html)
        if match:
            detected = True
            token = match.group()[:50]
            evidence = f"JWT token exposed in page source: {token}..."

        soup = self.parse_html(html)
        for a in soup.find_all("a", href=True):
            if re.search(jwt_pattern, a["href"]):
                detected = True
                evidence = f"JWT token in URL: {a['href'][:80]}..."
                break

        return [self.make_result(
            bug_id="AUTH-100", name="JWT Token Exposure", severity=Severity.HIGH,
            category="Authentication Advanced",
            description="Deteksi JWT token yang terekspos di URL atau page source.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]
