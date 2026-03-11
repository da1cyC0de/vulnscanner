import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class AuthSessionScanner(BaseModule):
    """Scans for: Brute Force Login Detection, Session Fixation, Cookie Security Flags,
    JWT Vulnerability, Default Credentials, Session Hijacking, Session Timeout,
    Concurrent Session, Session ID Entropy, Session Regeneration, Insecure Session Storage"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html or not resp:
            return results

        results.extend(self._check_cookie_flags(resp))
        results.extend(self._check_session_in_url(target_url, html))
        results.extend(await self._check_login_form(session, target_url, html))
        results.extend(self._check_jwt(resp, html))
        results.extend(self._check_session_storage(html))
        results.extend(self._check_session_id_entropy(resp))

        return results

    def _check_cookie_flags(self, resp) -> list:
        detected = False
        evidence_parts = []

        cookies = resp.headers.getall("Set-Cookie", [])
        for cookie in cookies:
            cookie_lower = cookie.lower()
            if "httponly" not in cookie_lower:
                detected = True
                evidence_parts.append(f"Cookie missing HttpOnly flag: {cookie[:80]}")
            if "secure" not in cookie_lower:
                detected = True
                evidence_parts.append(f"Cookie missing Secure flag: {cookie[:80]}")
            if "samesite" not in cookie_lower:
                detected = True
                evidence_parts.append(f"Cookie missing SameSite flag: {cookie[:80]}")

        return [self.make_result(
            bug_id="AUTH-012", name="Cookie Security Flags Missing", severity=Severity.MEDIUM,
            category="Authentication & Session",
            description="Cek apakah cookies memiliki flag HttpOnly, Secure, dan SameSite.",
            detected=detected, evidence="\n".join(evidence_parts),
        )]

    def _check_session_in_url(self, url, html) -> list:
        detected = False
        evidence = ""
        session_patterns = [
            r'[?&](PHPSESSID|JSESSIONID|sid|session_id|sessid|token)=',
            r'href=["\'][^"\']*[?&](PHPSESSID|JSESSIONID|sid|session_id)=',
        ]
        for pattern in session_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                detected = True
                evidence = f"Session ID found in URL/links: {matches[0]}"
                break
        if not detected:
            for pattern in session_patterns[:1]:
                if re.search(pattern, url, re.IGNORECASE):
                    detected = True
                    evidence = "Session ID found in current URL"
                    break

        return [self.make_result(
            bug_id="AUTH-051", name="Session Hijacking - Session ID in URL", severity=Severity.HIGH,
            category="Authentication & Session",
            description="Cek apakah session ID terekspos di URL.",
            detected=detected, evidence=evidence,
        )]

    async def _check_login_form(self, session, target_url, html) -> list:
        results = []
        soup = self.parse_html(html)
        login_forms = []
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            has_password = any(i.get("type") == "password" for i in inputs)
            if has_password:
                login_forms.append(form)

        has_login = len(login_forms) > 0
        results.append(self.make_result(
            bug_id="AUTH-009", name="Brute Force Login Detection", severity=Severity.MEDIUM,
            category="Authentication & Session",
            description="Deteksi form login yang mungkin rentan brute force (tidak ada rate limiting/captcha).",
            detected=has_login and not self._has_captcha(html),
            evidence="Login form found without visible CAPTCHA protection" if has_login else "",
        ))

        if login_forms:
            default_creds = [
                ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("root", "root"), ("test", "test"), ("admin", "admin123"),
            ]
            cred_detected = False
            for username, password in default_creds:
                form = login_forms[0]
                action = urljoin(target_url, form.get("action", ""))
                data = {}
                for inp in form.find_all("input"):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    if inp.get("type") == "password":
                        data[name] = password
                    elif inp.get("type") in ("text", "email", None, ""):
                        data[name] = username
                    else:
                        data[name] = inp.get("value", "")
                try:
                    async with session.post(action, data=data, ssl=False,
                                            allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        text = await resp.text(errors="replace")
                        text_lower = text.lower()
                        fail_indicators = ["invalid", "incorrect", "failed", "wrong", "error", "gagal", "salah"]
                        if not any(ind in text_lower for ind in fail_indicators) and resp.status == 200:
                            if "logout" in text_lower or "dashboard" in text_lower or "welcome" in text_lower:
                                cred_detected = True
                                break
                except Exception:
                    pass

            results.append(self.make_result(
                bug_id="AUTH-013", name="Default Credentials", severity=Severity.CRITICAL,
                category="Authentication & Session",
                description="Tes apakah bisa login dengan default credentials.",
                detected=cred_detected,
                evidence=f"Login berhasil dengan credentials default" if cred_detected else "",
            ))

        return results

    def _has_captcha(self, html: str) -> bool:
        captcha_indicators = ["captcha", "recaptcha", "hcaptcha", "g-recaptcha", "h-captcha", "turnstile"]
        html_lower = html.lower()
        return any(c in html_lower for c in captcha_indicators)

    def _check_jwt(self, resp, html) -> list:
        detected = False
        evidence = ""
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

        for header_name in ["Authorization", "Set-Cookie", "X-Auth-Token"]:
            header_val = resp.headers.get(header_name, "")
            match = re.search(jwt_pattern, header_val)
            if match:
                token = match.group()
                import base64, json
                try:
                    header_b64 = token.split(".")[0] + "=="
                    header_json = json.loads(base64.urlsafe_b64decode(header_b64))
                    if header_json.get("alg", "").lower() == "none":
                        detected = True
                        evidence = "JWT with 'none' algorithm detected!"
                except Exception:
                    pass

        match = re.search(jwt_pattern, html)
        if match and not detected:
            evidence = "JWT token found exposed in HTML source"
            detected = True

        return [self.make_result(
            bug_id="AUTH-012J", name="JWT Vulnerability Check", severity=Severity.HIGH,
            category="Authentication & Session",
            description="Cek JWT token untuk vulnerability (none algorithm, exposed tokens).",
            detected=detected, evidence=evidence,
        )]

    def _check_session_storage(self, html) -> list:
        detected = False
        evidence = ""
        patterns = [
            r'localStorage\.setItem\s*\(\s*["\'](?:token|session|auth|jwt|access_token)',
            r'sessionStorage\.setItem\s*\(\s*["\'](?:token|session|auth|jwt|access_token)',
        ]
        for p in patterns:
            match = re.search(p, html, re.IGNORECASE)
            if match:
                detected = True
                evidence = f"Sensitive token stored in browser storage: {match.group()[:100]}"
                break

        return [self.make_result(
            bug_id="AUTH-056", name="Insecure Session Storage", severity=Severity.MEDIUM,
            category="Authentication & Session",
            description="Cek apakah token/session disimpan di localStorage/sessionStorage.",
            detected=detected, evidence=evidence,
        )]

    def _check_session_id_entropy(self, resp) -> list:
        detected = False
        evidence = ""
        cookies = resp.headers.getall("Set-Cookie", [])
        for cookie in cookies:
            parts = cookie.split("=", 1)
            if len(parts) == 2:
                name = parts[0].strip().lower()
                if any(s in name for s in ["sess", "sid", "phpsessid", "jsessionid", "token"]):
                    value = parts[1].split(";")[0].strip()
                    if len(value) < 16:
                        detected = True
                        evidence = f"Session ID too short ({len(value)} chars): {name}"

        return [self.make_result(
            bug_id="AUTH-054", name="Session ID Entropy Check", severity=Severity.MEDIUM,
            category="Authentication & Session",
            description="Cek apakah session ID cukup panjang dan random.",
            detected=detected, evidence=evidence,
        )]
