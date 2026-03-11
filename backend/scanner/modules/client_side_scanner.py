import aiohttp
import re
from urllib.parse import urljoin, urlparse
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ClientSideScanner(BaseModule):
    """Scans for: Open Redirect, Clickjacking, CORS Misconfiguration, DOM-based hints,
    JS Source Map Exposure"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html or not resp:
            return results

        results.extend(await self._check_open_redirect(session, target_url, html))
        results.extend(self._check_clickjacking(resp))
        results.extend(await self._check_cors(session, target_url))
        results.extend(self._check_dom_based(html))
        results.extend(await self._check_source_maps(session, target_url, html))

        return results

    async def _check_open_redirect(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        redirect_params = ["url", "redirect", "next", "return", "returnUrl",
                           "goto", "redirect_uri", "continue", "dest", "destination"]

        for param in redirect_params:
            test_url = f"{target_url.rstrip('/')}?{param}=https://evil.com"
            try:
                async with session.get(test_url, ssl=False, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in (301, 302, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            detected = True
                            evidence = f"Open redirect via param '{param}': redirects to {location}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="CLI-021", name="Open Redirect", severity=Severity.MEDIUM,
            category="Client-Side",
            description="Tes Open Redirect melalui URL parameters.",
            detected=detected, evidence=evidence,
        )]

    def _check_clickjacking(self, resp) -> list:
        xfo = resp.headers.get("X-Frame-Options")
        csp = resp.headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        detected = not xfo and not has_frame_ancestors
        evidence = ""
        if detected:
            evidence = "No X-Frame-Options header and no CSP frame-ancestors directive found"

        return [self.make_result(
            bug_id="CLI-022", name="Clickjacking", severity=Severity.MEDIUM,
            category="Client-Side",
            description="Cek proteksi clickjacking (X-Frame-Options / CSP frame-ancestors).",
            detected=detected, evidence=evidence,
        )]

    async def _check_cors(self, session, target_url) -> list:
        detected = False
        evidence = ""
        try:
            headers = self._default_headers()
            headers["Origin"] = "https://evil.com"
            async with session.get(target_url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*":
                    detected = True
                    evidence = "CORS allows all origins (Access-Control-Allow-Origin: *)"
                elif "evil.com" in acao:
                    detected = True
                    evidence = f"CORS reflects arbitrary origin: {acao}"
                    if acac.lower() == "true":
                        evidence += " WITH credentials allowed (critical!)"
        except Exception:
            pass

        return [self.make_result(
            bug_id="CLI-023", name="CORS Misconfiguration", severity=Severity.HIGH,
            category="Client-Side",
            description="Cek CORS misconfiguration (wildcard, reflected origin).",
            detected=detected, evidence=evidence,
        )]

    def _check_dom_based(self, html) -> list:
        detected = False
        evidence_parts = []
        dangerous_sinks = [
            r'document\.write\s*\(', r'\.innerHTML\s*=', r'\.outerHTML\s*=',
            r'eval\s*\(', r'setTimeout\s*\(\s*["\']', r'setInterval\s*\(\s*["\']',
            r'document\.location\s*=', r'window\.location\s*=',
        ]
        dangerous_sources = [
            r'document\.URL', r'document\.referrer', r'location\.hash',
            r'location\.search', r'location\.href', r'window\.name',
        ]

        for pattern in dangerous_sinks:
            matches = re.findall(pattern, html)
            if matches:
                detected = True
                evidence_parts.append(f"Dangerous sink: {matches[0]}")

        for pattern in dangerous_sources:
            matches = re.findall(pattern, html)
            if matches:
                detected = True
                evidence_parts.append(f"Dangerous source: {matches[0]}")

        return [self.make_result(
            bug_id="CLI-024", name="DOM-based Vulnerability Hints", severity=Severity.MEDIUM,
            category="Client-Side",
            description="Deteksi penggunaan dangerous sinks dan sources di JavaScript.",
            detected=detected, evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_source_maps(self, session, target_url, html) -> list:
        detected = False
        evidence_parts = []
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', html)

        for js_file in js_files[:10]:
            js_url = urljoin(target_url, js_file)
            map_url = js_url + ".map"
            try:
                async with session.head(map_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        detected = True
                        evidence_parts.append(f"Source map found: {map_url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="CLI-025", name="JavaScript Source Map Exposure", severity=Severity.LOW,
            category="Client-Side",
            description="Cek apakah JavaScript source map file (.js.map) terekspos.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]
