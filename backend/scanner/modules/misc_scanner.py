import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class MiscScanner(BaseModule):
    """Scans for: JSONP Callback, Crossdomain.xml, Sitemap Sensitive URLs"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)

        results.extend(await self._check_crossdomain(session, target_url))
        results.extend(await self._check_sitemap(session, target_url))
        results.extend(self._check_jsonp(html, target_url))
        results.extend(self._check_cache_headers(resp, target_url))
        results.extend(self._check_internal_ip_disclosure(html, target_url))
        results.extend(await self._check_clientaccesspolicy(session, target_url))
        results.extend(self._check_sensitive_form_action(html, target_url))
        return results

    async def _check_crossdomain(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", "crossdomain.xml")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if 'domain="*"' in text or "allow-access-from" in text:
                        detected = True
                        evidence = f"crossdomain.xml allows wide access at {url}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="MISC-175", name="Crossdomain.xml Misconfiguration", severity=Severity.MEDIUM,
            category="Miscellaneous",
            description="Cek crossdomain.xml yang terlalu permissive.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    async def _check_sitemap(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", "sitemap.xml")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    sensitive = ["admin", "login", "dashboard", "config", "api", "internal", "private", "secret"]
                    found = [s for s in sensitive if s in text.lower()]
                    if found:
                        detected = True
                        evidence = f"Sitemap.xml contains sensitive paths: {', '.join(found)}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="MISC-176", name="Sitemap Sensitive URL Leakage", severity=Severity.LOW,
            category="Miscellaneous",
            description="Analisis sitemap.xml untuk path sensitif.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    def _check_jsonp(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        match = re.search(r'[?&]callback=|[?&]jsonp=|[?&]cb=', html)
        if match:
            detected = True
            evidence = f"JSONP callback parameter found: {match.group()}"

        return [self.make_result(
            bug_id="MISC-174", name="JSONP Callback Injection", severity=Severity.MEDIUM,
            category="Miscellaneous",
            description="Deteksi JSONP callback yang bisa disalahgunakan.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    def _check_cache_headers(self, resp, target_url) -> list:
        if not resp:
            return []
        detected = False
        evidence = ""
        cache_control = resp.headers.get("Cache-Control", "")
        pragma = resp.headers.get("Pragma", "")

        if not cache_control and not pragma:
            detected = True
            evidence = "No Cache-Control or Pragma headers set (sensitive data may be cached)"
        elif "no-store" not in cache_control.lower() and "no-cache" not in cache_control.lower():
            detected = True
            evidence = f"Cache-Control does not prevent caching: {cache_control}"

        return [self.make_result(
            bug_id="MISC-108", name="Cache Control Headers Check", severity=Severity.LOW,
            category="Miscellaneous",
            description="Cek apakah Cache-Control header mencegah caching data sensitif.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    def _check_internal_ip_disclosure(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        ip_pattern = r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'
        match = re.search(ip_pattern, html)
        if match:
            detected = True
            evidence = f"Internal IP address found in page: {match.group()}"

        return [self.make_result(
            bug_id="MISC-179", name="Internal IP Address Disclosure", severity=Severity.LOW,
            category="Miscellaneous",
            description="Deteksi alamat IP internal yang bocor di halaman web.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    async def _check_clientaccesspolicy(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", "clientaccesspolicy.xml")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if 'domain="*"' in text or "allow-from" in text:
                        detected = True
                        evidence = f"clientaccesspolicy.xml found with permissive policy at {url}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="MISC-180", name="ClientAccessPolicy.xml Misconfiguration", severity=Severity.MEDIUM,
            category="Miscellaneous",
            description="Cek clientaccesspolicy.xml yang terlalu permissive.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    def _check_sensitive_form_action(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        soup = self.parse_html(html)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith("http://") and target_url.startswith("https://"):
                detected = True
                evidence = f"Form submits to insecure HTTP endpoint: {action[:100]}"
                break

        return [self.make_result(
            bug_id="MISC-181", name="Insecure Form Action", severity=Severity.MEDIUM,
            category="Miscellaneous",
            description="Deteksi form yang submit data ke endpoint HTTP (bukan HTTPS).",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]
