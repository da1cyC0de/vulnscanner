import aiohttp
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CacheProxyScanner(BaseModule):
    """Scans for: Web Cache Poisoning, Cache Deception"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_cache_poisoning(session, target_url))
        results.extend(await self._check_cache_deception(session, target_url))
        results.extend(await self._check_proxy_misconfiguration(session, target_url))
        return results

    async def _check_cache_poisoning(self, session, target_url) -> list:
        detected = False
        evidence = ""
        try:
            headers = self._default_headers()
            headers["X-Forwarded-Host"] = "evil.com"
            async with session.get(target_url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                if "evil.com" in text:
                    detected = True
                    evidence = "X-Forwarded-Host 'evil.com' reflected in response (cache poisoning risk)"
        except Exception:
            pass

        return [self.make_result(
            bug_id="CACHE-111", name="Web Cache Poisoning", severity=Severity.HIGH,
            category="Cache & Proxy",
            description="Tes Web Cache Poisoning via X-Forwarded-Host header.",
            detected=detected, evidence=evidence,
        )]

    async def _check_cache_deception(self, session, target_url) -> list:
        detected = False
        evidence = ""
        try:
            test_url = target_url.rstrip("/") + "/nonexistent.css"
            async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    cache_header = resp.headers.get("X-Cache", resp.headers.get("CF-Cache-Status", ""))
                    if cache_header and "hit" in cache_header.lower():
                        detected = True
                        evidence = f"Page cached with static extension: {test_url} (Cache: {cache_header})"
                    elif "text/html" in resp.headers.get("Content-Type", ""):
                        detected = True
                        evidence = f"HTML content served for CSS URL: {test_url} (cache deception risk)"
        except Exception:
            pass

        return [self.make_result(
            bug_id="CACHE-112", name="Web Cache Deception", severity=Severity.HIGH,
            category="Cache & Proxy",
            description="Tes Web Cache Deception Attack.",
            detected=detected, evidence=evidence,
        )]

    async def _check_proxy_misconfiguration(self, session, target_url) -> list:
        detected = False
        evidence = ""
        headers = self._default_headers()
        headers["X-Forwarded-For"] = "127.0.0.1"
        headers["X-Original-URL"] = "/admin"
        headers["X-Rewrite-URL"] = "/admin"
        try:
            async with session.get(target_url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                if any(w in text.lower() for w in ["admin", "dashboard", "panel", "forbidden"]):
                    if resp.status == 200 and "admin" in text.lower():
                        detected = True
                        evidence = "X-Original-URL/X-Rewrite-URL bypass may work - admin content in response"
        except Exception:
            pass

        return [self.make_result(
            bug_id="CACHE-113", name="Reverse Proxy Bypass", severity=Severity.HIGH,
            category="Cache & Proxy",
            description="Cek bypass access control via X-Original-URL / X-Rewrite-URL headers.",
            detected=detected, evidence=evidence,
        )]
