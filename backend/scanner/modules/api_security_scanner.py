import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ApiSecurityScanner(BaseModule):
    """Scans for: API Endpoint Discovery, HTTP Method Tampering, Rate Limiting, Mass Assignment"""

    API_PATHS = [
        "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
        "api/users", "api/admin", "api/config", "api/status",
        "api/health", "api/docs", "api/swagger", "api/openapi",
        "v1", "v2", "swagger.json", "openapi.json",
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_api_endpoints(session, target_url))
        results.extend(await self._check_http_methods(session, target_url))
        results.extend(await self._check_rate_limiting(session, target_url))
        results.extend(await self._check_swagger_exposure(session, target_url))
        results.extend(await self._check_api_version_disclosure(session, target_url))
        return results

    async def _check_api_endpoints(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        for path in self.API_PATHS:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "")
                        if "json" in ct or "xml" in ct:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url} ({ct})")
            except Exception:
                pass

        return [self.make_result(
            bug_id="API-046", name="API Endpoint Discovery", severity=Severity.INFO,
            category="API Security",
            description="Deteksi endpoint API yang bisa diakses.",
            detected=detected, evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_http_methods(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE"]

        for method in dangerous_methods:
            try:
                async with session.request(method, target_url, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status not in (405, 501, 403, 404):
                        detected = True
                        evidence_parts.append(f"{method} → {resp.status}")
            except Exception:
                pass

        try:
            async with session.options(target_url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                allow = resp.headers.get("Allow", "")
                if allow:
                    for m in dangerous_methods:
                        if m in allow.upper():
                            detected = True
                            evidence_parts.append(f"OPTIONS Allow header includes: {allow}")
                            break
        except Exception:
            pass

        return [self.make_result(
            bug_id="API-047", name="HTTP Method Tampering", severity=Severity.MEDIUM,
            category="API Security",
            description="Cek apakah HTTP methods berbahaya (PUT, DELETE, TRACE) diizinkan.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_rate_limiting(self, session, target_url) -> list:
        detected = False
        evidence = ""
        success_count = 0
        for _ in range(20):
            try:
                async with session.get(target_url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        success_count += 1
                    elif resp.status == 429:
                        break
            except Exception:
                break

        if success_count >= 20:
            detected = True
            evidence = f"20 rapid requests all returned 200 - no rate limiting detected"

        return [self.make_result(
            bug_id="API-048", name="Rate Limiting Check", severity=Severity.MEDIUM,
            category="API Security",
            description="Cek apakah ada rate limiting untuk mencegah brute force.",
            detected=detected, evidence=evidence,
        )]

    async def _check_swagger_exposure(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        swagger_paths = [
            "swagger.json", "swagger/", "swagger-ui/", "swagger-ui.html",
            "api-docs", "api/docs", "openapi.json", "openapi.yaml",
            "docs", "redoc", "api/swagger",
        ]
        for path in swagger_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["swagger", "openapi", "api", "paths"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="API-134", name="Swagger/OpenAPI Docs Exposed", severity=Severity.MEDIUM,
            category="API Security",
            description="Cek apakah dokumentasi API (Swagger/OpenAPI) terekspos.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_api_version_disclosure(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        version_paths = ["api/", "api/v1/", "api/v2/", "api/v3/"]
        for path in version_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["version", "api_version", "v1", "v2"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] API version info at: {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="API-049", name="API Version Information Disclosure", severity=Severity.LOW,
            category="API Security",
            description="Cek apakah API version endpoint mengekspos informasi.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]
