import aiohttp
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ProtocolScanner(BaseModule):
    """Scans for: HTTP Method Override, HTTP Verb Tampering"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_method_override(session, target_url))
        results.extend(await self._check_http_smuggling(session, target_url))
        results.extend(await self._check_trace_method(session, target_url))
        return results

    async def _check_method_override(self, session, target_url) -> list:
        detected = False
        evidence = ""
        override_headers = [
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Method-Override", "PUT"),
            ("X-HTTP-Method", "PATCH"),
        ]
        for header_name, method in override_headers:
            try:
                headers = self._default_headers()
                headers[header_name] = method
                async with session.post(target_url, headers=headers, ssl=False,
                                        timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        detected = True
                        evidence = f"HTTP Method Override accepted: {header_name}: {method} (status: {resp.status})"
                        break
            except Exception:
                pass

        return [self.make_result(
            bug_id="PROTO-121", name="HTTP Method Override", severity=Severity.MEDIUM,
            category="HTTP Protocol",
            description="Cek apakah server menerima HTTP method override headers.",
            detected=detected, evidence=evidence,
        )]

    async def _check_http_smuggling(self, session, target_url) -> list:
        detected = False
        evidence = ""
        try:
            headers = self._default_headers()
            headers["Transfer-Encoding"] = "chunked"
            headers["Content-Length"] = "4"
            async with session.post(target_url, data="0\r\n\r\n", headers=headers, ssl=False,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status in (200, 400):
                    te = resp.headers.get("Transfer-Encoding", "")
                    cl = resp.headers.get("Content-Length", "")
                    if te and cl:
                        detected = True
                        evidence = f"Server returns both TE and CL headers (smuggling risk)"
        except Exception:
            pass

        return [self.make_result(
            bug_id="PROTO-120", name="HTTP Request Smuggling", severity=Severity.HIGH,
            category="HTTP Protocol",
            description="Cek potensi HTTP Request Smuggling (TE/CL conflict).",
            detected=detected, evidence=evidence,
        )]

    async def _check_trace_method(self, session, target_url) -> list:
        detected = False
        evidence = ""
        try:
            async with session.request("TRACE", target_url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "trace" in text.lower() or resp.headers.get("Content-Type", "").startswith("message/http"):
                        detected = True
                        evidence = f"TRACE method enabled (XST risk), status: {resp.status}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="PROTO-122", name="TRACE Method Enabled (XST)", severity=Severity.MEDIUM,
            category="HTTP Protocol",
            description="Cek apakah TRACE method aktif (Cross-Site Tracing risk).",
            detected=detected, evidence=evidence,
        )]
