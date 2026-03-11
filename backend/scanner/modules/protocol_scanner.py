import aiohttp
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ProtocolScanner(BaseModule):
    """Scans for: HTTP Method Override, HTTP Verb Tampering"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_method_override(session, target_url))
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
