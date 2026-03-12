import aiohttp
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class LoggingScanner(BaseModule):
    """Scans for: Log File Exposure, Error Log Leakage"""

    LOG_PATHS = [
        "error.log", "access.log", "debug.log", "app.log",
        "laravel.log", "storage/logs/laravel.log",
        "logs/error.log", "logs/access.log", "log/error.log",
        "var/log/apache2/error.log", "wp-content/debug.log",
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_log_files(session, target_url))
        results.extend(await self._check_security_txt(session, target_url))
        return results

    async def _check_log_files(self, session, target_url) -> list:
        detected = False
        evidence_parts = []

        for path in self.LOG_PATHS:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        log_indicators = ["error", "warning", "notice", "fatal",
                                          "stack trace", "exception", "[", "timestamp"]
                        if any(w in text.lower()[:500] for w in log_indicators):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="LOG-170", name="Log File Exposure", severity=Severity.HIGH,
            category="Logging & Monitoring",
            description="Cek file log yang terekspos dan bisa diakses publik.",
            detected=detected, evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_security_txt(self, session, target_url) -> list:
        detected = False
        evidence = ""
        paths = [".well-known/security.txt", "security.txt"]
        found = False
        for p in paths:
            url = urljoin(target_url.rstrip("/") + "/", p)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "contact:" in text.lower():
                            found = True
                            break
            except Exception:
                pass

        if not found:
            detected = True
            evidence = "security.txt not found (RFC 9116 recommended)"

        return [self.make_result(
            bug_id="LOG-171", name="Missing security.txt", severity=Severity.INFO,
            category="Logging & Monitoring",
            description="Cek apakah security.txt tersedia sesuai RFC 9116.",
            detected=detected, evidence=evidence,
        )]
