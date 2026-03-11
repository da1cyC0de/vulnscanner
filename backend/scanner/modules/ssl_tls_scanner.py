import aiohttp
import ssl
import socket
from urllib.parse import urlparse
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class SslTlsScanner(BaseModule):
    """Scans for: SSL Certificate Check, Weak Cipher, Mixed Content, HTTP/HTTPS Redirect"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        results.extend(await self._check_ssl_cert(hostname, port))
        results.extend(await self._check_https_redirect(session, target_url))
        results.extend(await self._check_mixed_content(session, target_url))
        results.extend(await self._check_hsts_preload(session, target_url))

        return results

    async def _check_ssl_cert(self, hostname, port) -> list:
        detected = False
        evidence = ""
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            conn.settimeout(10)
            conn.connect((hostname, 443))
            cert = conn.getpeercert()
            conn.close()

            import datetime
            not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            if not_after < datetime.datetime.now():
                detected = True
                evidence = f"SSL certificate expired: {cert['notAfter']}"
        except ssl.SSLCertVerificationError as e:
            detected = True
            evidence = f"SSL certificate error: {str(e)[:200]}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="SSL-040", name="SSL Certificate Check", severity=Severity.HIGH,
            category="SSL/TLS & Network",
            description="Cek SSL certificate (expired, self-signed, invalid).",
            detected=detected, evidence=evidence,
        )]

    async def _check_https_redirect(self, session, target_url) -> list:
        detected = False
        evidence = ""
        parsed = urlparse(target_url)
        if parsed.scheme == "https":
            http_url = target_url.replace("https://", "http://", 1)
        else:
            http_url = target_url

        try:
            async with session.get(http_url, ssl=False, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status not in (301, 302, 307, 308):
                    detected = True
                    evidence = f"HTTP ({http_url}) does not redirect to HTTPS (status: {resp.status})"
                else:
                    location = resp.headers.get("Location", "")
                    if not location.startswith("https://"):
                        detected = True
                        evidence = f"Redirects to non-HTTPS: {location}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="SSL-043", name="HTTP/HTTPS Redirect Check", severity=Severity.MEDIUM,
            category="SSL/TLS & Network",
            description="Cek apakah HTTP redirect ke HTTPS.",
            detected=detected, evidence=evidence,
        )]

    async def _check_mixed_content(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        parsed = urlparse(target_url)

        if parsed.scheme == "https":
            html, _ = await self.fetch_text(session, target_url)
            if html:
                import re
                http_resources = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', html)
                if http_resources:
                    detected = True
                    evidence_parts = http_resources[:5]

        return [self.make_result(
            bug_id="SSL-042", name="Mixed Content Detection", severity=Severity.MEDIUM,
            category="SSL/TLS & Network",
            description="Deteksi resource HTTP yang dimuat dari halaman HTTPS.",
            detected=detected, evidence="\n".join(evidence_parts),
        )]

    async def _check_hsts_preload(self, session, target_url) -> list:
        detected = False
        evidence = ""
        _, resp = await self.fetch_text(session, target_url)
        if resp:
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                detected = True
                evidence = "HSTS header missing entirely"
            elif "preload" not in hsts.lower():
                detected = True
                evidence = f"HSTS missing preload directive: {hsts}"

        return [self.make_result(
            bug_id="SSL-105", name="HSTS Preload Check", severity=Severity.LOW,
            category="SSL/TLS & Network",
            description="Cek apakah HSTS preload directive aktif.",
            detected=detected, evidence=evidence,
        )]
