import aiohttp
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class SecurityHeadersScanner(BaseModule):
    """Scans for all security headers: CSP, X-Frame-Options, X-Content-Type-Options,
    HSTS, X-XSS-Protection, Referrer-Policy, Permissions-Policy"""

    HEADERS_CHECK = [
        ("Content-Security-Policy", "CSP-033", "Missing Content-Security-Policy", Severity.MEDIUM,
         "CSP mencegah XSS dan injection dengan membatasi sumber resource yang bisa dimuat."),
        ("X-Frame-Options", "HDR-034", "Missing X-Frame-Options", Severity.MEDIUM,
         "X-Frame-Options mencegah halaman di-embed dalam iframe (clickjacking)."),
        ("X-Content-Type-Options", "HDR-035", "Missing X-Content-Type-Options", Severity.LOW,
         "Mencegah browser melakukan MIME-type sniffing."),
        ("Strict-Transport-Security", "HDR-036", "Missing Strict-Transport-Security (HSTS)", Severity.MEDIUM,
         "HSTS memaksa browser menggunakan HTTPS."),
        ("X-XSS-Protection", "HDR-037", "Missing X-XSS-Protection", Severity.LOW,
         "X-XSS-Protection mengaktifkan built-in XSS filter browser."),
        ("Referrer-Policy", "HDR-038", "Missing Referrer-Policy", Severity.LOW,
         "Mengontrol berapa banyak informasi referrer yang dikirim."),
        ("Permissions-Policy", "HDR-039", "Missing Permissions-Policy", Severity.LOW,
         "Mengontrol fitur browser yang boleh digunakan (camera, mic, geolocation)."),
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        _, resp = await self.fetch_text(session, target_url)
        if not resp:
            return results

        for header_name, bug_id, name, severity, description in self.HEADERS_CHECK:
            header_value = resp.headers.get(header_name)
            missing = header_value is None
            weak = False
            evidence = ""

            if not missing:
                if header_name == "X-Frame-Options" and header_value.upper() not in ("DENY", "SAMEORIGIN"):
                    weak = True
                    evidence = f"Weak value: {header_value}"
                elif header_name == "X-XSS-Protection" and header_value.strip() == "0":
                    weak = True
                    evidence = "XSS Protection explicitly disabled (value: 0)"
                elif header_name == "Content-Security-Policy" and "unsafe-inline" in header_value:
                    weak = True
                    evidence = f"CSP contains 'unsafe-inline': {header_value[:200]}"

            results.append(self.make_result(
                bug_id=bug_id, name=name, severity=severity,
                category="Security Headers",
                description=description,
                detected=missing or weak,
                endpoint=target_url,
                evidence=evidence if evidence else (f"Header '{header_name}' not found in response" if missing else ""),
            ))

        return results
