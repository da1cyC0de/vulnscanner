import aiohttp
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class EncodingBypassScanner(BaseModule):
    """Scans for: WAF Detection, HTTP Parameter Pollution"""

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "Akamai": ["akamai", "x-akamai-transformed"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Imperva": ["x-cdn", "incap_ses"],
    }

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._detect_waf(session, target_url))
        results.extend(await self._check_hpp(session, target_url))
        return results

    async def _detect_waf(self, session, target_url) -> list:
        detected = False
        evidence = ""

        try:
            async with session.get(target_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                headers_str = str(resp.headers).lower()
                server = resp.headers.get("Server", "").lower()

                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig in headers_str or sig in server:
                            detected = True
                            evidence = f"WAF detected: {waf_name} (signature: {sig})"
                            break
                    if detected:
                        break
        except Exception:
            pass

        return [self.make_result(
            bug_id="ENC-165", name="WAF Detection & Fingerprinting", severity=Severity.INFO,
            category="Encoding & Bypass",
            description="Deteksi dan identifikasi Web Application Firewall (WAF).",
            detected=detected, evidence=evidence,
        )]

    async def _check_hpp(self, session, target_url) -> list:
        detected = False
        evidence = ""
        test_url = f"{target_url.rstrip('/')}?id=1&id=2"
        try:
            async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                if resp.status == 200:
                    detected = True
                    evidence = "Server accepts duplicate parameters (HPP potential)"
        except Exception:
            pass

        return [self.make_result(
            bug_id="ENC-169", name="HTTP Parameter Pollution (HPP)", severity=Severity.LOW,
            category="Encoding & Bypass",
            description="Cek apakah server rentan terhadap HTTP Parameter Pollution.",
            detected=detected, evidence=evidence,
        )]
