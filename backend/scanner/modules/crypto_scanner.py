import aiohttp
import re
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CryptoScanner(BaseModule):
    """Scans for: Weak Hashing, Missing Certificate Transparency"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_weak_hashing(html, target_url))
        results.extend(self._check_insecure_random(html, target_url))
        results.extend(self._check_base64_secrets(html, target_url))
        return results

    def _check_weak_hashing(self, html, target_url) -> list:
        detected = False
        evidence_parts = []
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'

        md5s = re.findall(md5_pattern, html)
        sha1s = re.findall(sha1_pattern, html)

        if md5s:
            detected = True
            evidence_parts.append(f"Possible MD5 hash found: {md5s[0]}")
        if sha1s:
            detected = True
            evidence_parts.append(f"Possible SHA1 hash found: {sha1s[0]}")

        return [self.make_result(
            bug_id="CRYPT-144", name="Weak Hashing Detection", severity=Severity.LOW,
            category="Cryptographic",
            description="Deteksi penggunaan hash lemah (MD5, SHA1) di response.",
            detected=detected, endpoint=target_url if detected else "", evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_insecure_random(self, html, target_url) -> list:
        detected = False
        evidence = ""
        patterns = [
            r'Math\.random\(\)',
            r'random\.random\(\)',
            r'rand\(\)',
            r'mt_rand\(\)',
        ]
        for p in patterns:
            match = re.search(p, html)
            if match:
                detected = True
                evidence = f"Insecure random function found: {match.group()}"
                break

        return [self.make_result(
            bug_id="CRYPT-145", name="Insecure Random Number Generator", severity=Severity.MEDIUM,
            category="Cryptographic",
            description="Deteksi penggunaan fungsi random yang tidak aman secara kriptografis.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]

    def _check_base64_secrets(self, html, target_url) -> list:
        detected = False
        evidence = ""
        import base64
        b64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        matches = re.findall(b64_pattern, html)
        for m in matches[:10]:
            try:
                decoded = base64.b64decode(m).decode('utf-8', errors='replace')
                secret_keywords = ['password', 'secret', 'key', 'token', 'api_key', 'private']
                if any(kw in decoded.lower() for kw in secret_keywords):
                    detected = True
                    evidence = f"Base64-encoded secret found: {decoded[:80]}..."
                    break
            except Exception:
                pass

        return [self.make_result(
            bug_id="CRYPT-146", name="Base64 Encoded Secrets", severity=Severity.HIGH,
            category="Cryptographic",
            description="Deteksi secret yang di-encode Base64 di source code.",
            detected=detected, endpoint=target_url if detected else "", evidence=evidence,
        )]
