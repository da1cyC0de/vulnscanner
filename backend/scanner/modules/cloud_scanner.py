import aiohttp
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CloudScanner(BaseModule):
    """Scans for: Kubernetes Dashboard, Docker API, AWS Metadata SSRF,
    Firebase Misconfiguration"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_cloud_metadata(session, target_url))
        results.extend(await self._check_firebase(session, target_url))
        results.extend(await self._check_k8s_docker(session, target_url))
        return results

    async def _check_cloud_metadata(self, session, target_url) -> list:
        detected = False
        evidence = ""
        html, resp = await self.fetch_text(session, target_url)
        if html:
            metadata_urls = [
                "http://169.254.169.254", "http://metadata.google.internal",
                "http://169.254.170.2",
            ]
            for meta_url in metadata_urls:
                if meta_url in html:
                    detected = True
                    evidence = f"Cloud metadata URL reference found: {meta_url}"
                    break

        return [self.make_result(
            bug_id="CLOUD-151", name="Cloud Metadata SSRF Risk", severity=Severity.HIGH,
            category="Cloud & Container",
            description="Deteksi referensi ke cloud metadata endpoint (AWS/GCP/Azure).",
            detected=detected, evidence=evidence,
        )]

    async def _check_firebase(self, session, target_url) -> list:
        detected = False
        evidence = ""
        html, _ = await self.fetch_text(session, target_url)
        if html:
            import re
            firebase_match = re.search(r'(https://[a-zA-Z0-9-]+\.firebaseio\.com)', html)
            if firebase_match:
                fb_url = firebase_match.group(1) + "/.json"
                try:
                    async with session.get(fb_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="replace")
                            if text != "null" and len(text) > 5:
                                detected = True
                                evidence = f"Firebase database publicly accessible: {fb_url}"
                except Exception:
                    pass

        return [self.make_result(
            bug_id="CLOUD-153", name="Firebase Database Misconfiguration", severity=Severity.CRITICAL,
            category="Cloud & Container",
            description="Cek Firebase Realtime Database yang bisa diakses publik.",
            detected=detected, evidence=evidence,
        )]

    async def _check_k8s_docker(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        exposed_paths = [
            "dashboard", "kubernetes-dashboard", "api/v1/namespaces",
        ]
        for path in exposed_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["kubernetes", "docker", "namespace", "container"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="CLOUD-149", name="Kubernetes/Docker Dashboard Exposed", severity=Severity.CRITICAL,
            category="Cloud & Container",
            description="Cek Kubernetes Dashboard atau Docker API yang terekspos.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]
