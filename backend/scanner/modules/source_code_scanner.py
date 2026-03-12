import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class SourceCodeScanner(BaseModule):
    """Scans for: Git/SVN Exposure, Source Code Disclosure, API Key Leakage,
    Hardcoded Credentials, AWS/GCP/Azure Keys, Private Key Exposure, .env, config files"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)

        results.extend(await self._check_git_exposure(session, target_url))
        results.extend(await self._check_svn_exposure(session, target_url))
        results.extend(await self._check_env_file(session, target_url))
        results.extend(self._check_api_keys_in_js(html, target_url))
        results.extend(self._check_hardcoded_creds(html, target_url))
        results.extend(await self._check_private_keys(session, target_url))
        results.extend(await self._check_package_files(session, target_url))
        results.extend(await self._check_docker_exposure(session, target_url))
        results.extend(await self._check_cicd_config(session, target_url))
        results.extend(self._check_aws_credentials(html, target_url))

        return results

    async def _check_git_exposure(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", ".git/HEAD")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "ref:" in text:
                        detected = True
                        evidence = f"Git repository exposed at {url}: {text.strip()[:100]}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="SRC-075", name="Git Repository Exposure", severity=Severity.CRITICAL,
            category="Source Code & Secrets",
            description="Cek apakah folder .git terekspos dan bisa diakses.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    async def _check_svn_exposure(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", ".svn/entries")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if len(text) > 10 and "404" not in text.lower()[:100]:
                        detected = True
                        evidence = f"SVN repository exposed at {url}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="SRC-076", name="SVN Repository Exposure", severity=Severity.HIGH,
            category="Source Code & Secrets",
            description="Cek apakah folder .svn terekspos.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    async def _check_env_file(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", ".env")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "=" in text and any(k in text.upper() for k in ["DB_", "API_", "SECRET", "KEY", "PASSWORD", "TOKEN"]):
                        detected = True
                        evidence = f".env file exposed at {url}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="SRC-082", name=".env File Exposure", severity=Severity.CRITICAL,
            category="Source Code & Secrets",
            description="Cek apakah file .env terekspos dan berisi konfigurasi sensitif.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    def _check_api_keys_in_js(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence_parts = []
        patterns = [
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
            (r'(?:AKIA[0-9A-Z]{16})', "AWS Access Key"),
            (r'(?:sk-[a-zA-Z0-9]{20,})', "Secret Key pattern"),
            (r'(?:ghp_[a-zA-Z0-9]{36})', "GitHub Personal Token"),
            (r'(?:glpat-[a-zA-Z0-9\-]{20,})', "GitLab Token"),
        ]
        for pattern, label in patterns:
            matches = re.findall(pattern, html)
            if matches:
                detected = True
                evidence_parts.append(f"{label} found: {matches[0][:30]}...")

        return [self.make_result(
            bug_id="SRC-078", name="API Key Leakage in JavaScript", severity=Severity.HIGH,
            category="Source Code & Secrets",
            description="Deteksi API key yang terekspos di HTML/JavaScript source.",
            detected=detected, endpoint=target_url, evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_hardcoded_creds(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        patterns = [
            r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'(?:username|user)\s*[:=]\s*["\'](?:admin|root|test)["\'].*?(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                detected = True
                evidence = f"Hardcoded credential pattern found: {match.group()[:100]}"
                break

        return [self.make_result(
            bug_id="SRC-079", name="Hardcoded Credentials in Source", severity=Severity.HIGH,
            category="Source Code & Secrets",
            description="Deteksi password/credentials yang hardcoded di source code.",
            detected=detected, endpoint=target_url, evidence=evidence,
        )]

    async def _check_private_keys(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        key_files = ["server.key", "private.key", "id_rsa", "cert.pem", "key.pem"]

        for kf in key_files:
            url = urljoin(target_url.rstrip("/") + "/", kf)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "PRIVATE KEY" in text or "RSA PRIVATE" in text:
                            detected = True
                            evidence_parts.append(f"Private key exposed at: {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRC-081", name="Private Key File Exposure", severity=Severity.CRITICAL,
            category="Source Code & Secrets",
            description="Cek file private key (.pem, .key) yang terekspos.",
            detected=detected, endpoint=evidence_parts[0].split('at: ')[1] if evidence_parts else "", evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_package_files(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        package_paths = [
            "package.json", "composer.json", "Gemfile", "requirements.txt",
            "Pipfile", "go.mod", "pom.xml", "build.gradle",
        ]
        for pf in package_paths:
            url = urljoin(target_url.rstrip("/") + "/", pf)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if len(text) > 20 and "404" not in text.lower()[:100]:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRC-162", name="Package/Dependency File Exposure", severity=Severity.LOW,
            category="Source Code & Secrets",
            description="Deteksi file dependency (package.json, composer.json, dll) yang terekspos.",
            detected=detected, endpoint=evidence_parts[0].split('] ')[1] if evidence_parts else "", evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_docker_exposure(self, session, target_url) -> list:
        detected = False
        evidence = ""
        docker_paths = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]
        for dp in docker_paths:
            url = urljoin(target_url.rstrip("/") + "/", dp)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(k in text.lower() for k in ["from ", "run ", "expose", "services:", "image:"]):
                            detected = True
                            evidence = f"Docker config exposed at {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRC-077", name="Docker Configuration Exposed", severity=Severity.HIGH,
            category="Source Code & Secrets",
            description="Cek apakah file Dockerfile/docker-compose terekspos.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    async def _check_cicd_config(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        cicd_paths = [
            ".github/workflows/main.yml", ".gitlab-ci.yml", "Jenkinsfile",
            ".circleci/config.yml", ".travis.yml", "bitbucket-pipelines.yml",
        ]
        for cp in cicd_paths:
            url = urljoin(target_url.rstrip("/") + "/", cp)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if len(text) > 20 and "404" not in text.lower()[:100]:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRC-080", name="CI/CD Configuration Exposed", severity=Severity.HIGH,
            category="Source Code & Secrets",
            description="Cek file konfigurasi CI/CD yang terekspos (GitHub Actions, GitLab CI, dll).",
            detected=detected, endpoint=evidence_parts[0].split('] ')[1] if evidence_parts else "", evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_aws_credentials(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        patterns = [
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})', "AWS Secret Key"),
            (r'(?:ASIA[0-9A-Z]{16})', "AWS Temporary Access Key"),
        ]
        for pattern, label in patterns:
            match = re.search(pattern, html)
            if match:
                detected = True
                evidence = f"{label} found: {match.group()[:25]}..."
                break

        return [self.make_result(
            bug_id="SRC-083", name="AWS Credentials Exposed", severity=Severity.CRITICAL,
            category="Source Code & Secrets",
            description="Deteksi AWS access key/secret yang terekspos di source code.",
            detected=detected, endpoint=target_url, evidence=evidence,
        )]
