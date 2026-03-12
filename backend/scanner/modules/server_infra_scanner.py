import aiohttp
import re
from urllib.parse import urljoin, urlparse
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ServerInfraScanner(BaseModule):
    """Scans for: Subdomain hints, DNS info, Web Server Misconfiguration,
    PHP Info, GraphQL Introspection"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_server_status(session, target_url))
        results.extend(await self._check_phpinfo(session, target_url))
        results.extend(await self._check_graphql(session, target_url))
        results.extend(await self._check_cors_wildcard(session, target_url))
        results.extend(await self._check_default_pages(session, target_url))
        return results

    async def _check_server_status(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        status_paths = ["server-status", "server-info", "nginx_status",
                        "status", ".well-known/", "info.php"]
        for path in status_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["apache", "nginx", "server", "uptime", "requests"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRV-071", name="Web Server Status Page Exposed", severity=Severity.MEDIUM,
            category="Server & Infrastructure",
            description="Cek halaman status web server (Apache/Nginx status) yang terekspos.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_phpinfo(self, session, target_url) -> list:
        detected = False
        evidence = ""
        phpinfo_paths = ["phpinfo.php", "info.php", "php_info.php", "test.php", "i.php"]

        for path in phpinfo_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "phpinfo()" in text or "PHP Version" in text:
                            detected = True
                            evidence = f"phpinfo() page found at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRV-072", name="PHP Info Page Exposure", severity=Severity.HIGH,
            category="Server & Infrastructure",
            description="Cek halaman phpinfo() yang terekspos.",
            detected=detected, evidence=evidence,
        )]

    async def _check_graphql(self, session, target_url) -> list:
        detected = False
        evidence = ""
        graphql_paths = ["graphql", "graphiql", "api/graphql", "gql"]

        introspection_query = '{"query":"{ __schema { types { name } } }"}'

        for path in graphql_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                headers = self._default_headers()
                headers["Content-Type"] = "application/json"
                async with session.post(url, data=introspection_query, headers=headers,
                                        ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "__schema" in text or "types" in text:
                            detected = True
                            evidence = f"GraphQL introspection enabled at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="SRV-074", name="GraphQL Introspection Enabled", severity=Severity.MEDIUM,
            category="Server & Infrastructure",
            description="Cek apakah GraphQL introspection query aktif.",
            detected=detected, evidence=evidence,
        )]

    async def _check_cors_wildcard(self, session, target_url) -> list:
        detected = False
        evidence = ""
        try:
            headers = self._default_headers()
            headers["Origin"] = "https://attacker.com"
            async with session.get(target_url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "https://attacker.com" and acac.lower() == "true":
                    detected = True
                    evidence = f"Server reflects origin 'attacker.com' WITH credentials — critical CORS misconfiguration"
        except Exception:
            pass

        return [self.make_result(
            bug_id="SRV-075", name="CORS Origin Reflection with Credentials", severity=Severity.HIGH,
            category="Server & Infrastructure",
            description="Cek apakah server me-reflect origin attacker + allow credentials.",
            detected=detected, evidence=evidence,
        )]

    async def _check_default_pages(self, session, target_url) -> list:
        detected = False
        evidence = ""
        default_sigs = {
            "Apache": "it works", "Nginx": "welcome to nginx",
            "IIS": "iis windows server", "Tomcat": "apache tomcat",
        }
        try:
            async with session.get(target_url, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                text_lower = text.lower()
                for server, sig in default_sigs.items():
                    if sig in text_lower:
                        detected = True
                        evidence = f"Default {server} page detected — server not configured properly"
                        break
        except Exception:
            pass

        return [self.make_result(
            bug_id="SRV-076", name="Default Web Server Page", severity=Severity.LOW,
            category="Server & Infrastructure",
            description="Deteksi halaman default web server (Apache, Nginx, IIS, Tomcat).",
            detected=detected, evidence=evidence,
        )]
