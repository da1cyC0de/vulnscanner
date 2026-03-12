import aiohttp
import re
from urllib.parse import urljoin, urlparse
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CveScanner(BaseModule):
    """Scans for known critical CVEs via technology fingerprinting and active probes.

    CVEs covered:
      CVE-2025-29927  — Next.js Middleware Auth Bypass (CVSS 9.1)
      CVE-2024-4577   — PHP CGI Argument Injection / RCE (CVSS 9.8, Windows)
      CVE-2025-24813  — Apache Tomcat Partial PUT RCE (CVSS 9.8)
      CVE-2024-23897  — Jenkins CLI Arbitrary File Read (CVSS 9.8)
      CVE-2021-44228  — Log4Shell JNDI Injection (CVSS 10.0)
      CVE-2022-22965  — Spring4Shell RCE via DataBinder (CVSS 9.8)
      CVE-2025-68613  — n8n Workflow RCE (CVSS 9.9, CISA KEV 2026-03-11)
      CVE-2025-68929  — Frappe Framework SSTI RCE (CVSS 9.0)
      CVE-2026-32251  — Tolgee XXE / SSRF (CVSS 9.3)
      CVE-2026-32248  — Parse Server Account Takeover (CVSS 9.3)
      CVE-2026-32142  — Shopware /api/_info/config Disclosure (CVSS 5.3)
      CVE-2026-32230  — Uptime Kuma Private Monitor Exposure (CVSS 5.3)
    """

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)

        tech = self._fingerprint_tech(html or "", resp, target_url)

        results.extend(await self._check_nextjs_middleware_bypass(session, target_url, tech))
        results.extend(await self._check_php_cgi(session, target_url, tech))
        results.extend(await self._check_tomcat(session, target_url, resp, tech))
        results.extend(await self._check_jenkins(session, target_url))
        results.extend(await self._check_log4shell(session, target_url))
        results.extend(await self._check_spring4shell(session, target_url, tech))
        results.extend(await self._check_n8n(session, target_url, html or ""))
        results.extend(await self._check_frappe(session, target_url, html or ""))
        results.extend(await self._check_tolgee(session, target_url))
        results.extend(await self._check_parse_server(session, target_url, html or ""))
        results.extend(await self._check_shopware(session, target_url, html or ""))
        results.extend(await self._check_uptime_kuma(session, target_url))

        return results

    # ───────────────────────────────────────────────── helpers ────────────────

    def _fingerprint_tech(self, html: str, resp, target_url: str) -> dict:
        info = {
            "php_version": None,
            "tomcat_version": None,
            "server": "",
            "powered_by": "",
            "is_nextjs": False,
            "is_spring": False,
            "is_frappe": False,
            "is_n8n": False,
            "is_parse": False,
            "is_shopware": False,
            "is_tolgee": False,
            "is_uptime_kuma": False,
        }
        if resp:
            server = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")
            info["server"] = server
            info["powered_by"] = powered_by

            php_m = re.search(r'PHP/([\d.]+)', powered_by, re.I)
            if php_m:
                info["php_version"] = php_m.group(1)

            tc_m = re.search(r'Tomcat/([\d.]+)', server, re.I)
            if tc_m:
                info["tomcat_version"] = tc_m.group(1)
            elif "Apache-Coyote" in server or "Tomcat" in server:
                info["tomcat_version"] = "unknown"

        if html:
            h = html.lower()
            if "__next_data__" in h or "/_next/" in h or "_next/static" in h:
                info["is_nextjs"] = True
            if resp and "next.js" in resp.headers.get("X-Powered-By", "").lower():
                info["is_nextjs"] = True
            if "spring" in h and ("boot" in h or "webmvc" in h):
                info["is_spring"] = True
            if "/assets/frappe/" in h or '"frappe' in h:
                info["is_frappe"] = True
            if "n8n" in h and ("workflow" in h or "n8n.io" in h):
                info["is_n8n"] = True
            if "parseapp" in h or "parse-server" in h or "x-parse-" in h.lower():
                info["is_parse"] = True
            if "shopware" in h or "/storefront/" in h:
                info["is_shopware"] = True
            if "tolgee" in h:
                info["is_tolgee"] = True
            if "uptime kuma" in h or "uptimekuma" in h:
                info["is_uptime_kuma"] = True

        return info

    # ───────────────────────────────── CVE checks ─────────────────────────────

    async def _check_nextjs_middleware_bypass(self, session, target_url, tech) -> list:
        """CVE-2025-29927 — Next.js <14.2.25 / <15.2.3 middleware auth bypass."""
        if not tech["is_nextjs"]:
            # Still probe — fingerprint from HTML may miss server-rendered Next.js
            pass

        detected = False
        evidence = ""
        bypass_header = "middleware:middleware:middleware:middleware:middleware"
        protected_paths = ["/admin", "/dashboard", "/api/admin", "/api/auth/session"]

        for path in protected_paths:
            url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                # First: request without bypass header to get baseline
                headers_normal = self._default_headers()
                async with session.get(url, headers=headers_normal, ssl=False,
                                       allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r_normal:
                    baseline_status = r_normal.status

                if baseline_status not in (301, 302, 307, 308, 401, 403):
                    continue  # Not a protected path

                # Then: request WITH bypass header
                headers_bypass = self._default_headers()
                headers_bypass["x-middleware-subrequest"] = bypass_header
                async with session.get(url, headers=headers_bypass, ssl=False,
                                       allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r_bypass:
                    if r_bypass.status == 200 and baseline_status in (301, 302, 307, 308, 401, 403):
                        detected = True
                        evidence = (
                            f"CVE-2025-29927: Next.js middleware bypassed at {url} — "
                            f"baseline {baseline_status} → bypass 200 with "
                            f"x-middleware-subrequest header"
                        )
                        break
            except Exception:
                pass
            if detected:
                break

        return [self.make_result(
            bug_id="CVE-2025-29927",
            name="Next.js Middleware Auth Bypass",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2025-29927: Next.js <14.2.25 / <15.2.3 — attacker dapat bypass "
                "middleware authentication dengan header x-middleware-subrequest, "
                "mengakses halaman admin/protected tanpa login."
            ),
            detected=detected,
            endpoint=url if detected else "",
            evidence=evidence,
        )]

    async def _check_php_cgi(self, session, target_url, tech) -> list:
        """CVE-2024-4577 — PHP CGI argument injection (PHP on Windows / XAMPP)."""
        detected = False
        evidence = ""
        php_detected = bool(tech["php_version"] or "php" in tech["powered_by"].lower()
                            or "php" in tech["server"].lower())

        if not php_detected:
            return [self.make_result(
                bug_id="CVE-2024-4577",
                name="PHP CGI Argument Injection (RCE)",
                severity=Severity.CRITICAL,
                category="CVE / Known Exploits",
                description="CVE-2024-4577: PHP CGI RCE tidak terdeteksi — server tidak menggunakan PHP.",
                detected=False, evidence="",
            )]

        # /?-s causes PHP to output source code if PHP CGI mode is active
        test_url = target_url.rstrip("/") + "/?-s"
        try:
            async with session.get(test_url, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10),
                                   headers=self._default_headers()) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "<?php" in text or "<?=" in text or "<?" in text[:200]:
                        detected = True
                        evidence = (
                            f"CVE-2024-4577: PHP source code returned via /?-s — "
                            f"PHP CGI mode on Windows. PHP version: {tech['php_version'] or 'unknown'}"
                        )
        except Exception:
            pass

        return [self.make_result(
            bug_id="CVE-2024-4577",
            name="PHP CGI Argument Injection (RCE)",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2024-4577: PHP CGI mode di Windows (XAMPP/IIS) rentan terhadap "
                "argument injection. Attacker bisa execute arbitrary code via URL parameter. "
                "Fix: update PHP >= 8.3.8 / 8.2.20 / 8.1.29."
            ),
            detected=detected,
            endpoint=test_url if detected else "",
            evidence=evidence,
        )]

    async def _check_tomcat(self, session, target_url, resp, tech) -> list:
        """CVE-2025-24813 — Apache Tomcat Partial PUT RCE (<9.0.99 / <10.1.35 / <11.0.3)."""
        detected = False
        evidence = ""
        version = tech.get("tomcat_version")

        if not version:
            return [self.make_result(
                bug_id="CVE-2025-24813",
                name="Apache Tomcat Partial PUT RCE",
                severity=Severity.CRITICAL,
                category="CVE / Known Exploits",
                description="CVE-2025-24813: Apache Tomcat tidak terdeteksi.",
                detected=False, evidence="",
            )]

        # Check version against known vulnerable ranges
        version_vulnerable = False
        try:
            parts = [int(x) for x in version.split(".")[:2]]
            major, minor = parts[0], parts[1] if len(parts) > 1 else 0
            if major == 9 and minor < 99:
                version_vulnerable = True
            elif major == 10 and minor < 35:
                version_vulnerable = True
            elif major == 11 and minor < 3:
                version_vulnerable = True
        except Exception:
            version_vulnerable = True  # unknown version = potentially vulnerable

        if version_vulnerable:
            # Probe: try PUT with Content-Range to see if partial PUT is accepted
            test_url = urljoin(target_url.rstrip("/") + "/", "cve_probe_test.txt")
            try:
                headers = self._default_headers()
                headers["Content-Range"] = "bytes 0-3/10"
                headers["Content-Type"] = "text/plain"
                async with session.put(test_url, data=b"test", headers=headers,
                                       ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status in (200, 201, 204):
                        detected = True
                        evidence = (
                            f"CVE-2025-24813: Apache Tomcat {version} — partial PUT accepted "
                            f"(status {r.status}). Allows RCE via session file deserialization."
                        )
                    elif version_vulnerable:
                        # Version match alone is medium confidence
                        detected = True
                        evidence = (
                            f"CVE-2025-24813: Apache Tomcat version {version} is in vulnerable range "
                            f"(<9.0.99 / <10.1.35 / <11.0.3). Update immediately."
                        )
            except Exception:
                if version_vulnerable:
                    detected = True
                    evidence = (
                        f"CVE-2025-24813: Apache Tomcat version {version} is in vulnerable range. "
                        f"Update to 9.0.99+ / 10.1.35+ / 11.0.3+."
                    )

        return [self.make_result(
            bug_id="CVE-2025-24813",
            name="Apache Tomcat Partial PUT RCE",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2025-24813: Apache Tomcat Partial PUT RCE — server dengan "
                "DefaultServlet (partial PUT enabled) rentan. Attacker upload JSP shell "
                "via partial PUT → access file → RCE. Affects <9.0.99, <10.1.35, <11.0.3."
            ),
            detected=detected,
            endpoint=target_url if detected else "",
            evidence=evidence,
        )]

    async def _check_jenkins(self, session, target_url) -> list:
        """CVE-2024-23897 — Jenkins CLI arbitrary file read / RCE."""
        detected = False
        evidence = ""
        jenkins_paths = [
            "jenkins", "jenkins/", "ci", "hudson",
        ]
        jenkins_url = ""

        for path in jenkins_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       headers=self._default_headers()) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "jenkins" in text.lower() and ("dashboard" in text.lower()
                                                           or "build" in text.lower()
                                                           or "job" in text.lower()):
                            jenkins_url = url

                            # Check if CLI jar is downloadable (key indicator)
                            cli_url = urljoin(url.rstrip("/") + "/", "jnlpJars/jenkins-cli.jar")
                            async with session.get(cli_url, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=8)) as r_cli:
                                if r_cli.status == 200:
                                    detected = True
                                    evidence = (
                                        f"CVE-2024-23897: Jenkins CLI jar accessible at {cli_url}. "
                                        f"jenkins-cli.jar allows @/etc/passwd file read via CLI args. "
                                        f"Versions with agent-to-controller security disabled are RCE-vulnerable."
                                    )
                                    break
                            if not detected and jenkins_url:
                                detected = True
                                evidence = (
                                    f"CVE-2024-23897: Jenkins instance found at {jenkins_url}. "
                                    f"Check if running < 2.442 (LTS) / 2.470 (weekly)."
                                )
                            break
            except Exception:
                pass
            if detected:
                break

        return [self.make_result(
            bug_id="CVE-2024-23897",
            name="Jenkins CLI Arbitrary File Read",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2024-23897: Jenkins < 2.442 LTS — CLI args-as-files feature memungkinkan "
                "unauthenticated attacker membaca file arbitrary di server. "
                "Jika agent-to-controller disabled → RCE. Fix: update Jenkins >= 2.442 LTS."
            ),
            detected=detected,
            endpoint=jenkins_url if detected else "",
            evidence=evidence,
        )]

    async def _check_log4shell(self, session, target_url) -> list:
        """CVE-2021-44228 — Log4Shell JNDI injection via HTTP headers."""
        detected = False
        evidence = ""

        # Inject Log4Shell payload into various headers and check if it appears in error output
        jndi_payload = "${jndi:ldap://0.0.0.0/}"
        headers = self._default_headers()
        headers["User-Agent"] = jndi_payload
        headers["X-Forwarded-For"] = jndi_payload
        headers["Referer"] = jndi_payload
        headers["X-Api-Version"] = jndi_payload

        try:
            async with session.get(target_url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                # Direct reflection is rare but check if error reveals Java stack trace
                if any(kw in text for kw in [
                    "log4j", "JndiLookup", "log4j2", "org.apache.logging",
                    "javax.naming", "InitialContext", "jndi:"
                ]):
                    detected = True
                    evidence = (
                        "CVE-2021-44228: Log4Shell indicator — JNDI/Log4j related "
                        f"string reflected in response when injecting JNDI payload in headers. "
                        f"Server may be running vulnerable Log4j2 < 2.15.0."
                    )
        except Exception:
            pass

        # Also check for exposed log4j2 config files
        if not detected:
            for path in ["log4j2.xml", "log4j2-test.xml", "log4j.properties",
                         "WEB-INF/log4j2.xml", "WEB-INF/classes/log4j2.xml"]:
                url = urljoin(target_url.rstrip("/") + "/", path)
                try:
                    async with session.get(url, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=6),
                                           headers=self._default_headers()) as r:
                        if r.status == 200:
                            text = await r.text(errors="replace")
                            if "log4j" in text.lower() or "Configuration" in text:
                                detected = True
                                evidence = f"CVE-2021-44228: Log4j2 config file exposed at {url}"
                                break
                except Exception:
                    pass

        return [self.make_result(
            bug_id="CVE-2021-44228",
            name="Log4Shell — Log4j2 JNDI Injection",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2021-44228 (Log4Shell): Log4j2 <2.15.0 — JNDI lookup via ${jndi:ldap://...} "
                "dalam HTTP headers atau input fields menyebabkan RCE. "
                "Fix: upgrade Log4j2 >= 2.17.1, atau set log4j2.formatMsgNoLookups=true."
            ),
            detected=detected,
            endpoint=target_url if detected else "",
            evidence=evidence,
        )]

    async def _check_spring4shell(self, session, target_url, tech) -> list:
        """CVE-2022-22965 — Spring4Shell / Spring Core RCE."""
        detected = False
        evidence = ""

        if not tech["is_spring"]:
            # Check via Content-Type header response too
            pass

        # Probe: send class.module.classLoader parameter (Spring4Shell trigger)
        test_payloads = [
            {"class.module.classLoader.resources.context.configFile": "malicious"},
        ]
        try:
            headers = self._default_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            payload = "class.module.classLoader.resources.context.configFile=malicious"
            async with session.post(target_url, data=payload, headers=headers,
                                    ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                if resp.status == 400:
                    # 400 with specific Spring error message = Spring app is present
                    if "spring" in text.lower() or "Failed to convert" in text:
                        detected = True
                        evidence = (
                            "CVE-2022-22965: Spring Framework detected. "
                            "Server returned Spring-specific 400 error for class.module.classLoader "
                            "parameter. Verify Spring version < 5.3.18 / 5.2.20 for Spring4Shell."
                        )
                elif resp.status == 200 and tech["is_spring"]:
                    detected = True
                    evidence = (
                        "CVE-2022-22965: Spring Framework responded 200 to class.module.classLoader "
                        "probe. App may be vulnerable to Spring4Shell RCE. "
                        "Verify Spring version and WAR deployment on Tomcat."
                    )
        except Exception:
            pass

        # Also check Spring Boot Actuator /env for version fingerprint
        if not detected:
            actuator_url = urljoin(target_url.rstrip("/") + "/", "actuator/env")
            try:
                async with session.get(actuator_url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       headers=self._default_headers()) as r:
                    if r.status == 200:
                        text = await r.text(errors="replace")
                        if "spring" in text.lower() and ("version" in text.lower() or "classpath" in text.lower()):
                            detected = True
                            evidence = (
                                f"CVE-2022-22965: Spring Boot Actuator /env exposed at "
                                f"{actuator_url} — reveals Spring version and classpath. "
                                f"Check if Spring Core < 5.3.18."
                            )
            except Exception:
                pass

        return [self.make_result(
            bug_id="CVE-2022-22965",
            name="Spring4Shell — Spring Core RCE",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2022-22965 (Spring4Shell): Spring Framework <5.3.18 / <5.2.20 yang "
                "di-deploy sebagai WAR di Tomcat rentan RCE via class.module.classLoader. "
                "Fix: upgrade Spring Framework >= 5.3.18, atau Spring Boot >= 2.6.6."
            ),
            detected=detected,
            endpoint=target_url if detected else "",
            evidence=evidence,
        )]

    async def _check_n8n(self, session, target_url, html) -> list:
        """CVE-2025-68613 — n8n Workflow RCE (CVSS 9.9, CISA KEV 2026-03-11)."""
        detected = False
        evidence = ""

        is_n8n = "n8n" in html.lower() or "n8n.io" in html.lower()

        n8n_paths = [
            "workflow", "workflows", "#/workflows",
            "api/v1/workflows", "rest/workflows",
        ]
        n8n_url = ""

        for path in n8n_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       headers=self._default_headers()) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "n8n" in text.lower() or "workflow" in text.lower():
                            n8n_url = url
                            detected = True
                            evidence = (
                                f"CVE-2025-68613: n8n workflow interface exposed at {url}. "
                                f"n8n <1.120.4 allows authenticated RCE via expression injection "
                                f"in workflow configuration. CISA KEV — actively exploited."
                            )
                            break
            except Exception:
                pass
            if detected:
                break

        if not detected and is_n8n:
            detected = True
            evidence = (
                "CVE-2025-68613: n8n detected in page source. "
                "Verify n8n version — versions 0.211.0 to <1.120.4 are vulnerable to "
                "authenticated RCE via expression evaluation. CVSS 9.9."
            )
            n8n_url = target_url

        return [self.make_result(
            bug_id="CVE-2025-68613",
            name="n8n Workflow Expression RCE",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2025-68613 (CISA KEV): n8n 0.211.0 – <1.120.4 — expression evaluation "
                "dalam workflow tidak terisolasi cukup. Authenticated attacker bisa RCE "
                "dengan privileges n8n process. Fix: update n8n >= 1.120.4."
            ),
            detected=detected,
            endpoint=n8n_url if detected else "",
            evidence=evidence,
        )]

    async def _check_frappe(self, session, target_url, html) -> list:
        """CVE-2025-68929 — Frappe Framework SSTI → RCE (CVSS 9.0)."""
        detected = False
        evidence = ""

        is_frappe = "/assets/frappe/" in html or '"frappe' in html or "frappe" in html.lower()

        if is_frappe:
            # Confirm via /api/method/frappe.ping
            ping_url = urljoin(target_url.rstrip("/") + "/", "api/method/frappe.ping")
            try:
                async with session.get(ping_url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       headers=self._default_headers()) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "pong" in text.lower():
                            detected = True
                            evidence = (
                                f"CVE-2025-68929: Frappe Framework confirmed at {ping_url}. "
                                f"Frappe <14.99.6 / <15.88.1 — SSTI via crafted URL allows RCE. "
                                f"Fix: upgrade to Frappe 14.99.6+ or 15.88.1+."
                            )
                        else:
                            detected = True
                            evidence = (
                                f"CVE-2025-68929: Frappe Framework API active at {ping_url}. "
                                f"Verify Frappe version < 14.99.6 / 15.88.1 for SSTI RCE."
                            )
            except Exception:
                detected = True
                evidence = (
                    "CVE-2025-68929: Frappe Framework detected in page source. "
                    "Versions <14.99.6 / <15.88.1 vulnerable to SSTI RCE."
                )

        return [self.make_result(
            bug_id="CVE-2025-68929",
            name="Frappe Framework SSTI RCE",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2025-68929: Frappe <14.99.6 / <15.88.1 — authenticated user bisa "
                "diarahkan ke URL yang mengeksekusi Jinja template berbahaya di server, "
                "menghasilkan Remote Code Execution. Fix: upgrade Frappe segera."
            ),
            detected=detected,
            endpoint=target_url if detected else "",
            evidence=evidence,
        )]

    async def _check_tolgee(self, session, target_url) -> list:
        """CVE-2026-32251 — Tolgee XXE/SSRF (CVSS 9.3, unauthenticated file read)."""
        detected = False
        evidence = ""

        # Check for Tolgee API endpoint exposure
        tolgee_paths = ["api/public/projects", "api/v2/projects",
                        "api/public/server", "api/v2/administration/usage"]
        tolgee_url = ""

        for path in tolgee_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=6),
                                       headers=self._default_headers()) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "")
                        if "json" in ct:
                            text = await resp.text(errors="replace")
                            if any(k in text for k in ["organizationId", "projectId", "Tolgee", "tolgee"]):
                                detected = True
                                tolgee_url = url
                                evidence = (
                                    f"CVE-2026-32251: Tolgee localization platform API exposed "
                                    f"at {url}. Tolgee <3.166.3 — XML import allows XXE/SSRF. "
                                    f"Authenticated users can read arbitrary files from server."
                                )
                                break
            except Exception:
                pass
            if detected:
                break

        return [self.make_result(
            bug_id="CVE-2026-32251",
            name="Tolgee XXE / SSRF via XML Import",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2026-32251: Tolgee <3.166.3 — XML parser untuk import Android/resx files "
                "tidak menonaktifkan external entity processing, memungkinkan XXE dan SSRF. "
                "Fix: update Tolgee >= 3.166.3."
            ),
            detected=detected,
            endpoint=tolgee_url if detected else "",
            evidence=evidence,
        )]

    async def _check_parse_server(self, session, target_url, html) -> list:
        """CVE-2026-32248 — Parse Server account takeover via anonymous auth (CVSS 9.3)."""
        detected = False
        evidence = ""

        is_parse = (
            "parse-server" in html.lower()
            or "x-parse-application-id" in html.lower()
            or any(x in html for x in ["ParseUser", "Parse.initialize", "Parse.Cloud"])
        )

        parse_paths = ["parse/users", "1/users", "api/parse/users", "parse/login"]

        for path in parse_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       headers=self._default_headers()) as resp:
                    if resp.status in (200, 400, 401):
                        text = await resp.text(errors="replace")
                        if "objectId" in text or "sessionToken" in text or \
                           "code" in text and "error" in text:
                            detected = True
                            evidence = (
                                f"CVE-2026-32248: Parse Server API endpoint detected at {url}. "
                                f"Parse Server <9.6.0-alpha.12 / <8.6.38 — anonymous auth "
                                f"allows account takeover via NoSQL injection in login. "
                                f"Fix: update Parse Server."
                            )
                            break
            except Exception:
                pass
            if detected:
                break

        if not detected and is_parse:
            detected = True
            evidence = (
                "CVE-2026-32248: Parse Server JavaScript SDK detected in page. "
                "Verify Parse Server version < 9.6.0-alpha.12 / 8.6.38 for account takeover."
            )

        return [self.make_result(
            bug_id="CVE-2026-32248",
            name="Parse Server Account Takeover",
            severity=Severity.CRITICAL,
            category="CVE / Known Exploits",
            description=(
                "CVE-2026-32248: Parse Server <9.6.0-alpha.12 / <8.6.38 — attacker bisa "
                "ambil alih akun apapun yang dibuat dengan anonymous auth via crafted login "
                "request (NoSQL pattern injection). Fix: update Parse Server."
            ),
            detected=detected,
            endpoint=target_url if detected else "",
            evidence=evidence,
        )]

    async def _check_shopware(self, session, target_url, html) -> list:
        """CVE-2026-32142 — Shopware /api/_info/config license info disclosure (CVSS 5.3)."""
        detected = False
        evidence = ""

        is_shopware = "shopware" in html.lower() or "/storefront/" in html.lower()

        config_url = urljoin(target_url.rstrip("/") + "/", "api/_info/config")
        try:
            async with session.get(config_url, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=6),
                                   headers=self._default_headers()) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        text = await resp.text(errors="replace")
                        if any(k in text for k in ["version", "license", "shopware", "currency"]):
                            detected = True
                            evidence = (
                                f"CVE-2026-32142: Shopware /api/_info/config exposed at "
                                f"{config_url} — reveals license info and version details. "
                                f"Fix: Shopware >= 7.8.1 / 6.10.15."
                            )
        except Exception:
            pass

        return [self.make_result(
            bug_id="CVE-2026-32142",
            name="Shopware Config/License Info Disclosure",
            severity=Severity.MEDIUM,
            category="CVE / Known Exploits",
            description=(
                "CVE-2026-32142: Shopware /api/_info/config mengekspos informasi lisensi "
                "dan versi tanpa autentikasi. Fix: update Shopware >= 7.8.1 / 6.10.15."
            ),
            detected=detected,
            endpoint=config_url if detected else "",
            evidence=evidence,
        )]

    async def _check_uptime_kuma(self, session, target_url) -> list:
        """CVE-2026-32230 — Uptime Kuma private monitor data exposed (CVSS 5.3)."""
        detected = False
        evidence = ""

        # Check for Uptime Kuma status page
        kuma_paths = [
            "status", "status/page", "dashboard",
            "api/badge/1/ping", "api/badge/1/ping/30d",
        ]

        for path in kuma_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       headers=self._default_headers()) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "")
                        text = await resp.text(errors="replace")
                        if "uptime kuma" in text.lower() or "uptimekuma" in text.lower():
                            # Check the vulnerable badge endpoint
                            badge_url = urljoin(target_url.rstrip("/") + "/", "api/badge/1/ping")
                            async with session.get(badge_url, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=6)) as br:
                                if br.status == 200:
                                    detected = True
                                    evidence = (
                                        f"CVE-2026-32230: Uptime Kuma detected at {url}. "
                                        f"Versions 2.0.0–2.1.3 — /api/badge/:id/ping/ endpoint "
                                        f"exposes private monitor ping data without auth check. "
                                        f"Fix: update Uptime Kuma >= 2.2.0."
                                    )
                                    break
                            break
            except Exception:
                pass
            if detected:
                break

        return [self.make_result(
            bug_id="CVE-2026-32230",
            name="Uptime Kuma Private Monitor Data Exposure",
            severity=Severity.MEDIUM,
            category="CVE / Known Exploits",
            description=(
                "CVE-2026-32230: Uptime Kuma 2.0.0–2.1.3 — endpoint /api/badge/:id/ping "
                "tidak memverifikasi apakah monitor dalam public group, "
                "sehingga unauthenticated user dapat mengakses data private monitor. "
                "Fix: update >= 2.2.0."
            ),
            detected=detected,
            endpoint=target_url if detected else "",
            evidence=evidence,
        )]
