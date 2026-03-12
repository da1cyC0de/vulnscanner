import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class InfoDisclosureScanner(BaseModule):
    """Scans for: Server Version Leakage, Sensitive Files, Directory Listing,
    Error Message Leak, Admin Panel, Backup Files, robots.txt, Debug Mode"""

    SENSITIVE_PATHS = [
        ".env", ".git/HEAD", ".git/config", ".svn/entries",
        ".htaccess", ".htpasswd", "wp-config.php", "config.php",
        "configuration.php", "web.config", "database.yml",
        ".DS_Store", "Thumbs.db", "phpinfo.php",
        "server-status", "server-info",
    ]

    BACKUP_EXTENSIONS = [
        ".bak", ".old", ".orig", ".save", ".swp", ".swo",
        "~", ".copy", ".tmp", ".temp", ".backup",
    ]

    ADMIN_PATHS = [
        "admin", "administrator", "admin.php", "wp-admin", "wp-login.php",
        "cpanel", "phpmyadmin", "adminer", "adminer.php",
        "manager", "admin/login", "backend", "dashboard",
        "admin/index.php", "panel", "controlpanel",
        "_admin", "siteadmin", "webadmin",
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not resp:
            return results

        results.extend(self._check_server_headers(resp, target_url))
        results.extend(await self._check_sensitive_files(session, target_url))
        results.extend(await self._check_directory_listing(session, target_url))
        results.extend(self._check_error_disclosure(html, target_url))
        results.extend(await self._check_admin_panels(session, target_url))
        results.extend(await self._check_backup_files(session, target_url))
        results.extend(await self._check_robots_txt(session, target_url))
        results.extend(self._check_debug_mode(html, resp, target_url))
        results.extend(self._check_html_comments(html, target_url))
        results.extend(self._check_stack_trace_leak(html, target_url))
        results.extend(await self._check_sitemap_xml(session, target_url))

        return results

    def _check_server_headers(self, resp, target_url) -> list:
        detected = False
        evidence_parts = []
        leak_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                        "X-AspNetMvc-Version", "X-Generator"]
        for h in leak_headers:
            val = resp.headers.get(h)
            if val:
                detected = True
                evidence_parts.append(f"{h}: {val}")

        return [self.make_result(
            bug_id="INFO-026", name="Server Version Disclosure", severity=Severity.LOW,
            category="Information Disclosure",
            description="Deteksi kebocoran versi server dari HTTP headers.",
            detected=detected, endpoint=target_url, evidence="\n".join(evidence_parts),
        )]

    async def _check_sensitive_files(self, session, target_url) -> list:
        detected = False
        evidence_parts = []

        for path in self.SENSITIVE_PATHS:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if len(text) > 0 and "404" not in text.lower()[:200] and "not found" not in text.lower()[:200]:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="INFO-027", name="Sensitive File Exposure", severity=Severity.HIGH,
            category="Information Disclosure",
            description="Cek file sensitif yang terbuka (.env, .git, config, dll).",
            detected=detected, endpoint=evidence_parts[0].split('] ')[1] if evidence_parts else "", evidence="\n".join(evidence_parts[:15]),
        )]

    async def _check_directory_listing(self, session, target_url) -> list:
        detected = False
        evidence = ""
        test_dirs = ["", "css/", "js/", "images/", "uploads/", "assets/", "static/", "files/", "backup/"]

        for d in test_dirs:
            url = urljoin(target_url.rstrip("/") + "/", d)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "index of" in text.lower() or "directory listing" in text.lower() or '<a href="' in text.lower() and "parent directory" in text.lower():
                            detected = True
                            evidence = f"Directory listing enabled at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="INFO-028", name="Directory Listing", severity=Severity.MEDIUM,
            category="Information Disclosure",
            description="Cek apakah directory listing aktif di web server.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    def _check_error_disclosure(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        error_patterns = [
            r"(?:fatal error|parse error|warning|notice).*?(?:on line \d+|in /.+?\.php)",
            r"(?:traceback|file \".*?\", line \d+)",
            r"(?:stack trace:|exception in thread)",
            r"(?:microsoft ole db|odbc microsoft access)",
            r"(?:ora-\d{5}|pg_query|mysql_fetch|sqlite3)",
        ]
        html_lower = html.lower()
        for pattern in error_patterns:
            match = re.search(pattern, html_lower)
            if match:
                detected = True
                evidence = f"Error message found: {match.group()[:150]}"
                break

        return [self.make_result(
            bug_id="INFO-029", name="Error Message Information Leak", severity=Severity.MEDIUM,
            category="Information Disclosure",
            description="Deteksi pesan error yang membocorkan info teknis (stack trace, path, DB error).",
            detected=detected, endpoint=target_url, evidence=evidence,
        )]

    async def _check_admin_panels(self, session, target_url) -> list:
        detected = False
        evidence_parts = []

        for path in self.ADMIN_PATHS:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        text_lower = text.lower()
                        if any(w in text_lower for w in ["login", "password", "sign in", "admin", "dashboard"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="INFO-030", name="Admin Panel Finder", severity=Severity.MEDIUM,
            category="Information Disclosure",
            description="Cek endpoint admin panel yang bisa diakses.",
            detected=detected, endpoint=evidence_parts[0].split('] ')[1] if evidence_parts else "", evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_backup_files(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(":")[0]

        backup_files = [
            "backup.zip", "backup.tar.gz", "backup.sql", f"{domain}.zip",
            f"{domain}.sql", "db.sql", "database.sql", "dump.sql",
            "site.zip", "www.zip", "public.zip", "backup.rar",
        ]
        for bf in backup_files:
            url = urljoin(target_url.rstrip("/") + "/", bf)
            try:
                async with session.head(url, ssl=False, allow_redirects=False,
                                        timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        content_length = resp.headers.get("Content-Length", "0")
                        if int(content_length) > 1000:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url} ({content_length} bytes)")
            except Exception:
                pass

        return [self.make_result(
            bug_id="INFO-031", name="Backup File Finder", severity=Severity.HIGH,
            category="Information Disclosure",
            description="Cek file backup yang terekspos (zip, sql, tar.gz).",
            detected=detected, endpoint=evidence_parts[0].split('] ')[1].split(' (')[0] if evidence_parts else "", evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_robots_txt(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", "robots.txt")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "disallow" in text.lower():
                        detected = True
                        sensitive = [line.strip() for line in text.split("\n")
                                     if line.strip().lower().startswith("disallow") and len(line.strip()) > 12]
                        evidence = f"robots.txt found with {len(sensitive)} disallowed paths:\n" + "\n".join(sensitive[:10])
        except Exception:
            pass

        return [self.make_result(
            bug_id="INFO-032", name="robots.txt & Sitemap Analysis", severity=Severity.INFO,
            category="Information Disclosure",
            description="Analisis robots.txt untuk path sensitif.",
            detected=detected, endpoint=url, evidence=evidence,
        )]

    def _check_debug_mode(self, html, resp, target_url) -> list:
        detected = False
        evidence = ""
        if html:
            debug_indicators = [
                "debug = true", "debug_mode", "laravel", "whoops",
                "django debug", "flask debugger", "werkzeug debugger",
                "xdebug", "var_dump(", "print_r(",
                "stack trace", "traceback (most recent call",
            ]
            html_lower = html.lower()
            for indicator in debug_indicators:
                if indicator in html_lower:
                    detected = True
                    evidence = f"Debug indicator found: '{indicator}'"
                    break

        debug_headers = ["X-Debug-Token", "X-Debug-Token-Link"]
        for h in debug_headers:
            if resp and resp.headers.get(h):
                detected = True
                evidence = f"Debug header: {h}: {resp.headers.get(h)}"

        return [self.make_result(
            bug_id="INFO-073", name="Debug Mode Detection", severity=Severity.HIGH,
            category="Information Disclosure",
            description="Deteksi apakah debug mode aktif (Laravel, Django, Flask, dll).",
            detected=detected, endpoint=target_url, evidence=evidence,
        )]

    def _check_html_comments(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence_parts = []
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        sensitive_words = ["password", "secret", "api_key", "token", "todo",
                           "fixme", "hack", "bug", "database", "admin", "debug",
                           "credentials", "key", "internal"]
        for comment in comments:
            comment_lower = comment.lower().strip()
            if len(comment_lower) > 5:
                for word in sensitive_words:
                    if word in comment_lower:
                        detected = True
                        evidence_parts.append(f"Comment: <!--{comment.strip()[:100]}-->")
                        break

        return [self.make_result(
            bug_id="INFO-178", name="HTML Comment Sensitive Info Leakage", severity=Severity.LOW,
            category="Information Disclosure",
            description="Cek HTML comments yang mengandung informasi sensitif.",
            detected=detected, endpoint=target_url, evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_stack_trace_leak(self, html, target_url) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        traces = [
            r'at\s+[\w.]+\(.*?:\d+:\d+\)',
            r'File\s+"[^"]+",\s+line\s+\d+',
            r'#\d+\s+[\w\\]+->\w+\(.*?\)',
            r'java\.[\w.]+Exception',
            r'System\.\w+Exception',
        ]
        for pattern in traces:
            match = re.search(pattern, html)
            if match:
                detected = True
                evidence = f"Stack trace found: {match.group()[:120]}"
                break

        return [self.make_result(
            bug_id="INFO-033", name="Stack Trace Exposure", severity=Severity.MEDIUM,
            category="Information Disclosure",
            description="Deteksi stack trace yang terekspos di halaman web.",
            detected=detected, endpoint=target_url, evidence=evidence,
        )]

    async def _check_sitemap_xml(self, session, target_url) -> list:
        detected = False
        evidence = ""
        url = urljoin(target_url.rstrip("/") + "/", "sitemap.xml")
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "<url>" in text.lower() or "<loc>" in text.lower():
                        import re as _re
                        locs = _re.findall(r'<loc>(.*?)</loc>', text)
                        sensitive = [l for l in locs if any(w in l.lower() for w in ["admin", "api", "internal", "staging", "dev", "test", "debug"])]
                        if sensitive:
                            detected = True
                            evidence = f"Sensitive paths in sitemap.xml: {', '.join(sensitive[:5])}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="INFO-034", name="Sitemap.xml Sensitive Path Disclosure", severity=Severity.LOW,
            category="Information Disclosure",
            description="Analisis sitemap.xml untuk path sensitif yang terekspos.",
            detected=detected, endpoint=url, evidence=evidence,
        )]
