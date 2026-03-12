import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class PathDiscoveryScanner(BaseModule):
    """Scans for: Exposed paths, hidden directories, sensitive endpoints, config files,
    backup paths, API docs, debug panels, dev tools, and more."""

    # --- Common web paths grouped by risk category ---
    CRITICAL_PATHS = {
        # Git / VCS
        ".git/HEAD": ("Git Repository Exposed", "critical", "Repo .git terekspos — attacker bisa clone seluruh source code"),
        ".git/config": ("Git Config Exposed", "critical", "Config git bisa mengandung remote URL dan credentials"),
        ".svn/entries": ("SVN Repository Exposed", "critical", "Direktori .svn terekspos — source code bisa diakses"),
        ".hg/store": ("Mercurial Repo Exposed", "critical", "Repo Mercurial .hg terekspos"),
        # Env / Config
        ".env": ("Environment File Exposed", "critical", "File .env berisi API keys, database credentials, secrets"),
        ".env.local": ("Env Local File Exposed", "critical", "File .env.local berisi config sensitif lokal"),
        ".env.production": ("Production Env Exposed", "critical", "File .env.production berisi secrets production"),
        ".env.backup": ("Env Backup Exposed", "critical", "Backup file environment terekspos"),
        "wp-config.php": ("WordPress Config Exposed", "critical", "wp-config.php berisi database credentials"),
        "config.php": ("PHP Config Exposed", "critical", "File config.php berisi konfigurasi sensitif"),
        "configuration.php": ("Joomla Config Exposed", "critical", "File configuration.php Joomla terekspos"),
        "config/database.yml": ("Database Config Exposed", "critical", "Config database Rails terekspos"),
        "config/secrets.yml": ("Secrets Config Exposed", "critical", "File secrets.yml terekspos"),
        "settings.py": ("Django Settings Exposed", "critical", "File settings.py berisi SECRET_KEY dan DB config"),
        ".docker-compose.yml": ("Docker Compose Exposed", "critical", "Docker Compose file menunjukkan arsitektur internal"),
        "docker-compose.yml": ("Docker Compose Exposed", "critical", "Docker Compose file menunjukkan arsitektur internal"),
        "Dockerfile": ("Dockerfile Exposed", "critical", "Dockerfile menunjukkan build steps dan secrets"),
    }

    HIGH_PATHS = {
        # Admin panels
        "admin": ("Admin Panel Found", "high", "Admin panel terekspos — bisa jadi target brute force"),
        "administrator": ("Administrator Panel Found", "high", "Administrator panel ditemukan terbuka"),
        "admin/login": ("Admin Login Page", "high", "Halaman login admin terekspos"),
        "wp-admin": ("WordPress Admin", "high", "WordPress admin panel ditemukan"),
        "wp-login.php": ("WordPress Login", "high", "WordPress login page terekspos"),
        "phpmyadmin": ("phpMyAdmin Exposed", "high", "phpMyAdmin terekspos — akses database langsung"),
        "adminer.php": ("Adminer Exposed", "high", "Adminer database tool terekspos"),
        "cpanel": ("cPanel Found", "high", "Control panel hosting ditemukan"),
        "webmail": ("Webmail Found", "high", "Webmail interface ditemukan"),
        # Debug / Dev
        "debug": ("Debug Page Exposed", "high", "Halaman debug terekspos di production"),
        "_debug": ("Debug Toolbar Exposed", "high", "Debug toolbar terekspos"),
        "__debug__": ("Django Debug Toolbar", "high", "Django debug toolbar aktif di production"),
        "console": ("Console Exposed", "high", "Web console terekspos"),
        "elmah.axd": ("ELMAH Error Log", "high", "ELMAH error logging terekspos (ASP.NET)"),
        "trace.axd": ("ASP.NET Trace Exposed", "high", "ASP.NET trace terekspos"),
        # Sensitive files
        ".htaccess": ("htaccess Exposed", "high", "File .htaccess terekspos — berisi rewrite rules dan auth"),
        ".htpasswd": ("htpasswd Exposed", "high", "File .htpasswd terekspos — berisi password hashes"),
        "web.config": ("Web.config Exposed", "high", "IIS web.config terekspos — berisi connection strings"),
        "crossdomain.xml": ("Flash Crossdomain", "high", "crossdomain.xml bisa memungkinkan akses cross-origin"),
        # Backup
        "backup": ("Backup Directory Found", "high", "Direktori backup ditemukan dan bisa diakses"),
        "backup.zip": ("Backup ZIP Found", "high", "File backup.zip terekspos — berisi seluruh website"),
        "backup.tar.gz": ("Backup Archive Found", "high", "Archive backup terekspos"),
        "backup.sql": ("Database Backup Found", "high", "Backup database SQL terekspos — full data dump"),
        "db.sql": ("SQL Dump Found", "high", "SQL dump file terekspos"),
        "dump.sql": ("SQL Dump Found", "high", "Database dump terekspos"),
        "database.sql": ("Database Export Found", "high", "Export database terekspos"),
        # Server info
        "server-status": ("Apache Server Status", "high", "Apache server-status terekspos — info request aktif"),
        "server-info": ("Apache Server Info", "high", "Apache server-info terekspos — konfigurasi penuh"),
        "phpinfo.php": ("phpinfo() Exposed", "high", "phpinfo() terekspos — info lengkap server"),
        "info.php": ("PHP Info Page", "high", "Halaman PHP info terekspos"),
        # Spring Boot Actuator
        "actuator": ("Spring Actuator Exposed", "high", "Spring Boot Actuator terekspos"),
        "actuator/env": ("Actuator Env Exposed", "high", "Environment variables terekspos via Actuator"),
        "actuator/health": ("Actuator Health Exposed", "high", "Health endpoint Actuator terekspos"),
        "actuator/configprops": ("Actuator Config Exposed", "high", "Config properties Actuator terekspos"),
    }

    MEDIUM_PATHS = {
        # API Documentation
        "swagger": ("Swagger UI Found", "medium", "Swagger API documentation terekspos"),
        "swagger-ui": ("Swagger UI Found", "medium", "Swagger UI terekspos"),
        "swagger-ui.html": ("Swagger UI Page", "medium", "Halaman Swagger UI terekspos"),
        "api-docs": ("API Docs Found", "medium", "API documentation terekspos"),
        "docs": ("Docs Endpoint Found", "medium", "Endpoint /docs terekspos (FastAPI/Swagger)"),
        "redoc": ("ReDoc Found", "medium", "ReDoc API docs terekspos"),
        "graphql": ("GraphQL Endpoint", "medium", "GraphQL endpoint terekspos — bisa di-introspect"),
        "graphiql": ("GraphiQL IDE", "medium", "GraphiQL IDE terekspos"),
        # Common directories
        "uploads": ("Uploads Directory", "medium", "Direktori uploads terekspos"),
        "upload": ("Upload Directory", "medium", "Direktori upload terekspos"),
        "files": ("Files Directory", "medium", "Direktori files terekspos"),
        "media": ("Media Directory", "medium", "Direktori media terekspos"),
        "static": ("Static Directory", "medium", "Direktori static terekspos"),
        "assets": ("Assets Directory", "medium", "Direktori assets terekspos"),
        "tmp": ("Temp Directory", "medium", "Direktori temp terekspos"),
        "temp": ("Temp Directory", "medium", "Direktori temp terekspos"),
        "log": ("Log Directory", "medium", "Direktori log terekspos"),
        "logs": ("Logs Directory", "medium", "Direktori logs terekspos"),
        # CMS & Framework
        "wp-content": ("WordPress Content Dir", "medium", "Direktori wp-content terekspos"),
        "wp-includes": ("WordPress Includes Dir", "medium", "Direktori wp-includes terekspos"),
        "wp-json/wp/v2/users": ("WP User Enum", "medium", "WordPress user enumeration via REST API"),
        "feed": ("RSS Feed Found", "medium", "RSS feed terekspos — info content"),
        "sitemap.xml": ("Sitemap Found", "medium", "Sitemap XML ditemukan — struktur URL terekspos"),
        "robots.txt": ("Robots.txt Found", "medium", "robots.txt ditemukan — bisa mengandung path tersembunyi"),
        # Dev files
        ".DS_Store": ("DS_Store Exposed", "medium", "File .DS_Store terekspos — struktur folder macOS"),
        "Thumbs.db": ("Thumbs.db Exposed", "medium", "File Thumbs.db terekspos"),
        ".idea": ("IDE Config Exposed", "medium", "Direktori .idea IntelliJ/PyCharm terekspos"),
        ".vscode": ("VS Code Config Exposed", "medium", "Direktori .vscode terekspos"),
        "package.json": ("Package.json Exposed", "medium", "package.json terekspos — dependencies visible"),
        "composer.json": ("Composer.json Exposed", "medium", "composer.json terekspos — PHP dependencies visible"),
        "Gemfile": ("Gemfile Exposed", "medium", "Gemfile terekspos — Ruby dependencies visible"),
        "requirements.txt": ("Requirements.txt Exposed", "medium", "requirements.txt terekspos — Python dependencies visible"),
        # Error pages
        "404": ("Custom 404 Page", "info", "Custom 404 page — fingerprinting framework"),
        "500": ("Error Page Exposed", "medium", "Error page bisa mengandung stack trace"),
    }

    LOW_PATHS = {
        "favicon.ico": ("Favicon Found", "info", "Favicon bisa digunakan untuk fingerprinting"),
        "humans.txt": ("Humans.txt Found", "low", "Humans.txt ditemukan — info developer"),
        "security.txt": ("Security.txt Found", "info", "File security.txt — responsible disclosure"),
        ".well-known/security.txt": ("Security.txt Well-Known", "info", "Security policy ditemukan"),
        "license.txt": ("License File Found", "low", "File lisensi terekspos — fingerprinting CMS"),
        "readme.html": ("Readme Exposed", "low", "File readme terekspos — fingerprinting versi"),
        "README.md": ("README Exposed", "low", "README.md terekspos — info project"),
        "CHANGELOG.md": ("Changelog Exposed", "low", "Changelog terekspos — info versi"),
        "manifest.json": ("Manifest Exposed", "info", "Web app manifest ditemukan"),
    }

    # Paths that only apply to WordPress sites
    WP_SPECIFIC_PATHS = {
        "wp-config.php", "wp-admin", "wp-login.php",
        "wp-content", "wp-includes", "wp-json/wp/v2/users",
    }

    async def _detect_wordpress(self, session: aiohttp.ClientSession, target_url: str) -> bool:
        """Return True only if the site shows clear WordPress fingerprints."""
        try:
            async with session.get(
                target_url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
                headers=self._default_headers(),
            ) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    text_lower = text.lower()
                    return (
                        "/wp-content/" in text_lower
                        or "/wp-includes/" in text_lower
                        or 'content="wordpress' in text_lower
                        or "wordpress" in resp.headers.get("X-Powered-By", "").lower()
                    )
        except Exception:
            pass
        return False

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        discovered = []

        # Check WordPress before building path list — skip WP-specific paths on non-WP sites
        is_wordpress = await self._detect_wordpress(session, target_url)

        # Scan all path categories concurrently in batches
        all_paths = {}
        all_paths.update(self.CRITICAL_PATHS)
        all_paths.update(self.HIGH_PATHS)
        all_paths.update(self.MEDIUM_PATHS)
        all_paths.update(self.LOW_PATHS)

        if not is_wordpress:
            all_paths = {k: v for k, v in all_paths.items() if k not in self.WP_SPECIFIC_PATHS}

        # Batch concurrent requests (max 15 at a time to avoid overwhelming target)
        path_items = list(all_paths.items())
        batch_size = 15

        for i in range(0, len(path_items), batch_size):
            batch = path_items[i:i + batch_size]
            tasks = [self._probe_path(session, target_url, path, info) for path, info in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, dict) and r.get("found"):
                    discovered.append(r)

        # Generate individual results per discovered path
        for d in discovered:
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
            results.append(self.make_result(
                bug_id=f"PATH-{d['index']:03d}",
                name=d["name"],
                severity=sev_map.get(d["severity"], Severity.MEDIUM),
                category="Path Discovery",
                description=d["desc"],
                detected=True,
                endpoint=d["url"],
                evidence=f"[{d['status']}] {d['url']} — {d['content_hint']}",
            ))

        # If nothing found, return one "not detected" result
        if not results:
            results.append(self.make_result(
                bug_id="PATH-000",
                name="Path Discovery Scan",
                severity=Severity.INFO,
                category="Path Discovery",
                description="Scan brute-force path/direktori umum (admin, backup, config, .git, .env, API docs, dll).",
                detected=False,
                evidence="No exposed paths found",
            ))

        return results

    async def _probe_path(self, session, target_url, path, info) -> dict:
        name, severity, desc = info
        url = urljoin(target_url.rstrip("/") + "/", path)
        try:
            async with session.get(url, ssl=False, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   headers=self._default_headers()) as resp:
                status = resp.status
                if status == 200:
                    text = await resp.text(errors="replace")
                    text_lower = text.lower()
                    content_len = len(text)

                    # Filter false positives
                    if content_len < 10:
                        return {"found": False}
                    # Check if it's a generic 404 page served with 200 status
                    if any(fp in text_lower[:500] for fp in ["page not found", "404 not found", "not found",
                                                              "does not exist", "no such file"]):
                        return {"found": False}
                    # Check if it's the same page as the main page (soft 404)
                    if content_len > 100:
                        content_hint = self._get_content_hint(text, path)
                        # Track index for unique bug_id
                        all_paths_list = list(self.CRITICAL_PATHS.keys()) + list(self.HIGH_PATHS.keys()) + \
                                         list(self.MEDIUM_PATHS.keys()) + list(self.LOW_PATHS.keys())
                        idx = all_paths_list.index(path) + 1 if path in all_paths_list else 999

                        return {
                            "found": True,
                            "path": path,
                            "url": url,
                            "status": status,
                            "name": name,
                            "severity": severity,
                            "desc": desc,
                            "content_hint": content_hint,
                            "index": idx,
                        }
                # 403 = exists but forbidden — downgrade severity since it's actively blocked
                elif status == 403:
                    # CRITICAL→MEDIUM, HIGH→LOW, others unchanged (blocked = not directly exploitable)
                    sev_403_map = {"critical": "medium", "high": "low"}
                    sev_403 = sev_403_map.get(severity, severity)
                    all_paths_list = list(self.CRITICAL_PATHS.keys()) + list(self.HIGH_PATHS.keys()) + \
                                     list(self.MEDIUM_PATHS.keys()) + list(self.LOW_PATHS.keys())
                    idx = all_paths_list.index(path) + 1 if path in all_paths_list else 999
                    return {
                        "found": True,
                        "path": path,
                        "url": url,
                        "status": status,
                        "name": f"{name} (Forbidden)",
                        "severity": sev_403,
                        "desc": f"{desc} — path ada tapi diblokir (403 Forbidden)",
                        "content_hint": "403 Forbidden — path exists but access denied",
                        "index": idx,
                    }
        except Exception:
            pass
        return {"found": False}

    def _get_content_hint(self, text: str, path: str) -> str:
        """Extract a short meaningful snippet from response to show as evidence."""
        text_lower = text.lower()

        # For git files
        if ".git" in path:
            if "ref:" in text_lower[:100]:
                return f"Git HEAD: {text.strip()[:80]}"
            return f"Git content exposed ({len(text)} bytes)"

        # For env files
        if ".env" in path:
            lines = [l for l in text.split("\n")[:5] if l.strip() and not l.startswith("#")]
            if lines:
                # Redact values for safety
                hints = []
                for l in lines[:3]:
                    if "=" in l:
                        key = l.split("=")[0].strip()
                        hints.append(f"{key}=***")
                    else:
                        hints.append(l.strip()[:40])
                return "Env vars: " + ", ".join(hints)
            return f".env file ({len(text)} bytes)"

        # For config files
        if any(x in path for x in ["config", "settings", "database.yml", "secrets"]):
            return f"Config file exposed ({len(text)} bytes)"

        # For HTML pages
        if "<html" in text_lower or "<title" in text_lower:
            import re
            title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if title_match:
                return f"Page title: {title_match.group(1).strip()[:60]}"

        # For JSON responses
        if text.strip().startswith("{") or text.strip().startswith("["):
            return f"JSON response ({len(text)} bytes)"

        # For directory listings
        if "index of" in text_lower:
            return "Directory listing enabled"

        return f"Content found ({len(text)} bytes)"
