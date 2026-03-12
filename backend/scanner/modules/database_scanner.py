import aiohttp
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class DatabaseScanner(BaseModule):
    """Scans for: DB Dump Exposure, phpMyAdmin/Adminer, DB Connection String Leakage,
    DB Error Leakage"""

    DB_PANEL_PATHS = [
        "phpmyadmin", "phpmyadmin/", "pma", "myadmin", "mysql",
        "adminer.php", "adminer", "dbadmin",
    ]

    DB_FILES = [
        "dump.sql", "db.sql", "database.sql", "backup.sql",
        "data.sql", "mysql.sql", "db_backup.sql",
        "database.db", "data.db", "app.db", "sqlite.db",
        "database.sqlite", "database.sqlite3",
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)

        results.extend(await self._check_db_dumps(session, target_url))
        results.extend(await self._check_db_panels(session, target_url))
        results.extend(self._check_db_connection_strings(html))
        results.extend(self._check_db_errors(html))
        results.extend(await self._check_redis_exposed(session, target_url))
        results.extend(await self._check_mongodb_exposed(session, target_url))
        results.extend(await self._check_elasticsearch_exposed(session, target_url))

        return results

    async def _check_db_dumps(self, session, target_url) -> list:
        detected = False
        evidence_parts = []

        for f in self.DB_FILES:
            url = urljoin(target_url.rstrip("/") + "/", f)
            try:
                async with session.head(url, ssl=False, allow_redirects=False,
                                        timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        cl = int(resp.headers.get("Content-Length", "0"))
                        if cl > 100:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url} ({cl} bytes)")
            except Exception:
                pass

        return [self.make_result(
            bug_id="DB-057", name="Database Dump Exposure", severity=Severity.CRITICAL,
            category="Database Exposure",
            description="Cek file database dump yang terekspos (.sql, .db, .sqlite).",
            detected=detected, evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_db_panels(self, session, target_url) -> list:
        detected = False
        evidence_parts = []

        for path in self.DB_PANEL_PATHS:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["phpmyadmin", "adminer", "login", "server", "database"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="DB-058", name="phpMyAdmin/Adminer Panel Exposed", severity=Severity.HIGH,
            category="Database Exposure",
            description="Cek panel database admin (phpMyAdmin, Adminer) yang terekspos.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_db_connection_strings(self, html) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        import re
        patterns = [
            r'(?:mysql|postgres|mongodb|redis|sqlite)://[^\s"\'<>]+',
            r'(?:DB_HOST|DB_PASSWORD|DB_USER|DATABASE_URL)\s*[:=]\s*[^\s"\'<>]+',
            r'(?:jdbc|odbc):[^\s"\'<>]+',
        ]
        for p in patterns:
            match = re.search(p, html, re.IGNORECASE)
            if match:
                detected = True
                evidence = f"Database connection string found: {match.group()[:150]}"
                break

        return [self.make_result(
            bug_id="DB-062", name="Database Connection String Leakage", severity=Severity.CRITICAL,
            category="Database Exposure",
            description="Deteksi connection string database yang bocor di source code.",
            detected=detected, evidence=evidence,
        )]

    def _check_db_errors(self, html) -> list:
        if not html:
            return []
        detected = False
        evidence = ""
        import re
        db_errors = [
            r"mysql_(?:fetch|query|connect|num_rows)",
            r"pg_(?:query|connect|fetch)",
            r"sqlite(?:3)?_",
            r"ORA-\d{5}",
            r"SQLSTATE\[\w+\]",
            r"Microsoft SQL Server",
            r"MySQL server version",
            r"PostgreSQL.*ERROR",
        ]
        for pattern in db_errors:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                detected = True
                evidence = f"Database error message: {match.group()[:150]}"
                break

        return [self.make_result(
            bug_id="DB-063", name="Database Error Message Leakage", severity=Severity.MEDIUM,
            category="Database Exposure",
            description="Deteksi pesan error database yang membocorkan informasi.",
            detected=detected, evidence=evidence,
        )]

    async def _check_redis_exposed(self, session, target_url) -> list:
        detected = False
        evidence = ""
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        try:
            import asyncio
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 6379), timeout=5
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(100), timeout=3)
            if b"PONG" in data or b"redis" in data.lower():
                detected = True
                evidence = f"Redis server accessible at {hostname}:6379"
            writer.close()
        except Exception:
            pass

        return [self.make_result(
            bug_id="DB-059", name="Redis Server Exposed", severity=Severity.CRITICAL,
            category="Database Exposure",
            description="Cek apakah Redis server terekspos tanpa autentikasi.",
            detected=detected, evidence=evidence,
        )]

    async def _check_mongodb_exposed(self, session, target_url) -> list:
        detected = False
        evidence = ""
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        try:
            import asyncio
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 27017), timeout=5
            )
            writer.close()
            detected = True
            evidence = f"MongoDB port open at {hostname}:27017"
        except Exception:
            pass

        return [self.make_result(
            bug_id="DB-060", name="MongoDB Exposed", severity=Severity.CRITICAL,
            category="Database Exposure",
            description="Cek apakah MongoDB terekspos dan bisa diakses dari luar.",
            detected=detected, evidence=evidence,
        )]

    async def _check_elasticsearch_exposed(self, session, target_url) -> list:
        detected = False
        evidence = ""
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        es_url = f"http://{hostname}:9200"
        try:
            async with session.get(es_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "lucene" in text.lower() or "elasticsearch" in text.lower():
                        detected = True
                        evidence = f"Elasticsearch exposed at {es_url}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="DB-061", name="Elasticsearch Exposed", severity=Severity.HIGH,
            category="Database Exposure",
            description="Cek apakah Elasticsearch terekspos dan bisa diakses publik.",
            detected=detected, evidence=evidence,
        )]
