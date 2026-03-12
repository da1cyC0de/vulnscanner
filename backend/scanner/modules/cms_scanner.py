import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class CmsScanner(BaseModule):
    """Scans for: WordPress, Joomla, Drupal, Laravel, Django, Spring Boot detection & vulns"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(await self._check_wordpress(session, target_url, html))
        results.extend(await self._check_joomla(session, target_url, html))
        results.extend(await self._check_drupal(session, target_url, html))
        results.extend(await self._check_laravel(session, target_url, html))
        results.extend(await self._check_django(session, target_url, html))
        results.extend(await self._check_spring_boot(session, target_url))
        results.extend(await self._check_nextjs_debug(session, target_url))
        results.extend(await self._check_strapi_exposed(session, target_url))

        return results

    async def _check_wordpress(self, session, target_url, html) -> list:
        results = []
        is_wp = "wp-content" in html or "wp-includes" in html or "wordpress" in html.lower()

        if is_wp:
            version = ""
            match = re.search(r'content="WordPress\s+([\d.]+)"', html)
            if match:
                version = match.group(1)

            results.append(self.make_result(
                bug_id="CMS-084", name="WordPress Version Detection", severity=Severity.INFO,
                category="CMS Specific", description="Deteksi versi WordPress.",
                detected=True, evidence=f"WordPress detected. Version: {version or 'unknown'}",
            ))

            # User enumeration
            users_detected = False
            for i in range(1, 6):
                url = f"{target_url.rstrip('/')}/?author={i}"
                try:
                    async with session.get(url, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="replace")
                            if "author" in text.lower():
                                users_detected = True
                                break
                except Exception:
                    pass

            results.append(self.make_result(
                bug_id="CMS-086", name="WordPress User Enumeration", severity=Severity.MEDIUM,
                category="CMS Specific", description="Cek apakah user WordPress bisa dienumerasi.",
                detected=users_detected,
                evidence="User enumeration possible via ?author= parameter" if users_detected else "",
            ))

            # XML-RPC
            xmlrpc_detected = False
            xmlrpc_url = urljoin(target_url.rstrip("/") + "/", "xmlrpc.php")
            try:
                async with session.post(xmlrpc_url, data="<methodCall><methodName>system.listMethods</methodName></methodCall>",
                                        ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "methodResponse" in text:
                            xmlrpc_detected = True
            except Exception:
                pass

            results.append(self.make_result(
                bug_id="CMS-087", name="WordPress XML-RPC Enabled", severity=Severity.MEDIUM,
                category="CMS Specific", description="Cek apakah XML-RPC WordPress aktif (brute force risk).",
                detected=xmlrpc_detected,
                evidence=f"XML-RPC active at {xmlrpc_url}" if xmlrpc_detected else "",
            ))

        return results

    async def _check_joomla(self, session, target_url, html) -> list:
        is_joomla = "joomla" in html.lower() or "/components/com_" in html
        evidence = ""
        if is_joomla:
            try:
                url = urljoin(target_url.rstrip("/") + "/", "administrator/manifests/files/joomla.xml")
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        match = re.search(r'<version>([\d.]+)</version>', text)
                        if match:
                            evidence = f"Joomla version: {match.group(1)}"
            except Exception:
                pass

        return [self.make_result(
            bug_id="CMS-155", name="Joomla Detection", severity=Severity.INFO,
            category="CMS Specific", description="Deteksi Joomla CMS dan versinya.",
            detected=is_joomla, evidence=evidence or ("Joomla detected" if is_joomla else ""),
        )]

    async def _check_drupal(self, session, target_url, html) -> list:
        is_drupal = "drupal" in html.lower() or 'name="Generator" content="Drupal' in html
        evidence = ""
        if is_drupal:
            match = re.search(r'Drupal\s+([\d.]+)', html)
            if match:
                evidence = f"Drupal version: {match.group(1)}"

        return [self.make_result(
            bug_id="CMS-156", name="Drupal Detection", severity=Severity.INFO,
            category="CMS Specific", description="Deteksi Drupal CMS dan versinya.",
            detected=is_drupal, evidence=evidence or ("Drupal detected" if is_drupal else ""),
        )]

    async def _check_laravel(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        # Check for Laravel Telescope
        telescope_url = urljoin(target_url.rstrip("/") + "/", "telescope")
        try:
            async with session.get(telescope_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "telescope" in text.lower():
                        detected = True
                        evidence = f"Laravel Telescope exposed at: {telescope_url}"
        except Exception:
            pass

        if "laravel" in html.lower() or "csrf-token" in html.lower():
            if not detected:
                detected = True
                evidence = "Laravel framework detected"

        return [self.make_result(
            bug_id="CMS-158", name="Laravel Telescope/Debug Exposed", severity=Severity.HIGH,
            category="CMS Specific", description="Deteksi Laravel dan cek eksposur Telescope/debug.",
            detected=detected, evidence=evidence,
        )]

    async def _check_django(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        admin_url = urljoin(target_url.rstrip("/") + "/", "admin/")
        try:
            async with session.get(admin_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "django" in text.lower() or "csrfmiddlewaretoken" in text:
                        detected = True
                        evidence = f"Django admin panel found at: {admin_url}"
        except Exception:
            pass

        return [self.make_result(
            bug_id="CMS-159", name="Django Admin Exposed", severity=Severity.MEDIUM,
            category="CMS Specific", description="Deteksi Django admin panel yang terekspos.",
            detected=detected, evidence=evidence,
        )]

    async def _check_spring_boot(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        actuator_paths = ["actuator", "actuator/health", "actuator/env",
                          "actuator/beans", "actuator/configprops", "actuator/mappings"]

        for path in actuator_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["status", "beans", "spring", "actuator"]):
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="CMS-160", name="Spring Boot Actuator Exposed", severity=Severity.HIGH,
            category="CMS Specific", description="Deteksi Spring Boot Actuator endpoints yang terekspos.",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_nextjs_debug(self, session, target_url) -> list:
        detected = False
        evidence = ""
        paths = ["_next/data/", "__nextjs_original-stack-frame", "_next/static/"]
        for path in paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "buildId" in text or "next" in text.lower():
                            detected = True
                            evidence = f"Next.js internal path exposed: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="CMS-163", name="Next.js Debug/Internal Paths", severity=Severity.LOW,
            category="CMS Specific",
            description="Deteksi Next.js internal/debug paths yang terekspos.",
            detected=detected, evidence=evidence,
        )]

    async def _check_strapi_exposed(self, session, target_url) -> list:
        detected = False
        evidence = ""
        paths = ["admin/", "_health", "content-manager/", "users-permissions/"]
        for path in paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "strapi" in text.lower():
                            detected = True
                            evidence = f"Strapi CMS detected at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="CMS-164", name="Strapi CMS Exposed", severity=Severity.MEDIUM,
            category="CMS Specific",
            description="Deteksi Strapi CMS dan endpoint admin yang terekspos.",
            detected=detected, evidence=evidence,
        )]
