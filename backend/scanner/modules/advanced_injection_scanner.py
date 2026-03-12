import aiohttp
import re
from urllib.parse import urljoin, quote
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class AdvancedInjectionScanner(BaseModule):
    """Scans for: SSTI, SSRF indicators, XXE, HTTP Request Smuggling indicator"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        forms = self._extract_forms(html, target_url)
        results.extend(await self._check_ssti(session, forms))
        results.extend(await self._check_ssrf(session, target_url, forms))
        results.extend(await self._check_xxe(session, target_url))
        results.extend(await self._check_crlf_injection(session, target_url))
        return results

    def _extract_forms(self, html, base_url):
        soup = self.parse_html(html)
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", ""))
            method = form.get("method", "get").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs.append({"name": name, "type": inp.get("type", "text"), "value": inp.get("value", "")})
            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    async def _check_ssti(self, session, forms) -> list:
        detected = False
        evidence = ""
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{config}}", "secret_key"),
        ]
        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload, expected in ssti_payloads[:3]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False,
                                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        if expected in text and payload not in text:
                            detected = True
                            evidence = f"SSTI: payload '{payload}' evaluated to '{expected}' at {form['action']}"
                            break
                    except Exception:
                        pass
                if detected:
                    break
            if detected:
                break

        return [self.make_result(
            bug_id="ADV-089", name="Server-Side Template Injection (SSTI)", severity=Severity.CRITICAL,
            category="Advanced Injection", description="Tes SSTI pada form inputs.",
            detected=detected, evidence=evidence,
        )]

    async def _check_ssrf(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""
        ssrf_params = ["url", "uri", "path", "src", "source", "link", "redirect",
                       "file", "page", "load", "fetch", "proxy", "img"]

        for form in forms:
            for inp in form["inputs"]:
                if any(p in inp["name"].lower() for p in ssrf_params):
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = "http://127.0.0.1:80"
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False,
                                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["localhost", "127.0.0.1", "apache", "nginx", "welcome"]):
                            detected = True
                            evidence = f"SSRF indicator: internal resource loaded via param '{inp['name']}'"
                            break
                    except Exception:
                        pass
            if detected:
                break

        return [self.make_result(
            bug_id="ADV-090", name="Server-Side Request Forgery (SSRF)", severity=Severity.HIGH,
            category="Advanced Injection", description="Tes SSRF pada parameter URL.",
            detected=detected, evidence=evidence,
        )]

    async def _check_xxe(self, session, target_url) -> list:
        detected = False
        evidence = ""
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''

        try:
            headers = self._default_headers()
            headers["Content-Type"] = "application/xml"
            async with session.post(target_url, data=xxe_payload, headers=headers,
                                    ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text(errors="replace")
                if "root:" in text or "daemon:" in text:
                    detected = True
                    evidence = "XXE: /etc/passwd content returned in response"
        except Exception:
            pass

        return [self.make_result(
            bug_id="ADV-091", name="XML External Entity (XXE)", severity=Severity.CRITICAL,
            category="Advanced Injection", description="Tes XXE Injection.",
            detected=detected, evidence=evidence,
        )]

    async def _check_crlf_injection(self, session, target_url) -> list:
        detected = False
        evidence = ""
        test_url = f"{target_url.rstrip('/')}/%0d%0aX-Injected:%20true"
        try:
            async with session.get(test_url, ssl=False, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                for header_name, header_val in resp.headers.items():
                    if "x-injected" in header_name.lower():
                        detected = True
                        evidence = f"CRLF injection: injected header reflected — {header_name}: {header_val}"
                        break
                if not detected:
                    location = resp.headers.get("Location", "")
                    if "X-Injected" in location:
                        detected = True
                        evidence = f"CRLF injection reflected in Location header"
        except Exception:
            pass

        return [self.make_result(
            bug_id="ADV-092", name="CRLF Injection", severity=Severity.HIGH,
            category="Advanced Injection",
            description="Tes CRLF Injection (HTTP Response Splitting).",
            detected=detected, evidence=evidence,
        )]
