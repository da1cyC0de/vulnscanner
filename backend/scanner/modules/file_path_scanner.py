import aiohttp
from urllib.parse import quote
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class FilePathScanner(BaseModule):
    """Scans for: Path Traversal / LFI, RFI"""

    LFI_PAYLOADS = [
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..\\..\\..\\etc\\passwd", "/etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        forms = self._extract_forms(html, target_url)
        results.extend(await self._check_lfi(session, target_url, forms))
        results.extend(await self._check_rfi(session, target_url, forms))
        return results

    def _extract_forms(self, html, base_url):
        from urllib.parse import urljoin
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

    async def _check_lfi(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""
        file_params = ["file", "page", "path", "include", "template", "doc",
                       "folder", "dir", "load", "view", "content", "module"]

        for form in forms:
            for inp in form["inputs"]:
                if any(p in inp["name"].lower() for p in file_params):
                    for payload in self.LFI_PAYLOADS[:3]:
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
                            if "root:" in text or "daemon:" in text or "[boot loader]" in text:
                                detected = True
                                evidence = f"LFI: payload '{payload}' returned system file via param '{inp['name']}'"
                                break
                        except Exception:
                            pass
                    if detected:
                        break
            if detected:
                break

        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        for pname, pval in params.items():
            if detected:
                break
            if any(p in pname.lower() for p in file_params):
                for payload in self.LFI_PAYLOADS[:3]:
                    test_url = target_url.replace(f"{pname}={pval[0]}", f"{pname}={quote(payload)}")
                    try:
                        async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            text = await resp.text(errors="replace")
                        if "root:" in text or "daemon:" in text:
                            detected = True
                            evidence = f"LFI via URL param '{pname}' with payload: {payload}"
                            break
                    except Exception:
                        pass

        return [self.make_result(
            bug_id="FILE-139", name="Path Traversal / Local File Inclusion (LFI)", severity=Severity.CRITICAL,
            category="File & Path",
            description="Tes Local File Inclusion / Path Traversal.",
            detected=detected, evidence=evidence,
        )]

    async def _check_rfi(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""
        file_params = ["file", "page", "path", "include", "url", "src"]

        for form in forms:
            for inp in form["inputs"]:
                if any(p in inp["name"].lower() for p in file_params):
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = "https://httpbin.org/robots.txt"
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False,
                                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        if "user-agent" in text.lower():
                            detected = True
                            evidence = f"RFI: remote file content loaded via param '{inp['name']}'"
                            break
                    except Exception:
                        pass
            if detected:
                break

        return [self.make_result(
            bug_id="FILE-140", name="Remote File Inclusion (RFI)", severity=Severity.CRITICAL,
            category="File & Path",
            description="Tes Remote File Inclusion.",
            detected=detected, evidence=evidence,
        )]
