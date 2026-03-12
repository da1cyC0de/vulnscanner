import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class BusinessLogicScanner(BaseModule):
    """Scans for: Parameter Tampering / Price Manipulation, Hidden Field Manipulation,
    Race Condition Indicator, Negative Value Testing"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_hidden_fields(html, target_url))
        results.extend(await self._check_parameter_tampering(session, target_url, html))
        results.extend(await self._check_negative_values(session, target_url, html))
        results.extend(await self._check_race_condition(session, target_url, html))
        results.extend(self._check_idor_references(html, target_url))
        results.extend(await self._check_privilege_escalation(session, target_url))

        return results

    def _check_hidden_fields(self, html, target_url) -> list:
        detected = False
        evidence_parts = []
        soup = self.parse_html(html)

        sensitive_names = ["price", "total", "amount", "cost", "discount", "qty", "quantity",
                           "role", "admin", "is_admin", "user_type", "level", "status",
                           "harga", "subtotal", "tax", "fee", "payment"]

        for form in soup.find_all("form"):
            for inp in form.find_all("input", {"type": "hidden"}):
                name = (inp.get("name") or "").lower()
                value = inp.get("value", "")
                for s in sensitive_names:
                    if s in name:
                        detected = True
                        evidence_parts.append(f"Hidden field '{inp.get('name')}' = '{value}' in form")
                        break

        return [self.make_result(
            bug_id="BIZ-018", name="Hidden Field Manipulation", severity=Severity.HIGH,
            category="Business Logic",
            description="Deteksi hidden form fields sensitif (harga, role, discount) yang bisa diubah oleh attacker.",
            detected=detected, endpoint=target_url, evidence="\n".join(evidence_parts[:10]),
        )]

    async def _check_parameter_tampering(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        soup = self.parse_html(html)

        price_fields = ["price", "total", "amount", "cost", "harga", "subtotal", "payment_amount"]

        for form in soup.find_all("form"):
            action = urljoin(target_url, form.get("action", ""))
            inputs = form.find_all("input")
            data_original = {}
            tamper_field = None

            for inp in inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                if name:
                    data_original[name] = value
                    if any(p in name.lower() for p in price_fields):
                        tamper_field = name

            if tamper_field and data_original.get(tamper_field):
                data_tampered = data_original.copy()
                data_tampered[tamper_field] = "1"
                try:
                    async with session.post(action, data=data_tampered, ssl=False,
                                            timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        text = await resp.text(errors="replace")
                        if resp.status == 200:
                            error_words = ["invalid", "error", "rejected", "failed", "not allowed"]
                            if not any(w in text.lower() for w in error_words):
                                detected = True
                                evidence = f"Price field '{tamper_field}' accepted tampered value '1' at {action}"
                except Exception:
                    pass

        return [self.make_result(
            bug_id="BIZ-017", name="Parameter Tampering / Price Manipulation", severity=Severity.CRITICAL,
            category="Business Logic",
            description="Tes apakah nilai harga/nominal bisa diubah dan diterima oleh backend.",
            detected=detected, endpoint=action if detected else "", evidence=evidence,
        )]

    async def _check_negative_values(self, session, target_url, html) -> list:
        detected = False
        evidence = ""
        soup = self.parse_html(html)

        numeric_names = ["price", "quantity", "qty", "amount", "total", "count", "num"]

        for form in soup.find_all("form"):
            action = urljoin(target_url, form.get("action", ""))
            inputs = form.find_all("input")
            data = {}
            test_field = None

            for inp in inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                if name:
                    data[name] = value
                    if any(n in name.lower() for n in numeric_names):
                        test_field = name

            if test_field:
                data[test_field] = "-1"
                try:
                    async with session.post(action, data=data, ssl=False,
                                            timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        text = await resp.text(errors="replace")
                        if resp.status == 200:
                            reject_words = ["invalid", "negative", "must be positive", "error", "not valid"]
                            if not any(w in text.lower() for w in reject_words):
                                detected = True
                                evidence = f"Negative value '-1' accepted for field '{test_field}' at {action}"
                except Exception:
                    pass

        return [self.make_result(
            bug_id="BIZ-020", name="Negative Value Testing", severity=Severity.HIGH,
            category="Business Logic",
            description="Tes apakah backend menerima nilai negatif untuk quantity/price.",
            detected=detected, endpoint=action if detected else "", evidence=evidence,
        )]

    async def _check_race_condition(self, session, target_url, html) -> list:
        soup = self.parse_html(html)
        forms = soup.find_all("form", method=re.compile("post", re.I))
        has_post_forms = len(forms) > 0

        return [self.make_result(
            bug_id="BIZ-019", name="Race Condition Indicator", severity=Severity.MEDIUM,
            category="Business Logic",
            description="Deteksi form POST yang mungkin rentan race condition (double submit).",
            detected=has_post_forms,
            endpoint=target_url,
            evidence=f"Found {len(forms)} POST forms that may be vulnerable to race conditions" if has_post_forms else "",
        )]

    def _check_idor_references(self, html, target_url) -> list:
        detected = False
        evidence_parts = []
        soup = self.parse_html(html)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if re.search(r'[?&](id|user_id|account_id|order_id|invoice_id)=\d+', href, re.I):
                detected = True
                evidence_parts.append(f"Potential IDOR link: {href[:100]}")

        return [self.make_result(
            bug_id="BIZ-021", name="IDOR Reference in Links", severity=Severity.MEDIUM,
            category="Business Logic",
            description="Deteksi link dengan parameter ID numerik yang mungkin rentan IDOR.",
            detected=detected, endpoint=target_url, evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_privilege_escalation(self, session, target_url) -> list:
        detected = False
        evidence = ""
        priv_paths = ["admin", "admin/", "dashboard", "manager", "moderator", "superuser"]
        for p in priv_paths:
            url = urljoin(target_url.rstrip("/") + "/", p)
            try:
                async with session.get(url, ssl=False, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if any(w in text.lower() for w in ["dashboard", "panel", "admin", "settings", "manage"]):
                            detected = True
                            evidence = f"Admin/privileged page accessible without auth at {url} (status {resp.status})"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="BIZ-022", name="Privilege Escalation - Unprotected Admin", severity=Severity.HIGH,
            category="Business Logic",
            description="Cek apakah halaman admin/privileged bisa diakses tanpa autentikasi.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]
