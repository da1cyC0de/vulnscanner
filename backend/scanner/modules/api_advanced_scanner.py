import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class ApiAdvancedScanner(BaseModule):
    """Scans for: BOLA, BFLA, GraphQL Depth/Batch"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        results.extend(await self._check_idor(session, target_url))
        results.extend(await self._check_graphql_batch(session, target_url))
        results.extend(await self._check_wsdl(session, target_url))
        results.extend(await self._check_graphql_introspection(session, target_url))
        return results

    async def _check_idor(self, session, target_url) -> list:
        detected = False
        evidence_parts = []
        idor_paths = [
            "api/users/1", "api/user/1", "api/profile/1",
            "api/order/1", "api/invoice/1", "user/1", "profile/1",
            "account/1", "api/v1/users/1", "api/v1/user/1",
        ]
        for path in idor_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "")
                        if "json" in ct:
                            detected = True
                            evidence_parts.append(f"[{resp.status}] {url}")
            except Exception:
                pass

        return [self.make_result(
            bug_id="APIAV-129", name="IDOR / Broken Object Level Authorization", severity=Severity.HIGH,
            category="API Advanced",
            description="Cek endpoint API yang mungkin rentan IDOR (akses data user lain).",
            detected=detected, endpoint=evidence_parts[0].split('] ')[1] if evidence_parts else "", evidence="\n".join(evidence_parts[:5]),
        )]

    async def _check_graphql_batch(self, session, target_url) -> list:
        detected = False
        evidence = ""
        gql_paths = ["graphql", "api/graphql"]

        batch_query = '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'

        for path in gql_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                headers = self._default_headers()
                headers["Content-Type"] = "application/json"
                async with session.post(url, data=batch_query, headers=headers,
                                        ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "__typename" in text or isinstance(text, str) and text.startswith("["):
                            detected = True
                            evidence = f"GraphQL batch queries accepted at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="APIAV-132", name="GraphQL Batch Attack", severity=Severity.MEDIUM,
            category="API Advanced",
            description="Cek apakah GraphQL menerima batch queries (brute force risk).",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    async def _check_wsdl(self, session, target_url) -> list:
        detected = False
        evidence = ""
        wsdl_paths = ["?wsdl", "service?wsdl", "ws?wsdl", "api?wsdl"]

        for path in wsdl_paths:
            url = target_url.rstrip("/") + "/" + path
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "wsdl" in text.lower() or "definitions" in text.lower():
                            detected = True
                            evidence = f"WSDL disclosure at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="APIAV-135", name="WSDL Disclosure (SOAP)", severity=Severity.LOW,
            category="API Advanced",
            description="Cek apakah WSDL file SOAP service terekspos.",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]

    async def _check_graphql_introspection(self, session, target_url) -> list:
        detected = False
        evidence = ""
        gql_paths = ["graphql", "api/graphql", "gql"]
        query = '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}}}"}'

        for path in gql_paths:
            url = urljoin(target_url.rstrip("/") + "/", path)
            try:
                headers = self._default_headers()
                headers["Content-Type"] = "application/json"
                async with session.post(url, data=query, headers=headers,
                                        ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "queryType" in text or "mutationType" in text:
                            detected = True
                            evidence = f"GraphQL introspection exposes schema details at: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="APIAV-136", name="GraphQL Schema Introspection", severity=Severity.MEDIUM,
            category="API Advanced",
            description="GraphQL introspection mengekspos detail schema (queries, mutations).",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]
