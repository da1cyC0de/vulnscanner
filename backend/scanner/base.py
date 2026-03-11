import abc
import asyncio
import aiohttp
import ssl
from typing import Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .models import VulnerabilityResult, Severity


class BaseModule(abc.ABC):
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=15)

    @abc.abstractmethod
    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        pass

    async def fetch(self, session: aiohttp.ClientSession, url: str, method: str = "GET",
                    data: dict = None, headers: dict = None, allow_redirects: bool = True,
                    timeout: int = 15) -> Optional[aiohttp.ClientResponse]:
        try:
            custom_timeout = aiohttp.ClientTimeout(total=timeout)
            kwargs = {
                "url": url,
                "headers": headers or self._default_headers(),
                "timeout": custom_timeout,
                "allow_redirects": allow_redirects,
                "ssl": False,
            }
            if method.upper() == "POST" and data:
                kwargs["data"] = data
            async with session.request(method, **kwargs) as resp:
                await resp.read()
                return resp
        except Exception:
            return None

    async def fetch_text(self, session: aiohttp.ClientSession, url: str, **kwargs) -> tuple[Optional[str], Optional[aiohttp.ClientResponse]]:
        try:
            custom_timeout = aiohttp.ClientTimeout(total=kwargs.get("timeout", 15))
            async with session.get(url, headers=kwargs.get("headers", self._default_headers()),
                                   timeout=custom_timeout, ssl=False,
                                   allow_redirects=kwargs.get("allow_redirects", True)) as resp:
                text = await resp.text(errors="replace")
                return text, resp
        except Exception:
            return None, None

    def _default_headers(self) -> dict:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    def parse_html(self, html: str) -> BeautifulSoup:
        return BeautifulSoup(html, "html.parser")

    def make_result(self, bug_id: str, name: str, severity: Severity, category: str,
                    description: str, detected: bool = False, **kwargs) -> VulnerabilityResult:
        return VulnerabilityResult(
            bug_id=bug_id, name=name, severity=severity, category=category,
            description=description, detected=detected, **kwargs
        )
