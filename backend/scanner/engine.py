import asyncio
import time
import re
import aiohttp
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

from .models import ScanProgress, ScanStatus, VulnerabilityResult, validate_url
from .modules.injection_scanner import InjectionScanner
from .modules.auth_session_scanner import AuthSessionScanner
from .modules.business_logic_scanner import BusinessLogicScanner
from .modules.info_disclosure_scanner import InfoDisclosureScanner
from .modules.security_headers_scanner import SecurityHeadersScanner
from .modules.ssl_tls_scanner import SslTlsScanner
from .modules.client_side_scanner import ClientSideScanner
from .modules.file_upload_scanner import FileUploadScanner
from .modules.api_security_scanner import ApiSecurityScanner
from .modules.csrf_scanner import CsrfScanner
from .modules.database_scanner import DatabaseScanner
from .modules.server_infra_scanner import ServerInfraScanner
from .modules.source_code_scanner import SourceCodeScanner
from .modules.cms_scanner import CmsScanner
from .modules.advanced_injection_scanner import AdvancedInjectionScanner
from .modules.advanced_auth_scanner import AdvancedAuthScanner
from .modules.cache_proxy_scanner import CacheProxyScanner
from .modules.email_scanner import EmailScanner
from .modules.websocket_scanner import WebSocketScanner
from .modules.protocol_scanner import ProtocolScanner
from .modules.client_side_advanced_scanner import ClientSideAdvancedScanner
from .modules.api_advanced_scanner import ApiAdvancedScanner
from .modules.file_path_scanner import FilePathScanner
from .modules.crypto_scanner import CryptoScanner
from .modules.cloud_scanner import CloudScanner
from .modules.supply_chain_scanner import SupplyChainScanner
from .modules.encoding_bypass_scanner import EncodingBypassScanner
from .modules.logging_scanner import LoggingScanner
from .modules.misc_scanner import MiscScanner
from .modules.path_discovery_scanner import PathDiscoveryScanner
from .modules.cve_scanner import CveScanner


class ScannerEngine:
    # Max extra pages to crawl beyond the main URL
    MAX_CRAWL_PAGES = 5

    # These modules benefit from running on each discovered sub-page
    # (form-based / content-based checks). Infrastructure modules are excluded.
    PAGE_MODULE_NAMES = {
        "InjectionScanner",
        "BusinessLogicScanner",
        "InfoDisclosureScanner",
        "ClientSideScanner",
        "FileUploadScanner",
        "CsrfScanner",
        "AdvancedInjectionScanner",
        "ClientSideAdvancedScanner",
        "FilePathScanner",
        "SourceCodeScanner",
        "MiscScanner",
        "CryptoScanner",
        "SupplyChainScanner",
        "EmailScanner",
    }

    def __init__(self):
        self.modules = [
            InjectionScanner(),
            AuthSessionScanner(),
            BusinessLogicScanner(),
            InfoDisclosureScanner(),
            SecurityHeadersScanner(),
            SslTlsScanner(),
            ClientSideScanner(),
            FileUploadScanner(),
            ApiSecurityScanner(),
            CsrfScanner(),
            DatabaseScanner(),
            ServerInfraScanner(),
            SourceCodeScanner(),
            CmsScanner(),
            AdvancedInjectionScanner(),
            AdvancedAuthScanner(),
            CacheProxyScanner(),
            EmailScanner(),
            WebSocketScanner(),
            ProtocolScanner(),
            ClientSideAdvancedScanner(),
            ApiAdvancedScanner(),
            FilePathScanner(),
            CryptoScanner(),
            CloudScanner(),
            SupplyChainScanner(),
            EncodingBypassScanner(),
            LoggingScanner(),
            MiscScanner(),
            PathDiscoveryScanner(),
            CveScanner(),
        ]
        # Pre-filter page-level modules for quick lookup
        self.page_modules = [m for m in self.modules if m.__class__.__name__ in self.PAGE_MODULE_NAMES]

    async def _crawl_site(self, target_url: str, session: aiohttp.ClientSession) -> list[str]:
        """Crawl the target site and return up to MAX_CRAWL_PAGES unique internal URLs
        (beyond the main URL itself) by following <a href> links on the home page."""
        parsed = urlparse(target_url)
        base_netloc = parsed.netloc
        visited = {target_url}
        extra_urls = []

        try:
            async with session.get(
                target_url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return []
                ct = resp.headers.get("Content-Type", "")
                if "html" not in ct:
                    return []
                text = await resp.text(errors="replace")

                skip_exts = (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
                             ".css", ".js", ".ico", ".xml", ".zip", ".tar", ".gz", ".woff")
                hrefs = re.findall(r'href=["\']([^"\'#\s]+)["\']', text)
                for href in hrefs:
                    if len(extra_urls) >= self.MAX_CRAWL_PAGES:
                        break
                    if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                        continue
                    full_url = urljoin(target_url, href)
                    url_p = urlparse(full_url)
                    if url_p.netloc != base_netloc:
                        continue
                    if any(url_p.path.lower().endswith(ext) for ext in skip_exts):
                        continue
                    clean = url_p._replace(fragment="").geturl()
                    if clean not in visited:
                        visited.add(clean)
                        extra_urls.append(clean)
        except Exception:
            pass

        return extra_urls

    async def scan(self, target_url: str, progress_callback: Optional[Callable] = None) -> ScanProgress:
        target_url = validate_url(target_url)
        progress = ScanProgress(
            total_modules=len(self.modules),
            status=ScanStatus.RUNNING,
            start_time=time.time(),
        )

        if progress_callback:
            await progress_callback(progress)

        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Phase 1: Discover all internal pages via link crawling
            extra_urls = await self._crawl_site(target_url, session)

            for module in self.modules:
                module_name = module.__class__.__name__
                progress.current_module = module_name

                if progress_callback:
                    await progress_callback(progress)

                try:
                    results = await asyncio.wait_for(
                        module.scan(target_url, session),
                        timeout=60
                    )
                    if results:
                        progress.results.extend(results)
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass

                # Phase 2: Run page-content modules on each discovered sub-page
                if extra_urls and module in self.page_modules:
                    for extra_url in extra_urls:
                        try:
                            extra_results = await asyncio.wait_for(
                                module.scan(extra_url, session),
                                timeout=20,
                            )
                            if extra_results:
                                # Only include detected findings (skip "not found" noise)
                                progress.results.extend(r for r in extra_results if r.detected)
                        except (asyncio.TimeoutError, Exception):
                            pass

                progress.completed_modules += 1
                if progress_callback:
                    await progress_callback(progress)

        progress.status = ScanStatus.COMPLETED
        progress.end_time = time.time()

        if progress_callback:
            await progress_callback(progress)

        return progress
