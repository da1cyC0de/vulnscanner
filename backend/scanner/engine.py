import asyncio
import time
import aiohttp
from typing import Callable, Optional

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


class ScannerEngine:
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
        ]

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

                progress.completed_modules += 1
                if progress_callback:
                    await progress_callback(progress)

        progress.status = ScanStatus.COMPLETED
        progress.end_time = time.time()

        if progress_callback:
            await progress_callback(progress)

        return progress
