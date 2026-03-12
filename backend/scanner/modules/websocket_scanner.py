import aiohttp
import re
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class WebSocketScanner(BaseModule):
    """Scans for: WebSocket Security, Origin Validation"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_websocket_usage(html))
        results.extend(self._check_ws_origin_bypass(html))
        return results

    def _check_websocket_usage(self, html) -> list:
        detected = False
        evidence_parts = []

        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']ws://',
            r'new\s+WebSocket\s*\(\s*["\']wss?://',
            r'socket\.io', r'sockjs', r'signalr',
        ]

        for pattern in ws_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                detected = True
                if "ws://" in match.group():
                    evidence_parts.append(f"Insecure WebSocket (ws://) found: {match.group()[:100]}")
                else:
                    evidence_parts.append(f"WebSocket usage found: {match.group()[:100]}")

        return [self.make_result(
            bug_id="WS-117", name="WebSocket Security Check", severity=Severity.MEDIUM,
            category="WebSocket",
            description="Cek penggunaan WebSocket dan keamanannya (ws vs wss).",
            detected=detected, evidence="\n".join(evidence_parts[:5]),
        )]

    def _check_ws_origin_bypass(self, html) -> list:
        detected = False
        evidence = ""
        if re.search(r'new\s+WebSocket', html):
            if not re.search(r'origin|Origin|checkOrigin', html):
                detected = True
                evidence = "WebSocket connection without origin validation in code"

        return [self.make_result(
            bug_id="WS-118", name="WebSocket Origin Validation Missing", severity=Severity.MEDIUM,
            category="WebSocket",
            description="WebSocket tanpa validasi origin bisa rentan Cross-Site WebSocket Hijacking.",
            detected=detected, evidence=evidence,
        )]
