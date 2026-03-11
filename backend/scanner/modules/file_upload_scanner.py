import aiohttp
import re
from urllib.parse import urljoin
from ..base import BaseModule
from ..models import VulnerabilityResult, Severity


class FileUploadScanner(BaseModule):
    """Scans for: Unrestricted File Upload Detection, File Extension Bypass"""

    async def scan(self, target_url: str, session: aiohttp.ClientSession) -> list[VulnerabilityResult]:
        results = []
        html, resp = await self.fetch_text(session, target_url)
        if not html:
            return results

        results.extend(self._check_file_upload_forms(html, target_url))
        return results

    def _check_file_upload_forms(self, html, target_url) -> list:
        detected = False
        evidence_parts = []
        soup = self.parse_html(html)

        for form in soup.find_all("form"):
            file_inputs = form.find_all("input", {"type": "file"})
            if file_inputs:
                for fi in file_inputs:
                    accept = fi.get("accept", "")
                    name = fi.get("name", "unknown")
                    if not accept or accept == "*/*":
                        detected = True
                        evidence_parts.append(f"File upload '{name}' without restriction (accept='{accept}')")
                    elif any(ext in accept for ext in [".php", ".jsp", ".asp", ".exe", ".sh"]):
                        detected = True
                        evidence_parts.append(f"File upload '{name}' allows dangerous types: {accept}")

        return [
            self.make_result(
                bug_id="FILE-044", name="Unrestricted File Upload", severity=Severity.HIGH,
                category="File Upload",
                description="Deteksi form file upload yang tidak ada pembatasan tipe file.",
                detected=detected, evidence="\n".join(evidence_parts[:5]),
            ),
            self.make_result(
                bug_id="FILE-045", name="File Extension Bypass Check", severity=Severity.HIGH,
                category="File Upload",
                description="Deteksi kemungkinan bypass ekstensi pada file upload.",
                detected=detected,
                evidence="Upload forms found that may accept dangerous file types" if detected else "",
            ),
        ]
