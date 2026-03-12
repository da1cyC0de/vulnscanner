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
        results.extend(await self._check_upload_directory(session, target_url))
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
                detected=detected, endpoint=target_url, evidence="\n".join(evidence_parts[:5]),
            ),
            self.make_result(
                bug_id="FILE-045", name="File Extension Bypass Check", severity=Severity.HIGH,
                category="File Upload",
                description="Deteksi kemungkinan bypass ekstensi pada file upload.",
                detected=detected,
                endpoint=target_url,
                evidence="Upload forms found that may accept dangerous file types" if detected else "",
            ),
        ]

    async def _check_upload_directory(self, session, target_url) -> list:
        detected = False
        evidence = ""
        upload_dirs = ["uploads/", "upload/", "files/", "media/", "attachments/", "images/uploads/"]
        for d in upload_dirs:
            url = urljoin(target_url.rstrip("/") + "/", d)
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        if "index of" in text.lower() or "parent directory" in text.lower():
                            detected = True
                            evidence = f"Upload directory listing enabled: {url}"
                            break
            except Exception:
                pass

        return [self.make_result(
            bug_id="FILE-046", name="Upload Directory Listing", severity=Severity.HIGH,
            category="File Upload",
            description="Cek apakah direktori upload bisa di-browse (directory listing).",
            detected=detected, endpoint=url if detected else "", evidence=evidence,
        )]
