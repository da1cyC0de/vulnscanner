import aiohttp
import json
import os
import re
from pathlib import Path

# Load .env file if exists (for local development)
_env_file = Path(__file__).resolve().parent.parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.5-flash"


def _extract_json(text: str) -> dict:
    """Robustly extract JSON from AI response that may include thinking tokens or markdown."""
    text = text.strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Remove markdown code blocks
    cleaned = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
    cleaned = re.sub(r'\n?```\s*$', '', cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Find the first { ... } block (greedy)
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("No valid JSON found in response", text, 0)


async def generate_fix_guide(vuln_data: dict) -> dict:
    """Generate AI-powered fix guide using Google Gemini (free tier)."""

    if not GEMINI_API_KEY:
        return {
            "ai_generated": False,
            "error": "API key belum diset. Ambil GRATIS di https://aistudio.google.com/apikey lalu set env: GEMINI_API_KEY=AIzaSy..."
        }

    prompt = f"""Kamu adalah security expert. Analisis vulnerability berikut yang ditemukan dari scan website, lalu berikan panduan fix yang SPESIFIK.

**Vulnerability:**
- Name: {vuln_data.get('name', 'Unknown')}
- Bug ID: {vuln_data.get('bug_id', '')}
- Severity: {vuln_data.get('severity', '')}
- Category: {vuln_data.get('category', '')}
- Description: {vuln_data.get('description', '')}
- Evidence: {vuln_data.get('evidence', 'Tidak ada evidence detail')}
- Target URL: {vuln_data.get('target_url', '')}

Berikan response dalam format JSON (HANYA JSON, tanpa markdown code block):
{{
  "title": "judul fix singkat",
  "risk_explanation": "penjelasan risiko spesifik berdasarkan evidence yang ditemukan",
  "fix_steps": ["langkah 1", "langkah 2", "langkah 3"],
  "code_before": "contoh kode RENTAN yang relevan dengan vulnerability ini (multi-line string)",
  "code_after": "contoh kode yang sudah DIPERBAIKI (multi-line string)",
  "server_config": "konfigurasi server yang perlu diubah (Nginx/Apache/dll) jika relevan, kosongkan jika tidak",
  "references": ["link referensi 1", "link referensi 2"]
}}

PENTING:
- Jawab dalam Bahasa Indonesia
- Berikan code contoh yang NYATA dan bisa langsung dipakai
- Sesuaikan fix dengan evidence yang ditemukan
- Jangan generic, harus spesifik ke vulnerability ini"""

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                api_url,
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [
                        {
                            "parts": [{"text": prompt}]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.3,
                        "maxOutputTokens": 8192,
                        "responseMimeType": "application/json"
                    }
                },
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    err_body = await resp.text()
                    if "leaked" in err_body.lower():
                        msg = "API key sudah expired/leaked. Buat key baru di https://aistudio.google.com/apikey lalu update .env file."
                    elif resp.status == 403:
                        msg = "API key tidak valid atau expired. Cek GEMINI_API_KEY di file .env"
                    elif resp.status == 429:
                        msg = "Rate limit tercapai. Tunggu beberapa menit lalu coba lagi."
                    else:
                        msg = f"AI service error (status {resp.status}). Coba lagi nanti."
                    return {
                        "ai_generated": False,
                        "error": msg
                    }

                data = await resp.json()
                # gemini-2.5-flash may return thinking in separate parts
                # find the part that contains actual JSON content
                parts = data["candidates"][0]["content"]["parts"]
                content = ""
                for part in parts:
                    text = part.get("text", "")
                    if text and ("{" in text):
                        content = text.strip()
                        break
                if not content:
                    content = parts[-1].get("text", "").strip()

                result = _extract_json(content)
                result["ai_generated"] = True
                return result

    except json.JSONDecodeError:
        return {
            "ai_generated": False,
            "error": "AI response tidak valid JSON, coba lagi"
        }
    except aiohttp.ClientError:
        return {
            "ai_generated": False,
            "error": "Gagal connect ke AI service. Coba lagi nanti."
        }
    except Exception:
        return {
            "ai_generated": False,
            "error": "Terjadi error saat memproses AI. Coba lagi."
        }
