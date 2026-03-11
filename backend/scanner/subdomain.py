"""Subdomain discovery using crt.sh (Certificate Transparency logs)."""
import aiohttp
import json
from urllib.parse import urlparse


async def discover_subdomains(target_url: str) -> dict:
    """Discover subdomains via crt.sh CT logs (no API key needed)."""
    parsed = urlparse(target_url)
    domain = parsed.hostname or parsed.path
    # Strip www
    if domain.startswith("www."):
        domain = domain[4:]

    subdomains = set()
    errors = []

    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # crt.sh - Certificate Transparency
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    try:
                        entries = json.loads(text)
                        for entry in entries:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub and sub.endswith(domain) and "*" not in sub:
                                    subdomains.add(sub)
                    except json.JSONDecodeError:
                        errors.append("crt.sh returned invalid data")
                else:
                    errors.append(f"crt.sh returned status {resp.status}")
    except Exception as e:
        errors.append(f"crt.sh error: {str(e)}")

    # Check which subdomains are live
    live = []
    if subdomains:
        timeout = aiohttp.ClientTimeout(total=5)
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            for sub in sorted(subdomains):
                try:
                    async with session.get(f"https://{sub}", ssl=False) as resp:
                        live.append({
                            "subdomain": sub,
                            "status": resp.status,
                            "live": True
                        })
                except Exception:
                    try:
                        async with session.get(f"http://{sub}", ssl=False) as resp:
                            live.append({
                                "subdomain": sub,
                                "status": resp.status,
                                "live": True
                            })
                    except Exception:
                        live.append({
                            "subdomain": sub,
                            "status": 0,
                            "live": False
                        })

    return {
        "domain": domain,
        "total_found": len(subdomains),
        "live_count": sum(1 for s in live if s["live"]),
        "subdomains": live,
        "errors": errors
    }
