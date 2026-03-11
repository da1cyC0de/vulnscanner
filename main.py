import asyncio
import json
import os
import uuid
import ipaddress
import time
import re
from collections import defaultdict
from datetime import datetime
from dataclasses import asdict
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse
from pydantic import BaseModel, field_validator

from backend.scanner.engine import ScannerEngine
from backend.scanner.models import ScanProgress, ScanStatus, Severity
from backend.fix_guides.guides import get_fix_guide
from backend.ai_service import generate_fix_guide
from backend.reports.exporter import export_json, export_csv, export_markdown, export_html
from backend.scanner.subdomain import discover_subdomains

app = FastAPI(title="VulnScanner", version="1.0.0")

# CORS - allow frontend from any origin (VPS deployment)
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:4200,http://127.0.0.1:4200").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Storage with auto-cleanup ---
MAX_STORED_SCANS = 100
scan_results: dict[str, ScanProgress] = {}
scan_targets: dict[str, str] = {}  # scan_id -> target_url
scan_timestamps: dict[str, float] = {}  # scan_id -> created_at


def _cleanup_old_scans():
    """Remove oldest scans if storage exceeds limit."""
    if len(scan_results) <= MAX_STORED_SCANS:
        return
    sorted_ids = sorted(scan_timestamps, key=scan_timestamps.get)
    to_remove = sorted_ids[:len(sorted_ids) - MAX_STORED_SCANS]
    for sid in to_remove:
        scan_results.pop(sid, None)
        scan_targets.pop(sid, None)
        scan_timestamps.pop(sid, None)


def _store_scan(scan_id: str, progress: ScanProgress, target_url: str = ""):
    """Store scan result with timestamp and auto-cleanup."""
    scan_results[scan_id] = progress
    scan_timestamps[scan_id] = time.time()
    if target_url:
        scan_targets[scan_id] = target_url
    _cleanup_old_scans()


# --- SSRF Protection ---
_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # link-local / cloud metadata
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def _validate_target_url(url: str) -> str:
    """Validate URL: format check + block internal/private IPs (SSRF protection)."""
    url = url.strip()
    if len(url) > 2048:
        raise ValueError("URL terlalu panjang (max 2048 chars)")
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL tidak valid")
    # Block obvious internal hostnames
    if hostname in ('localhost', '0.0.0.0') or hostname.endswith('.internal') or hostname.endswith('.local'):
        raise ValueError("Scanning internal/private hosts tidak diperbolehkan")
    # Block private/reserved IPs
    try:
        ip = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                raise ValueError("Scanning internal/private IP tidak diperbolehkan")
    except ValueError as ve:
        if "tidak diperbolehkan" in str(ve):
            raise
        # hostname is not an IP — that's fine
    return url


# --- Rate Limiting ---
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 30  # max requests per window
RATE_WINDOW = 60  # seconds


def _check_rate_limit(client_ip: str):
    """Simple in-memory rate limiter."""
    now = time.time()
    _rate_store[client_ip] = [t for t in _rate_store[client_ip] if now - t < RATE_WINDOW]
    if len(_rate_store[client_ip]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests. Coba lagi nanti.")
    _rate_store[client_ip].append(now)


class ScanRequest(BaseModel):
    url: str
    modules: Optional[list[str]] = None  # None = scan all

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        return _validate_target_url(v)


class MassScanRequest(BaseModel):
    urls: list[str]
    modules: Optional[list[str]] = None

    @field_validator('urls')
    @classmethod
    def validate_urls(cls, v):
        if len(v) > 10:
            raise ValueError('Maksimal 10 URL')
        return [_validate_target_url(u) for u in v]


class SubdomainRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if len(v) > 500:
            raise ValueError('Domain terlalu panjang')
        return v


class AIFixRequest(BaseModel):
    bug_id: str
    name: str = ""
    severity: str = ""
    category: str = ""
    description: str = ""
    evidence: str = ""
    target_url: str = ""

    @field_validator('evidence', 'description')
    @classmethod
    def limit_length(cls, v):
        return v[:5000] if v else v


class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


def serialize_progress(progress: ScanProgress) -> dict:
    results_list = []
    for r in progress.results:
        if not r.detected:
            continue
        result_dict = asdict(r)
        result_dict["severity"] = r.severity.value
        result_dict["title"] = r.name  # frontend expects 'title'
        results_list.append(result_dict)

    return {
        "total_modules": progress.total_modules,
        "completed_modules": progress.completed_modules,
        "current_module": progress.current_module,
        "status": progress.status.value,
        "progress_percent": progress.progress_percent,
        "elapsed_time": progress.elapsed_time,
        "summary": progress.summary,
        "results": results_list,
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request):
    _check_rate_limit(request.client.host)
    scan_id = str(uuid.uuid4())[:8]
    _store_scan(scan_id, ScanProgress(status=ScanStatus.PENDING), req.url)
    return {"scan_id": scan_id, "url": req.url}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return serialize_progress(scan_results[scan_id])


@app.get("/api/fix/{bug_id}")
async def get_fix(bug_id: str):
    guide = get_fix_guide(bug_id)
    return guide


@app.post("/api/ai-fix")
async def ai_fix(req: AIFixRequest, request: Request):
    _check_rate_limit(request.client.host)
    result = await generate_fix_guide(req.model_dump())
    return result


# --- Module list endpoint ---
@app.get("/api/modules")
async def list_modules():
    engine = ScannerEngine()
    modules = []
    for m in engine.modules:
        name = m.__class__.__name__
        modules.append({
            "id": name,
            "name": name.replace("Scanner", "").replace("_", " "),
        })
    return {"modules": modules, "total": len(modules)}


# --- Export endpoints ---
@app.get("/api/export/{scan_id}/{fmt}")
async def export_report(scan_id: str, fmt: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = serialize_progress(scan_results[scan_id])
    target = scan_targets.get(scan_id, "unknown")

    if fmt == "json":
        return PlainTextResponse(
            export_json(data, target),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="vulnscan_{scan_id}.json"'}
        )
    elif fmt == "csv":
        return PlainTextResponse(
            export_csv(data),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="vulnscan_{scan_id}.csv"'}
        )
    elif fmt == "md":
        return PlainTextResponse(
            export_markdown(data, target),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="vulnscan_{scan_id}.md"'}
        )
    elif fmt == "html":
        return HTMLResponse(
            export_html(data, target),
            headers={"Content-Disposition": f'attachment; filename="vulnscan_{scan_id}.html"'}
        )
    else:
        raise HTTPException(status_code=400, detail="Format must be json, csv, md, or html")


# --- Subdomain Discovery ---
@app.post("/api/subdomain")
async def subdomain_scan(req: SubdomainRequest, request: Request):
    _check_rate_limit(request.client.host)
    result = await discover_subdomains(req.url)
    return result


# --- Mass Scan ---
@app.post("/api/mass-scan")
async def mass_scan(req: MassScanRequest, request: Request):
    _check_rate_limit(request.client.host)
    results = {}
    for url in req.urls[:10]:  # max 10 URLs
        scan_id = str(uuid.uuid4())[:8]
        engine = ScannerEngine()
        if req.modules:
            engine.modules = [m for m in engine.modules if m.__class__.__name__ in req.modules]
        progress = await engine.scan(url)
        _store_scan(scan_id, progress, url)
        results[scan_id] = {
            "url": url,
            "total_vulns": len(progress.results),
            "summary": progress.summary,
        }
    return {"scans": results, "total_urls": len(results)}


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_text()
        message = json.loads(data)
        target_url = message.get("url", "")

        if not target_url:
            await websocket.send_text(json.dumps({"error": "URL is required"}))
            return

        # Validate URL (SSRF protection)
        try:
            target_url = _validate_target_url(target_url)
        except ValueError as ve:
            await websocket.send_text(json.dumps({"error": str(ve)}))
            return

        scan_id = str(uuid.uuid4())[:8]
        engine = ScannerEngine()
        scan_targets[scan_id] = target_url

        # Module selection support
        selected_modules = message.get("modules", None)
        if selected_modules and isinstance(selected_modules, list):
            engine.modules = [m for m in engine.modules if m.__class__.__name__ in selected_modules]
            engine.modules = engine.modules or ScannerEngine().modules  # fallback if none match

        async def progress_callback(progress: ScanProgress):
            scan_results[scan_id] = progress
            try:
                await websocket.send_text(json.dumps(
                    {"scan_id": scan_id, **serialize_progress(progress)},
                    cls=EnumEncoder
                ))
            except Exception:
                pass

        await websocket.send_text(json.dumps({
            "scan_id": scan_id,
            "status": "starting",
            "message": f"Starting scan for {target_url}..."
        }))

        progress = await engine.scan(target_url, progress_callback)
        _store_scan(scan_id, progress, target_url)

        await websocket.send_text(json.dumps({
            "scan_id": scan_id,
            "status": "completed",
            **serialize_progress(progress)
        }, cls=EnumEncoder))

    except WebSocketDisconnect:
        pass
    except json.JSONDecodeError:
        await websocket.send_text(json.dumps({"error": "Invalid JSON"}))
    except Exception:
        try:
            await websocket.send_text(json.dumps({"error": "Internal server error"}))
        except Exception:
            pass
