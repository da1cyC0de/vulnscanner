import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class VulnerabilityResult:
    bug_id: str
    name: str
    severity: Severity
    category: str
    description: str
    endpoint: str = ""
    parameter: str = ""
    evidence: str = ""
    risk: str = ""
    fix_title: str = ""
    fix_description: str = ""
    fix_code_before: str = ""
    fix_code_after: str = ""
    fix_tips: list = field(default_factory=list)
    fix_references: list = field(default_factory=list)
    detected: bool = False


@dataclass
class ScanProgress:
    total_modules: int = 0
    completed_modules: int = 0
    current_module: str = ""
    status: ScanStatus = ScanStatus.PENDING
    start_time: float = 0
    end_time: float = 0
    results: list = field(default_factory=list)

    @property
    def progress_percent(self) -> int:
        if self.total_modules == 0:
            return 0
        return int((self.completed_modules / self.total_modules) * 100)

    @property
    def elapsed_time(self) -> float:
        if self.start_time == 0:
            return 0
        end = self.end_time if self.end_time > 0 else time.time()
        return round(end - self.start_time, 2)

    @property
    def summary(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in self.results:
            if r.detected:
                counts[r.severity.value] += 1
        return {
            "total_scanned": self.completed_modules,
            "total_vulnerabilities": sum(counts.values()),
            "severity_counts": counts,
            "elapsed_time": self.elapsed_time,
            "status": self.status.value,
        }


def validate_url(url: str) -> str:
    if not url:
        raise ValueError("URL tidak boleh kosong")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("URL tidak valid")
    return url
