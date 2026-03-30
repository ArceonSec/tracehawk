"""
tracehawk FastAPI backend — REST API to trigger scans and serve results.
"""

import os
import sys
import json
import uuid
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ── paths ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
SCANNER_PATH = ROOT_DIR / "scanner" / "scanner.py"
OUTPUT_DIR = ROOT_DIR / "output"
SCANS_DIR = OUTPUT_DIR / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)

# ── app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="tracehawk API",
    description="REST API for the tracehawk shift-left security scanner",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(
        default="./test-repos",
        description="Local path or git URL to scan",
    )
    tools: str = Field(
        default="semgrep,gitleaks,trivy",
        description="Comma-separated list of tools to run",
    )
    output: str = Field(
        default="json",
        description="Output format: json | terminal | both",
    )


class ScanSummary(BaseModel):
    scan_id: str
    target: str
    tools: list[str]
    status: str
    total_findings: int
    severity_counts: dict[str, int]
    started_at: str
    completed_at: Optional[str] = None


class ScanResult(ScanSummary):
    findings: list[dict]


# ── helpers ────────────────────────────────────────────────────────────

def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# Add to sys.path so we can import the scanner module
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scanner.scanner import run_scan

def _run_scanner(target: str, tools: str) -> list[dict]:
    """
    Run the scanner directly via function call and return parsed findings.
    """
    tools_list = [t.strip() for t in tools.split(",")]
    # Run the scanner function
    findings = run_scan(target, tools_list)
    return findings


def _save_scan(scan: dict) -> None:
    scan_file = SCANS_DIR / f"{scan['scan_id']}.json"
    with open(scan_file, "w") as f:
        json.dump(scan, f, indent=2)


def _load_scan(scan_id: str) -> Optional[dict]:
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if not scan_file.exists():
        return None
    with open(scan_file, "r") as f:
        return json.load(f)


def _list_scans() -> list[dict]:
    scans = []
    for scan_file in sorted(SCANS_DIR.glob("*.json"), reverse=True):
        with open(scan_file, "r") as f:
            data = json.load(f)
            # Return summary without full findings list
            scans.append({
                "scan_id": data["scan_id"],
                "target": data["target"],
                "tools": data["tools"],
                "status": data["status"],
                "total_findings": data["total_findings"],
                "severity_counts": data["severity_counts"],
                "started_at": data["started_at"],
                "completed_at": data.get("completed_at"),
            })
    return scans


# ── routes ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name": "tracehawk API",
        "version": "0.1.0",
        "docs": "/docs",
        "endpoints": {
            "POST /scan": "Trigger a new scan",
            "GET /scans": "List all scan results",
            "GET /scans/{scan_id}": "Get a specific scan result",
            "GET /scans/latest": "Get the most recent scan result",
            "GET /health": "Health check",
        },
    }


@app.get("/health")
def health_check():
    """Health check — verify tools are available."""
    tools_status = {}

    for tool, cmd in [
        ("semgrep", ["semgrep", "--version"]),
        ("gitleaks", ["gitleaks", "version"]),
        ("trivy", ["trivy", "--version"]),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            tools_status[tool] = {
                "available": result.returncode == 0,
                "version": result.stdout.strip().split("\n")[0] if result.returncode == 0 else None,
            }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools_status[tool] = {"available": False, "version": None}

    all_available = all(t["available"] for t in tools_status.values())

    return {
        "status": "healthy" if all_available else "degraded",
        "tools": tools_status,
    }


@app.post("/scan", response_model=ScanResult)
def trigger_scan(req: ScanRequest):
    """Trigger a new security scan."""
    scan_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    tools_list = [t.strip() for t in req.tools.split(",")]

    # Run scanner
    try:
        findings = _run_scanner(req.target, req.tools)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanner error: {str(e)}")

    completed_at = datetime.now(timezone.utc).isoformat()

    scan = {
        "scan_id": scan_id,
        "target": req.target,
        "tools": tools_list,
        "status": "completed",
        "total_findings": len(findings),
        "severity_counts": _severity_counts(findings),
        "started_at": started_at,
        "completed_at": completed_at,
        "findings": findings,
    }

    _save_scan(scan)

    return scan


@app.get("/scans")
def list_scans():
    """List all scan results (summaries only)."""
    return _list_scans()


@app.get("/scans/latest", response_model=ScanResult)
def get_latest_scan():
    """Get the most recent scan result."""
    scans = _list_scans()
    if not scans:
        raise HTTPException(status_code=404, detail="No scans found")
    latest = scans[0]
    full_scan = _load_scan(latest["scan_id"])
    if not full_scan:
        raise HTTPException(status_code=404, detail="Scan data not found")
    return full_scan


@app.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    """Get a specific scan result by ID."""
    scan = _load_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: str):
    """Delete a specific scan result."""
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    scan_file.unlink()
    return {"message": f"Scan {scan_id} deleted"}


@app.get("/findings")
def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity (e.g., CRITICAL, HIGH)"),
    tool: Optional[str] = Query(None, description="Filter by tool (e.g., semgrep, gitleaks, trivy)"),
):
    """Get all findings from the latest scan, with optional filtering."""
    scans = _list_scans()
    if not scans:
        raise HTTPException(status_code=404, detail="No scans found")

    latest = _load_scan(scans[0]["scan_id"])
    if not latest:
        raise HTTPException(status_code=404, detail="Scan data not found")

    findings = latest.get("findings", [])

    if severity:
        findings = [f for f in findings if (f.get("severity") or "").upper() == severity.upper()]
    if tool:
        findings = [f for f in findings if f.get("tool") == tool.lower()]

    return {
        "scan_id": latest["scan_id"],
        "total": len(findings),
        "findings": findings,
    }
