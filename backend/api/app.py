"""
tracehawk FastAPI backend — REST API to trigger scans and serve results.
"""

import os
import sys
import json
import uuid
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load .env file when running locally; no-op inside Docker where Compose injects vars.
load_dotenv()

from fastapi import FastAPI, HTTPException, Query, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# ── auth ───────────────────────────────────────────────────────────────
API_TOKEN = os.getenv("TRACEHAWK_API_KEY")
if not API_TOKEN:
    raise RuntimeError(
        "TRACEHAWK_API_KEY environment variable is not set. "
        "Create a .env file and set a strong random key before starting."
    )

api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=True)

def verify_api_key(api_key: str = Security(api_key_scheme)):
    if api_key != API_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

# ── paths ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
SCANNER_PATH = ROOT_DIR / "api" / "scanner.py"
OUTPUT_DIR = ROOT_DIR / "output"
SCANS_DIR = OUTPUT_DIR / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)

# ── storage backend ────────────────────────────────────────────────────
# When GCS_BUCKET_NAME is set, scans are stored in a GCS bucket (Cloud Run).
# When absent, falls back to local filesystem (local dev / Docker Compose).
import logging as _logging

GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
_gcs_bucket = None

if GCS_BUCKET_NAME:
    try:
        from google.cloud import storage as gcs_storage
        _gcs_client = gcs_storage.Client()
        _gcs_bucket = _gcs_client.bucket(GCS_BUCKET_NAME)
        _logging.info(f"GCS storage enabled: gs://{GCS_BUCKET_NAME}/scans/")
    except Exception as e:
        _logging.warning(f"GCS init failed ({e}), falling back to local storage")
        _gcs_bucket = None
else:
    _logging.info("GCS_BUCKET_NAME not set — using local filesystem storage")

# ── app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="tracehawk API",
    description="REST API for the tracehawk shift-left security scanner",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Svelte/Vite dev
        "http://localhost:3000",  # React default
        "http://localhost:8080",  # Nginx container
    ],
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
    code_snippet: Optional[str] = Field(
        default=None,
        description="Optional: Raw code string for snippet scanning mode",
    )
    filename: Optional[str] = Field(
        default=None,
        description="Optional: Custom filename for the code snippet (e.g., script.py)",
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
    categorized_findings: dict = {}


# ── helpers ────────────────────────────────────────────────────────────

def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


from api.scanner import run_scan

def _run_scanner(target: str, tools: str) -> list[dict]:
    """
    Run the scanner directly via function call and return parsed findings.
    """
    tools_list = [t.strip() for t in tools.split(",")]
    # Run the scanner function
    findings = run_scan(target, tools_list)
    return findings


def _save_scan(scan: dict) -> None:
    data = json.dumps(scan, indent=2)
    if _gcs_bucket:
        blob = _gcs_bucket.blob(f"scans/{scan['scan_id']}.json")
        blob.upload_from_string(data, content_type="application/json")
    else:
        scan_file = SCANS_DIR / f"{scan['scan_id']}.json"
        with open(scan_file, "w") as f:
            f.write(data)


def _load_scan(scan_id: str) -> Optional[dict]:
    # Allow alphanumeric + hyphens only
    if not all(c.isalnum() or c == '-' for c in scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    if _gcs_bucket:
        blob = _gcs_bucket.blob(f"scans/{scan_id}.json")
        if not blob.exists():
            return None
        return json.loads(blob.download_as_text())
    else:
        scan_file = SCANS_DIR / f"{scan_id}.json"
        if not scan_file.exists():
            return None
        with open(scan_file, "r") as f:
            return json.load(f)


def _list_scans() -> list[dict]:
    scans = []
    if _gcs_bucket:
        blobs = _gcs_bucket.list_blobs(prefix="scans/", delimiter="/")
        for blob in blobs:
            if not blob.name.endswith(".json"):
                continue
            data = json.loads(blob.download_as_text())
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
        # Sort by started_at descending (newest first)
        scans.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    else:
        for scan_file in sorted(SCANS_DIR.glob("*.json"), reverse=True):
            with open(scan_file, "r") as f:
                data = json.load(f)
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
    """Health check — verify tools are available. Requires auth to see version details."""
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
def trigger_scan(req: ScanRequest, api_key: str = Depends(verify_api_key)):
    """Trigger a new security scan."""
    scan_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    tools_list = [t.strip() for t in req.tools.split(",")]

    # Run scanner
    try:
        if req.code_snippet:
            # Create a secure temporary directory for the snippet
            with tempfile.TemporaryDirectory() as td:
                safe_filename = Path(req.filename or "snippet.py").name
                file_path = Path(td) / safe_filename
                file_path.write_text(req.code_snippet, encoding="utf-8")
                
                # Execute scanner against the temporary directory
                findings = _run_scanner(str(td), req.tools)
        else:
            findings = _run_scanner(req.target, req.tools)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import logging
        logging.error(f"Internal scanner workflow error: {e}")
        raise HTTPException(status_code=500, detail="Scanner encountered an internal execution error.")

    completed_at = datetime.now(timezone.utc).isoformat()

    categorized_findings = {}
    for f in findings:
        cat = f.get("category", "Uncategorized")
        if cat not in categorized_findings:
            categorized_findings[cat] = []
        categorized_findings[cat].append(f)

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
        "categorized_findings": categorized_findings,
    }

    _save_scan(scan)

    return scan


@app.get("/scans")
def list_scans(api_key: str = Depends(verify_api_key)):
    """List all scan results (summaries only)."""
    return _list_scans()


@app.get("/scans/latest", response_model=ScanResult)
def get_latest_scan(api_key: str = Depends(verify_api_key)):
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
def get_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Get a specific scan result by ID."""
    scan = _load_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Delete a specific scan result."""
    if not all(c.isalnum() or c == '-' for c in scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    if _gcs_bucket:
        blob = _gcs_bucket.blob(f"scans/{scan_id}.json")
        if not blob.exists():
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        blob.delete()
    else:
        scan_file = SCANS_DIR / f"{scan_id}.json"
        if not scan_file.exists():
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        scan_file.unlink()
    return {"message": f"Scan {scan_id} deleted"}


# Max findings per AI remediation call — prevents oversized prompt injection payloads.
_MAX_REMEDIATION_FINDINGS = 50


class RemediationRequest(BaseModel):
    category: str
    findings: list[dict]


@app.post("/ai/remediate/category")
def remediate_category(req: RemediationRequest, api_key: str = Depends(verify_api_key)):
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY not configured on server")

    if len(req.findings) > _MAX_REMEDIATION_FINDINGS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many findings: maximum {_MAX_REMEDIATION_FINDINGS} per request.",
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=gemini_key)

        # Build structured finding summaries for the prompt
        finding_summaries = []
        for i, f in enumerate(req.findings, 1):
            summary = (
                f"Finding #{i}:\n"
                f"  Tool: {f.get('tool', 'unknown')}\n"
                f"  Rule: {f.get('rule', 'N/A')}\n"
                f"  File: {f.get('file', 'N/A')}\n"
                f"  Line: {f.get('line', 'N/A')}\n"
                f"  Severity: {f.get('severity', 'N/A')}\n"
                f"  CWE: {', '.join(f.get('cwe', [])) or 'N/A'}\n"
                f"  Message: {f.get('message', 'N/A')}\n"
                f"  Code Snippet: {f.get('snippet', 'N/A')}"
            )
            finding_summaries.append(summary)

        findings_text = "\n\n".join(finding_summaries)

        # System instruction — kept separate from user-controlled data to prevent prompt injection.
        system_instruction = (
            "You are an expert Application Security / DevSecOps Engineer performing a security audit.\n\n"
            f"The following findings all fall under OWASP category: **{req.category}**\n\n"
            "Your job is to provide:\n"
            "1. `category_explanation` — A concise explanation (2-4 sentences, NO markdown formatting) of why "
            "   this OWASP category is dangerous and what real-world attacks it enables.\n"
            "2. `fixes` — A list of ACTIONABLE remediation steps for each finding. The fix content depends on "
            "   which scanner tool detected it:\n\n"
            "   **For `trivy` findings (vulnerable dependencies):**\n"
            "   - `vulnerable_code` = the current package version string (e.g. `requests==2.25.1`)\n"
            "   - `remediated_code_snippet` = the safe version pin (e.g. `requests>=2.32.0`)\n"
            "   - `explanation` = What the CVE does, what version fixes it, and whether it's a breaking change.\n"
            "     If the package has known breaking changes, mention them.\n\n"
            "   **For `semgrep` findings (code vulnerabilities):**\n"
            "   - `vulnerable_code` = the exact vulnerable code snippet\n"
            "   - `remediated_code_snippet` = the corrected, safe replacement code that fixes the vulnerability\n"
            "   - `explanation` = What the vulnerability is and how the fix neutralizes it.\n\n"
            "   **For `gitleaks` findings (leaked secrets):**\n"
            "   - `vulnerable_code` = the leaked secret pattern (redacted)\n"
            "   - `remediated_code_snippet` = show how to load from environment variables instead "
            "     (e.g. `os.environ.get('API_KEY')` or `process.env.API_KEY`)\n"
            "   - `explanation` = Steps to revoke/rotate the leaked credential. Be specific: "
            "     e.g. 'Go to AWS IAM console > rotate this access key' or "
            "     'Revoke this GitHub token at github.com/settings/tokens'.\n\n"
            "Respond STRICTLY in valid JSON matching this schema:\n"
            "{\n"
            '  "category_explanation": "Plain text explanation of the systemic risk. No markdown.",\n'
            '  "fixes": [\n'
            '    {\n'
            '      "file": "exact file path from the finding",\n'
            '      "line": 123,\n'
            '      "vulnerable_code": "the dangerous code or version string",\n'
            '      "remediated_code_snippet": "the safe replacement code, version pin, or env var usage",\n'
            '      "explanation": "Plain text. What was wrong and exactly how to fix it. No markdown."\n'
            '    }\n'
            '  ]\n'
            "}\n"
            "IMPORTANT: Do NOT use any markdown formatting (no **, no ##, no *, no backticks) in any field values. "
            "Use plain text only. Do not include any text outside the JSON block."
        )

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=findings_text,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
            ),
        )

        # Validate the response structure
        parsed = json.loads(response.text)
        if not isinstance(parsed.get("category_explanation"), str):
            parsed["category_explanation"] = "AI analysis could not generate an explanation for this category."
        if not isinstance(parsed.get("fixes"), list):
            parsed["fixes"] = []

        return parsed

    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Gemini returned invalid JSON. Please retry.")
    except Exception as e:
        import logging
        # Log the full error server-side, but sanitize client response
        logging.error(f"Gemini API Error: {e}")
        error_msg = str(e)
        # Never leak API keys or internal file paths in responses
        if gemini_key and gemini_key in error_msg:
            error_msg = "Authentication error with AI provider."
        elif "quota" in error_msg.lower() or "rate" in error_msg.lower():
            error_msg = "AI provider rate limit exceeded. Please try again later."
        elif "not found" in error_msg.lower():
            error_msg = "AI model not available. Check server configuration."
        else:
            error_msg = "AI remediation generation failed. Check server logs."
        raise HTTPException(status_code=500, detail=error_msg)


@app.get("/findings")
def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity (e.g., CRITICAL, HIGH)"),
    tool: Optional[str] = Query(None, description="Filter by tool (e.g., semgrep, gitleaks, trivy)"),
    api_key: str = Depends(verify_api_key)
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
