import subprocess
import json
import os
import sys
import argparse
import tempfile
import contextlib
import re
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_NORMALIZE = {"WARNING": "MEDIUM", "INFO": "LOW"}
FAIL_ON_SEVERITY = "HIGH"

# ── OWASP category mapping for gitleaks secret types ──
GITLEAKS_OWASP_MAP = {
    "aws":           "A05:2021 - Security Misconfiguration",
    "gcp":           "A05:2021 - Security Misconfiguration",
    "azure":         "A05:2021 - Security Misconfiguration",
    "private-key":   "A02:2021 - Cryptographic Failures",
    "generic-api":   "A07:2021 - Identification and Authentication Failures",
    "password":      "A07:2021 - Identification and Authentication Failures",
    "jwt":           "A02:2021 - Cryptographic Failures",
    "oauth":         "A07:2021 - Identification and Authentication Failures",
    "token":         "A07:2021 - Identification and Authentication Failures",
}
GITLEAKS_OWASP_DEFAULT = "A07:2021 - Identification and Authentication Failures"


def _normalize_severity(raw):
    """Normalize scanner-specific severity labels to a standard set."""
    sev = (raw or "").upper().strip()
    return SEVERITY_NORMALIZE.get(sev, sev)


def _classify_gitleaks_owasp(rule_id):
    """Map a gitleaks RuleID to the most specific OWASP category."""
    if not rule_id:
        return GITLEAKS_OWASP_DEFAULT
    rule_lower = rule_id.lower()
    for key, category in GITLEAKS_OWASP_MAP.items():
        if key in rule_lower:
            return category
    return GITLEAKS_OWASP_DEFAULT


def _extract_cwe(metadata):
    """Pull CWE identifiers from semgrep metadata."""
    cwe_raw = metadata.get("cwe", [])
    if isinstance(cwe_raw, str):
        cwe_raw = [cwe_raw]
    # Extract just the CWE-NNN identifiers
    cwe_ids = []
    for item in cwe_raw:
        match = re.search(r"CWE-\d+", str(item))
        if match:
            cwe_ids.append(match.group())
    return cwe_ids


# ---------------- SEMGREP ----------------

def run_semgrep(target):
    cmd = ["semgrep", "--config=p/security-audit", target, "--json", "--quiet"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def scan_semgrep(target):
    raw = run_semgrep(target)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings = []
    for err in data.get("errors", []):
        findings.append({
            "tool": "semgrep",
            "category": "A00: Scanner Execution Failure",
            "rule": "semgrep-critical-error",
            "file": "Pipeline Config",
            "line": None,
            "severity": "CRITICAL",
            "cwe": [],
            "message": f"Scanner Error: {err.get('message', 'Unknown error')}",
            "snippet": f"code: {err.get('code')}"
        })

    for f in data.get("results", []):
        metadata = f.get("extra", {}).get("metadata", {})
        owasp_cats = metadata.get("owasp", ["A00: Uncategorized Code Vulnerability"])
        category = owasp_cats[0] if isinstance(owasp_cats, list) and len(owasp_cats) > 0 else (owasp_cats or "A00: Uncategorized Code Vulnerability")
        cwe_ids = _extract_cwe(metadata)

        findings.append({
            "tool": "semgrep",
            "category": category,
            "rule": f.get("check_id"),
            "file": f.get("path"),
            "line": f.get("start", {}).get("line"),
            "severity": _normalize_severity(f.get("extra", {}).get("severity")),
            "cwe": cwe_ids,
            "message": f.get("extra", {}).get("message"),
            "snippet": f.get("extra", {}).get("lines", "")
        })
    return findings


# ---------------- GITLEAKS ----------------

def run_gitleaks(target):
    with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
        cmd = [
            "gitleaks", "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", tmp.name,
            "--no-git"
        ]
        subprocess.run(cmd, capture_output=True, text=True)
        try:
            with open(tmp.name, "r") as f:
                return f.read()
        except FileNotFoundError:
            return "[]"

def scan_gitleaks(target):
    raw = run_gitleaks(target)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings = []
    for f in data:
        rule_id = f.get("RuleID", "")
        findings.append({
            "tool": "gitleaks",
            "category": _classify_gitleaks_owasp(rule_id),
            "rule": rule_id,
            "file": f.get("File"),
            "line": f.get("StartLine"),
            "severity": "CRITICAL",
            "cwe": ["CWE-798"],  # Hardcoded credentials
            "message": f.get("Description"),
            "snippet": f.get("Match", f.get("Secret", ""))
        })
    return findings


# ---------------- TRIVY ----------------

def run_trivy(target):
    cmd = [
        "trivy", "fs", target,
        "--format", "json",
        "--quiet",
        "--exit-code", "0"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def scan_trivy(target):
    raw = run_trivy(target)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            # Extract CWE IDs from trivy's CweIDs field
            cwe_ids = vuln.get("CweIDs", []) or []
            findings.append({
                "tool": "trivy",
                "category": "A06:2021 - Vulnerable and Outdated Components",
                "rule": vuln.get("VulnerabilityID"),
                "file": result.get("Target"),
                "line": None,
                "severity": _normalize_severity(vuln.get("Severity")),
                "cwe": cwe_ids,
                "message": vuln.get("Title"),
                "snippet": f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}"
            })
    return findings


# ---------------- CLONE ----------------

@contextlib.contextmanager
def resolve_target(target):
    if target.startswith("http://") or target.startswith("https://") or target.startswith("git@"):
        temp_dir = tempfile.TemporaryDirectory()
        clone_dir = temp_dir.name
        print(f"Cloning {target}...")
        subprocess.run(["git", "clone", "--depth=1", "--", target, clone_dir], check=True)
        try:
            yield clone_dir
        finally:
            temp_dir.cleanup()
    else:
        # Use pathlib for path traversal check — str.startswith() is insufficient
        # because "/app_etc".startswith("/app") is True even though the paths diverge.
        app_root = Path(BASE_DIR).parent.resolve()
        target_path = Path(target).resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        
        if not (target_path.is_relative_to(app_root) or target_path.is_relative_to(temp_root)):
            raise ValueError(
                "Path traversal detected: Target must be within the application root."
            )
        yield str(target_path)


# ---------------- FAIL CHECK ----------------

def should_fail(findings):
    fail_index = SEVERITY_ORDER.index(FAIL_ON_SEVERITY)
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev in SEVERITY_ORDER and SEVERITY_ORDER.index(sev) >= fail_index:
            return True
    return False


# ---------------- API ----------------

def run_scan(target, tools_list):
    findings = []
    with resolve_target(target) as resolved_target:
        if "semgrep" in tools_list:
            findings.extend(scan_semgrep(resolved_target))
        if "gitleaks" in tools_list:
            findings.extend(scan_gitleaks(resolved_target))
        if "trivy" in tools_list:
            findings.extend(scan_trivy(resolved_target))
            
        # Strip the resolved target directory prefix from all file paths
        # so that remote git repos and snippet scans return relative paths.
        # We do this INSIDE the context manager while the temporary target exists.
        resolved_prefix = str(Path(resolved_target).resolve())
        for f in findings:
            file_path = f.get("file")
            if file_path:
                # Handle absolute paths returned by tools
                abs_path = str(Path(file_path).resolve())
                if abs_path.startswith(resolved_prefix):
                    f["file"] = abs_path[len(resolved_prefix):].lstrip("\\/")
                elif file_path.startswith(resolved_target):
                    f["file"] = file_path[len(resolved_target):].lstrip("\\/")
                
    return findings


# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(
        prog="devsec-scanner",
        description="Scan code for vulnerabilities using semgrep, gitleaks, and trivy"
    )
    parser.add_argument(
        "--target", "-t",
        default=os.path.join(os.path.dirname(BASE_DIR), "test-repos"),
        help="Local path or git URL to scan (default: ./test-repos)"
    )
    parser.add_argument(
        "--tools", 
        default="semgrep,gitleaks,trivy",
        help="Comma-separated list of tools to run (default: semgrep,gitleaks,trivy)"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "terminal", "both"],
        default="both",
        help="Output format (default: both)"
    )

    args = parser.parse_args()
    tools = [t.strip() for t in args.tools.split(",")]

    print(f"Scanning: {args.target}")
    print(f"Tools: {', '.join(tools)}\n")

    findings = run_scan(args.target, tools)

    print(f"\nTotal findings: {len(findings)}\n")

    if args.output in ("json", "both"):
        output_dir = "/output"
        try:
            os.makedirs(output_dir, exist_ok=True)
            out_file = os.path.join(output_dir, "results.json")
            with open(out_file, "w") as f:
                json.dump(findings, f, indent=2)
            print(f"Results written to {out_file}")
        except PermissionError:
            try:
                # Fallback to local app directory or tmp if standard mount fails
                fallback_dir = os.path.join(os.path.dirname(BASE_DIR), "output")
                os.makedirs(fallback_dir, exist_ok=True)
                out_file = os.path.join(fallback_dir, "results.json")
                with open(out_file, "w") as f:
                    json.dump(findings, f, indent=2)
                print(f"Results written to {out_file} (fallback)")
            except Exception as e:
                print(f"Warning: Could not write results to disk: {e}")

    if args.output in ("terminal", "both"):
        print(json.dumps(findings, indent=2))

    if should_fail(findings):
        print("\nScan FAILED: HIGH or CRITICAL findings detected")
        sys.exit(1)

    print("\nScan PASSED")


if __name__ == "__main__":
    main()