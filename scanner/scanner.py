import subprocess
import json
import os
import sys
import argparse
import tempfile
import contextlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
FAIL_ON_SEVERITY = "HIGH"


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
    for f in data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "rule": f.get("check_id"),
            "file": f.get("path"),
            "line": f.get("start", {}).get("line"),
            "severity": (f.get("extra", {}).get("severity") or "").upper(),
            "message": f.get("extra", {}).get("message")
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
        findings.append({
            "tool": "gitleaks",
            "rule": f.get("RuleID"),
            "file": f.get("File"),
            "line": f.get("StartLine"),
            "severity": "CRITICAL",
            "message": f.get("Description")
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
            findings.append({
                "tool": "trivy",
                "rule": vuln.get("VulnerabilityID"),
                "file": result.get("Target"),
                "line": None,
                "severity": vuln.get("Severity"),
                "message": vuln.get("Title")
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
        abs_target = os.path.abspath(target)
        app_root = os.path.dirname(BASE_DIR)
        # Prevent path traversal outside of application root
        if not abs_target.startswith(app_root):
            raise ValueError("Path traversal detected: Target directory must be within application root.")
        yield abs_target


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
    return findings


# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(
        prog="devsec-scanner",
        description="Scan code for vulnerabilities using semgrep, gitleaks, and trivy"
    )
    parser.add_argument(
        "--target", "-t",
        default=os.path.join(BASE_DIR, "test-repos"),
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

    findings = []
    with resolve_target(args.target) as target:
        print(f"Scanning: {target}")
        print(f"Tools: {', '.join(tools)}\n")

        if "semgrep" in tools:
            print("Running semgrep...")
            findings.extend(scan_semgrep(target))
        if "gitleaks" in tools:
            print("Running gitleaks...")
            findings.extend(scan_gitleaks(target))
        if "trivy" in tools:
            print("Running trivy...")
            findings.extend(scan_trivy(target))

    print(f"\nTotal findings: {len(findings)}\n")

    if args.output in ("json", "both"):
        os.makedirs("/output", exist_ok=True)
        with open("/output/results.json", "w") as f:
            json.dump(findings, f, indent=2)
        print("Results written to /output/results.json")

    if args.output in ("terminal", "both"):
        print(json.dumps(findings, indent=2))

    if should_fail(findings):
        print("\nScan FAILED: HIGH or CRITICAL findings detected")
        sys.exit(1)

    print("\nScan PASSED")


if __name__ == "__main__":
    main()