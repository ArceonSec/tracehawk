# tracehawk 🦅

> shift-left security scanner — SAST, secrets detection, and dependency auditing in one container.

---

## what it does

tracehawk runs three security tools against your code in a single Docker container and outputs a unified JSON report:

| tool | what it catches |
|------|----------------|
| **semgrep** | vulnerable code patterns (SAST) |
| **gitleaks** | hardcoded secrets and leaked API keys |
| **trivy** | CVEs in dependencies (`requirements.txt`, `package.json`, etc.) |

---

## quickstart

**build:**
```bash
docker build -t tracehawk .
```

**scan a local directory:**
```bash
docker run --rm \
  -v ${PWD}/output:/output \
  -v ${PWD}/.trivy-cache:/root/.cache/trivy \
  tracehawk python main.py --target /path/to/code
```

**scan a remote git repo:**
```bash
docker run --rm \
  -v ${PWD}/output:/output \
  -v ${PWD}/.trivy-cache:/root/.cache/trivy \
  tracehawk python main.py --target https://github.com/user/repo
```

results are written to `output/results.json`.

---

## cli flags

| flag | description | default |
|------|-------------|---------|
| `--target`, `-t` | local path or git URL to scan | `./test-repos` |
| `--tools` | comma-separated list of tools to run | `semgrep,gitleaks,trivy` |
| `--output`, `-o` | `json`, `terminal`, or `both` | `both` |

**examples:**
```bash
# run only semgrep and gitleaks
python main.py --tools semgrep,gitleaks

# terminal output only, no file
python main.py --output terminal

# single tool against a specific path
python main.py --target ./src --tools trivy
```

---

## output format
```json
[
  {
    "tool": "semgrep",
    "rule": "python.lang.security.audit.eval-detected",
    "file": "/app/test-repos/eval.py",
    "line": 2,
    "severity": "WARNING",
    "message": "Detected use of eval() — possible code injection vulnerability."
  },
  {
    "tool": "gitleaks",
    "rule": "generic-api-key",
    "file": "/app/test-repos/test.txt",
    "line": 1,
    "severity": "CRITICAL",
    "message": "Detected a Generic API Key."
  },
  {
    "tool": "trivy",
    "rule": "CVE-2024-35195",
    "file": "requirements.txt",
    "line": null,
    "severity": "MEDIUM",
    "message": "requests: subsequent requests to the same host ignore cert verification"
  }
]
```

scan exits with code `1` if any `HIGH` or `CRITICAL` findings are detected — ready for CI/CD pipelines.

---

## trivy cache

trivy downloads its vulnerability DB on first run (~88MB). mount a local cache volume to avoid re-downloading every time:
```bash
-v ${PWD}/.trivy-cache:/root/.cache/trivy
```

add `.trivy-cache/` to your `.gitignore`.

---

## version pinning note

trivy is pinned to `v0.69.3`. `v0.69.4` was compromised in a supply chain attack on March 19, 2026 — a malicious commit injected code into the GitHub Actions release pipeline. `v0.69.3` is the latest confirmed safe release. see the [aquasecurity advisory](https://github.com/aquasecurity/trivy/security/advisories) for details.

---

## roadmap

- [ ] FastAPI backend — REST API to trigger scans and serve results
- [ ] React frontend — web UI with tool toggles, severity filters, findings dashboard
- [ ] Gemini 2.0 Flash integration — AI-powered fix suggestions per finding
- [ ] auto-remediation agent — auto bump vulnerable deps, redact leaked secrets, suggest code patches
- [ ] GitHub Actions integration — run tracehawk as a CI check on every PR

---

## stack

- Python 3.11 / Alpine 3.19
- semgrep `1.73.0`
- gitleaks `8.18.2`
- trivy `0.69.3`
- Docker

---

## license

MIT