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

**1. start the platform:**
```bash
docker compose up --build -d
```
This spins up the FastAPI backend and maps port 8000 for the REST API.

**2. scan a target via API:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "./test-repos", "tools": "semgrep,gitleaks,trivy", "output": "json"}'
```

**3. view results:**
Check `output/scans/` on your host machine or visit the Swagger UI at `http://localhost:8000/docs`.

---

## cli usage

You can still use the script internally if you prefer the CLI mode over the REST API:

| flag | description | default |
|------|-------------|---------|
| `--target`, `-t` | local path or git URL to scan | `./test-repos` |
| `--tools` | comma-separated list of tools to run | `semgrep,gitleaks,trivy` |
| `--output`, `-o` | `json`, `terminal`, or `both` | `both` |

**examples:**
```bash
# run only semgrep and gitleaks
docker compose exec tracehawk python scanner/scanner.py --tools semgrep,gitleaks

# single tool against a specific path
docker compose exec tracehawk python scanner/scanner.py --target ./src --tools trivy
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

- [x] **P1**: FastAPI backend — REST API to trigger scans and serve results, all inside Docker
- [ ] **P2**: Svelte frontend — real-time pipeline visualization, findings dashboard, side-by-side vulnerable vs fixed code diff
- [ ] **P3**: GitHub OAuth integration — scan private repos securely
- [ ] **P4**: Gemini 2.0 Flash integration — plain language explanations of findings, intelligent fix code generation, context-aware dependency suggestions, and complete report generation
- [ ] **P5**: Ops Healthboard integration — feed pipeline run data out to external dashboards
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