# tracehawk 🦅

> shift-left security scanner — SAST, secrets detection, dependency auditing, and AI-powered remediation in one container.

---

## what it does

tracehawk runs three security tools against your code in a single Docker container, classifies findings by OWASP Top 10 category + CWE, and optionally generates AI remediation strategies via Gemini:

| tool | what it catches | classification |
|------|----------------|----------------|
| **semgrep** | vulnerable code patterns (SAST) | OWASP + CWE from rule metadata |
| **gitleaks** | hardcoded secrets and leaked API keys | secret-type → OWASP mapping |
| **trivy** | CVEs in dependencies (`requirements.txt`, `package.json`, etc.) | A06:2021 + CVE/CWE IDs |

---

## architecture

```
┌─────────────────────────────────────────────────────┐
│  Browser (localhost:5173)                            │
│  ┌───────────────────────────────────────┐           │
│  │  Svelte Frontend                      │           │
│  │  • Dashboard + scan trigger           │           │
│  │  • Finding cards with OWASP/CWE tags  │           │
│  │  • AI remediation diff viewer         │           │
│  └────────────────┬──────────────────────┘           │
│                   │ REST (X-API-Key)                  │
│  ┌────────────────▼──────────────────────┐           │
│  │  FastAPI Backend (localhost:8000)      │           │
│  │  ┌──────────────────────────────┐     │           │
│  │  │  scanner.py                  │     │           │
│  │  │  • semgrep  → OWASP/CWE     │     │           │
│  │  │  • gitleaks → OWASP/CWE     │     │           │
│  │  │  • trivy    → OWASP/CWE     │     │           │
│  │  └──────────────────────────────┘     │           │
│  │  ┌──────────────────────────────┐     │           │
│  │  │  /ai/remediate/category      │     │           │
│  │  │  Gemini 2.5 Flash            │────►│ Google AI │
│  │  └──────────────────────────────┘     │           │
│  └───────────────────────────────────────┘           │
└─────────────────────────────────────────────────────┘
```

---

## setup

**1. configure secrets:**
```bash
cp .env.example .env
# Edit .env — set a strong TRACEHAWK_API_KEY and your GEMINI_API_KEY
```

**2. start the platform:**
```bash
docker compose up --build -d
```
This spins up:
- **tracehawk** — FastAPI backend on port `8000`
- **frontend** — Svelte dashboard on port `5173`

**3. scan a target via API:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $TRACEHAWK_API_KEY" \
  -d '{"target": "./test-repos", "tools": "semgrep,gitleaks,trivy", "output": "json"}'
```

**4. view results:**
- **Dashboard**: `http://localhost:5173`
- **Swagger UI**: `http://localhost:8000/docs`
- **API scans**: stored in `output/scans/` on the host (volume-mounted)
- **CLI output**: written to `output/results.json` (when using CLI mode)

---

## cli usage

You can use the scanner directly inside the container if you prefer CLI mode:

| flag | description | default |
|------|-------------|---------|
| `--target`, `-t` | local path or git URL to scan | `./test-repos` |
| `--tools` | comma-separated list of tools to run | `semgrep,gitleaks,trivy` |
| `--output`, `-o` | `json`, `terminal`, or `both` | `both` |

**examples:**
```bash
# run only semgrep and gitleaks
docker compose exec tracehawk python api/scanner.py --tools semgrep,gitleaks

# single tool against a specific path
docker compose exec tracehawk python api/scanner.py --target ./src --tools trivy
```

---

## output format
```json
[
  {
    "tool": "semgrep",
    "category": "A03:2021 - Injection",
    "rule": "python.lang.security.audit.eval-detected",
    "file": "test-repos/eval.py",
    "line": 2,
    "severity": "MEDIUM",
    "cwe": ["CWE-95"],
    "message": "Detected use of eval() — possible code injection vulnerability.",
    "snippet": "eval(user_input)"
  },
  {
    "tool": "gitleaks",
    "category": "A07:2021 - Identification and Authentication Failures",
    "rule": "generic-api-key",
    "file": "test-repos/test.txt",
    "line": 1,
    "severity": "CRITICAL",
    "cwe": ["CWE-798"],
    "message": "Detected a Generic API Key.",
    "snippet": "AKIA..."
  },
  {
    "tool": "trivy",
    "category": "A06:2021 - Vulnerable and Outdated Components",
    "rule": "CVE-2024-35195",
    "file": "requirements.txt",
    "line": null,
    "severity": "MEDIUM",
    "cwe": ["CWE-295"],
    "message": "requests: subsequent requests to the same host ignore cert verification",
    "snippet": "requests@2.32.3"
  }
]
```

scan exits with code `1` if any `HIGH` or `CRITICAL` findings are detected — ready for CI/CD pipelines.

---

## ai remediation

tracehawk uses **Gemini 2.5 Flash** to generate category-wise remediation strategies. The `/ai/remediate/category` endpoint:

1. Receives a batch of findings grouped by OWASP category
2. Generates a category-level risk explanation
3. Returns per-finding vulnerable → fixed code diffs with explanations

requires a `GEMINI_API_KEY` in `.env`. see the Swagger docs at `/docs` for the full API schema.

---

## trivy cache

trivy downloads its vulnerability DB on first run (~88MB). the docker-compose config mounts a named volume to avoid re-downloading every time.

add `.trivy-cache/` to your `.gitignore` if running locally.

---

## version pinning note

trivy is pinned to `v0.69.3`. `v0.69.4` was compromised in a supply chain attack on March 19, 2026 — a malicious commit injected code into the GitHub Actions release pipeline. `v0.69.3` is the latest confirmed safe release. see the [aquasecurity advisory](https://github.com/aquasecurity/trivy/security/advisories) for details.

---

## roadmap

- [x] **P1**: FastAPI backend — REST API to trigger scans and serve results, all inside Docker
- [x] **P2**: Svelte frontend — real-time pipeline visualization, findings dashboard with OWASP/CWE classification
- [x] **P4**: Gemini 2.5 Flash integration — category-wise risk explanations, per-finding vulnerable-vs-fixed code diffs
- [ ] **P3**: GitHub OAuth integration — scan private repos securely
- [ ] **P5**: Ops Healthboard integration — feed pipeline run data out to external dashboards
- [ ] GitHub Actions integration — run tracehawk as a CI check on every PR

---

## stack

| layer | technology |
|-------|-----------|
| **Runtime** | Python 3.11 / Alpine 3.19 |
| **API** | FastAPI + Uvicorn |
| **Frontend** | Svelte 5 + Vite |
| **Serving** | nginx-unprivileged (Alpine) |
| **SAST** | semgrep `1.73.0` |
| **Secrets** | gitleaks `8.18.2` |
| **SCA** | trivy `0.69.3` |
| **AI** | Gemini 2.5 Flash |
| **Container** | Docker / Docker Compose |

---

## license

MIT