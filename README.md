# tracehawk 🦅

> AI-powered DevSecOps platform that detects vulnerabilities, exposed secrets, and vulnerable dependencies, then generates OWASP-mapped remediation guidance.

---

## what is tracehawk?

Most security scanners stop at detection.

TraceHawk combines multiple security tools into a unified security analysis pipeline:

* **Semgrep** for vulnerable code detection (SAST)
* **Gitleaks** for exposed secrets and API keys
* **Trivy** for dependency vulnerability scanning
* **Gemini 2.5 Flash** for AI-powered remediation guidance

Instead of producing isolated findings, TraceHawk normalizes results into a unified security model, maps them to OWASP Top 10 categories and CWE identifiers, and generates actionable remediation guidance for developers.

---

## screenshots

### dashboard

> <img width="1902" height="851" alt="image" src="https://github.com/user-attachments/assets/fe089e6c-a6fa-475a-925a-594506ecfd1c" />


### findings view

<img width="1493" height="162" alt="image" src="https://github.com/user-attachments/assets/4303b93a-000f-41f4-9809-e01b6244b475" />

### ai remediation

<img width="1918" height="865" alt="image" src="https://github.com/user-attachments/assets/c82022c2-b153-4175-babd-07963789cf89" />


---

## what it does

TraceHawk runs three security tools against your codebase, normalizes their findings, classifies them by OWASP Top 10 category and CWE identifiers, and optionally generates AI-powered remediation guidance.

| tool         | what it catches                                                    | classification                 |
| ------------ | ------------------------------------------------------------------ | ------------------------------ |
| **semgrep**  | vulnerable code patterns (SAST)                                    | OWASP + CWE from rule metadata |
| **gitleaks** | hardcoded secrets and leaked API keys                              | secret-type → OWASP mapping    |
| **trivy**    | vulnerable dependencies (`requirements.txt`, `package.json`, etc.) | A06:2021 + CVE/CWE IDs         |

---

## architecture

```text
┌─────────────────────────────────────────────────────┐
│ Browser (localhost:5173)                            │
│                                                     │
│  Svelte Frontend                                    │
│  • Dashboard                                        │
│  • Scan Trigger                                     │
│  • Findings Explorer                               │
│  • AI Remediation Viewer                            │
│                                                     │
└──────────────────┬──────────────────────────────────┘
                   │
                   │ REST API
                   ▼
┌─────────────────────────────────────────────────────┐
│ FastAPI Backend (localhost:8000)                    │
│                                                     │
│  Scanner Engine                                     │
│   ├── Semgrep                                       │
│   ├── Gitleaks                                      │
│   └── Trivy                                         │
│                                                     │
│  Finding Normalization                              │
│   ├── OWASP Mapping                                 │
│   ├── CWE Mapping                                   │
│   └── Severity Classification                       │
│                                                     │
│  AI Remediation Engine                              │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
          Gemini 2.5 Flash
```

---

## setup

### 1. configure secrets

```bash
cp .env.example .env
```

Update:

```env
TRACEHAWK_API_KEY=your-random-secret
GEMINI_API_KEY=your-gemini-key
```

---

### 2. start the platform

```bash
docker compose up --build -d
```

This starts:

* **backend** — FastAPI backend on port `8000`
* **frontend** — Svelte dashboard on port `5173`

---

### 3. trigger a scan

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $TRACEHAWK_API_KEY" \
  -d '{
    "target": "./test-repos",
    "tools": "semgrep,gitleaks,trivy",
    "output": "json"
  }'
```

---

### 4. access the platform

| service         | url                          |
| --------------- | ---------------------------- |
| Dashboard       | http://localhost:5173        |
| API Docs        | http://localhost:8000/docs   |
| Health Endpoint | http://localhost:8000/health |

---

## cli usage

The scanner can also be used directly inside the container.

| flag             | description                   | default                  |
| ---------------- | ----------------------------- | ------------------------ |
| `--target`, `-t` | local path or git URL to scan | `./test-repos`           |
| `--tools`        | comma-separated list of tools | `semgrep,gitleaks,trivy` |
| `--output`, `-o` | `json`, `terminal`, `both`    | `both`                   |

### examples

```bash
docker compose exec backend \
python api/scanner.py --tools semgrep,gitleaks
```

```bash
docker compose exec backend \
python api/scanner.py --target ./src --tools trivy
```

---

## sample output

```json
[
  {
    "tool": "semgrep",
    "category": "A03:2021 - Injection",
    "rule": "python.lang.security.audit.eval-detected",
    "file": "app.py",
    "line": 42,
    "severity": "MEDIUM",
    "cwe": ["CWE-95"],
    "message": "Detected use of eval()",
    "snippet": "eval(user_input)"
  }
]
```

TraceHawk exits with code `1` when HIGH or CRITICAL findings are detected, making it suitable for CI/CD integration.

---

## ai remediation

TraceHawk uses **Gemini 2.5 Flash** to generate category-wise remediation guidance.

The remediation pipeline:

1. Groups findings by OWASP category
2. Generates risk explanations
3. Produces vulnerable → remediated code examples
4. Provides actionable remediation guidance

Example outputs include:

* Secure code replacements
* Dependency upgrade recommendations
* Secret rotation guidance
* OWASP risk explanations
* CWE-specific remediation advice

---

## ci/cd

TraceHawk includes a DevSecOps workflow:

```text
feature
   ↓
staging
   ↓
CI Validation

✓ Ruff
✓ Docker Build
✓ Gitleaks
✓ Semgrep
✓ Health Check

   ↓
prod
   ↓
Manual Approval
   ↓
Production Sync
```

This ensures all releases pass security and build validation before deployment.

---

## trivy cache

Trivy downloads its vulnerability database during first execution.

A dedicated Docker volume is mounted to persist the cache between runs:

```yaml
trivy-cache:
```

This prevents repeated downloads and significantly speeds up subsequent scans.

---

## release

### v1.0.0 — tracehawk mvp

Features:

* Unified Semgrep, Gitleaks, and Trivy scanning
* OWASP Top 10 classification
* CWE mapping
* AI remediation workflows
* Dockerized deployment
* REST API
* Svelte dashboard
* DevSecOps CI/CD pipeline

---

## technology stack

| layer               | technology              |
| ------------------- | ----------------------- |
| Runtime             | Python 3.11             |
| API                 | FastAPI + Uvicorn       |
| Frontend            | Svelte 5 + Vite         |
| Serving             | Nginx Unprivileged      |
| SAST                | Semgrep                 |
| Secret Detection    | Gitleaks                |
| Dependency Scanning | Trivy                   |
| AI                  | Gemini 2.5 Flash        |
| Containerization    | Docker + Docker Compose |
| CI/CD               | GitHub Actions          |

---

## license

MIT
