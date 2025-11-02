# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

ZORBOX is a national sandbox malware analysis platform built for the Secure Tomorrow Hackathon. It's a microservices-based system that accepts file uploads or URLs, performs static and dynamic analysis, enriches findings with threat intelligence, and generates comprehensive reports (JSON, PDF, STIX 2.1).

### Core Architecture

The system uses a **pipeline orchestration model** with these key components:

- **Orchestrator** (`orchestrator/`) — Central coordinator managing job state machine: `queued → running → enriching → reporting → done/failed`
- **Static Analyzer** (`static-analyzer/`) — PE/Office/Script analysis, YARA scanning, IOC extraction
- **Sandbox Native** (`sandbox-native/`) — Isolated execution using firejail/nsjail/bwrap/strace
- **TI Enrichment** (`ti-enrichment/`) — Threat intelligence lookups (local DB + optional VirusTotal)
- **Reporter Service** (`reporter-service/`) — Report generation (JSON, PDF, STIX) with hybrid rule-based + AI scoring
- **Frontend UI** (`frontend-ui/`) — React/Vite upload interface with status monitoring
- **OSS Sandbox Adapters** (`cuckoo-api/`, `cape-api/`) — API-compatible stubs for Cuckoo/CAPEv2 integration

**Data Flow**: UI → Orchestrator (job creation) → Static Analyzer + Sandbox adapters (parallel) → TI Enrichment → Reporter (scoring + exports) → UI displays results

## Common Commands

### Local Development (Docker Compose)

```powershell
# Start all services with monitoring stack
cd infra
docker compose up -d --build

# Run smoke tests
PowerShell -File .\smoke.ps1

# View logs
docker compose logs -f orchestrator
docker compose logs -f reporter

# Stop all services
docker compose down
```

### Python Services (Backend)

Each Python service (`orchestrator/`, `reporter-service/`, `ti-enrichment/`, `static-analyzer/`, `sandbox-native/`) uses the same development pattern:

```powershell
# Install dependencies
cd <service-name>
pip install -e .

# Install dev dependencies for testing
pip install -e ".[dev]"

# Run service locally
uvicorn app.main:app --reload --port <PORT>
# Ports: orchestrator=8080, reporter=8090, ti=8070, static-analyzer=8060, sandbox=8050

# Run tests (when available)
pytest

# Note: Currently no tests are committed; pytest is in dev dependencies but test files don't exist yet
```

### Frontend Development

```powershell
cd frontend-ui

# Install dependencies
npm ci

# Run dev server (hot reload)
npm run dev
# Opens at http://localhost:5173

# Run tests
npm test

# Build for production
npm run build

# Environment variables for dev
$env:VITE_API_BASE="http://localhost:8080"
$env:VITE_REPORTER_BASE="http://localhost:8090"
```

### Testing & CI

```powershell
# Run smoke tests after compose up
cd infra
.\smoke.ps1  # Windows
./smoke.sh   # Linux/macOS

# CI workflows run automatically on push/PR:
# - .github/workflows/ci.yml: Python install checks + Docker builds + frontend test/build
# - .github/workflows/node-ci.yml: Frontend-only CI

# Manual CI trigger (if needed)
# Push to main/master branch or create PR
```

### Monitoring & Observability

```powershell
# Access monitoring dashboards (after docker compose up)
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)

# View metrics from any service
curl http://localhost:8080/metrics  # orchestrator
curl http://localhost:8090/metrics  # reporter
curl http://localhost:8060/metrics  # static-analyzer

# Health checks
curl http://localhost:8080/healthz
curl http://localhost:8090/healthz
```

## Key Configuration

### Environment Variables

**Orchestrator** (coordinates all services):
- `ANALYZER_BASE` — Static analyzer URL (default: `http://static_analyzer:8060`)
- `REPORTER_BASE` — Reporter service URL (default: `http://reporter:8090`)
- `TI_BASE` — TI enrichment URL (default: `http://ti:8070`)
- `SANDBOX_BASE` — Sandbox native URL (default: `http://sandbox:8050`)
- `CUCKOO_BASE`, `CAPE_BASE` — Optional OSS sandbox URLs
- `URL_ALLOWLIST`, `URL_BLOCKLIST` — URL filtering (comma-separated patterns)
- `UPLOADS_QUOTA_MB`, `RETENTION_HOURS` — Storage limits
- `VT_API_KEY` — VirusTotal API key (optional, for TI enrichment)

**Reporter** (scoring configuration):
- `RULE_W`, `AI_W` — Scoring weights (default: 0.6 rule, 0.4 AI)

**Frontend UI**:
- `VITE_API_BASE` — Orchestrator URL (default: `http://localhost:8080`)
- `VITE_REPORTER_BASE` — Reporter URL (default: `http://localhost:8090`)

### File Upload Constraints

- Max upload size: **10 MB** (enforced by orchestrator)
- Supported archives: ZIP (full support), 7z/RAR (limited, requires password)
- Encrypted archives require password via `POST /provide-password` endpoint
- File types: EXE, DLL, PS1, JS, Office docs (docx/xls/ppt), PDF, APK, Python, scripts (bat/cmd/vbs)

## Important Implementation Details

### State Machine (Orchestrator)

Jobs flow through states tracked in memory (with disk snapshots planned):
- `queued` → `running` → `enriching` → `reporting` → `done`
- Special states: `waiting_password` (encrypted archive), `failed` (error)

State transitions trigger downstream service calls:
- `running`: calls Static Analyzer + Sandbox adapters in parallel
- `enriching`: calls TI Enrichment with extracted IOCs
- `reporting`: calls Reporter to generate exports

### Scoring System (Reporter)

Hybrid approach combining rules and explainable AI:

1. **Rule-based scoring**: YARA hits, suspicious PE imports, macros, obfuscation patterns, TI reputation
2. **AI scoring**: Lightweight linear model using features like entropy, URL count, suspicious API calls
3. **Aggregation**: `final_score = 0.6 * rule_score + 0.4 * ai_score` (configurable)
4. **Risk levels**: 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical

### Security & Isolation

- Sandboxes run with **no network access** by default (egress deny in NetworkPolicy)
- Files stored in `uploads/<job-id>/` with restricted permissions (0700 dirs, 0600 files)
- Containers run as non-root `svc` user
- Archive extraction uses **zip-slip protection** (canonical path validation)
- Kubernetes manifests include: `readOnlyRootFilesystem`, `runAsNonRoot`, seccomp profiles

### Archive Handling

The orchestrator handles password-protected archives:
- ZIP: stdlib `zipfile` with password support
- 7z: `py7zr` library (list + extract with password)
- RAR: detected but extraction requires `rarfile` backend (MVP limitation)
- Nested extraction depth limit: 1-2 levels to prevent zip bombs

Workflow: Submit encrypted archive → state becomes `waiting_password` → user submits password via `POST /provide-password` → processing resumes

### Metrics & Observability

Each service exposes Prometheus metrics at `/metrics`:

**Orchestrator**:
- `orchestrator_jobs_in_state{state}` — gauge of jobs in each state
- `orchestrator_queue_length` — current queue size
- `orchestrator_job_latency_seconds` — histogram of job duration

**Reporter**:
- `reporter_reports_generated_total` — counter
- `reporter_pdf_generation_time_seconds` — histogram

**TI Enrichment**:
- `ti_queries_total` — counter
- `ti_reputation_unknown_total` — counter for IOCs without reputation

**Static Analyzer**:
- `analyzer_jobs_processed_total`
- `analyzer_yara_hits_total`

Prometheus scrapes all services; Grafana dashboards visualize job states, queue length, error rates.

## Service Dependencies

```
Frontend UI
    ↓
Orchestrator (hub) ← depends on all others
    ├→ Static Analyzer (independent)
    ├→ Sandbox Native (independent)
    ├→ TI Enrichment (independent)
    ├→ Reporter (independent, called last)
    └→ Cuckoo/CAPE APIs (optional OSS adapters)
```

**Important**: Orchestrator is the only service with external dependencies. All others are stateless and can be developed/tested independently.

## Testing Strategy

### Current State (MVP)
- CI runs install checks and builds but **no unit tests exist yet**
- Smoke tests verify HTTP health/metrics endpoints
- `pytest` is in dev dependencies but no test files written

### Adding Tests
When writing tests for Python services:
- Use `pytest` (already in `pyproject.toml[dev]`)
- Place tests in `tests/` directory at service root
- Test file pattern: `test_*.py` or `*_test.py`
- Use `httpx.AsyncClient` for FastAPI endpoint testing

Frontend tests:
- Use Vitest + React Testing Library (already configured)
- Test file pattern: `*.test.jsx`
- Run with `npm test`

## Common Development Patterns

### Adding a New Endpoint (FastAPI services)

1. Define request/response models in `schemas.py` (or inline with Pydantic)
2. Add endpoint handler in `main.py`
3. Add Prometheus counter/histogram if tracking latency/counts
4. Document in service README.md
5. Update smoke tests if it's a critical endpoint

### Modifying the State Machine (Orchestrator)

The state transitions are in `orchestrator/app/state.py`:
- Modify `process_job()` coroutine for new states
- Update `VALID_STATES` constant
- Ensure `orchestrator_jobs_in_state` metric tracks new state
- Update Grafana dashboard queries

### Adding YARA Rules (Static Analyzer)

Place `.yar` files in `static-analyzer/app/rules/`:
- One rule per file or multi-rule files
- Rules auto-load on service start
- Test with `yara-python` directly: `yara.compile(filepath=...)`

### Archive Format Support

Modify `orchestrator/app/archive.py`:
- Add detection logic in `needs_password()`
- Implement listing/extraction in respective functions
- Update error handling for unsupported formats
- Add integration test in smoke script

## Known Limitations & TODOs

From the playbook and pitch documents:

1. **CI workflows exist but tests are minimal** — `pytest` stubs present but no test files
2. **YARA rules**: Only `malware_basics.yar` is populated; other `.yar` files are placeholders
3. **Dynamic behavior depth**: Sandbox adapters execute basic commands (strings) under isolation; full VM-based execution (like real Cuckoo/CAPE) is not implemented
4. **TI sources**: Only local heuristics + optional VirusTotal; no MISP/OTX/AbuseIPDB integration
5. **Frontend panels**: Timeline/IOC/YARA filters mentioned but minimally implemented
6. **Kubernetes security**: Basic NetworkPolicy exists; full RBAC/OPA policies not implemented
7. **Secrets management**: VT_API_KEY via env var; no Vault/sealed secrets integration
8. **RAR extraction**: Detected but requires `rarfile` library backend not included in MVP

## Kubernetes Deployment

Manifests in `infra/k8s/`:

```powershell
# Deploy in order
kubectl apply -f infra/k8s/namespace.yaml
kubectl apply -f infra/k8s/static-analyzer.yaml
kubectl apply -f infra/k8s/reporter.yaml
kubectl apply -f infra/k8s/ti.yaml
kubectl apply -f infra/k8s/sandbox.yaml
kubectl apply -f infra/k8s/orchestrator.yaml

# Orchestrator has NetworkPolicy: egress only to internal services
# Edit infra/k8s/ti.yaml Secret to add VT_API_KEY if needed
```

Services use ClusterIP; add Ingress/NodePort for external access.

## API Quick Reference

### Orchestrator (8080)
- `POST /analyze` — Submit file (multipart) or URL; optional `password`, `adapters`
- `GET /result/{job_id}` — Job status + exports
- `GET /jobs?state=<state>` — List jobs by state
- `POST /provide-password` — Submit password for encrypted archives
- `POST /reanalysis` — Create new job from existing
- `GET /audit?limit=N` — View audit log

### Reporter (8090)
- `POST /report` — Generate exports from aggregated analysis
- `GET /exports/{job_id}/report.{json|pdf|stix.json}` — Download exports
- `GET /example` — Demo report

### Static Analyzer (8060)
- `POST /analyze` — Analyze file (returns heuristics + YARA + IOCs)
- `GET /schema` — JSON schema for output

### TI Enrichment (8070)
- `POST /enrich` — Enrich domains/IPs/hashes with reputation

### Sandbox Native (8050)
- `POST /run` — Execute file with adapter (strace/firejail/bwrap/nsjail/mock)

## File Structure Notes

- **Monorepo** with independent service directories
- Each service has: `Dockerfile`, `pyproject.toml` (Python) or `package.json` (Node), `README.md`, `app/` code
- Shared docs in `docs/` (playbook, runbook)
- Infrastructure in `infra/` (compose, k8s manifests, monitoring configs)
- CI workflows in `.github/workflows/`
- Ansible stub in `ansible/` (minimal playbook)

## Debugging Tips

1. **Job stuck in state**: Check orchestrator logs; state machine may have hit exception without transitioning to `failed`
2. **Service unreachable**: Verify docker-compose networking; services use service names as hostnames
3. **Metrics not appearing**: Check Prometheus targets at `http://localhost:9090/targets`
4. **PDF generation slow**: Reporter uses ReportLab (no browser); slow PDF = complex report data
5. **Encrypted archive fails**: Check logs for password errors; use `POST /provide-password` endpoint
6. **YARA not matching**: Verify `.yar` files in `static-analyzer/app/rules/` are valid syntax

## References

- **Main playbook**: `ZORBOX_MVP_PLAYBOOK.md` — comprehensive architecture, scoring rules, acceptance criteria
- **Runbook**: `docs/ZORBOX_FINAL_RUNBOOK.md` — deployment, API details, configurations
- **Pitch**: `pitch.md` — implementation status, demo commands, what's missing
