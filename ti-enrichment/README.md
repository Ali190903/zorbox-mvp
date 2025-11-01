# TI-Enrichment Service (MVP)

Enriches indicators (domains, IPs, hashes) with basic reputation using a local DB and optional VirusTotal API.

## Endpoints
- `POST /enrich` — `{ domains:[], ips:[], hashes:[] }` → `{ reputation: {good/unknown/bad}, details }`
- `GET /healthz` — Liveness
- `GET /metrics` — Prometheus metrics

## Metrics
- `ti_queries_total`
- `ti_reputation_unknown_total`
- `ti_latency_seconds`

## Secrets
- `VT_API_KEY` — optional; configure via GitHub Secrets → environment.

## Run
- Python 3.11+
- Dev: `uvicorn app.main:app --reload --port 8070`
