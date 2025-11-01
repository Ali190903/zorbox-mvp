# Reporter Service (MVP)

Generates exports (JSON, PDF, STIX) from aggregated analysis.

## Endpoints
- `POST /report` → Accepts aggregated JSON, writes JSON/PDF/STIX exports, returns URLs.
- `GET /healthz` → Liveness.
- `GET /metrics` → Prometheus metrics (reports generated, PDF gen time).

## Run
- Python 3.11+
- Install: `pip install -e .`
- Dev: `uvicorn app.main:app --reload --port 8090`

## Notes
- PDF via ReportLab (no headless browser dependency).
- STIX: minimal STIX 2.1 bundle with indicators built from IOCs.
