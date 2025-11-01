# Infra (MVP)

Local development via docker-compose. Monitoring via Prometheus/Grafana is planned; k8s manifests to be added.

## Compose
- Orchestrator: :8080
- Reporter: :8090
- TI-Enrichment: :8070

## Run
- `docker compose up --build`

## Notes
- Configure service images/contexts as needed.
