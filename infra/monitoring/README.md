# Monitoring (MVP)

Stack: Prometheus + Grafana. Scrapes orchestrator (:8080), reporter (:8090), ti-enrichment (:8070).

## Files
- `prometheus.yml` — scrape configs + includes `alerts.yml`
- `alerts.yml` — alerts for service down, high queue; disk usage (requires node_exporter)

## Run
- With docker-compose (root `infra/docker-compose.yml`): Prometheus at :9090, Grafana at :3000

## Notes
- Add node_exporter for disk alerts: `prom/node-exporter` and add its job to `prometheus.yml`.
- Import a Grafana dashboard or create panels: job state counts, queue length, PDF gen time.
