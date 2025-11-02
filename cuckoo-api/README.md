# Cuckoo Sandbox API-Compatible Service (MVP)

## Overview
This is a **lightweight, API-compatible** implementation of Cuckoo Sandbox REST API v2 for the ZORBOX MVP/Hackathon.

## Purpose
- Provides Cuckoo-compatible REST API endpoints
- Allows orchestrator integration testing
- Demonstrates OSS sandbox integration capability
- **Note**: This is a minimal implementation without full VM-based malware execution

## API Endpoints

### POST /tasks/create/file
Submit file for analysis
- Returns: `{"task_id": <int>}`

### GET /tasks/view/{task_id}
Get task status
- Returns: Task metadata and status

### GET /tasks/report/{task_id}
Get analysis report (when ready)
- Returns: Cuckoo-format JSON report

### GET /healthz
Health check

## Production Deployment
For **full Cuckoo Sandbox** with VM-based analysis:
1. Use official Cuckoo Docker: `docker pull cuckoosandbox/cuckoo:latest`
2. Or install Cuckoo on dedicated Ubuntu server
3. Configure VirtualBox/KVM VMs
4. Update `CUCKOO_BASE` environment variable in orchestrator

## References
- Cuckoo Sandbox: https://cuckoosandbox.org/
- Cuckoo API Docs: https://cuckoo.readthedocs.io/en/latest/usage/api/
