# CAPEv2 Sandbox API-Compatible Service (MVP)

## Overview
This is a **lightweight, API-compatible** implementation of CAPE Sandbox (Cuckoo fork) REST API for the ZORBOX MVP/Hackathon.

## Purpose
- Provides CAPE-compatible REST API endpoints
- Demonstrates advanced OSS sandbox integration
- CAPE specializes in payload extraction and config analysis
- **Note**: This is a minimal implementation without full VM-based malware execution

## API Endpoints

### POST /tasks/create/file
Submit file for analysis
- Returns: `{"task_id": <int>}`

### GET /tasks/view/{task_id}
Get task status

### GET /tasks/report/{task_id}
Get analysis report with CAPE-specific fields:
- Extracted payloads
- Malware configurations
- Behavioral analysis

### GET /healthz
Health check

## Production Deployment
For **full CAPEv2 Sandbox**:
1. Install CAPEv2: https://github.com/kevoreilly/CAPEv2
2. Configure Windows VMs with monitoring
3. Enable payload extraction modules
4. Update `CAPE_BASE` environment variable in orchestrator

## References
- CAPEv2 GitHub: https://github.com/kevoreilly/CAPEv2
- CAPE Documentation: https://capesandbox.com/
