from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi import Body
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST


app = FastAPI(title="ZORBOX TI Enrichment", version="0.1.0")

registry = CollectorRegistry()
ti_queries_total = Counter("ti_queries_total", "TI queries processed", registry=registry)
ti_unknown_total = Counter("ti_reputation_unknown_total", "Unknown reputation results", registry=registry)
ti_latency = Histogram("ti_latency_seconds", "TI enrichment latency", registry=registry)

VT_API_KEY = os.getenv("VT_API_KEY")


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


def local_reputation(indicator: str) -> str:
    # Very simple heuristic/stub
    ind = indicator.lower()
    bad_keywords = ("mal", "evil", ".ru")
    if any(k in ind for k in bad_keywords):
        return "bad"
    return "unknown"


@app.post("/enrich")
def enrich(payload: Dict[str, List[str]] = Body(...)):
    start = time.time()
    domains = payload.get("domains", [])
    ips = payload.get("ips", [])
    hashes = payload.get("hashes", [])

    result: Dict[str, Dict[str, str]] = {"domains": {}, "ips": {}, "hashes": {}}

    # MVP: local reputation only; VT integration can be added if VT_API_KEY exists
    for d in domains:
        rep = local_reputation(d)
        if rep == "unknown":
            ti_unknown_total.inc()
        result["domains"][d] = rep
    for ip in ips:
        rep = local_reputation(ip)
        if rep == "unknown":
            ti_unknown_total.inc()
        result["ips"][ip] = rep
    for h in hashes:
        rep = local_reputation(h)
        if rep == "unknown":
            ti_unknown_total.inc()
        result["hashes"][h] = rep

    ti_queries_total.inc()
    ti_latency.observe(time.time() - start)
    return {"reputation": result, "vt": bool(VT_API_KEY)}


@app.get("/metrics")
def metrics():
    output = generate_latest(registry)
    return PlainTextResponse(output.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)

