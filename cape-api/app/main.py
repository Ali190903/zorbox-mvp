"""
ZORBOX - CAPEv2 Sandbox API-Compatible Service
Lightweight implementation for MVP/Hackathon
"""
from __future__ import annotations
import time
import uuid
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse

app = FastAPI(title="CAPE Sandbox API (MVP)", version="2.0-compatible")

# In-memory task storage
TASKS: Dict[int, Dict[str, Any]] = {}
TASK_COUNTER = 2000

@app.get("/")
def root():
    return {
        "version": "2.4.0-mvp",
        "hostname": "cape-mvp",
        "machines": {"total": 1, "available": 1},
        "tasks": {"total": len(TASKS)}
    }

@app.post("/tasks/create/file")
async def create_task(file: UploadFile = File(...)):
    """Create analysis task - CAPE API compatible"""
    global TASK_COUNTER
    TASK_COUNTER += 1
    task_id = TASK_COUNTER
    
    data = await file.read()
    
    TASKS[task_id] = {
        "id": task_id,
        "task_id": task_id,
        "status": "pending",
        "target": file.filename,
        "category": "file",
        "package": "exe",
        "submitted_on": time.time(),
        "started_on": None,
        "completed_on": None,
        "file_size": len(data),
        "file_name": file.filename,
    }
    
    TASKS[task_id]["status"] = "running"
    TASKS[task_id]["started_on"] = time.time()
    
    return JSONResponse(content={"task_id": task_id, "task_ids": [task_id]})

@app.get("/tasks/view/{task_id}")
def view_task(task_id: int):
    """Get task status - CAPE API compatible"""
    if task_id not in TASKS:
        return JSONResponse(status_code=404, content={"error": "Task not found"})
    
    task = TASKS[task_id]
    
    if task["status"] == "running":
        elapsed = time.time() - task["started_on"]
        if elapsed > 5:
            task["status"] = "reported"
            task["completed_on"] = time.time()
    
    return {"task": task}

@app.get("/tasks/report/{task_id}")
def get_report(task_id: int):
    """Get analysis report - CAPE API compatible"""
    if task_id not in TASKS:
        return JSONResponse(status_code=404, content={"error": "Task not found"})
    
    task = TASKS[task_id]
    
    if task["status"] != "reported":
        return JSONResponse(status_code=400, content={"error": "Report not available yet"})
    
    report = {
        "info": {
            "id": task_id,
            "category": "file",
            "started": task["started_on"],
            "ended": task["completed_on"],
            "duration": int(task["completed_on"] - task["started_on"]),
            "machine": {"name": "cape1", "platform": "windows", "version": "10"}
        },
        "target": {
            "file": {
                "name": task["file_name"],
                "size": task["file_size"],
            }
        },
        "signatures": [
            {"name": "cape_payload_extraction", "severity": 3, "description": "CAPE MVP analysis"},
        ],
        "CAPE": {
            "payloads": [],
            "configs": []
        },
        "behavior": {
            "processes": [
                {"process_name": task["file_name"], "pid": 5678}
            ]
        },
        "network": {
            "http": [],
            "dns": []
        }
    }
    
    return report

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "cape-api-mvp"}
