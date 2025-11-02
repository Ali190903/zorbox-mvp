"""
ZORBOX - Cuckoo Sandbox API-Compatible Service
Lightweight implementation for MVP/Hackathon
"""
from __future__ import annotations
import time
import uuid
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse

app = FastAPI(title="Cuckoo Sandbox API (MVP)", version="2.0-compatible")

# In-memory task storage
TASKS: Dict[int, Dict[str, Any]] = {}
TASK_COUNTER = 1000

@app.get("/")
def root():
    return {
        "version": "2.0.7-mvp",
        "hostname": "cuckoo-mvp",
        "machines": {"total": 1, "available": 1},
        "tasks": {"total": len(TASKS), "pending": sum(1 for t in TASKS.values() if t["status"] == "pending")}
    }

@app.post("/tasks/create/file")
async def create_task(file: UploadFile = File(...)):
    """Create analysis task - Cuckoo API compatible"""
    global TASK_COUNTER
    TASK_COUNTER += 1
    task_id = TASK_COUNTER
    
    data = await file.read()
    
    # Store task
    TASKS[task_id] = {
        "id": task_id,
        "task_id": task_id,
        "status": "pending",
        "target": file.filename,
        "category": "file",
        "package": "exe",
        "timeout": 120,
        "priority": 1,
        "machine": "cuckoo1",
        "platform": "windows",
        "submitted_on": time.time(),
        "started_on": None,
        "completed_on": None,
        "file_size": len(data),
        "file_name": file.filename,
    }
    
    # Simulate task progression in background
    # In real Cuckoo, VM würde run the sample
    # Here: mark as running immediately
    TASKS[task_id]["status"] = "running"
    TASKS[task_id]["started_on"] = time.time()
    
    return JSONResponse(content={"task_id": task_id, "task_ids": [task_id]})

@app.get("/tasks/view/{task_id}")
def view_task(task_id: int):
    """Get task status - Cuckoo API compatible"""
    if task_id not in TASKS:
        return JSONResponse(status_code=404, content={"error": "Task not found"})
    
    task = TASKS[task_id]
    
    # Auto-complete old tasks (simulate processing)
    if task["status"] == "running":
        elapsed = time.time() - task["started_on"]
        if elapsed > 5:  # Complete after 5 seconds
            task["status"] = "reported"
            task["completed_on"] = time.time()
    
    return {"task": task}

@app.get("/tasks/report/{task_id}")
def get_report(task_id: int):
    """Get analysis report - Cuckoo API compatible"""
    if task_id not in TASKS:
        return JSONResponse(status_code=404, content={"error": "Task not found"})
    
    task = TASKS[task_id]
    
    if task["status"] != "reported":
        return JSONResponse(status_code=400, content={"error": "Report not available yet"})
    
    # Return minimal Cuckoo-style report
    report = {
        "info": {
            "id": task_id,
            "category": "file",
            "started": task["started_on"],
            "ended": task["completed_on"],
            "duration": int(task["completed_on"] - task["started_on"]),
            "machine": {"name": "cuckoo1", "platform": "windows", "version": "10"}
        },
        "target": {
            "file": {
                "name": task["file_name"],
                "size": task["file_size"],
            }
        },
        "signatures": [
            {"name": "cuckoo_mvp_analysis", "severity": 2, "description": "MVP analysis completed"},
        ],
        "behavior": {
            "processes": [
                {"process_name": task["file_name"], "pid": 1234, "calls": 42}
            ],
            "summary": {
                "files": ["C:\\temp\\sample.dat"],
                "keys": ["HKLM\\Software\\Test"],
            }
        },
        "network": {
            "http": [],
            "dns": [],
            "tcp": [],
            "udp": [],
        },
        "static": {
            "pe_timestamp": "2024-01-01 00:00:00"
        },
        "debug": {
            "errors": [],
            "log": "Analysis completed successfully (MVP mode)"
        }
    }
    
    return report

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "cuckoo-api-mvp"}
