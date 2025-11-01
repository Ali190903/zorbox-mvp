from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

from .schemas import JobState, JobSummary


@dataclass
class Job:
    id: str
    state: JobState
    created_at: float
    updated_at: float
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_sha256: Optional[str] = None
    archive_type: Optional[str] = None
    requires_password: Optional[bool] = None
    error: Optional[str] = None
    export_json_url: Optional[str] = None
    export_pdf_url: Optional[str] = None
    export_stix_url: Optional[str] = None

    def to_summary(self) -> JobSummary:
        return JobSummary(
            id=self.id,
            state=self.state,
            created_at=self.created_at,
            updated_at=self.updated_at,
            file_name=self.file_name,
            file_size=self.file_size,
            file_sha256=self.file_sha256,
            error=self.error,
            archive_type=self.archive_type,
            requires_password=self.requires_password,
            export={
                "json_url": self.export_json_url,
                "pdf_url": self.export_pdf_url,
                "stix_url": self.export_stix_url,
            } if any([self.export_json_url, self.export_pdf_url, self.export_stix_url]) else None,
        )


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.jobs: Dict[str, Job] = {}

    def create(self, file_name: Optional[str] = None, file_size: Optional[int] = None, file_sha256: Optional[str] = None) -> Job:
        with self._lock:
            jid = str(uuid.uuid4())
            now = time.time()
            job = Job(
                id=jid,
                state=JobState.queued,
                created_at=now,
                updated_at=now,
                file_name=file_name,
                file_size=file_size,
                file_sha256=file_sha256,
            )
            self.jobs[jid] = job
            return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self.jobs.get(job_id)

    def set_state(self, job_id: str, state: JobState, error: Optional[str] = None) -> None:
        with self._lock:
            job = self.jobs[job_id]
            job.state = state
            job.updated_at = time.time()
            job.error = error

    def by_state(self, state: Optional[JobState] = None):
        with self._lock:
            if state is None:
                return list(self.jobs.values())
            return [j for j in self.jobs.values() if j.state == state]
