from __future__ import annotations

import hashlib
import io
import re
from typing import Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Counter, generate_latest, CONTENT_TYPE_LATEST


app = FastAPI(title="ZORBOX Static Analyzer", version="0.1.0")

registry = CollectorRegistry()
jobs_processed = Counter("analyzer_jobs_processed_total", "Static analyzer jobs processed", registry=registry)
yara_hits = Counter("analyzer_yara_hits_total", "YARA hits (stub)", registry=registry)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sniff_type(name: Optional[str], data: bytes) -> str:
    fn = (name or '').lower()
    if fn.endswith('.ps1'): return 'ps1'
    if fn.endswith('.js'): return 'js'
    if fn.endswith('.pdf'): return 'pdf'
    if any(fn.endswith(x) for x in ('.doc', '.docm', '.docx', '.xls', '.xlsx', '.ppt', '.pptm', '.pptx')):
        return 'office'
    if fn.endswith('.exe') or fn.endswith('.dll'): return 'pe'
    if fn.endswith('.apk'): return 'apk'
    if fn.endswith('.jar'): return 'jar'
    if fn.endswith('.zip') or data[:4] == b'PK\x03\x04': return 'zip'
    if data.startswith(b'%PDF'): return 'pdf'
    return 'unknown'


def heuristics(ftype: str, text: str) -> Dict[str, Any]:
    h: Dict[str, Any] = {}
    if ftype == 'ps1':
        h['encoded_command'] = bool(re.search(r'-enc(odedcommand)?\b', text, re.I))
        h['suspicious_cmdlets'] = bool(re.search(r'(Invoke-WebRequest|Invoke-Expression|Add-MpPreference)', text, re.I))
    if ftype == 'js':
        h['uses_eval'] = 'eval(' in text
        h['uses_unescape'] = 'unescape(' in text
        h['urls_found'] = re.findall(r'https?://[\w\.-/]+', text)[:10]
    if ftype == 'pdf':
        h['openaction'] = '/OpenAction' in text
        h['has_js'] = '/JS' in text
    if ftype == 'office':
        h['macro_tokens'] = bool(re.search(r'(Sub\s+AutoOpen|CreateObject|Declare PtrSafe)', text, re.I))
    return h


@app.get('/healthz', response_class=PlainTextResponse)
def healthz():
    return 'ok'


@app.get('/metrics')
def metrics():
    output = generate_latest(registry)
    return PlainTextResponse(output.decode('utf-8'), media_type=CONTENT_TYPE_LATEST)


@app.post('/analyze')
async def analyze(file: UploadFile = File(...)):
    data = await file.read()
    digest = sha256_bytes(data)
    # limit text size to avoid huge payload
    sample_text = ''
    try:
        sample_text = data[:100000].decode('utf-8', 'ignore')
    except Exception:
        sample_text = ''
    ftype = sniff_type(file.filename, data)
    h = heuristics(ftype, sample_text)
    jobs_processed.inc()
    return {
        'file': {
            'name': file.filename,
            'size': len(data),
            'sha256': digest,
            'type': ftype,
        },
        'heuristics': h,
        'strings_sample': sample_text[:2000],
        'yara_hits': [],
    }

