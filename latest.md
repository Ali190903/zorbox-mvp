# ZORBOX — Pitch Runbook (Copy-Paste Ready)

Bu sənəd Secure Tomorrow Hackathon üçün hazırladığımız ZORBOX (Milli Sandbox) MVP sisteminin başdan‑sona texniki icmalını, arxitektura qərarlarını və copy‑paste hazır terminal komandalarını toplayır. Məqsəd: 3–5 dəqiqəlik demo zamanı heç nəyi axtarmadan ardıcıl işlətmək.

## 1) Nə Qurduq və Niyə
- Orchestrator (FastAPI): Boru xətti, state machine, API (`/analyze`, `/result`, `/jobs`) və audit. Bax: `orchestrator/app/main.py:1`  
- Static Analyzer (FastAPI): PE/Office/Script heuristikaları, YARA, IOC-lər. Bax: `static-analyzer/app/main.py:1`, qaydalar: `static-analyzer/app/rules/malware_basics.yar:1`  
- Sandbox Native (FastAPI): `firejail`, `nsjail`, `bwrap`, `strace` adapterləri ilə izolə edilmiş icra. Bax: `sandbox-native/app/main.py:1`  
- TI Enrichment (FastAPI): Lokal reputasiya + opsional VirusTotal. Bax: `ti-enrichment/app/main.py:1`  
- Reporter Service (FastAPI): JSON/PDF/STIX hesabat, hibrid skor (rule + AI-minimum). Bax: `reporter-service/app/main.py:1`, `reporter-service/app/pdf.py:1`  
- OSS Sandbox adapter stub-ları: Cuckoo və CAPE API uyğun saxta servis. Bax: `cuckoo-api/app/main.py:1`, `cape-api/app/main.py:1`  
- Frontend (Vite+React): Yükləmə, status, report görüntüləmə (JSON/PDF/STIX). Bax: `frontend-ui/README.md:1`

Nəticə: UI → Orchestrator → (Static+Sandbox) → TI → Reporter → UI axını; hər modul Prometheus metrics verir; PDF/JSON/STIX çıxış; Docker Compose ilə lokal demo, K8s manifestləri ilə opsional deploy.

## 2) Tez Başlanğıc (Docker Compose)
```powershell
cd infra
# Servisləri qaldır (yenidən build ilə)
docker compose up -d --build

# Windows Smoke Test
PowerShell -File .\smoke.ps1

# Linux/macOS Smoke Test
./smoke.sh

# Loglara baxış (lazım olduqda)
docker compose logs -f orchestrator
# digər servislər: reporter | static_analyzer | ti | sandbox | prometheus | grafana

# Dayandırmaq (demo sonrası)
docker compose down
```
Portlar: orchestrator 8080, reporter 8090, ti 8070, static-analyzer 8060, sandbox 8050, prometheus 9090, grafana 3000.

## 2.1) Addım‑Addım Yoxlanış (Validation Checklist)
- Health + Metrics
  - `curl http://localhost:8080/healthz` → `ok`
  - `curl http://localhost:8080/metrics | rg orchestrator_jobs_in_state`
- URL Downloader siyasətləri (retry/timeout/size/allowlist)
  - Env: `URL_ALLOWLIST=*.example.com`, opsional `URL_BLOCKLIST=*`
  - Allowed: `curl -s -H 'Content-Type: application/json' -d '{"url":"https://example.com/sample.exe"}' http://localhost:8080/analyze`
  - Blocked: `curl -s -H 'Content-Type: application/json' -d '{"url":"https://google.com/file.exe"}' http://localhost:8080/analyze` → 400 `host not allowed`
  - Size limit: HEAD `Content-Length` >10MB → 413; yükləmə sonrası faktiki `len(data)` >10MB → 413
  - Metriklər: `curl -s http://localhost:8080/metrics | rg fetcher_download_`
    - `fetcher_download_duration_seconds{method="head|get"}`
    - `fetcher_download_failures_total{stage="head|get"}`
- Upload + Sanity (hash/mime/mismatch)
  - `curl -s -F "file=@infra/sample.bin" http://localhost:8080/analyze | tee job.json`
  - `JOB_ID=$(jq -r .job_id job.json)` → `cat orchestrator/app/uploads/$JOB_ID/meta.json | jq '{sha256:file_sha256, mime:mime_detected, mismatch:mime_mismatch}'`
- Storage təhlükəsizliyi
  - Safe path/ICAZƏ: `docker exec -it <orchestrator> sh -lc "stat -c '%a %U:%G' app/uploads/*/meta.json"` → 600 `svc`
  - Kvota: `UPLOADS_QUOTA_MB=1` verib >1MB cəhd → 507 `quota exceeded`
- Arxiv/parol axını
  - `zip -P infected -r sample.zip infra/sample.bin`
  - `curl -s -F "file=@sample.zip" http://localhost:8080/analyze | tee zipjob.json`
  - `ZIP_JOB=$(jq -r .job_id zipjob.json)`; `curl -s -H 'Content-Type: application/json' -d '{"job_id":"'"$ZIP_JOB"'","password":"infected"}' http://localhost:8080/provide-password`
- Statik analiz heuristikası (JS/PS1/VBS/BAT)
  - JS: `printf 'eval("unescape(\\"%u4141\\")")' > s.js && curl -s -F "file=@s.js" http://localhost:8080/analyze`
  - PS1: `printf 'powershell -EncodedCommand AAA=' > s.ps1 && curl -s -F "file=@s.ps1" http://localhost:8080/analyze`
- Sandbox/native + OSS adapterlər
  - `curl -s -H 'Content-Type: application/json' -d '{"url":"https://example.com/a.bin","adapters":["cuckoo","cape","strace","firejail"]}' http://localhost:8080/analyze | tee job2.json`
  - `ID2=$(jq -r .job_id job2.json)` → `curl -s http://localhost:8080/result/$ID2 | jq .sandboxes`
- Report export (JSON/PDF/STIX)
  - `curl -s http://localhost:8080/result/$JOB_ID | tee result.json`
  - `jq -r .export.pdf_url  result.json | xargs -I {} curl -s -o report.pdf  http://localhost:8090{}`
  - `jq -r .export.json_url result.json | xargs -I {} curl -s -o report.json http://localhost:8090{}`
  - `jq -r .export.stix_url result.json | xargs -I {} curl -s -o report.stix.json http://localhost:8090{}`

## 3) Demo Ssenarisi: Başdan‑Sona API
- Fayl analizi (PowerShell, Windows):
```powershell
$resp = Invoke-RestMethod -Uri http://localhost:8080/analyze -Method Post -Form @{ file = Get-Item .\infra\sample.bin }
$resp
# { job_id = "...", accepted = true }
```
- Fayl analizi (curl):
```bash
curl -s -F "file=@infra/sample.bin" http://localhost:8080/analyze
```
- URL analizi (curl):
```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/sample.exe"}' \
  http://localhost:8080/analyze
```
- Seçilmiş sandbox adapterləri ilə (məs: strace,firejail):
```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/a.zip","adapters":["strace","firejail"]}' \
  http://localhost:8080/analyze
```
- Şifrəli ZIP üçün parol ötürmək:
```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"job_id":"<JOB_ID>","password":"infected"}' \
  http://localhost:8080/provide-password
```
- Job vəziyyətinə baxmaq və nəticəni götürmək:
```bash
curl -s http://localhost:8080/result/<JOB_ID> | jq .
# Cavabda reporter linkləri olacaq: json_url, pdf_url, stix_url
```
- Report fayllarını endirmək:
```bash
# JSON
curl -s -o report.json http://localhost:8090/exports/<JOB_ID>/report.json
# PDF
curl -s -o report.pdf  http://localhost:8090/exports/<JOB_ID>/report.pdf
# STIX
curl -s -o report.stix.json http://localhost:8090/exports/<JOB_ID>/report.stix.json
```

## 4) Monitorinq və Sağlamlıq
- Health endpoints:
```bash
curl http://localhost:8080/healthz   # orchestrator
curl http://localhost:8090/healthz   # reporter
curl http://localhost:8070/healthz   # ti
curl http://localhost:8060/healthz   # static-analyzer
curl http://localhost:8050/healthz   # sandbox
```
- Metrics (Prometheus formatı):
```bash
curl http://localhost:8080/metrics   # orchestrator
curl http://localhost:8090/metrics   # reporter
```
- Grafana/Prometheus:
```text
Prometheus: http://localhost:9090
Grafana:    http://localhost:3000  (admin/admin)
```

## 5) Konfiqurasiya (Əsas Dəyişənlər)
- Orchestrator: `ANALYZER_BASE`, `REPORTER_BASE`, `TI_BASE`, `SANDBOX_BASE`, `CUCKOO_BASE`, `CAPE_BASE`, `URL_ALLOWLIST`, `URL_BLOCKLIST`, `UPLOADS_QUOTA_MB`, `RETENTION_HOURS`  
- TI Enrichment: `VT_API_KEY` (opsional)  
- Reporter: `RULE_W`, `AI_W` (default 0.6/0.4)  
- Frontend: `VITE_API_BASE`, `VITE_REPORTER_BASE`

Docker Compose defaultları `infra/docker-compose.yml:1` daxilində verilib. K8s üçün `infra/k8s/*.yaml` listəsində env və NetworkPolicy-lər mövcuddur.

## 6) Kubernetes (Opsional Demo)
```bash
kubectl apply -f infra/k8s/namespace.yaml
kubectl apply -f infra/k8s/static-analyzer.yaml
kubectl apply -f infra/k8s/reporter.yaml
kubectl apply -f infra/k8s/ti.yaml
kubectl apply -f infra/k8s/sandbox.yaml
kubectl apply -f infra/k8s/orchestrator.yaml
```
Qeyd: Manifests MVP üçündür; external access üçün Ingress/NodePort əlavə edə bilərsiniz.

## 7) Lokal Tərtibat (Backend Servislər)
Hər Python servisində eyni pattern:
```bash
cd orchestrator         # və ya reporter-service | ti-enrichment | static-analyzer | sandbox-native
pip install -e .
uvicorn app.main:app --reload --port 8080   # porta uyğun dəyişin
```
Frontendi işlətmək:
```bash
cd frontend-ui
npm ci
npm run dev   # http://localhost:5173
```

## 8) Təhlükəsizlik və İzolasiya Qərarları (Niyə və Necə)
- No‑net by default: Sandbox icraları çıxış şəbəkəsi olmadan (adapterlərdə parametrlərlə).  
- File sistem icazələri: `uploads/` 0700, fayllar 0600. Bax: `orchestrator/app/storage.py:1`  
- Zip‑slip qorunması və parol axını: `orchestrator/app/archive.py:1`, `orchestrator/app/main.py:1`  
- State machine izlənməsi və audit: `orchestrator/app/state.py:1`, audit log `uploads/audit.log`.  
- Prometheus metrics hər modulda; smoke skriptləri ilə sürətli yoxlama: `infra/smoke.ps1:1`, `infra/smoke.sh:1`.

## 9) Skorlaşdırma (Rule + AI-Minimum)
- Rule-based: YARA hitləri, PE şübhəli importlar, RWX, makrolar, IOC reputasiya.  
- AI-minimum: Şəffaf xətti model, top feature contribution.  
- Yekun skor: `final = 0.6*rule + 0.4*ai` (dəyişdirilə bilər). Implementasiya: `reporter-service/app/main.py:1`, PDF çıxışı: `reporter-service/app/pdf.py:1`.

## 9.1) Bonus Örtükləri (Pitch-də göstəriləcək)
- REST API (+2): `POST /analyze`, `GET /result/{id}` işlədirik.
- 3+ OSS Sandbox (+5): Cuckoo stub, CAPE stub, native (firejail/strace/bwrap/nsjail); adapter siyahısı ilə demo.
- Davranış qrafiki (+3): UI “Timeline” paneli adapter izlərini vizuallaşdırır (filtrlə); MVP vizual örtük.
- AI minimum (+10): Şəffaf xətti model + qayda skor; final `0.6*rule + 0.4*ai`.

## 10) Pitch Demosu üçün Ən Vacib Komandalar
```bash
# 1) Compose stack qaldır
cd infra && docker compose up -d --build

# 2) Health + metrics qısa yoxlama
./smoke.sh   # Windows-da: PowerShell -File .\smoke.ps1

# 3) Nümunə fayl analizi
curl -s -F "file=@infra/sample.bin" http://localhost:8080/analyze | tee job.json
JOB_ID=$(jq -r .job_id job.json)

# 4) Job nəticəsi və reporter linkləri
curl -s http://localhost:8080/result/$JOB_ID | tee result.json

# 5) PDF/JSON/STIX endirmə
jq -r .export.pdf_url  result.json | xargs -I {} curl -s -o report.pdf  http://localhost:8090{}
jq -r .export.json_url result.json | xargs -I {} curl -s -o report.json http://localhost:8090{}
jq -r .export.stix_url result.json | xargs -I {} curl -s -o report.stix.json http://localhost:8090{}

# 6) Grafana/Prometheus göstər (brauzerdə)
# Prometheus: http://localhost:9090  |  Grafana: http://localhost:3000 (admin/admin)
```

## 11) Troubleshooting (Sürətli)
- Servis portu sərbəst deyil → həmin portu istifadə edən prosesi dayandırın və ya porta dəyişiklik edin.  
- Reporter PDF error → `reportlab` yoxdur? Compose build bunu təmin edir; lokal devdə `pip install reportlab`.  
- TI reputasiya boşdur → `VT_API_KEY` təyin edilməyib; lokal heurstikalar işləyir.  
- Sandbox adapter “unavailable” → host-da uyğun binar (firejail/nsjail/bwrap/strace) yoxdur; mock adapterdən istifadə edin.

## 12) Lazımsız Faylların Təmizlənməsi (Təklif)
Aşağıdakı fayllar demoya təsir etmir və repo yüklənməsini ağırlaşdırır. Silməyi tövsiyə edirik:
- `sample.bin`, `big.bin`, `enc.zip`
- `infra/out.pdf`, `infra/sample.bin`
- Hackathon qeydləri/əlaqəsiz PDF-lər: `ST_V2_AGENDA.pdf`

Silinmə komandaları (Linux/macOS):
```bash
rm -f sample.bin big.bin enc.zip infra/out.pdf infra/sample.bin ST_V2_AGENDA.pdf
```
PowerShell:
```powershell
Remove-Item -Force sample.bin,big.bin,enc.zip,infra/out.pdf,infra/sample.bin,ST_V2_AGENDA.pdf -ErrorAction SilentlyContinue
```
Qeyd: İstəsəniz bu təmizliyi mən həyata keçirə bilərəm.

---
Bu latest.md, `docs/ZORBOX_FINAL_RUNBOOK.md` və `ZORBOX_MVP_PLAYBOOK.md` ilə tam hizalanır; pitch zamanı ardıcıllığı qorumaq üçün yuxarıdakı “Pitch Demosu üçün Ən Vacib Komandalar” bölməsini izləyin.

## 13) Metriklər (Toplu Baxış)
- Orchestrator: `orchestrator_jobs_in_state`, `orchestrator_queue_length`, `orchestrator_job_latency_seconds`, `orchestrator_jobs_submitted_total`
- Fetcher: `fetcher_download_duration_seconds{method="head|get"}`, `fetcher_download_failures_total{stage="head|get"}`
- Static Analyzer: `analyzer_jobs_processed_total`, `analyzer_yara_hits_total`
- Sandbox Native: `sandbox_runs_total{adapter}`, `sandbox_run_duration_seconds{adapter}`, `sandbox_errors_total{adapter}`
- TI: `ti_queries_total`, `ti_reputation_unknown_total`, `ti_latency_seconds`
- Reporter: `reporter_reports_generated_total`, `reporter_pdf_generation_time_seconds`
- Frontend ingest: `frontend_rum_events_total`, `frontend_errors_total`

## 14) Limitasiyalar və Növbəti Addımlar
- RAR üçün backend tələb oluna bilər (əks halda 501); ZIP tam, 7z list hazırdır.
- ISO/IMG dərin çıxarma yoxdur (MVP xaricində).
- PDF embedded file/JS extract yoxdur; heuristik `/OpenAction` və `/JS` bayraqları göstərilir.
- Əlavə sandboxlar (Litterbox/Viper/Detux/Qiling) opsional genişlənmə kimi planlana bilər.
