# ZORBOX: Milli Sandbox Layihəsi — MVP Playbook

Bu sənəd Secure Tomorrow Hackathon üçün ZORBOX sisteminin MVP-ni maksimal bala uyğun, təhlükəsiz, etibarlı, davamlı, skalabil və anlaşılan şəkildə çatdırmaq üçün end-to-end arxitektura, icra planı, yoxlama siyahıları və izlənəbilənlik (traceability) təqdim edir. Bütün maddələr texniki sənəd və qiymətləndirmə meyarları ilə hizalanır.

## Məqsəd və Uğur Mezarları

- 48 saatda end-to-end demo; bütün rubrika kateqoriyalarından xal toplamaq; bonusları vurmaq.
- Uğur şərtləri (Acceptance):
  - `POST /analyze` və `GET /result/{id}` işləyir (bonus +2).
  - 1 native + ən azı 4 open-source sandbox adapteri işlək (bonus +5).
  - JSON və PDF (STIX 2.1 opsional) report çıxışı.
  - Hər modulda Prometheus metrics + logs; Grafana dashboard + alertlər.
  - Hər modulda Dockerfile, `.github/workflows/ci.yml`, README, PR şablonu; Ansible stub.
  - Təhlükəsizlik: fayl təcridi, icazə nəzarəti, seccomp, namespaces, read-only kök FS.
  - Davranış qrafiki vizualizasiyası (bonus +3).

Qeyd (AI barədə): Texniki sənəddə “AI tətbiqi məcburidir” qeyd olunur; bonusda isə “AI minimum istifadə +10”. Strategiya: Default qayda-əsaslı scoring (AI-minimum) + opsional yüngül AI modulu (aktiv etmək vacib deyil). Demo zamanı AI-minimum aktiv qalır ki, bonus qorunsun.

## Arxitektura və Komponentlər

- Orchestrator (Python/FastAPI)
  - Boru xətti koordinasiyası, state machine: queued → running → enriching → reporting → done/failed
  - API: `POST /analyze`, `GET /result/{id}`, `GET /jobs?state=...`
  - Metrics: `orchestrator_jobs_in_state{state}`, `orchestrator_queue_length`, `orchestrator_job_latency_seconds`
  - README + JSON schema + PR şablon

- Sandbox-native (Python wrapper + nsjail/bwrap/strace)
  - Syscall, fayl, şəbəkə davranış toplanması; CPU/Mem/Time limitlər; no-net by default
  - Artifacts: `trace.log`, izlənən fayllar, çıxış kodu, run müddəti
  - Metrics: `sandbox_runs_total`, `sandbox_run_duration_seconds`, `sandbox_errors_total`

- Sandbox-adapters (4 OSS)
  - nsjail, firejail, bwrap, gVisor (runsc) — vahid interface: `run(sample) → { artifacts, log, rc }`
  - Metrics: `sandbox_adapter_runs_total{adapter=...}`, `sandbox_adapter_errors_total{adapter=...}`

- TI-enrichment (Python/FastAPI)
  - Domain/IP/Hash reputation: lokal TI DB + opsional VirusTotal
  - Metrics: `ti_queries_total`, `ti_reputation_unknown_total`, `ti_latency_seconds`
  - Secrets: API keys GitHub Secrets-də

- Reporter-service (Python/FastAPI)
  - Aggregation: sandbox + TI nəticələr → JSON schema
  - PDF (ReportLab) və STIX 2.1 (stix2)
  - Storage-a JSON/PDF/STIX yazır, linkləri qaytarır
  - Metrics: `reporter_reports_generated_total`, `reporter_pdf_generation_time_seconds`

- Frontend-ui (React + Vite)
  - Səhifələr: Upload, Status/Jobs, Report viewer (JSON/PDF link), Feedback
  - Davranış qrafiki (syscall/file/net qovşaqları)
  - RUM metrics, frontend error logging

- Storage
  - MVP: lokal qovluq (quarantine/uploads, exports)
  - Opsional: MinIO (S3 uyğun), presigned URL-lər

- Infra
  - docker-compose (lokal), k8s manifests (Deployment, Service, NetworkPolicy, HPA)
  - Prometheus/Grafana stack; Alertlər: disk usage, job queue length, error rate

### Data Flow (High-Level)

1) UI `POST /analyze` (file/URL) → Orchestrator job-id qaytarır  
2) Orchestrator → sandbox adapterləri (paralel/sıralı) → artifacts/logs  
3) TI-enrichment IOC-ları enrich edir  
4) Reporter-service JSON → PDF/STIX → Storage linklər  
5) Orchestrator state `done` → UI `GET /result/{id}` göstərir  
6) Feedback UI → Orchestrator → qaydalara təsir (opsional)

## API Dizaynı (MVP)

- POST `/analyze`
  - Request: multipart `file` və ya JSON `{ "url": "https://..." }`; optional `password`; optional `adapters` siyahısı
  - Response: `{ "job_id": "uuid", "accepted": true }`

- GET `/result/{id}`
  - Response: JSON report snapshot + export linkləri

- GET `/jobs?state=queued|running|...`
  - Response: `{ "items": [ { id, state, created_at, ... } ] }`

JSON Report Schema (eskiz)
- `id`, `submitted_at`, `file`: `{name,size,sha256,source}`  
- `sandboxes[]`: `{name,status,duration_ms,findings:{syscalls[],files[],net[]}}`  
- `ti`: `{ips[],domains[],hashes[],reputation}`  
- `score`: `{total, rules[]}`  
- `export`: `{json_url,pdf_url,stix_url}`

## Təhlükəsizlik Dizaynı

- Sandbox izolasiya: unprivileged containers, user namespaces, seccomp, AppArmor (mümkün), `readOnlyRootFilesystem`, `no-new-privileges`.
- Fayl təcridi: uploads no-exec mount; işləmə yalnız sandbox-da; egress deny (sandbox), yalnız TI whitelisted.
- İcazələr: k8s RBAC; admin endpointlər üçün auth; rate limiting (Ingress/boundary qatında).
- Secrets: VT API key GitHub Secrets; env olaraq inject.
- Audit: hər modulda structured audit log; immutable job ID-lər.

## Müşahidə və Monitorinq

- Hər servisdə `/metrics` (Prometheus)
- Panellər (Grafana): job states, queue length, sandbox error rate, report duration
- Alertlər: `queue_length > 20` (5 dəq), `error_rate > 5%`, `disk_free < 10%`, `report_latency_p95 > 30s`

## Repo Strukturu (Monorepo)

- `orchestrator/` — FastAPI service, Dockerfile, README, ci.yml, ansible/
- `sandbox-native/` — exec wrapper, limits, strace parsers
- `sandbox-adapters/` — `nsjail/`, `firejail/`, `bwrap/`, `gvisor/`
- `ti-enrichment/` — TI API + local DB
- `reporter-service/` — JSON/PDF/STIX exporter
- `frontend-ui/` — Vite React app
- `infra/` — `docker-compose.yml`, `k8s/`, `prometheus/`, `grafana/`
- `storage/` — lokal data/exports (gitignored)
- `.github/` — `workflows/` (CI), `PULL_REQUEST_TEMPLATE.md`, `ISSUE_TEMPLATE/`
- `docs/` — bu playbook, JSON schema, API docs

## Texnoloji Seçimlər (MVP üçün sabit)

- Backend: Python 3.11+ (FastAPI + Uvicorn), Prometheus client
- Frontend: React + Vite, ECharts/vis-network (grafik)
- PDF: ReportLab (headless browser asılılığı yoxdur)
- STIX: `stix2` Python kitabxanası
- Storage: Lokal qovluq (MVP), MinIO (opsional)
- Queue: Orchestrator daxilində in-memory + disk snapshot (MVP), sonradan Redis
- Testlər: Pytest (backend), Vitest/RTL (frontend)
- Format: Black/ruff, Prettier/ESLint

## MVP İş Axını və Acceptance Kriteriyaları

1) Upload və Analyze
- Acceptance: `POST /analyze` faylı/URL-i qəbul edir, `job_id` qaytarır; fayl hash-lanır, quarantine-ə yazılır.
- Check: 2MB test faylı ilə 200 OK, job state `queued`.

2) Sandbox İcra
- Acceptance: native + ≥3 adapter işləyir; artifacts/logs yaranır; scoring çıxır.
- Check: `sandbox_adapter_runs_total` artımı; duration < 60s (demo faylı).

3) TI Enrichment
- Acceptance: IOC-lar çıxarılır və reputation əlavə olunur.
- Check: `ti_queries_total` artımı; `ti_reputation_unknown_total` ≤ 20%.

4) Reportlama
- Acceptance: JSON report; PDF çıxışı; STIX (opsional).
- Check: Storage-da JSON/PDF faylları; `reporter_reports_generated_total` artımı; PDF generation p95 < 5s.

5) UI
- Acceptance: Upload → Status → Report viewer; JSON/PDF linkləri; feedback işləyir.
- Check: E2E demo ssenarisi; davranış qrafiki paneli görünür.

6) Müşahidə və Alert
- Acceptance: Prometheus scrape; Grafana dashboard; alert qaydaları yüklənib.
- Check: queue_length simulyasiyası ilə test alert trigger.

## MVP Parametrlər və Validasiya (Frontend/Backend)

- Frontend Upload
  - Metadata: `(filename, size, content-type)`
  - Limit: `0 < size ≤ 10 MB`; `mime-type` uyğun gəlir; allowed extensions konfiqurasiya olunandır
  - UI: Upload + URL sahəsi + archive password input; progress göstəricisi; `job-id` qaytarılır

- URL-dən Avtomatik Yükləmə (Downloader)
  - Alətlər: `requests/axios` (server tərəfi)
  - Yoxlamalar: content-type check, redirect handling
  - Nəticə: Yerli fayl kopyası, initial headers, HTTP status
  - Validasiya: `HTTP 200`; `Content-Length` mövcud və limit daxilində
  - Davranış: `retry(3)`, `timeout(30s)`, domain `allowlist/blocklist`
  - TLS: SNI/SSL validation aktivdir
  - Headers: HTTP başlıqlar TI enrichment üçün saxlanılır

- İlk Sanity Yoxlaması
  - Giriş: Fayl path
  - Alətlər: `file magic (libmagic)`, `hash (SHA256/MD5)`, `size`, `mime`
  - Çıxış: metadata record `(hash,mime,size)`
  - Validasiya: Hash generasiya uğurlu; `mime != suspicious mismatch` halları flag edilir
  - Davranış: DB entry yaz; `mime-hint` ilə `extension` mismatch olduqda flag

## Storage (Karantin) — Tələblər (MVP)

- No-exec storage: Karantin qovluqları `noexec` mount-da, yalnız servis istifadəçisi (`owner=svc_user`), immutable perms.
- Safe path: Canonical path yoxlanışı (zip-slip qarşısı); yalnız təyin edilmiş `base_dir`-in altında yazmaq.
- Retention policy: müddətə bağlı təmizləmə (MVP-də sənədli plan / cron stub).
- Quota: storage kvotası yoxlanır (MVP-də ölçü limiti + xəbərdarlıq metrics).
- Logs: əsas addımlar structured log-da; kritik log əskikdirsə əməliyyatı rədd et (MVP-də guard check).

## Arxiv Emalı — Şifrə və Dərinlik (MVP)

- Dəstəklənənlər: `.zip` (stdlib), `.rar`, `.7z` (plan, üçüncü tərəf lib-lərlə; MVP-də yalnız ZIP minimal)
- UI: password field və "provide later" flag.
- Şifrə siyasəti: Şifrəli arxivdə parol verilməyibsə, emal dayandırılır və iş tələb olunan parol ilə flagged edilir.
- Dərinlik: nested extraction depth = N (MVP: N=1–2 sənədli parametr), ölçü limiti tətbiq edilir.
- Təhlükəsizlik: zip-slip qarşısı, fayl adlarının kanonizasiyası, yalnız karantin altına extract.

## Statik Analiz Boru Xətti (MVP)

- Alətlər (MVP seçimi):
  - Strelka (metadata, YARA scan, hash, file carving)
  - PE parsers: `pefile` (və ya `lief`) — imports/exports/sections/entropy
  - Office: `oletools` (makro çıxarışı, şübhəli sözlər), embedded obyekt çıxarışı
  - PDF: `pdf-parser/pdfid` ekvivalenti (JS/embedded, OpenAction, metadata)
  - JS: beautify/AST (`jsbeautify` və ya sadə tokenizasiya), eval/unescape aşkarlanması
- Çıxış: Statik report JSON — strings, imports, macros, embedded objs, YARA hits, basic heuristics
- Acceptance:
  - Parsers crash ETMƏSİN; YARA qaydaları valid formatda tətbiq edilsin
  - JSON schema-ya uyğunluq (validator test)
- Arxitektura:
  - Modular microservices (MVP-də modul kimi eyni repositoriyada), `analyzer.static.*` interfeysləri
  - Output JSON schema stabil saxlanılır, reporter-service tərəfindən istehlak olunur

## Dinamik/Sandbox Analiz (opsional, MVP)

- Hədəflər: Cuckoo, CAPEv2, Firejail-based Simple Sandbox, və ya Native engine
- Çıxış: Behavioral report — network calls, processes, registry/files, syscalls
- Acceptance:
  - Sandbox icrası time-limit daxilində tamamlanır (məs. 120s)
  - Network izolasiya aktivdir (egress deny və ya sinkhole)
  - Snapshots: pre/post FS snapshot alınır və fayl diff-i çıxarılır (MVP: opsional)
  - Resurslar: CPU/Memory kvotaları; seccomp/AppArmor/Firejail profilləri tətbiq olunur
- İstisna/Plan B:
  - İnfra limitli olduqda minimal emulyasiya (CAPE/Cuckoo remote) və ya `no-dynamic` flag ilə buraxma

## Native Engine Augmentasiya (opsional, advanced)

- Giriş: Binary/syscall traces
- Texnika: Custom syscalls monitor, `ptrace`/qemu, memory dumper
- Çıxış: Syscall trace, suspicious sequences, memory IOCs
- Acceptance: Trace ardıcıllığı konsistent; host komprometasiya YOX
- İnteqrasiya: Scoring servisinə əlavə feature-lər kimi feed edilir

## IOC/YARA/TI Enrichment

- Giriş: Statik+dinamik çıxarışlar (IOCs)
- Mənbələr: YARA DB, lokal TI feed-lər, VirusTotal API (mövcuddursa)
- Çıxış: Enriched IOCs + reputation tags
- Acceptance:
  - Minimum top-5 IOC çıxarılıb enrich edilsin
  - YARA qaydaları ilə uyğun gələnlər işarələnsin
- Xəritə: `indicator -> confidence score`; scoring üçün vahid reputasiya metri yaradılır

## AI Scoring və Rule-based Scoring (Hybrid)

- Features: imports, YARA, behavior, TI və s.
- Model: yüngül və izah edilə bilən (logistic/regression tree) + qayda mühərriki
- Çıxış: `AI score (0–100)`, rule triggers, əsas feature-lərin listi (explainability)
- Acceptance:
  - Model score + top features qaytarır; qaydalar ayrıca qiymətləndirilir
  - Admin/UI-də çəkilər tənzimlənə bilir (konfiq fayl və ya parametrlər)

## Final Risk Aggregation

- Giriş: AI score + rule hits + reputation
- Metod: Weighted aggregator (konfiqurasiya edilə bilir)
- Çıxış: Final risk səviyyəsi (Low/Medium/High/Critical) + rəqəmsal skor
- Acceptance:
  - Stabil xəritə; unit testlər keçilir
  - Admin UI-dan çəkilərin tənzimlənməsi (hackathon tuning üçün)

## Report Generation & Export (MVP)

- Giriş: Aggregated analysis (static+dynamic+TI+scoring)
- Alətlər: JSON schema validator; PDF generator (ReportLab); STIX serializer (minimal STIX 2.1 bundle)
- Çıxışlar: PDF, JSON, STIX + UI report linkləri
- Acceptance:
  - Exports valid JSON & STIX (bundle with indicators/observed-data)
  - PDF oxunaqlıdır (executive summary + technical annex)
  - Nümunə PDF şablonu və yüklənə bilən fayllar təqdim olunur
- API (reporter-service):
  - `POST /report` — input: aggregated JSON; output: `{ json_url, pdf_url, stix_url }`
  - `GET /healthz`, `GET /metrics`
- Metrics:
  - `reporter_reports_generated_total`
  - `reporter_pdf_generation_time_seconds`

## Frontend Vizualizasiya & Drill-down

- Elementlər: Charts, timeline, IOC list, YARA hits, download düymələri
- İnteraktivlik: Filtrlər (type/severity/time), axtarış, genişlənən bölmələr
- Acceptance:
  - Bütün əsas məlumatlar əlçatandır; filtrlər işləyir
  - Davranış timeline və YARA hits listi göstərilir; JSON/PDF/STIX yükləmə düymələri aktivdir

## Feedback Loop & Reanalysis

- UI: “Mark FP / Request reanalysis” düymələri
- Backend: Re-run queue, manual override mexanizmi
- Çıxış: Re-analysis job yaradılır; qaydalar tənzimlənir (weight/whitelist)
- Acceptance:
  - Re-analysis tamamlanır; tənzimlənmiş qaydalar sandbox/scoring-də tətbiq olunur

## Audit & Logging

- Mərkəzi loglama: ELK/Graylog inteqrasiyası üçün strukturlaşdırılmış JSON loglar
- Audit trails: Hər əməliyyat `user-id`/`job-id` ilə qeyd olunur; immutable storage
- Admin: Sadə audit viewer (MVP üçün log axtarışı və job üzrə filtr)

## Keyfiyyət Qapıları (Quality Gates)

- Kod: SOLID, DRY, KISS; modul sərhədləri aydın; side-effect minimallaşdırılır.
- Təhlükəsizlik: unprivileged containers; read-only; input validation; yalnız sandbox-da exec.
- Ölçülmə: hər əsas əməliyyatda metrics/log; structured JSON logging.
- Sənədləşmə: hər modul README (run/test/config/metrics); PR şablonu; API docs.
- CI: lint + test + build; image build; PR-da required checks.

## Detallı İcra Addımları

0) Hazırlıq
- Repo init; monorepo dirs; `docs/` altına bu sənəd.
- GitHub Secrets: `VT_API_KEY` (opsional).

1) Orchestrator (FastAPI)
- Endpoints: `/analyze`, `/result/{id}`, `/jobs`.
- State machine + in-memory queue; job snapshot diskə persist.
- Metrics + structured logging; README + JSON schema + PR template.

2) Sandbox-native
- `nsjail`/`bwrap` exec wrapper; `strace -f -tt -o trace.log`.
- Parsers: syscall timeline, opened files, net attempts.
- Limits: CPU/mem/time; no net by default; metrics.

3) Sandbox-adapters (nsjail/firejail/bwrap/gvisor)
- Vahid interface; config profilləri; artifacts normalizasiyası; metrics label-lı.

4) TI-enrichment
- API: `POST /enrich`; lokal DB + opsional VT; caching + rate-limit.

5) Reporter-service
- Aggregate → JSON schema; PDF (ReportLab) + STIX (stix2); storage yazısı; metrics.

6) Frontend-ui
- Upload, Jobs, Job Detail (JSON/PDF link, graph), Feedback; RUM + error log.

7) Infra
- docker-compose: bütün servislər + Prometheus/Grafana.
- k8s: Deployments, Services, NetworkPolicy, Resources; scrape config; alert rules.

8) CI/CD
- GitHub Actions: python/node lint/test/build, docker build; PR Template.

9) Test Plan
- Unit: parsers, schema validation, TI enrichment.
- Integration: `/analyze` → `/result/{id}` happy path.
- E2E: upload → done → report linkləri.
- Security: sandbox egress deny, no-exec mount doğrulaması (lokal imkanlara uyğun).

## Skorinq Qaydaları (Qısa və izah edilə bilən)

- Şübhəli syscalls: `ptrace`, `execve` → +20
- Şübhəli fayl yolları: `AppData/…/Startup` → +15
- Şəbəkə cəhdləri: qeyri-standart portlar → +10
- TI reputasiyası: bad → +30; unknown → +5; good → +0
- Toplam: 0–100; eşik: ≥60 şübhəli

AI-minimum: Qayda əsaslı scoring default; AI-modul opsional saxlanır.

## Tələblərin Genişləndirilməsi (Son göndərdiyiniz mətnə uyğun)

### Fayl Tipləri — Prioritet Matrisi (MVP)

- MUST-HAVE (MVP, ilk 48 saat): `.exe`, `.dll`, `.ps1`, `.js`, `.docx/.xls/.ppt` (makrolar), `.zip/.rar/.7z` (şifrə sahəsi ilə)
- NICE-TO-HAVE: `.py`, `.bat/.cmd/.vbs`, `.pdf`, `.apk`
- OPTIONAL / ADVANCED: `.jar`, `.elf/.bin`, `.iso/.img`

Yönləndirmə qeydləri:
- `.dll` side-loading: `.exe` ilə eyni PE analizi (PE metadata, exported functions, suspicious imports, YARA)
- `.ps1`: statik string/IOC çıxarışı, obfuscation (base64, encoded commands), regex-based IOC matçı; sandboxlaşdırılmamış icradan qaçın
- `.js`: statik token/URL extraction, obfuscation (eval, unescape), YARA; brauzer-sandboxı deyil, statik prioritet
- Office: VBA makro deteksiyası, embedded obyektlərin çıxarılması; icra ETMƏ
- Arxivlər: şifrəli/şifrəsiz; nested extraction limitləri; zip-slip qarşısı; UI-da password input
- `.apk`: manifest/permissions, strings/URL; dinamik analiz sonraya
- `.elf/.bin`, `.jar`, `.iso/.img`: yalnız statik/outline; dinamik emulyasiya sonrakı mərhələyə saxlanır

### Açıq Mənbə Sandbox Hədəfləri (MVP seçimi)

- Must-have: Cuckoo Sandbox, CAPEv2, Firejail-based Simple Sandbox, Strelka (statik/YARA)
- Nice-to-have: Litterbox, Viper, Qiling Framework
- Optional/Advanced: StuxnetBox/Flare VM, Joe Sandbox CE, Detux, Sandsifter

Adapter xəritələməsi:
- `sandbox-integration`: Cuckoo/CAPEv2 API icrası (dinamik)
- `sandbox-native`: Firejail/nsjail/bwrap ilə minimal icra + `strace` toplama
- `static-analyzer`: Strelka (carving/YARA) inteqrasiyası və lokaldakı parsers

Qeyd: Real VM-lərlə dərin dinamik analiz infra tələb edir; MVP üçün minimal və etibarlı yolla işləyən adapterlər seçilir.

### Sistem Axını (MVP)

1) Fayl yüklə və ya URL daxil et (Frontend)
2) URL təqdim edilibsə fayl avtomatik endirilir (Downloader)
3) İlk sanity: hash, mime, size; metadata (Backend)
4) Karantin & Storage: no-exec, immutable perms (Infra/Backend)
5) Arxiv & şifrə: UI-dan parola; təhlükəsiz extract; dərinlik limiti (Archive-handler)
6) Statik analiz: PE/Office/Script, YARA/IOCs (Static-analyzer)
7) Dinamik/sandbox: Cuckoo/CAPEv2/native exec (Sandbox-integration)
8) Native engine augmentasiya: syscall/network trace (opsional)
9) TI enrichment: VT/local feeds (TI-enrichment)
10) AI + Rule-based scoring: izah edilə bilən (Scoring-service)
11) Aggregation: weights ilə final score və risk səviyyəsi
12) Report export: JSON, PDF, STIX (Reporter-service)
13) UI vizualizasiya: timeline, IOC, YARA hits, download
14) Feedback loop: reanalysis/retry
15) Audit & logging: mərkəzi log, audit trails

### Skorinq — Hybrid Model və Xəritə

- Rule-based: YARA severity, makro varlığı, PE imports, entropy və s.
- AI-based: sadə izah edilə bilən model (logistic regression/tree) — features: `yara_count`, `entropy_score`, `num_urls`, `suspicious_api_calls`, `reputation_score`
- Aggregation: `final_score = 0.6*rule_score + 0.4*ai_score` (konfiqurasiya edilə bilər)
- Risk xəritəsi: `0–29 Low`, `30–59 Medium`, `60–79 High`, `80–100 Critical`

### Modul Xəritəsi (GitHub Strategiyasına uyğun)

- `uploader-service`: Fayl/URL submit; metrics: `uploader.requests_total`, `upload_size_bytes`
- `fetcher-service`: URL yükləmə; `fetcher.download_duration_seconds`, `fetcher.download_failures_total`
- `storage-service`: Safe storage + ilkin yoxlamalar; `storage.files_stored_total`, `storage.hash_time_seconds`
- `archive-handler`: Arxiv/şifrəli fayl emalı; `archive.extractions_total`, `archive.encrypted_count`
- `static-analyzer`: Statik analiz; `analyzer.jobs_processed_total`, `analyzer.yara_hits_total`
- `sandbox-integration`: Dinamik analiz (Cuckoo/CAPEv2/native); `sandbox.runs_total`, `sandbox.timeouts_total`
- `scoring-service`: Rule + AI score; `scoring.requests_total`, `scoring.latency_seconds`
- `orchestrator`: Boru xətti; `orchestrator.jobs_in_state{state}`, `queue_length`
- `reporter-service`: JSON/PDF/STIX; `reporter.reports_generated_total`, `reporter.pdf_generation_time_seconds`
- `frontend-ui`: Upload/status/report/feedback; RUM metrics, frontend errors
- `ti-enrichment`: TI reputation; `ti.queries_total`, `ti.reputation_unknown_total`
- `infra`: IaC + monitoring; k8s/docker-compose; Prometheus/Grafana; alerts

Qeyd: MVP üçün `uploader/fetcher/storage/archive-handler/static-analyzer/sandbox-integration/scoring` funksiyaları ilkin mərhələdə `orchestrator` tərkibində modul kimi reallaşdırılıb, monorepo ayrışması isə ardınca edilə bilər.

## Köməkçi Cədvəl — Fayl Tipləri (MVP 48 saat)

| Fayl tipi | Prioritet | Niyə vacibdir | MVP-də minimal analiz (48h) | Qeyd / Risk |
|---|---|---|---|---|
| .exe | Must-have | Windows-da ən çox istifadə olunan zərərli fayl tipi | Hash (MD5/SHA256), PE metadata (imports/exports), packer/obfuscator göstəriciləri, YARA; VT/AV lookup (API varsa) | Sandboxing tam deyilsə statik analiz yetər; varsa təhlükəsiz icra. Linux-da strace + limits |
| .dll | Must-have | DLL-based yükləyicilər və side-loading hücumları | PE metadata, exported functions, suspicious imports, YARA; .exe ilə eyni analiz boru xətti | Birbaşa icra olunmur; side-loading kontekstində qeyd olunur |
| .ps1 | Must-have | Post-exploitation/persistence skriptləri geniş yayılıb | Static string/IOC çıxarışı, suspicious cmdlet/obfuscation (base64, encoded commands), regex-based IOC match (PowerShell constrained əvəzinə) | Kod icrası risklidir; sandboxlaşdırılmamış icra olmamalıdır; yalnız statik |
| .js | Must-have | Malicious web/launcher skriptləri; makro və drive-by scenariləri üçün əhəmiyyətli | Static token/URL extraction, obfuscation detection (eval, unescape), basic YARA | Browser-sandboxing çətindir; statik analiz prioritetdir |
| .docx/.xls/.ppt | Must-have | Makro vasitəli hücumlar | VBA macro presence flag, macro extract (mövcudsə), suspicious keywords | Makro İCRA ETMƏ; yalnız extract+scan |
| .zip/.rar/.7z | Must-have | Fayl ötürmə, eksfil vasitəsi; parollu arxivlər | Archive listing, nested extraction limit, hash/mime mismatch, password prompt | Zip-slip qarşısı; parol tələb et; bruteforce ETMƏ |
| .pdf | Nice-to-have | Exploitable sənədlər, embedded JS | JS/embedded extract, OpenAction, metadata, URLs | Kompleks exploit analizi YOX |
| .apk | Nice-to-have | Mobil təhdidlər | Manifest/permissions, strings/URL extract | Dinamik analiz sonrakı mərhələyə |
| .py | Nice-to-have | Açıq mənbə/script hücumları, məktəblər/CTF üçün faydalıdır | Static AST-based suspicious API detection, IOC extraction | İcra ETMƏ; yalnız statik. Python bytecode dəstəyi əlavə oluna bilər |
| .bat/.cmd/.vbs | Nice-to-have | Sadə persistence və script hücumları; təlim məqsədi üçün faydalıdır | String/command extraction, suspicious command patterns (powershell, wmic) | Sadə analizlə kifayət |
| .jar | Optional | Java əsaslı malware/web exploitation | Class listing, reflection usage, embedded native libs | Resurs məhdudsa, sonraya saxla |
| .elf/.bin | Optional/Advanced | Linux server-side hədəflər | ELF headers/sections, strings | Dinamik emulyasiya (qemu) YOX |
| .iso/.img | Optional | Disk image-lər/forensik | Read-only listing, böyük binarilərin seçilməsi | Mount təhlükəsizlik/məzuniyyət; MVP-də təxirə sal |

## Traceability — Texniki Sənəd Uyğunluğu

- Orchestrator: “Boru xətti koordinasiyası; README + JSON schema, PR şablon; metrics: orchestrator.jobs_in_state{state}, queue length” → Plan və metrics bölməsində 1:1.
- Reporter-service: “JSON, PDF, STIX; storage-a göndər; metrics: reporter.reports_generated_total, reporter.pdf_generation_time_seconds; README, PR şablon” → Dəqiq əhatə olunub.
- Frontend-ui: “Upload, status, report viewer, feedback; RUM metrics, frontend errors; README, build + unit test, PR şablon” → UI və müşahidə bölmələrində var.
- TI-enrichment: “Domain/IP reputation; TI DB, optional VirusTotal; metrics: ti.queries_total, ti.reputation_unknown_total; API keys GitHub Secrets-də; PR şablon” → TI bölməsində var.
- Infra: “k8s manifests, docker-compose, Prometheus/Grafana stack; Alerts: disk usage, job queue, errors; README + monitoring docs, PR şablon” → Infra və monitoring bölmələrində var.
- Ümumi: “Hər modulun Dockerfile, .github/workflows/ci.yml, Ansible faylı; Prometheus metrics və logs expose” → Repo strukturu və keyfiyyət qapılarında var.
- Orchestrator mərkəzi job state izləyicisi; Frontend UI nəticə/feedback → Arxitektura və Data Flow bölmələrində var.
- Qiymətləndirmə meyarları: prototip işləkliyi; native + ≥4 OSS sandbox; təhlükəsizlik; UI; export; kod/sənədləşmə; əlavə xüsusiyyətlər → MVP acceptance, test plan və bonus strategiyasında əhatə olunub.
- Bonus: REST API endpoint (+2) — var; ≥3 sandbox (+5) — 4 adapter planlanıb; davranış qrafiki (+3) — UI bölməsində; AI minimum (+10) — strategiyada.

## Demo Ssenarisi

1) UI ilə fayl/URL yüklə → job ID  
2) Jobs səhifəsində state keçidi: queued → running → enriching → reporting → done  
3) Job detail: JSON result, PDF link, STIX download  
4) Davranış qrafiki göstər (syscall/file/net)  
5) Grafana dashboard: jobs in state, queue, durations, errors  
6) Feedback göndər və logda təsdiq gör

## Risklər və Mitigasiyalar

- Sandbox asılılıqları və profillər: container izolasiya + fallback native run
- PDF aləti gecikməsi: ReportLab seçimi (headless Chrome asılılığı yoxdur)
- TI rate limit: caching + backoff; offline lokal DB
- AI ziddiyyəti: AI-minimum default; AI-modul opsional

## Lokal Qurulum (Development)

- Tələblər: Docker, Docker Compose, Python 3.11+, Node 20+, Make (opsional)
- Addımlar: `docker compose up -d` və ya servis-özəl `uvicorn`/`npm run dev`
- Test: Backend `pytest -q`; Frontend `npm test`

## CI/CD Sxemi (GitHub Actions)

- Python job: ruff + black --check + pytest + docker build
- Node job: eslint + vitest + build
- Docker build-push (opsional): `ghcr.io/<org>/<service>:<sha>`
- PR şablonu: Niyə/necəyə, test sübutları, rubrika maddələri, screenshot-lar
- Required checks: lint, unit tests, build

## K8s Manifests (Eskiz)

- Deployment: `readOnlyRootFilesystem: true`, `runAsNonRoot: true`, limits/requests
- Service: ClusterIP; Ingress (UI+API)
- NetworkPolicy: sandbox pods egress deny (TI whitelisted)
- HPA: CPU-based autoscaling (opsional)
- Prometheus: scrape annotations və ya ServiceMonitor

## Ansible (Stub)

- Roll: demo mühitində Docker Compose + konfiqlər
- Tasks: env faylları, compose up, user/group

## Yoxlama Siyahıları (Checklists)

- MVP E2E
  - [ ] `/analyze` → ID qaytarır
  - [ ] Job `done` ≤ 60s (demo faylı)
  - [ ] JSON/PDF/STIX çıxışı var
  - [ ] Prometheus metrics toplanır
  - [ ] UI upload/status/report işləkdir

- Təhlükəsizlik
  - [ ] `readOnlyRootFilesystem`
  - [ ] `no-new-privileges`
  - [ ] Seccomp profil aktivdir
  - [ ] Sandbox egress deny

- Sənədləşmə
  - [ ] Hər modul README + metrics bölməsi
  - [ ] PR şablonu mövcuddur
  - [ ] CI workflow-ları işləkdir

---

## Frontend UI (MVP)

- Səhifələr/Komponentlər
  - Upload formu: Fayl/URL, archive password input, progress, job-id
  - Jobs/Status: status listəsi və filterlər
  - Job Detail: JSON/PDF/STIX linkləri, timeline, IOC/YARA listi, Feedback
- RUM & Errors
  - RUM: navigation timing, API latency ölçümü; backend log/metrics-ə forward
  - Errors: JS error listener → backend `/frontend-errors` (MVP: log)
- Build/Test/PR
  - Build: Vite React
  - Test: Vitest + Testing Library (minimum 1 test)
  - PR: şablon + CI (lint/test/build)

## TI-Enrichment Service (MVP)

- API: `POST /enrich` — input `{ domains:[], ips:[], hashes:[] }`; output reputasiya mapı
- Secrets: `VT_API_KEY` (GitHub Secrets → env); yoxdursa offline-local DB
- Metrics: `ti_queries_total`, `ti_reputation_unknown_total`, `ti_latency_seconds`
- Davranış: in-memory cache; backoff (əgər VT aktivdirsə)

## Infra (IaC & Monitoring)

- docker-compose: orchestrator, reporter, ti-enrichment, (opsional) frontend-ui, Prometheus, Grafana
- k8s manifests: Deployment, Service, Ingress, NetworkPolicy, Resource limits (YAML)
- Monitoring: Prometheus/Grafana stack; scrape targets: orchestrator:8080, reporter:8090, ti:8070
- Alerts: disk usage (node_exporter tələb edir), job queue (`orchestrator_queue_length`), service down (`up==0`), error rate (servis-özəl)
- Sənədləşmə: `infra/README.md`, `infra/monitoring/README.md`; PR şablonu
- Qeyd: Hər modulda Dockerfile və `.github/workflows/ci.yml` mövcuddur; Ansible faylları stublar daxil edildi
