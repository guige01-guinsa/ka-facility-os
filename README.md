# ka-facility-os

`ka-facility-os` is a FastAPI service for facility inspection/work-order operations.

## 1) Local run (Windows / PowerShell)

```powershell
cd C:\ka-facility-os
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

Open:
- API: `http://127.0.0.1:8001`
- Docs: `http://127.0.0.1:8001/docs`
- Health: `http://127.0.0.1:8001/health`
- Meta: `http://127.0.0.1:8001/meta`

## API summary

- Public
  - `GET /` (browser single-shell tabbed main page; tabs: overview/work-orders/inspections/reports/adoption)
  - `GET /web/adoption` (browser HTML adoption/post-MVP portal page)
  - `GET /web/console` (browser HTML operations console for human-readable module views)
  - `GET /api/service-info` (machine-readable service endpoint map)
  - `GET /api/public/modules` (public module registry; browser `Accept: text/html` renders card view)
  - `GET /api/public/adoption-plan` (public JSON plan)
  - `GET /api/public/adoption-plan/campaign` (public promotion/education/fun kit)
  - `GET /api/public/adoption-plan/schedule.csv` (weekly execution schedule export)
  - `GET /api/public/adoption-plan/schedule.ics` (calendar import for schedule management)
  - `GET /api/public/adoption-plan/w02` (W02 Scheduled SOP + sandbox execution pack)
  - `GET /api/public/adoption-plan/w02/checklist.csv` (W02 SOP/sandbox checklist export)
  - `GET /api/public/adoption-plan/w02/schedule.ics` (W02 calendar import)
  - `GET /api/public/post-mvp` (post-MVP roadmap/backlog/release/KPI/risk plan)
  - `GET /api/public/post-mvp/backlog.csv` (execution backlog export)
  - `GET /api/public/post-mvp/releases.ics` (release calendar import)
  - `GET /api/public/post-mvp/kpi-dashboard` (post-MVP KPI dashboard specification)
  - `GET /api/public/post-mvp/risks` (post-MVP risk register)
- Auth/RBAC
  - `GET /api/auth/me`
  - `GET /api/admin/users` (permission: `admins:manage`)
  - `POST /api/admin/users` (permission: `admins:manage`)
  - `PATCH /api/admin/users/{user_id}/active` (permission: `admins:manage`)
  - `POST /api/admin/users/{user_id}/tokens` (permission: `admins:manage`)
  - `GET /api/admin/tokens` (permission: `admins:manage`)
  - `POST /api/admin/tokens/{token_id}/rotate` (permission: `admins:manage`)
  - `POST /api/admin/tokens/{token_id}/revoke` (permission: `admins:manage`)
  - `GET /api/admin/token-policy` (permission: `admins:manage`)
  - `GET /api/admin/audit-logs` (permission: `admins:manage`)
  - `GET /api/admin/audit-integrity?month=YYYY-MM` (permission: `admins:manage`)
  - `POST /api/admin/audit-chain/rebaseline?from_month=YYYY-MM` (permission: `admins:manage`)
  - `GET /api/admin/audit-archive/monthly?month=YYYY-MM` (permission: `admins:manage`)
  - `GET /api/admin/audit-archive/monthly/csv?month=YYYY-MM` (permission: `admins:manage`)
  - `GET /api/admin/policies/sla?site=...` (permission: `admins:manage`)
  - `PUT /api/admin/policies/sla?site=...` (permission: `admins:manage`)
  - `POST /api/admin/policies/sla/proposals` (permission: `admins:manage`)
  - `GET /api/admin/policies/sla/proposals` (permission: `admins:manage`)
  - `GET /api/admin/policies/sla/proposals/{id}` (permission: `admins:manage`)
  - `POST /api/admin/policies/sla/proposals/{id}/approve` (permission: `admins:manage`)
  - `POST /api/admin/policies/sla/proposals/{id}/reject` (permission: `admins:manage`)
  - `GET /api/admin/policies/sla/revisions` (permission: `admins:manage`)
  - `POST /api/admin/policies/sla/revisions/{id}/restore` (permission: `admins:manage`)
  - `GET /api/ops/job-runs` (permission: `admins:manage`)
  - `GET /api/ops/dashboard/summary` (permission: `admins:manage`)
  - `GET /api/ops/dashboard/trends` (permission: `admins:manage`)
  - `GET /api/ops/runbook/checks` (permission: `admins:manage`)
  - `POST /api/ops/runbook/checks/run` (permission: `admins:manage`)
  - `GET /api/ops/runbook/checks/latest` (permission: `admins:manage`)
  - `GET /api/ops/handover/brief` (permission: `admins:manage`)
  - `GET /api/ops/handover/brief/csv` (permission: `admins:manage`)
  - `GET /api/ops/handover/brief/pdf` (permission: `admins:manage`)
  - `GET /api/ops/alerts/deliveries` (permission: `admins:manage`)
  - `POST /api/ops/alerts/deliveries/{id}/retry` (permission: `admins:manage`)
  - `POST /api/ops/alerts/retries/run` (permission: `admins:manage`)
  - `POST /api/ops/sla/simulate` (permission: `admins:manage`)
  - `GET /api/ops/security/posture` (permission: `admins:manage`)
- Workflow locks (W01 role workflow lock)
  - `GET /api/workflow-locks` (`workflow_locks:read`)
  - `POST /api/workflow-locks` (`workflow_locks:write` or admin override)
  - `GET /api/workflow-locks/{id}` (`workflow_locks:read`)
  - `PATCH /api/workflow-locks/{id}/draft` (`workflow_locks:write` on `draft`)
  - `POST /api/workflow-locks/{id}/submit` (`workflow_locks:write` on `draft`)
  - `POST /api/workflow-locks/{id}/approve` (`workflow_locks:approve` on `review`)
  - `POST /api/workflow-locks/{id}/reject` (`workflow_locks:approve` on `review`)
  - `POST /api/workflow-locks/{id}/lock` (`owner` on `approved`)
  - `POST /api/workflow-locks/{id}/unlock` (`workflow_locks:admin` override only; requires `reason` + `requested_ticket`)
- W02 execution tracker (assignee/completion/evidence upload)
  - `POST /api/adoption/w02/tracker/bootstrap` (`adoption_w02:write`)
  - `GET /api/adoption/w02/tracker/items` (`adoption_w02:read`)
  - `GET /api/adoption/w02/tracker/overview?site=...` (`adoption_w02:read`)
  - `PATCH /api/adoption/w02/tracker/items/{id}` (`adoption_w02:write`)
  - `POST /api/adoption/w02/tracker/items/{id}/evidence` (`adoption_w02:write`, multipart upload, max 5MB)
  - `GET /api/adoption/w02/tracker/items/{id}/evidence` (`adoption_w02:read`)
  - `GET /api/adoption/w02/tracker/evidence/{id}/download` (`adoption_w02:read`)
- Inspections
  - `POST /api/inspections` (`inspections:write`)
  - `GET /api/inspections` (`inspections:read`)
  - `GET /api/inspections/{id}` (`inspections:read`)
  - `GET /inspections/{id}/print` (`inspections:read`)
- Work orders
  - `POST /api/work-orders` (`work_orders:write`)
  - `GET /api/work-orders` (`work_orders:read`)
  - `GET /api/work-orders/{id}` (`work_orders:read`)
  - `PATCH /api/work-orders/{id}/ack` (`work_orders:write`)
  - `PATCH /api/work-orders/{id}/complete` (`work_orders:write`)
  - `PATCH /api/work-orders/{id}/cancel` (`work_orders:write`)
  - `PATCH /api/work-orders/{id}/reopen` (`work_orders:write`)
  - `POST /api/work-orders/{id}/comments` (`work_orders:write`)
  - `GET /api/work-orders/{id}/events` (`work_orders:read`)
  - `POST /api/work-orders/escalations/run` (`work_orders:escalate`)
- Monthly audit reports
  - `GET /api/reports/monthly?month=YYYY-MM&site=...` (`reports:read`)
  - `GET /reports/monthly/print?month=YYYY-MM&site=...` (`reports:read`)
  - `GET /api/reports/monthly/csv?month=YYYY-MM&site=...` (`reports:export`)
  - `GET /api/reports/monthly/pdf?month=YYYY-MM&site=...` (`reports:export`)

## RBAC and token auth

- Header key: `X-Admin-Token`
- Tokens are stored as hash in DB (`admin_tokens`), linked to users (`admin_users`).
- Site scope:
  - `admin_users.site_scope`: allowed sites (`["*"]` means all sites)
  - `admin_tokens.site_scope`: optional override (if omitted, inherits user scope)
  - API access to inspections/work-orders/reports/escalation/dashboard is filtered by effective site scope
- Role defaults:
  - `owner`: `*`
  - `manager`: inspections/work-orders/reports
  - `operator`: inspections/work-orders
  - `auditor`: read + report export
  - workflow-lock matrix:
    - `operator`: draft edit + submit
    - `manager`: review approve/reject
    - `owner`: approved lock
    - locked unlock: admin override only (`workflow_locks:admin`)
  - W02 tracker:
    - `manager/operator`: read + write
    - `auditor`: read
- Legacy bootstrap:
  - If `ADMIN_TOKEN` env exists, startup seeds `legacy-admin` owner token.
  - Existing `ADMIN_TOKEN` remains backward-compatible.

Quick check:

```powershell
curl -H "X-Admin-Token: <token>" "http://127.0.0.1:8001/api/auth/me"
```

Create admin user:

```powershell
curl -X POST "http://127.0.0.1:8001/api/admin/users" `
  -H "X-Admin-Token: <owner-token>" `
  -H "Content-Type: application/json" `
  -d "{\"username\":\"ops_manager\",\"display_name\":\"Ops Manager\",\"role\":\"manager\",\"permissions\":[],\"site_scope\":[\"Site A\",\"Site B\"]}"
```

Issue token for user:

```powershell
curl -X POST "http://127.0.0.1:8001/api/admin/users/2/tokens" `
  -H "X-Admin-Token: <owner-token>" `
  -H "Content-Type: application/json" `
  -d "{\"label\":\"ops-manager-main\",\"site_scope\":[\"Site A\"]}"
```

## SLA escalation automation

Manual batch:

```powershell
python -m app.jobs.sla_escalation --limit 500
python -m app.jobs.sla_escalation --dry-run
python -m app.jobs.alert_retry --limit 300 --max-attempt-count 10 --min-last-attempt-age-sec 30
python -m app.jobs.monthly_audit_archive --write-file
python -m app.jobs.ops_daily_check
```

Render cron target commands:
- `python -m app.jobs.sla_escalation --limit 500` (`*/15 * * * *`)
- `python -m app.jobs.alert_retry --limit 300 --max-attempt-count 10 --min-last-attempt-age-sec 30` (`*/10 * * * *`)
- `python -m app.jobs.monthly_audit_archive --write-file` (`5 0 1 * *`)
- `python -m app.jobs.ops_daily_check` (`15 0 * * *`)

Optional alert webhook env:
- `ALERT_WEBHOOK_URL` (sync false secret env)
- `ALERT_WEBHOOK_URLS` (comma-separated, multi-channel broadcast)
- `ALERT_WEBHOOK_TIMEOUT_SEC` (default `5`)
- `ALERT_WEBHOOK_RETRIES` (default `3`)
- `EVIDENCE_ALLOWED_CONTENT_TYPES` (comma-separated allowlist for W02 evidence upload; default: pdf/txt/csv/json/png/jpeg/webp)
- `API_RATE_LIMIT_ENABLED` (default `1`)
- `API_RATE_LIMIT_WINDOW_SEC` (default `60`)
- `API_RATE_LIMIT_MAX_PUBLIC` (default `120` requests/window per IP)
- `API_RATE_LIMIT_MAX_PUBLIC_HEAVY` (default `60`; csv/pdf/ics endpoints)
- `API_RATE_LIMIT_MAX_AUTH` (default `300` requests/window per admin token)
- `API_RATE_LIMIT_MAX_AUTH_ADMIN` (default `180`; `/api/admin/*`)
- `API_RATE_LIMIT_MAX_AUTH_WRITE` (default `120`; auth write methods)
- `API_RATE_LIMIT_MAX_AUTH_UPLOAD` (default `40`; evidence upload)
- `API_RATE_LIMIT_STORE` (`memory|redis|auto`, default `auto`)
- `API_RATE_LIMIT_REDIS_URL` (Redis URL for shared global throttling)
- `ADMIN_TOKEN_REQUIRE_EXPIRY` (default `1`)
- `ADMIN_TOKEN_MAX_TTL_DAYS` (default `30`)
- `ADMIN_TOKEN_ROTATE_AFTER_DAYS` (default `45`)
- `ADMIN_TOKEN_ROTATE_WARNING_DAYS` (default `7`)
- `ADMIN_TOKEN_MAX_IDLE_DAYS` (default `30`; auto-disable by inactivity)
- `ADMIN_TOKEN_MAX_ACTIVE_PER_USER` (default `5`)
- `EVIDENCE_STORAGE_BACKEND` (`fs|db`, default `fs`)
- `EVIDENCE_STORAGE_PATH` (default `data/evidence-objects`)
- `EVIDENCE_SCAN_MODE` (`basic|off`, default `basic`)
- `EVIDENCE_SCAN_BLOCK_SUSPICIOUS` (default `0`)
- `AUDIT_ARCHIVE_SIGNING_KEY` (HMAC key for signed monthly audit archive)

Security hardening:
- common response headers enabled (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`)
- HTML endpoints (`/`, `/web/*`, `/api/*` browser view) include CSP header
- authenticated API responses include `Cache-Control: no-store`
- W02 evidence upload blocks unsupported content types and empty files, max size 5MB
- API rate limit returns `429` with `Retry-After`, `X-RateLimit-*`, `X-RateLimit-Policy`, `X-RateLimit-Backend`
- admin token policy enforces bounded TTL, inactivity disable, rotate warning metadata, and rotate API
- W02 evidence supports file-system object storage mode (`fs`), SHA-256 integrity check, and basic malware signature scan
- admin audit logs maintain hash-chain fields (`prev_hash`, `entry_hash`) for integrity validation
- monthly audit archive endpoints provide signed JSON/CSV exports

Job monitoring:
- `GET /api/ops/job-runs?job_name=sla_escalation`
- `GET /api/ops/dashboard/summary?days=30&job_limit=10`
- `GET /api/ops/dashboard/trends?days=30`
- `GET /api/ops/runbook/checks`
- `POST /api/ops/runbook/checks/run`
- `GET /api/ops/runbook/checks/latest`
- `GET /api/ops/security/posture`
- `GET /api/ops/handover/brief?window_hours=12&due_soon_hours=6&max_items=10`
- `GET /api/ops/handover/brief/csv?window_hours=12&due_soon_hours=6&max_items=10`
- `GET /api/ops/handover/brief/pdf?window_hours=12&due_soon_hours=6&max_items=10`
- `GET /api/public/adoption-plan`
- `GET /api/public/adoption-plan/campaign`
- `GET /api/public/modules`
- `GET /web/adoption`
- `GET /web/console`
- `GET /api/public/adoption-plan/schedule.csv`
- `GET /api/public/adoption-plan/schedule.ics`
- `GET /api/public/adoption-plan/w02`
- `GET /api/public/adoption-plan/w02/checklist.csv`
- `GET /api/public/adoption-plan/w02/schedule.ics`
- `GET /api/public/post-mvp`
- `GET /api/public/post-mvp/backlog.csv`
- `GET /api/public/post-mvp/releases.ics`
- `GET /api/public/post-mvp/kpi-dashboard`
- `GET /api/public/post-mvp/risks`
- `GET /api/ops/alerts/deliveries?status=failed`
- `POST /api/ops/alerts/retries/run` (batch retry)
- `POST /api/ops/sla/simulate` (what-if simulator)

Browser rendering note:
- For `GET /api/*`, browser requests with `Accept: text/html` are automatically shown as HTML viewer pages.
- To force raw JSON in browser, append `?raw=1` (example: `/api/public/post-mvp?raw=1`).

SLA approval flow:
- `POST /api/ops/sla/simulate` to preview impact
- `POST /api/admin/policies/sla/proposals` to create pending proposal
- `POST /api/admin/policies/sla/proposals/{id}/approve` to apply policy
- `POST /api/admin/policies/sla/proposals/{id}/reject` to close without apply
- `GET /api/admin/policies/sla/revisions` to inspect change history
- `POST /api/admin/policies/sla/revisions/{id}/restore` to rollback policy snapshot
- approval safety: proposal requester cannot self-approve

SLA policy (rule engine):
- `GET /api/admin/policies/sla` (default policy)
- `GET /api/admin/policies/sla?site=SiteA` (site override; falls back to default if override is missing)
- `PUT /api/admin/policies/sla` (update default policy)
- `PUT /api/admin/policies/sla?site=SiteA` (upsert site override)
- policy fields:
  - `default_due_hours`: per-priority default due time (applied when `due_at` is omitted on work-order create)
  - `escalation_grace_minutes`: additional grace before escalation batch marks overdue work orders as escalated
- global escalation run (`site` omitted) resolves grace per work-order site

## Work-order workflow

- Status transition rules:
  - `open -> acked|completed|canceled`
  - `acked -> completed|canceled`
  - `completed -> open` (reopen)
  - `canceled -> open` (reopen)
- Timeline events are stored in `work_order_events` and can be queried via:
  - `GET /api/work-orders/{id}/events`

## Audit logs

Sensitive actions are stored in `admin_audit_logs`:
- admin user/token lifecycle
- inspection/work-order writes
- SLA escalation run
- monthly report CSV/PDF exports
- audit integrity checks and archive exports

Integrity/Archive:
- each audit row stores `prev_hash` + `entry_hash` (chain)
- `GET /api/admin/audit-integrity` verifies current month chain
- `POST /api/admin/audit-chain/rebaseline` repairs hash chain from target month (or full history)
- `GET /api/admin/audit-archive/monthly` returns signed monthly archive payload

Example:

```powershell
curl -H "X-Admin-Token: <owner-token>" "http://127.0.0.1:8001/api/admin/audit-logs?limit=50"
```

## CI and ops scripts

- CI workflow: `.github/workflows/ci.yml` (`pytest -q`)
- Deploy + smoke script:

```powershell
.\scripts\deploy_and_verify.ps1 `
  -DeployHookUrl "https://api.render.com/deploy/<serviceId>?key=<hookKey>" `
  -ServiceId "<render-service-id>" `
  -BaseUrl "https://ops.ka-part.com" `
  -AdminToken "<owner-token>" `
  -RollbackOnFailure
```

Direct smoke helper supports backend expectation and optional strict audit-chain gate:

```powershell
.\scripts\post_deploy_smoke.ps1 -BaseUrl "https://ops.ka-part.com" -AdminToken "<owner-token>" -ExpectRateLimitBackend "redis"
```

- Backup/restore rehearsal helper:

```powershell
.\scripts\backup_restore_rehearsal.ps1
```

- Redis allowlist update helper:

```powershell
.\scripts\set_redis_allowlist.ps1 `
  -RedisId "red-xxxxxxxx" `
  -Cidrs @("203.0.113.10/32","198.51.100.0/24") `
  -DescriptionPrefix "ka-facility-os"
```

## PostgreSQL mode

This app uses:
- `DATABASE_URL` set -> PostgreSQL
- `DATABASE_URL` unset -> local SQLite fallback (`data/facility.db`)

After deploy, verify:
- `GET /meta` -> `"db": "postgresql"`

## Database migrations (Alembic)

This project uses Alembic for schema migrations.

Run manually:

```powershell
alembic upgrade head
```

Startup behavior:
- app startup runs `alembic upgrade head` automatically via `ensure_database()`

## Render deploy

`render.yaml` includes:
- Web service `ka-facility-os`
- Cron service `ka-facility-os-sla-escalation`
- Cron service `ka-facility-os-alert-retry`
- Cron service `ka-facility-os-audit-archive`
- Cron service `ka-facility-os-ops-daily-check`

For safe subdomain split setup (`ops.ka-part.com`), see:
- `RENDER_SUBDOMAIN_SETUP.md`
