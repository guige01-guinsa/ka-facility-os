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

- Auth/RBAC
  - `GET /api/auth/me`
  - `GET /api/admin/users` (permission: `admins:manage`)
  - `POST /api/admin/users` (permission: `admins:manage`)
  - `PATCH /api/admin/users/{user_id}/active` (permission: `admins:manage`)
  - `POST /api/admin/users/{user_id}/tokens` (permission: `admins:manage`)
  - `GET /api/admin/tokens` (permission: `admins:manage`)
  - `POST /api/admin/tokens/{token_id}/revoke` (permission: `admins:manage`)
  - `GET /api/admin/audit-logs` (permission: `admins:manage`)
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
  - `GET /api/ops/handover/brief` (permission: `admins:manage`)
  - `GET /api/ops/alerts/deliveries` (permission: `admins:manage`)
  - `POST /api/ops/alerts/deliveries/{id}/retry` (permission: `admins:manage`)
  - `POST /api/ops/alerts/retries/run` (permission: `admins:manage`)
  - `POST /api/ops/sla/simulate` (permission: `admins:manage`)
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
```

Render cron target command:
- `python -m app.jobs.sla_escalation --limit 500`
- schedule: `*/15 * * * *`

Optional alert webhook env:
- `ALERT_WEBHOOK_URL` (sync false secret env)
- `ALERT_WEBHOOK_URLS` (comma-separated, multi-channel broadcast)
- `ALERT_WEBHOOK_TIMEOUT_SEC` (default `5`)
- `ALERT_WEBHOOK_RETRIES` (default `3`)

Job monitoring:
- `GET /api/ops/job-runs?job_name=sla_escalation`
- `GET /api/ops/dashboard/summary?days=30&job_limit=10`
- `GET /api/ops/dashboard/trends?days=30`
- `GET /api/ops/handover/brief?window_hours=12&due_soon_hours=6&max_items=10`
- `GET /api/ops/alerts/deliveries?status=failed`
- `POST /api/ops/alerts/retries/run` (batch retry)
- `POST /api/ops/sla/simulate` (what-if simulator)

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

For safe subdomain split setup (`ops.ka-part.com`), see:
- `RENDER_SUBDOMAIN_SETUP.md`
