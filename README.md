# ka-facility-os

`ka-facility-os` is an isolated FastAPI starter project for your apartment facility operations service.

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

## Inspection MVP endpoints

- `POST /api/inspections` create one inspection (admin token)
- `GET /api/inspections` list inspections
- `GET /api/inspections/{id}` get one inspection
- `GET /inspections/{id}/print` printable A4 HTML report

## Work Order endpoints

- `POST /api/work-orders` create work order (admin token)
- `GET /api/work-orders` list work orders
- `GET /api/work-orders/{id}` get work order
- `PATCH /api/work-orders/{id}/ack` acknowledge work order (admin token)
- `PATCH /api/work-orders/{id}/complete` complete work order (admin token)
- `POST /api/work-orders/escalations/run` run overdue SLA escalation (admin token)

## Audit Report endpoints

- `GET /api/reports/monthly?month=YYYY-MM&site=...` monthly audit summary (admin token)
- `GET /reports/monthly/print?month=YYYY-MM&site=...` printable monthly report (admin token)

## Admin token

- Header key: `X-Admin-Token`
- If `ADMIN_TOKEN` env var is set, protected endpoints require this header.
- If `ADMIN_TOKEN` is empty, auth is bypassed (local convenience mode).

Example create:

```powershell
curl -X POST "http://127.0.0.1:8001/api/inspections" `
  -H "X-Admin-Token: <your-admin-token>" `
  -H "Content-Type: application/json" `
  -d "{\"site\":\"OO Apartment\",\"location\":\"Substation\",\"cycle\":\"monthly\",\"inspector\":\"Hong\",\"inspected_at\":\"2026-02-26T09:30:00\",\"voltage_r\":220,\"voltage_s\":221,\"voltage_t\":219,\"insulation_mohm\":5.2,\"notes\":\"ok\"}"
```

Example work order create:

```powershell
curl -X POST "http://127.0.0.1:8001/api/work-orders" `
  -H "X-Admin-Token: <your-admin-token>" `
  -H "Content-Type: application/json" `
  -d "{\"title\":\"Pump alarm\",\"description\":\"B2 pump vibration\",\"site\":\"OO Apartment\",\"location\":\"B1 mechanical room\",\"priority\":\"high\",\"assignee\":\"Kim\",\"reporter\":\"Guard\",\"due_at\":\"2026-02-27T09:00:00+00:00\"}"
```

Example escalation run:

```powershell
curl -X POST "http://127.0.0.1:8001/api/work-orders/escalations/run" `
  -H "X-Admin-Token: <your-admin-token>" `
  -H "Content-Type: application/json" `
  -d "{\"dry_run\":false,\"limit\":500}"
```

Batch command (scheduler/cron):

```powershell
python -m app.jobs.sla_escalation --limit 500
python -m app.jobs.sla_escalation --dry-run
```

## PostgreSQL mode

This app uses:
- `DATABASE_URL` set -> PostgreSQL
- `DATABASE_URL` unset -> local SQLite fallback (`data/facility.db`)

Render production recommendation:
- Create a PostgreSQL instance in Render.
- Set service env var `DATABASE_URL` to the Render Postgres internal connection string.
- Redeploy service.

After deploy, check:
- `GET /meta` -> `"db": "postgresql"`

## 2) Git init and first commit

```powershell
git init
git branch -M main
git add .
git commit -m "chore: bootstrap ka-facility-os"
```

## 3) GitHub push

```powershell
git remote add origin https://github.com/<your-id>/<your-repo>.git
git push -u origin main
```

## 4) Render deploy

Use this repo in Render as a Web Service.

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

`render.yaml` is already included for infrastructure-as-code style deployment.

For safe subdomain split setup (`ops.ka-part.com`), see:
- `RENDER_SUBDOMAIN_SETUP.md`
