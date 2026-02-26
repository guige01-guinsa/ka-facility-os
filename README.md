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

- `POST /api/inspections` create one inspection
- `GET /api/inspections` list inspections
- `GET /api/inspections/{id}` get one inspection
- `GET /inspections/{id}/print` printable A4 HTML report

Example create:

```powershell
curl -X POST "http://127.0.0.1:8001/api/inspections" `
  -H "Content-Type: application/json" `
  -d "{\"site\":\"OO Apartment\",\"location\":\"Substation\",\"cycle\":\"monthly\",\"inspector\":\"Hong\",\"inspected_at\":\"2026-02-26T09:30:00\",\"voltage_r\":220,\"voltage_s\":221,\"voltage_t\":219,\"insulation_mohm\":5.2,\"notes\":\"ok\"}"
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
