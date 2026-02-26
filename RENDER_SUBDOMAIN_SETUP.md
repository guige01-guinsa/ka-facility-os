# Render Subdomain Setup (Safe Split)

This project is deployed as a separate Render web service, so the existing `ka-part` service remains unchanged.

Current service:
- Render service: `ka-facility-os`
- Default URL: `https://ka-facility-os.onrender.com`
- Health URL: `https://ka-facility-os.onrender.com/health`

Custom domain:
- `ops.ka-part.com`

## DNS record to add

Add this CNAME at your DNS provider:

- Type: `CNAME`
- Name/Host: `ops`
- Target/Value: `ka-facility-os.onrender.com`
- TTL: `Auto` (or 300)

After DNS propagation, Render will issue TLS automatically and `ops.ka-part.com` will become active.

## PostgreSQL setting

For production persistence, set service env var:

- Key: `DATABASE_URL`
- Value: Render PostgreSQL internal connection string

After setting, redeploy and verify:

- `https://ops.ka-part.com/meta` should show `"db": "postgresql"`

## Admin / RBAC setting

Bootstrap token (legacy-compatible):

- Key: `ADMIN_TOKEN`
- Value: your secret random string

Startup seeds `legacy-admin` owner token into RBAC tables.

Protected endpoints require:
- Header `X-Admin-Token: <token>`

Create additional RBAC users/tokens via API:
- `POST /api/admin/users`
- `POST /api/admin/users/{user_id}/tokens`

## SLA cron service

Create a Render Cron Job with:

- Name: `ka-facility-os-sla-escalation`
- Command: `python -m app.jobs.sla_escalation --limit 500`
- Schedule: `*/15 * * * *`
- Env var: same `DATABASE_URL` as web service

`render.yaml` already includes this cron definition.

## Monthly report export

- CSV download: `https://ops.ka-part.com/api/reports/monthly/csv?month=YYYY-MM`
- PDF download: `https://ops.ka-part.com/api/reports/monthly/pdf?month=YYYY-MM`

## Quick verification

1. Open Render dashboard for the service and check Custom Domains status.
2. Run:
   - `nslookup ops.ka-part.com`
   - `curl https://ops.ka-part.com/health`
3. Expected API response:
   - `{\"status\":\"ok\"}`
