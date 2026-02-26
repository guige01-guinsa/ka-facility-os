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

## Admin token setting

Set protected API token:

- Key: `ADMIN_TOKEN`
- Value: your secret random string

Protected endpoints require:

- Header `X-Admin-Token: <ADMIN_TOKEN>`

## Quick verification

1. Open Render dashboard for the service and check Custom Domains status.
2. Run:
   - `nslookup ops.ka-part.com`
   - `curl https://ops.ka-part.com/health`
3. Expected API response:
   - `{\"status\":\"ok\"}`
