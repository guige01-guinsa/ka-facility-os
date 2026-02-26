# Render Subdomain Setup (Safe Split)

This project is deployed as a separate Render web service, so the existing `ka-part` service remains unchanged.

Current service:
- Render service: `ka-facility-os`
- Default URL: `https://ka-facility-os.onrender.com`
- Health URL: `https://ka-facility-os.onrender.com/health`

Custom domain already added in Render:
- `ops.ka-part.com` (verification pending)

## DNS record to add

Add this CNAME at your DNS provider:

- Type: `CNAME`
- Name/Host: `ops`
- Target/Value: `ka-facility-os.onrender.com`
- TTL: `Auto` (or 300)

After DNS propagation, Render will issue TLS automatically and `ops.ka-part.com` will become active.

## Quick verification

1. Open Render dashboard for the service and check Custom Domains status.
2. Run:
   - `nslookup ops.ka-part.com`
   - `curl https://ops.ka-part.com/health`
3. Expected API response:
   - `{\"status\":\"ok\"}`
