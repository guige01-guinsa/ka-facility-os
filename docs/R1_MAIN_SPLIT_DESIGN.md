# R1 Main Split Design

Date: 2026-03-06

## Goal

Reduce `app/main.py` from a monolithic file into a bootstrap module that only:

- creates the FastAPI app
- wires routers
- keeps temporary compatibility exports for jobs

## Current Problems

- `app/main.py` mixes HTTP routes, HTML rendering, JS/CSS payloads, policy logic, DB access, and job entry points.
- `app/jobs/*` imports functions directly from `app.main`, which couples batch execution to the full web app module.
- `tests/test_api.py` is also monolithic, which makes future extraction riskier.

## Split Principles

- Keep all external API paths unchanged during R1.
- Do not change database schema or response payloads in Day 1.
- Move code by domain boundary first, then refactor internals.
- Keep `app.main` compatibility shims until jobs and tests stop importing from it.

## Target Package Tree

```text
app/
  main.py
  database.py
  schemas.py
  web/
    __init__.py
    main_tabs.py
    facility_console.py
    public_pages.py
    tutorial.py
  domains/
    __init__.py
    iam/
      __init__.py
      router_auth.py
      router_admin.py
      service.py
      security.py
    ops/
      __init__.py
      router_core.py
      router_governance.py
      router_alerts.py
      service.py
    adoption/
      __init__.py
      router_tracker.py
      router_ops.py
      service.py
    public/
      __init__.py
      router.py
      service.py
```

## Responsibility Map

- `app.main`
  - FastAPI app creation
  - middleware registration
  - router include
  - compatibility exports for batch jobs
- `app.web.main_tabs`
  - `_build_system_main_tabs_html`
  - main console CSS/JS rendering helpers
- `app.web.facility_console`
  - `_build_facility_console_html`
  - facility module browser renderer
- `app.web.public_pages`
  - `_build_public_main_page_html`
  - W04 common mistakes HTML
- `app.web.tutorial`
  - `_build_tutorial_simulator_html`
  - tutorial sample rendering
- `app.domains.iam.*`
  - `/api/auth/*`
  - `/api/admin/users*`
  - `/api/admin/tokens*`
  - `/api/admin/audit*`
  - permission and token helpers
- `app.domains.ops.*`
  - inspections, work orders, reports, workflow locks
  - dashboard, runbook, deploy smoke, DR
  - governance, remediation, alerts
- `app.domains.adoption.*`
  - W02-W15 tracker CRUD
  - adoption KPI and policy APIs
- `app.domains.public.*`
  - public adoption plan APIs
  - public modules APIs
  - public tutorial APIs

## Recommended Extraction Order

1. Move HTML builders into `app.web.*`
2. Move IAM auth/admin routes and helpers
3. Move ops core CRUD routes
4. Move governance and alerts
5. Move adoption tracker routes
6. Move public routes
7. Replace job imports from `app.main` with domain modules
8. Split API tests by domain

## Day 1 Rules

- Day 1 does not move runtime code yet.
- Day 1 creates the target package layout and documents the move order.
- Day 2 starts with `app.web.*` extraction because it is high-volume and low-risk.

## Compatibility Constraints

- `app.jobs.*` currently imports from `app.main`; those imports must keep working until the job modules are updated.
- `tests/test_api.py` assumes the current app entry point remains `app.main:app`.
- Render deployment and smoke scripts should continue to call the same service URL and APIs without changes.

## Day 1 Deliverables

- this design document
- `app/web/*` scaffold
- `app/domains/*` scaffold
- roadmap update marking R1 Day 1 as complete
