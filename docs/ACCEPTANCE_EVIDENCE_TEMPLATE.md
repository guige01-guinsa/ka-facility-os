# Acceptance Evidence Template

## Metadata

- Date:
- Operator:
- Environment:
- Deploy ID:
- Commit:
- Base URL:
- Checklist Version:
- Scenario:
- Variant:

## Input

- Site:
- Location / Building / Unit:
- Month / Year:
- Organization:
- Attachment name:

## API Evidence

| Step | Endpoint | Request Key | Expected | Observed |
| --- | --- | --- | --- | --- |
| 1 |  |  |  |  |
| 2 |  |  |  |  |
| 3 |  |  |  |  |
| 4 |  |  |  |  |

## Resource IDs

- inspection_id:
- work_order_id:
- document_id:
- attachment_id:
- billing_run_id:
- billing_statement_ids:

## Report Evidence

- Integrated monthly report:
- Official document monthly report:
- Billing statements query:

## Smoke / Runbook Evidence

- `pytest -m acceptance` result:
- `pytest -m smoke` result:
- `SMOKE_OK`:
- `/api/ops/runbook/checks` overall_status:
- `/api/ops/governance/gate` decision:

## Audit / Trace Evidence

- audit action:
- resource_type:
- resource_id:
- created_at:

## Attachments

- screenshot / html / csv / pdf path:
- blob sha256:
- archive reference:

## Result

- status: pass / fail / blocked
- failure summary:
- follow-up action:
