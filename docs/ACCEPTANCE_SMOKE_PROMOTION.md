# Acceptance Smoke Promotion

## Decision Summary

| Scenario | Smoke Variant | Decision | Run Class | Reason |
| --- | --- | --- | --- | --- |
| A1 legal inspection | `A1-lite` | Promote first | privileged post-deploy smoke candidate | Broad signal across inspection, work order, SLA, integrated report, with low runtime and no binary upload dependency |
| A2 official documents | `A2-lite` | Promote second | privileged post-deploy smoke expansion candidate | Covers attachment upload and overdue automation, but adds blob write/download cost |
| A3 billing | `A3-lite` | Hold for nightly | non-blocking daily/nightly smoke candidate | Highest write volume and month-scoped billing data setup, better suited to scheduled smoke than every deploy |

## A1-lite

- Status: implemented in `scripts/post_deploy_smoke.ps1` and `tests/api/test_smoke_a1_lite.py`.
- Evidence archive: `POST /api/ops/deploy/smoke/record` now persists a JSON artifact under `DEPLOY_SMOKE_ARCHIVE_PATH/YYYY/MM`.

- Objective: verify `inspection -> linked work_order -> integrated monthly report`.
- Required endpoints:
  - `POST /api/inspections`
  - `POST /api/work-orders`
  - `PATCH /api/work-orders/{id}/ack`
  - `PATCH /api/work-orders/{id}/complete`
  - `GET /api/reports/monthly/integrated`
- Synthetic data:
  - site: `SMOKE-A1`
  - location: `B1 수변전실`
  - OPS checklist payload with `checklist_set_id=electrical_60`
- Evidence to record:
  - `inspection_id`
  - `work_order_id`
  - `priority_upgraded=true`
  - integrated report `work_orders.status_counts.completed >= 1`

## A2-lite

- Status: implemented in `scripts/post_deploy_smoke.ps1` behind `RunA2Lite`, with regression coverage in `tests/api/test_smoke_a2_lite.py`.
- Evidence archive: when smoke record is enabled, the privileged run is archived through the same deploy-smoke artifact path.

- Objective: verify `official_document -> attachment -> overdue sync -> monthly report`.
- Required endpoints:
  - `POST /api/official-documents`
  - `POST /api/official-documents/{document_id}/attachments`
  - `POST /api/official-documents/overdue/run`
  - `GET /api/reports/official-documents/monthly`
- Synthetic data:
  - site: `SMOKE-A2`
  - organization: `한전`
  - one small PDF attachment
- Evidence to record:
  - `document_id`
  - `attachment_id`
  - overdue sync `work_order_created_count` or `linked_existing_work_order_count`
  - monthly report `total_documents >= 1`

## A3-lite

- Objective: verify `meter_reading -> billing run -> statements`.
- Required endpoints:
  - `POST /api/billing/units`
  - `POST /api/billing/rate-policies`
  - `POST /api/billing/common-charges`
  - `POST /api/billing/meter-readings`
  - `POST /api/billing/runs/generate`
  - `GET /api/billing/statements`
- Synthetic data:
  - site: `SMOKE-A3`
  - billing month: current `YYYY-MM`
  - two units
- Evidence to record:
  - `run_id`
  - `statement_count=2`
  - `common_charge_total`
  - statement `unit_number` list

## Promotion Order

1. Keep `A1-lite` as the default privileged post-deploy smoke business-path check.
2. Keep `A2-lite` available as an opt-in privileged smoke expansion until attachment/evidence runtime cost is accepted.
3. Keep `A3-lite` as scheduled smoke unless deploy-time billing coverage becomes mandatory.

## Guardrails

- Use dedicated synthetic sites (`SMOKE-A1`, `SMOKE-A2`, `SMOKE-A3`) so runbook evidence remains queryable.
- Keep `RecordSmokeRun` enabled so privileged smoke artifacts are archived and reviewable without console logs.
- Reuse a single small attachment payload for `A2-lite`.
- Do not query admin audit logs in deploy-blocking smoke. Keep smoke focused on business-path success and report reflection.
- Keep acceptance tests as the full contract; smoke variants should remain lighter and faster.
