# A1 Acceptance: Legal Inspection to Integrated Monthly Report

## Purpose

- Fix the owner happy-path for `법정점검 -> 이상조치 작업지시 -> SLA -> 감사로그 -> 월간 통합 리포트`.
- Leave role-matrix expansion for a later acceptance pass.

## Scenario

1. Create an OPS checklist inspection with abnormal findings.
2. Create a linked work order from that inspection.
3. Verify SLA automation upgraded priority and auto-filled `due_at`.
4. Acknowledge and complete the work order.
5. Verify audit logs for inspection/work-order actions.
6. Verify the monthly integrated report reflects the inspection and completed work order.

## Fixed Input

- Site: `A1 Acceptance Site`
- Location: `B1 수변전실`
- Checklist set: `electrical_60`
- Abnormal count: `3`
- Requested work-order priority: `low`
- Expected effective priority: `critical`

## Pass Criteria

- Inspection is created successfully.
- Inspection-linked work order is created with priority upgrade and automatic due date.
- Work order transitions `open -> acked -> completed`.
- Audit log contains `inspection_create`, `work_order_create`, `work_order_ack`, `work_order_complete`.
- Monthly integrated report shows at least one inspection and one completed work order for the site/month.

## Execution

```powershell
.\scripts\run_pytest.ps1 -q tests/api/test_acceptance_a1.py
.\scripts\run_pytest.ps1 -q -m acceptance
```
