# Acceptance Role Matrix

## Scope

- This matrix fixes the API-level role behavior for the A1/A2/A3 acceptance scenarios.
- Site scope is assumed to match the scenario site.

## A1 Legal Inspection Flow

- `owner`: inspection/work-order create-update, integrated report read/export, admin audit log read
- `manager`: inspection/work-order create-update, integrated report read/export, admin audit log denied
- `operator`: inspection/work-order create-update, integrated report denied, admin audit log denied
- `auditor`: inspection/work-order read, integrated report read/export, write denied, admin audit log denied

## A2 Official Document Flow

- `owner`: document create/attach/overdue sync/close, monthly report read/export, admin audit log read
- `manager`: document create/attach/overdue sync/close, monthly report read/export, admin audit log denied
- `operator`: document create/attach/overdue sync/close, monthly report denied, admin audit log denied
- `auditor`: document/attachment read, monthly report read/export, write denied, admin audit log denied

## A3 Billing Flow

- `owner`: billing unit/policy/common charge/meter reading/run generate, statement read, admin audit log read
- `manager`: billing unit/policy/common charge/meter reading/run generate, statement read, admin audit log denied
- `operator`: billing unit/policy/common charge/meter reading/run generate, statement read, admin audit log denied
- `auditor`: billing statement/rate-policy/meter-reading read, write denied, admin audit log denied

## Execution

```powershell
.\scripts\run_pytest.ps1 -q tests/api/test_acceptance_role_matrix.py
.\scripts\run_pytest.ps1 -q -m acceptance
```
