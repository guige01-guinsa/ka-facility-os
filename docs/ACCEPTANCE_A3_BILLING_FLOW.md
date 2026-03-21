# A3 Acceptance: Meter Reading to Billing Statements

## Purpose

- Fix the owner happy-path for `검침 -> 공용요금 배부 -> 청구 생성 -> 청구 조회`.
- Leave role-matrix expansion for a later acceptance pass.

## Scenario

1. Register billing units and rate policy for the target month.
2. Record common charges and meter readings.
3. Generate the billing run.
4. Query billing statements for the same site/month/utility type.
5. Verify the generated statements reflect common-charge allocation and audit logging.

## Fixed Input

- Site: `A3 Billing Site`
- Utility type: `electricity`
- Billing month: runtime current month (`YYYY-MM`)
- Units: `1001호`, `1002호`

## Pass Criteria

- Meter readings are saved successfully.
- Common charges are allocated into generated billing statements.
- Billing statements are queryable for the same site/month.
- Audit log contains `billing_rate_policy_create`, `billing_meter_reading_create`, `billing_common_charge_create`, `billing_run_generate`.
- Statement totals and common-fee allocation are internally consistent.

## Execution

```powershell
.\scripts\run_pytest.ps1 -q tests/api/test_acceptance_a3.py
.\scripts\run_pytest.ps1 -q -m acceptance
```
