# Acceptance Key Linkage Table

## Core Rule

- `site` is the only key family shared across A1, A2, and A3 as a durable partition key.
- `inspection_id`, `work_order_id`, `document_id`, `run_id`, `reading_id` are durable relational IDs inside each domain.
- `equipment`, `equipment_location`, `checklist_set_id`, `qr_id` now survive as inspection/work-order snapshots.
- `equipment_id` / `qr_asset_id` now complement those snapshots through `ops_equipment_assets` / `ops_qr_assets`, and CRUD UI/API is available.
- `checklist_set_id` is now backed by `ops_checklist_sets` / `ops_checklist_set_items`, and revision approval is recorded in `ops_checklist_set_revisions`.
- QR catalog changes now persist before/after rows in `ops_qr_asset_revisions`.

## Current Linkage

| Key Family | Canonical Form | Current Source of Truth | Persisted In | Used By | Coverage | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| site | free-text string | API payload and every domain row | inspections, work_orders, official_documents, billing tables | all A1/A2/A3 flows | strong | no dedicated site master table |
| inspection_id | integer PK | `inspections.id` | inspections, work_orders.inspection_id, official_documents.linked_inspection_id | A1, A2 | strong | no reverse foreign key enforcement at DB level |
| work_order_id | integer PK | `work_orders.id` | work_orders, official_documents.linked_work_order_id | A1, A2 | strong | no shared business key beyond numeric ID |
| document_id | integer PK | `official_documents.id` | official_documents, official_document_attachments.document_id | A2 | strong | not linked to billing or QR domain |
| registry_number | `ORG-SITE-YYYY-NNNN` | official document create logic | official_documents.registry_number | A2 reporting/export | medium | organization/site text changes can shift business readability |
| building + unit_number | free-text pair | billing unit create payload | utility_billing_units, utility_meter_readings, utility_billing_statements | A3 | strong in billing | not linked to inspections or work orders |
| billing_month | `YYYY-MM` | billing payload | utility_common_charges, utility_meter_readings, utility_billing_runs, utility_billing_statements | A3, integrated report billing section | strong | no cross-domain time-key standard beyond shared month label |
| policy_id | integer PK | `utility_rate_policies.id` | utility_billing_runs.policy_id, utility_billing_statements.policy_id | A3 | strong | isolated to billing domain |
| reading_id | integer PK | `utility_meter_readings.id` | utility_billing_statements.reading_id | A3 | strong | isolated to billing domain |
| checklist_set_id | string | `ops_checklist_sets.set_id` | inspections.checklist_set_id, work_orders.checklist_set_id, ops_qr_assets.checklist_set_id, ops_checklist_set_items.set_id, ops_checklist_set_revisions.set_id | A1 parsing/validation | medium | lifecycle/version are now modeled, but diff/release search is still basic |
| equipment_id | integer PK | `ops_equipment_assets.id` | inspections.equipment_id, work_orders.equipment_id, ops_qr_assets.equipment_id | A1 inspection/work-order linkage | medium | lifecycle state now exists, but search/filter policy is still basic |
| equipment | free-text string | OPS checklist payload / QR asset JSON | inspections.equipment_snapshot, work_orders.equipment_snapshot, ops_qr_assets.equipment_snapshot | A1 operator input / audit rendering | medium | snapshot still coexists with master and can drift in legacy/manual payloads |
| equipment_location | free-text string | OPS checklist payload | inspections.equipment_location_snapshot, work_orders.equipment_location_snapshot | A1 operator input | medium | still overlaps `inspections.location` semantics |
| qr_asset_id | integer PK | `ops_qr_assets.id` | inspections.qr_asset_id, work_orders.qr_asset_id | A1 inspection/work-order linkage | medium | lifecycle state now exists, but search/filter policy is still basic |
| qr_id | string | `ops_qr_assets.qr_id` | inspections.qr_id, work_orders.qr_id, ops_qr_assets.qr_id, ops_qr_asset_revisions.qr_id | QR placeholder/bulk-update tooling, QR revision review, monthly archive attachment | medium | integrated reports now pivot on `qr_asset_id`, but `qr_id` itself remains a readable snapshot rather than the canonical join key |

## Scenario Chains

### A1

1. `site + location + inspected_at` create an inspection row.
2. `inspection_id` links the follow-up work order.
3. `site + month` drives the default integrated report aggregation, and `equipment_id` / `qr_asset_id` can optionally narrow the OPS/document sections.

### A2

1. `site + document_id` identify the official document.
2. `document_id` links attachments.
3. `linked_inspection_id` and `linked_work_order_id` bridge document history into A1 entities.
4. `site + month` drives official-document monthly reporting.

### A3

1. `site + building + unit_number` identify the billing unit.
2. `site + utility_type + reading_month + building + unit_number` identify a meter reading.
3. `run_id`, `policy_id`, and `reading_id` build billing statements.
4. `site + billing_month` feeds the integrated billing section.

## Priority Gaps

1. Define a shared site master so `site` is not just repeated free text.
2. Decide how billing should behave under `equipment_id` / `qr_asset_id` asset scope, because the current integrated report deliberately excludes billing there.
3. Decide whether billing units need linkage to work orders or official documents for resident-facing traceability.
4. Reuse QR revision history in integrated reports and admin audit-chain analytics so catalog changes become first-class cross-domain evidence.
5. Use `docs/OPS_KEY_NORMALIZATION_GAP_ANALYSIS.md` as the code-level migration plan for the next normalization phase.
