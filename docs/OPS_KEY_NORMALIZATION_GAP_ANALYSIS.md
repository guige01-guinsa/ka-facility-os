# OPS Key Normalization Gap Analysis

## Scope

- Focus keys: `equipment`, `equipment_location`, `qr_id`, `checklist_set_id`.
- Reviewed layers: database schema, OPS inspection validation, QR/checklist catalog loading, UI form submission, integrated reporting.

## Implementation Update (2026-03-14)

- Phase 1 snapshot persistence is now in place.
- `inspections` persists `equipment_snapshot`, `equipment_location_snapshot`, `qr_id`, `checklist_set_id`, `checklist_version`.
- `work_orders` persists `equipment_snapshot`, `equipment_location_snapshot`, `qr_id`, `checklist_set_id` when the row is linked to an inspection or derived from one.
- Existing rows are backfilled during migration from OPS note metadata when possible.
- Phase 2a relational linkage is now in place.
- `ops_equipment_assets` and `ops_qr_assets` are created through migration and backfilled from existing inspection/work-order rows.
- `inspections` and `work_orders` now persist `equipment_id` and `qr_asset_id` alongside the snapshot columns.
- `GET /api/ops/inspections/checklists/catalog` exposes `equipment_id` / `qr_asset_id`, and the web UI submits those IDs with the snapshot metadata.
- Phase 2b checklist relational master is now in place.
- `ops_checklist_sets` and `ops_checklist_set_items` are created through migration and are now used to validate `checklist_set_id` / `default_item`.
- `POST/PATCH/DELETE /api/ops/inspections/checklists/equipment-assets|sets|qr-assets` now mutate DB-backed masters first, then export the JSON catalog.
- Phase 2c lifecycle/version governance is now in place.
- `ops_equipment_assets`, `ops_qr_assets`, and `ops_checklist_sets` now persist `lifecycle_state`.
- `ops_checklist_set_revisions` now records draft/pending/approved/rejected checklist revisions, and approval applies the new live version.
- Phase 2d QR revision audit is now in place.
- `ops_qr_asset_revisions` now records QR create/update/delete and placeholder bulk-update before/after snapshots with actor/source metadata.

## Current State

### 1. `inspections` now persists OPS keys as snapshots and relational IDs

- `app/database.py`
  - `inspections` now has first-class snapshot columns for `equipment_snapshot`, `equipment_location_snapshot`, `qr_id`, `checklist_set_id`, and `checklist_version`.
  - `equipment_id` and `qr_asset_id` now complement the snapshots.
  - The row still keeps `notes` as the full evidence payload.
- `app/domains/ops/router_core.py`
  - `POST /api/inspections` validates OPS checklist payload and now persists both the relational IDs and the key snapshots alongside `risk_level` and `risk_flags`.
- `app/main.py`
  - `_validate_ops_inspection_payload` still enforces note metadata integrity before the snapshots are stored.
  - `_resolve_ops_master_asset_ids` rejects master-id / snapshot mismatches with `422`.

### 2. `work_orders` now carries inspection-derived snapshots and relational IDs

- `app/database.py`
  - `work_orders` now stores `equipment_id`, `qr_asset_id`, `equipment_snapshot`, `equipment_location_snapshot`, `qr_id`, and `checklist_set_id`.
- `app/domains/ops/router_core.py`
  - `POST /api/work-orders` can derive SLA context from `inspection_id`.
  - The same inspection linkage now copies the OPS key snapshots and relational IDs into the work-order row.

### 3. QR assets and checklist sets now have relational masters

- `app/main.py`
  - `_load_ops_special_checklists_payload` still reads the JSON file as bootstrap input, but runtime catalog reads now rebuild from DB-backed checklist/equipment/QR masters.
  - `ops_checklist_sets` / `ops_checklist_set_items` now anchor `checklist_set_id` and item membership.
  - `ops_equipment_assets` / `ops_qr_assets` still back the relational equipment/QR lookup.
  - `_resolve_ops_master_asset_ids` now rejects retired/replaced equipment, QR assets, and checklist sets for new inspections.
- `app/domains/ops/router_governance.py`
  - `POST/PATCH/DELETE /api/ops/inspections/checklists/equipment-assets`
  - `POST/PATCH/DELETE /api/ops/inspections/checklists/sets`
  - `POST/PATCH/DELETE /api/ops/inspections/checklists/qr-assets`
  - `GET /api/ops/inspections/checklists/qr-assets/revisions`
  - `GET/POST /api/ops/inspections/checklists/revisions`
  - `POST /api/ops/inspections/checklists/revisions/{id}/submit|approve|reject`
  - Write paths now mutate DB masters, persist QR revision rows where applicable, and then export `data/apartment_facility_special_checklists.json`.

### 4. UI auto-fill now posts `master id + snapshot`, and master CRUD is available in-console

- `app/web/main_tabs.py`
  - Equipment master selection now fills inspection equipment/location even without QR selection.
  - QR selection fills `equipment`, `location`, and default item on the inspection form.
  - Checklist set selection fills `task_type`.
  - Final submission now sends `equipment_id`, `qr_asset_id`, and the snapshot text together.
  - The same tab now exposes `OPS 마스터 관리` for equipment / checklist set / QR CRUD.

### 5. Reports aggregate by `site` and time, not by normalized equipment identity

- `app/domains/ops/router_official_documents.py`
  - Integrated monthly reporting merges OPS inspections, work orders, official documents, and utility billing.
  - The join axis is effectively `site + period`.
- Result:
  - The system can answer "what happened this month at site X?"
  - It cannot reliably answer "show all inspections/work orders/documents for QR asset Y" without reparsing text or note blobs.

## Concrete Gaps

| Gap | Current behavior | Operational risk |
| --- | --- | --- |
| `equipment_snapshot` is still free text | history is preserved and now paired with `equipment_id`, but legacy/manual payloads can still drift | reports need to decide whether to trust master or snapshot in renamed-equipment cases |
| `equipment_location_snapshot` still overlaps `inspections.location` | snapshot value is now queryable, but semantics are still duplicated | location meaning can diverge without a master model |
| `qr_id` and `qr_asset_id` coexist | relational lookup, CRUD, lifecycle state, revision history, and integrated report asset scope now exist | `qr_id` is still a readable snapshot while `qr_asset_id` is the true join key, so downstream exports need to stay explicit about which one they trust |
| `checklist_set_id` and checklist master coexist | relational master, revision approval, and release-note rules now exist | downstream report/export consumers still treat checklist version as metadata, not as a pivot key |
| checklist/QR catalog still exports to JSON | DB-backed masters are now the write path, but file export remains for bootstrap/backup compatibility | revision/audit semantics are weaker than a pure DB-only model |
| QR revision history is still partly domain-local | `ops_qr_asset_revisions` persists before/after + actor/source, and monthly archive now attaches a summary/sample | integrated reports can pivot by asset scope now, but revision rows are still attachment/evidence data rather than first-class report inputs |

## Recommended Target Model

### Phase 1. Persist the keys without breaking current payloads

- Completed:
  - `inspections.equipment_snapshot`
  - `inspections.equipment_location_snapshot`
  - `inspections.qr_id`
  - `inspections.checklist_set_id`
  - `inspections.checklist_version`
  - `work_orders.equipment_snapshot`
  - `work_orders.equipment_location_snapshot`
  - `work_orders.qr_id`
  - `work_orders.checklist_set_id`
- `notes` remains the human-readable evidence bundle, but it is no longer the only place where the key material survives.

### Phase 2. Introduce relational masters

- Completed first cut:
  - `ops_equipment_assets`
    - `id`
    - `equipment_key`
    - `equipment_name`
    - `location_name`
  - `ops_qr_assets`
    - `id`
    - `qr_id`
    - `equipment_id`
    - `equipment_snapshot`
    - `equipment_location_snapshot`
    - `default_item`
    - `checklist_set_id`
- Add `ops_checklist_sets`
  - `set_id`
  - `task_type`
  - `label`
  - `source`
- Add `ops_checklist_set_items`
  - `set_id`
  - `seq`
  - `item_text`
- Remaining:
  - billing behavior under asset-scoped reporting
  - reduced dependency on JSON bootstrap/export
  - wider reuse of QR revision rows in audit/export/report surfaces

### Phase 3. Extend downstream linkage

- Rebuild downstream reporting and document/billing linkage on top of the already-persisted `equipment_id`, `qr_asset_id`, and `checklist_set_id`.
- When an official document or billing artifact is derived from a work order or inspection, store the upstream reference explicitly instead of relying on `site` only.

## Migration Strategy

1. Add nullable columns first and backfill from existing inspection note payloads.
2. Update create endpoints so the server persists normalized key snapshots whenever note metadata is present.
3. Switch UI submission from "free text only" to "master id + snapshot text".
4. Keep the JSON export/import path only as a bootstrap or backup format.
5. Add lifecycle and approval rules on top of the DB-backed CRUD path.
   - Completed first cut on 2026-03-14.

## Priority Recommendation

1. Decide the billing rule for asset-scoped integrated reports now that `equipment_id` / `qr_asset_id` pivoting exists for OPS and official-document sections.
2. Extend official-document and billing linkage beyond `site`.
3. Reuse `ops_qr_asset_revisions` in integrated report and audit-chain analytics so QR catalog changes are not trapped inside OPS-only views.
