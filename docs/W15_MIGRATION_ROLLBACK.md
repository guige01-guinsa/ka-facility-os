# W15 Migration Rollback Strategy

Target migration:
- `migrations/versions/20260303_0021_adoption_w15_tracker.py`
- revision: `20260303_0021`
- down revision: `20260302_0020`

## Why this migration is forward-only

`20260303_0021` creates additive tables and indexes for W15:
- `adoption_w15_tracker_items`
- `adoption_w15_evidence_files`
- `adoption_w15_site_runs`

Because this is additive and non-breaking for previous app versions, the safest production rollback is:
1. rollback application image/version first
2. keep DB schema as-is
3. complete incident recovery

The migration `downgrade()` is intentionally no-op.

## Production rollback runbook

### 1) Immediate service recovery (recommended)
1. Deploy the previous known-good app revision.
2. Keep DB at current head (`20260303_0021`).
3. Run smoke tests:
   - `GET /health`
   - `GET /api/service-info`
   - representative read/write API checks used by your release gate.

This is safe because older app code does not require dropping W15 tables.

### 2) Optional schema rollback (only if explicitly required)

Only run this if policy/compliance requires physical schema rollback.

Prerequisites:
1. Stop writes to the service (maintenance mode).
2. Backup DB and confirm restore point.
3. Execute in a controlled window.

PostgreSQL example:

```sql
BEGIN;
DROP INDEX IF EXISTS ix_w15_evidence_storage_key;
DROP INDEX IF EXISTS ix_w15_evidence_sha256;
DROP INDEX IF EXISTS ix_w15_evidence_site_uploaded_at;
DROP INDEX IF EXISTS ix_w15_evidence_tracker_uploaded_at;
DROP INDEX IF EXISTS ix_w15_tracker_assignee;
DROP INDEX IF EXISTS ux_w15_tracker_site_type_key;
DROP INDEX IF EXISTS ix_w15_tracker_site_status;
DROP INDEX IF EXISTS ux_w15_site_runs_site;
DROP INDEX IF EXISTS ix_w15_site_runs_status;
DROP TABLE IF EXISTS adoption_w15_evidence_files;
DROP TABLE IF EXISTS adoption_w15_site_runs;
DROP TABLE IF EXISTS adoption_w15_tracker_items;
UPDATE alembic_version SET version_num = '20260302_0020';
COMMIT;
```

After rollback:
1. Start service with pre-W15 revision.
2. Run smoke + regression tests.
3. Verify no references to `/api/adoption/w15/*` and `/api/ops/adoption/w15/*` remain in active release paths.

## Safety checklist

Before any rollback:
1. capture incident timestamp, deploy id, and DB backup id
2. confirm on-call owner and approver
3. confirm blast radius (single env vs all envs)

After rollback:
1. verify API 5xx rate and latency recovery
2. verify audit logs continue to write
3. create post-incident action items before re-attempting W15 rollout
