from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.database import ensure_database
from app.domains.complaints import importer, service


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import apartment painting complaint workbooks")
    parser.add_argument("--site", required=True, help="site name, for example 연산더샵")
    parser.add_argument(
        "--workbook",
        action="append",
        dest="workbooks",
        required=True,
        help="xlsx workbook path; repeat this flag for multiple files",
    )
    parser.add_argument("--apply", action="store_true", help="write complaint cases into the current database")
    parser.add_argument("--actor", default="excel-importer", help="created_by value for imported rows")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    workbook_paths = [Path(item).expanduser().resolve() for item in args.workbooks]
    for path in workbook_paths:
        if not path.exists():
            raise SystemExit(f"workbook not found: {path}")

    summary = importer.summarize_workbooks(workbook_paths, site=args.site)
    all_rows = []
    for path in workbook_paths:
        all_rows.extend(importer.iter_workbook_rows(path, site=args.site))
    deduped, duplicates = importer.dedupe_rows(all_rows)

    result = {
        "site": args.site,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "preview": summary,
        "apply_requested": bool(args.apply),
    }
    if not args.apply:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    ensure_database()
    batch_id = datetime.now(timezone.utc).strftime("paint-%Y%m%d%H%M%S")
    action_counts: dict[str, int] = {}
    for row in deduped:
        payload = row.__dict__.copy()
        payload["import_batch_id"] = batch_id
        import_result = service.import_case_row(row=payload, actor_username=args.actor)
        action = str(import_result["action"])
        action_counts[action] = action_counts.get(action, 0) + 1

    result["applied"] = {
        "import_batch_id": batch_id,
        "rows_processed": len(deduped),
        "duplicates_skipped": sum(len(items) for items in duplicates.values()),
        "action_counts": action_counts,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
