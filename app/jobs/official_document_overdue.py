import argparse
import json

from app.database import ensure_database
from app.main import run_official_document_overdue_sync_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run overdue official document automation.")
    parser.add_argument("--site", default=None, help="Filter by site name")
    parser.add_argument("--dry-run", action="store_true", help="Only preview overdue candidates")
    parser.add_argument("--limit", type=int, default=100, help="Max official documents to process per run")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_official_document_overdue_sync_job(
        site=args.site,
        dry_run=args.dry_run,
        limit=args.limit,
        trigger="cron",
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
