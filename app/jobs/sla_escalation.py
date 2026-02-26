import argparse
import json

from app.database import ensure_database
from app.main import run_sla_escalation_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SLA escalation job for overdue work orders.")
    parser.add_argument("--site", default=None, help="Filter by site name")
    parser.add_argument("--dry-run", action="store_true", help="Only preview overdue candidates")
    parser.add_argument("--limit", type=int, default=500, help="Max work orders to process per run")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_sla_escalation_job(
        site=args.site,
        dry_run=args.dry_run,
        limit=args.limit,
        trigger="cron",
    )
    print(json.dumps(result.model_dump(), ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
