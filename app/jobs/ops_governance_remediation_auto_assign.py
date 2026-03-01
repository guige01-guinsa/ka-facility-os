import argparse
import json

from app.database import ensure_database
from app.main import run_ops_governance_remediation_auto_assign_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run governance remediation auto-assignment job.")
    parser.add_argument("--dry-run", action="store_true", help="Preview assignments without updating tracker items")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of suggestion candidates to process",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_ops_governance_remediation_auto_assign_job(
        trigger="cron",
        dry_run=args.dry_run,
        limit=args.limit,
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
