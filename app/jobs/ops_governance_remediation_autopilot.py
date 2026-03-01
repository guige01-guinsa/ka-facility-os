import argparse
import json

from app.database import ensure_database
from app.main import run_ops_governance_remediation_autopilot_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run governance remediation autopilot.")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate actions without modifying tracker state")
    parser.add_argument("--force", action="store_true", help="Run actions even if trigger thresholds are not met")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_ops_governance_remediation_autopilot_job(
        trigger="cron",
        dry_run=args.dry_run,
        force=args.force,
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
