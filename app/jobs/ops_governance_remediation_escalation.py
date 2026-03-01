import argparse
import json

from app.database import ensure_database
from app.main import run_ops_governance_remediation_escalation_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run governance remediation escalation job.")
    parser.add_argument("--dry-run", action="store_true", help="Only preview candidates; do not send alerts")
    parser.add_argument(
        "--include-due-soon-hours",
        type=int,
        default=None,
        help="Include open items due within this many hours (0 means overdue only)",
    )
    parser.add_argument(
        "--notify",
        choices=["auto", "on", "off"],
        default="auto",
        help="Alert notify mode: auto(env default), on, off",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    notify_enabled = None
    if args.notify == "on":
        notify_enabled = True
    elif args.notify == "off":
        notify_enabled = False
    result = run_ops_governance_remediation_escalation_job(
        trigger="cron",
        dry_run=args.dry_run,
        include_due_soon_hours=args.include_due_soon_hours,
        notify_enabled=notify_enabled,
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()

