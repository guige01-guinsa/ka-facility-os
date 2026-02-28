import argparse
import json

from app.database import ensure_database
from app.main import run_alert_guard_recover_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recover quarantined/warning alert channels in batch.")
    parser.add_argument("--event-type", default=None, help="Optional event_type scope for guard evaluation")
    parser.add_argument(
        "--state",
        default="quarantined",
        choices=["quarantined", "warning", "all"],
        help="Which channel states to probe",
    )
    parser.add_argument("--max-targets", type=int, default=None, help="Maximum number of targets to probe")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, no probe calls")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_alert_guard_recover_job(
        event_type=args.event_type,
        state_filter=args.state,
        max_targets=args.max_targets,
        dry_run=args.dry_run,
        trigger="cron",
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
