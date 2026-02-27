import argparse
import json

from app.database import ensure_database
from app.main import run_alert_retry_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retry failed/warning alert deliveries.")
    parser.add_argument("--event-type", default=None, help="Optional event_type filter")
    parser.add_argument("--status", action="append", dest="statuses", help="Status filter (repeatable)")
    parser.add_argument("--limit", type=int, default=300, help="Max deliveries to retry")
    parser.add_argument("--max-attempt-count", type=int, default=10, help="Skip rows already retried this many times")
    parser.add_argument(
        "--min-last-attempt-age-sec",
        type=int,
        default=30,
        help="Retry only deliveries older than this threshold",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_alert_retry_job(
        event_type=args.event_type,
        only_status=args.statuses or ["failed", "warning"],
        limit=args.limit,
        max_attempt_count=args.max_attempt_count,
        min_last_attempt_age_sec=args.min_last_attempt_age_sec,
        trigger="cron",
    )
    print(json.dumps(result.model_dump(), ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()

