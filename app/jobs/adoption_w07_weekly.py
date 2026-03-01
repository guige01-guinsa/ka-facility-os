import argparse
import json

from app.database import ensure_database
from app.main import run_w07_sla_quality_weekly_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run W07 weekly SLA quality automation job.")
    parser.add_argument("--site", default=None, help="Optional site scope")
    parser.add_argument("--days", type=int, default=14, help="Window days for snapshot (7-90)")
    parser.add_argument("--force-notify", action="store_true", help="Bypass alert cooldown and force notify")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_w07_sla_quality_weekly_job(
        site=args.site,
        days=args.days,
        trigger="cron",
        force_notify=args.force_notify,
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()

