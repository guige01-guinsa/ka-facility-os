import argparse
import json

from app.database import ensure_database
from app.main import run_alert_mttr_slo_check_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run MTTR SLO check and automation actions.")
    parser.add_argument("--event-type", default=None, help="Optional event_type scope for MTTR evaluation")
    parser.add_argument("--force-notify", action="store_true", help="Bypass notify cooldown")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_alert_mttr_slo_check_job(
        event_type=args.event_type,
        force_notify=args.force_notify,
        trigger="cron",
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
