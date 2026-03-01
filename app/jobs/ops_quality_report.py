import argparse
import json

from app.database import ensure_database
from app.main import run_ops_quality_report_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ops quality report automation.")
    parser.add_argument("--window", choices=["weekly", "monthly"], default="weekly")
    parser.add_argument("--month", default=None, help="YYYY-MM (monthly only)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_ops_quality_report_job(window=args.window, month=args.month, trigger="cron")
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
