import argparse
import json

from app.database import ensure_database
from app.main import run_ops_daily_check_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run daily ops runbook/security checks.")
    return parser.parse_args()


def main() -> None:
    parse_args()
    ensure_database()
    result = run_ops_daily_check_job(trigger="cron")
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
