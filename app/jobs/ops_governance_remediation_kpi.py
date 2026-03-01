import argparse
import json

from app.database import ensure_database
from app.main import run_ops_governance_remediation_kpi_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run governance remediation KPI snapshot job.")
    parser.add_argument("--window-days", type=int, default=None, help="Backlog trend window (days)")
    parser.add_argument("--due-soon-hours", type=int, default=None, help="Due-soon threshold (hours)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_ops_governance_remediation_kpi_job(
        trigger="cron",
        window_days=args.window_days,
        due_soon_hours=args.due_soon_hours,
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
