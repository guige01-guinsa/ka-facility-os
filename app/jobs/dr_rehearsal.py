import argparse
import json

from app.database import ensure_database
from app.main import run_dr_rehearsal_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run DR rehearsal backup/restore validation.")
    parser.add_argument("--no-restore-check", action="store_true", help="Skip restore simulation validation.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    result = run_dr_rehearsal_job(trigger="cron", simulate_restore=(not args.no_restore_check))
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
