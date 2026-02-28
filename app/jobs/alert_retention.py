import argparse
import json

from app.database import ensure_database
from app.main import run_alert_retention_job


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run alert delivery retention cleanup.")
    parser.add_argument("--retention-days", type=int, default=None, help="Retention days before deletion")
    parser.add_argument("--max-delete", type=int, default=None, help="Maximum rows to delete")
    parser.add_argument("--dry-run", action="store_true", help="Preview candidates without deletion")
    parser.add_argument("--write-archive", action="store_true", help="Write CSV archive before deletion")
    parser.add_argument("--no-archive", action="store_true", help="Disable archive write for this run")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    write_archive: bool | None = None
    if args.write_archive:
        write_archive = True
    elif args.no_archive:
        write_archive = False

    result = run_alert_retention_job(
        retention_days=args.retention_days,
        max_delete=args.max_delete,
        dry_run=args.dry_run,
        write_archive=write_archive,
        trigger="cron",
    )
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
