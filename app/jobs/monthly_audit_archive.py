import argparse
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from app.database import ensure_database
from app.main import build_monthly_audit_archive


def _default_target_month() -> str:
    today = datetime.now(timezone.utc).date()
    first_day_this_month = today.replace(day=1)
    prev_day = first_day_this_month - timedelta(days=1)
    return f"{prev_day.year:04d}-{prev_day.month:02d}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build signed monthly admin audit archive.")
    parser.add_argument("--month", default=None, help="Target month in YYYY-MM (default: previous month)")
    parser.add_argument("--max-entries", type=int, default=10000, help="Maximum number of entries to include")
    parser.add_argument("--output-dir", default="data/audit-archives", help="Directory for archive artifacts")
    parser.add_argument("--write-file", action="store_true", help="Write archive JSON file to output dir")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_database()
    month = args.month or _default_target_month()
    archive = build_monthly_audit_archive(
        month=month,
        max_entries=max(1, int(args.max_entries)),
        include_entries=True,
    )
    if args.write_file:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"audit-archive-{archive['month']}.json"
        output_file.write_text(json.dumps(archive, ensure_ascii=False, indent=2), encoding="utf-8")
        archive["output_file"] = str(output_file)
    print(json.dumps(archive, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()

