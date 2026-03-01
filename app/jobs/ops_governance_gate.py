import json

from app.database import ensure_database
from app.main import run_ops_governance_gate_job


def main() -> None:
    ensure_database()
    result = run_ops_governance_gate_job(trigger="cron")
    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
