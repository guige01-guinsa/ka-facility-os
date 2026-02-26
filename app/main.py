from datetime import datetime, timezone
from os import getenv
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Header, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import insert, select, update

from app.database import DATABASE_URL, ensure_database, get_conn, inspections, work_orders
from app.schemas import (
    InspectionCreate,
    InspectionRead,
    MonthlyReportRead,
    SlaEscalationRunRequest,
    SlaEscalationRunResponse,
    WorkOrderAck,
    WorkOrderComplete,
    WorkOrderCreate,
    WorkOrderRead,
)

app = FastAPI(
    title="KA Facility OS",
    description="Inspection MVP for apartment facility operations",
    version="0.4.0",
)

ADMIN_TOKEN = getenv("ADMIN_TOKEN", "")


@app.on_event("startup")
def on_startup() -> None:
    ensure_database()


def _calculate_risk(payload: InspectionCreate) -> tuple[str, list[str]]:
    flags: list[str] = []

    if payload.insulation_mohm is not None and payload.insulation_mohm <= 1:
        flags.append("insulation_low")
    if payload.winding_temp_c is not None and payload.winding_temp_c >= 90:
        flags.append("temp_high")

    volts = [payload.voltage_r, payload.voltage_s, payload.voltage_t]
    if all(v is not None for v in volts):
        values = [float(v) for v in volts]
        avg = sum(values) / 3
        if avg > 0:
            max_unbalance = max(abs(v - avg) / avg * 100 for v in values)
            if max_unbalance > 3:
                flags.append("voltage_unbalance")

    if "insulation_low" in flags or "temp_high" in flags:
        return "danger", flags
    if flags:
        return "warning", flags
    return "normal", flags


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    raise ValueError("Unsupported datetime value")


def _as_optional_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    return _as_datetime(value)


def _row_to_read_model(row: dict[str, Any]) -> InspectionRead:
    risk_flags_raw = row["risk_flags"] or ""
    risk_flags = [x for x in risk_flags_raw.split(",") if x]

    return InspectionRead(
        id=row["id"],
        site=row["site"],
        location=row["location"],
        cycle=row["cycle"],
        inspector=row["inspector"],
        inspected_at=_as_datetime(row["inspected_at"]),
        transformer_kva=row["transformer_kva"],
        voltage_r=row["voltage_r"],
        voltage_s=row["voltage_s"],
        voltage_t=row["voltage_t"],
        current_r=row["current_r"],
        current_s=row["current_s"],
        current_t=row["current_t"],
        winding_temp_c=row["winding_temp_c"],
        grounding_ohm=row["grounding_ohm"],
        insulation_mohm=row["insulation_mohm"],
        notes=row["notes"],
        risk_level=row["risk_level"],
        risk_flags=risk_flags,
        created_at=_as_datetime(row["created_at"]),
    )


def _is_overdue(status: str, due_at: datetime | None) -> bool:
    if due_at is None:
        return False
    if status in {"completed", "canceled"}:
        return False
    return due_at < datetime.now(timezone.utc)


def _month_window(month: str | None) -> tuple[datetime, datetime, str]:
    if month is None:
        now = datetime.now(timezone.utc)
        normalized = f"{now.year:04d}-{now.month:02d}"
    else:
        normalized = month

    try:
        year, month_num = normalized.split("-")
        start = datetime(int(year), int(month_num), 1, tzinfo=timezone.utc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="month must be YYYY-MM format") from exc

    if start.month == 12:
        end = datetime(start.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(start.year, start.month + 1, 1, tzinfo=timezone.utc)
    return start, end, normalized


def require_admin_token(
    x_admin_token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
) -> None:
    # Token is enforced only when ADMIN_TOKEN is configured.
    if not ADMIN_TOKEN:
        return
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")


def _row_to_work_order_model(row: dict[str, Any]) -> WorkOrderRead:
    due_at = _as_optional_datetime(row["due_at"])
    status = row["status"]
    return WorkOrderRead(
        id=row["id"],
        title=row["title"],
        description=row["description"] or "",
        site=row["site"],
        location=row["location"],
        priority=row["priority"],
        status=status,
        assignee=row["assignee"],
        reporter=row["reporter"],
        inspection_id=row["inspection_id"],
        due_at=due_at,
        acknowledged_at=_as_optional_datetime(row["acknowledged_at"]),
        completed_at=_as_optional_datetime(row["completed_at"]),
        resolution_notes=row["resolution_notes"] or "",
        is_escalated=bool(row["is_escalated"]),
        is_overdue=_is_overdue(status, due_at),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def run_sla_escalation_job(
    *,
    site: str | None = None,
    dry_run: bool = False,
    limit: int = 200,
) -> SlaEscalationRunResponse:
    now = datetime.now(timezone.utc)
    stmt = (
        select(work_orders)
        .where(work_orders.c.due_at.is_not(None))
        .where(work_orders.c.due_at < now)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.is_escalated.is_(False))
        .order_by(work_orders.c.due_at.asc())
        .limit(limit)
    )
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
        ids = [int(r["id"]) for r in rows]
        escalated_count = 0
        if ids and not dry_run:
            conn.execute(
                update(work_orders)
                .where(work_orders.c.id.in_(ids))
                .values(is_escalated=True, updated_at=now)
            )
            escalated_count = len(ids)

    return SlaEscalationRunResponse(
        checked_at=now,
        dry_run=dry_run,
        site=site,
        candidate_count=len(ids),
        escalated_count=escalated_count,
        work_order_ids=ids,
    )


def build_monthly_report(month: str | None, site: str | None) -> MonthlyReportRead:
    start, end, month_label = _month_window(month)
    now = datetime.now(timezone.utc)

    inspections_stmt = (
        select(inspections)
        .where(inspections.c.inspected_at >= start)
        .where(inspections.c.inspected_at < end)
    )
    work_orders_stmt = (
        select(work_orders)
        .where(work_orders.c.created_at >= start)
        .where(work_orders.c.created_at < end)
    )
    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site == site)

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()

    risk_counts = {"normal": 0, "warning": 0, "danger": 0}
    flag_counts: dict[str, int] = {}
    for row in inspection_rows:
        risk_level = row["risk_level"] or "normal"
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        flags = (row["risk_flags"] or "").split(",")
        for flag in flags:
            if not flag:
                continue
            flag_counts[flag] = flag_counts.get(flag, 0) + 1

    status_counts = {"open": 0, "acked": 0, "completed": 0, "canceled": 0}
    escalated_count = 0
    overdue_open_count = 0
    resolution_hours: list[float] = []
    for row in work_order_rows:
        status = row["status"] or "open"
        status_counts[status] = status_counts.get(status, 0) + 1
        if row["is_escalated"]:
            escalated_count += 1

        due_at = _as_optional_datetime(row["due_at"])
        if due_at is not None and status not in {"completed", "canceled"} and due_at < now:
            overdue_open_count += 1

        created_at = _as_optional_datetime(row["created_at"])
        completed_at = _as_optional_datetime(row["completed_at"])
        if created_at is not None and completed_at is not None:
            hours = (completed_at - created_at).total_seconds() / 3600
            if hours >= 0:
                resolution_hours.append(hours)

    total_work_orders = len(work_order_rows)
    completed_count = status_counts.get("completed", 0)
    completion_rate = round((completed_count / total_work_orders * 100), 2) if total_work_orders else 0.0
    avg_resolution_hours = round(sum(resolution_hours) / len(resolution_hours), 2) if resolution_hours else None

    return MonthlyReportRead(
        month=month_label,
        site=site,
        generated_at=now,
        inspections={
            "total": len(inspection_rows),
            "risk_counts": risk_counts,
            "top_risk_flags": dict(sorted(flag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        },
        work_orders={
            "total": total_work_orders,
            "status_counts": status_counts,
            "escalated_count": escalated_count,
            "overdue_open_count": overdue_open_count,
            "completion_rate_percent": completion_rate,
            "avg_resolution_hours": avg_resolution_hours,
        },
    )


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "ka-facility-os",
        "status": "running",
        "docs": "/docs",
        "inspection_api": "/api/inspections",
        "work_order_api": "/api/work-orders",
        "escalation_api": "/api/work-orders/escalations/run",
        "monthly_report_api": "/api/reports/monthly",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/meta")
def meta() -> dict[str, str]:
    db_backend = "postgresql" if DATABASE_URL.startswith("postgresql+") else "sqlite"
    return {"env": getenv("ENV", "local"), "db": db_backend}


@app.post("/api/inspections", response_model=InspectionRead, status_code=201)
def create_inspection(
    payload: InspectionCreate,
    _: None = Depends(require_admin_token),
) -> InspectionRead:
    risk_level, flags = _calculate_risk(payload)
    now = datetime.now(timezone.utc)
    inspected_at = _to_utc(payload.inspected_at)

    with get_conn() as conn:
        result = conn.execute(
            insert(inspections).values(
                site=payload.site,
                location=payload.location,
                cycle=payload.cycle,
                inspector=payload.inspector,
                inspected_at=inspected_at,
                transformer_kva=payload.transformer_kva,
                voltage_r=payload.voltage_r,
                voltage_s=payload.voltage_s,
                voltage_t=payload.voltage_t,
                current_r=payload.current_r,
                current_s=payload.current_s,
                current_t=payload.current_t,
                winding_temp_c=payload.winding_temp_c,
                grounding_ohm=payload.grounding_ohm,
                insulation_mohm=payload.insulation_mohm,
                notes=payload.notes,
                risk_level=risk_level,
                risk_flags=",".join(flags),
                created_at=now,
            )
        )
        inspection_id = result.inserted_primary_key[0]
        if inspection_id is None:
            raise HTTPException(status_code=500, detail="Failed to create inspection")

        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=500, detail="Failed to load created inspection")

    return _row_to_read_model(row)


@app.get("/api/inspections", response_model=list[InspectionRead])
def list_inspections(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[InspectionRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(inspections)
            .order_by(inspections.c.inspected_at.desc(), inspections.c.id.desc())
            .limit(limit)
            .offset(offset)
        ).mappings().all()
    return [_row_to_read_model(r) for r in rows]


@app.get("/api/inspections/{inspection_id}", response_model=InspectionRead)
def get_inspection(inspection_id: int) -> InspectionRead:
    with get_conn() as conn:
        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection not found")
    return _row_to_read_model(row)


@app.get("/inspections/{inspection_id}/print", response_class=HTMLResponse)
def print_inspection(inspection_id: int) -> str:
    with get_conn() as conn:
        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection not found")

    data = _row_to_read_model(row)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Inspection #{data.id}</title>
  <style>
    @page {{ size: A4; margin: 12mm; }}
    body {{ font-family: Arial, sans-serif; color: #111; }}
    h1 {{ margin-bottom: 10px; font-size: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ border: 1px solid #ddd; padding: 6px; font-size: 13px; }}
    .k {{ width: 30%; background: #f7f7f7; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Inspection Report #{data.id}</h1>
  <table>
    <tr><td class="k">Site</td><td>{data.site}</td></tr>
    <tr><td class="k">Location</td><td>{data.location}</td></tr>
    <tr><td class="k">Cycle</td><td>{data.cycle}</td></tr>
    <tr><td class="k">Inspector</td><td>{data.inspector}</td></tr>
    <tr><td class="k">Inspected At</td><td>{data.inspected_at.isoformat()}</td></tr>
    <tr><td class="k">Risk Level</td><td>{data.risk_level}</td></tr>
    <tr><td class="k">Risk Flags</td><td>{", ".join(data.risk_flags) or "-"}</td></tr>
    <tr><td class="k">Transformer (kVA)</td><td>{data.transformer_kva or "-"}</td></tr>
    <tr><td class="k">Voltage (R/S/T)</td><td>{data.voltage_r or "-"} / {data.voltage_s or "-"} / {data.voltage_t or "-"}</td></tr>
    <tr><td class="k">Current (R/S/T)</td><td>{data.current_r or "-"} / {data.current_s or "-"} / {data.current_t or "-"}</td></tr>
    <tr><td class="k">Winding Temp (C)</td><td>{data.winding_temp_c or "-"}</td></tr>
    <tr><td class="k">Grounding (ohm)</td><td>{data.grounding_ohm or "-"}</td></tr>
    <tr><td class="k">Insulation (Mohm)</td><td>{data.insulation_mohm or "-"}</td></tr>
    <tr><td class="k">Notes</td><td>{data.notes or "-"}</td></tr>
    <tr><td class="k">Created At</td><td>{data.created_at.isoformat()}</td></tr>
  </table>
</body>
</html>
"""


@app.post("/api/work-orders", response_model=WorkOrderRead, status_code=201)
def create_work_order(
    payload: WorkOrderCreate,
    _: None = Depends(require_admin_token),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    due_at = _as_optional_datetime(payload.due_at)

    with get_conn() as conn:
        result = conn.execute(
            insert(work_orders).values(
                title=payload.title,
                description=payload.description,
                site=payload.site,
                location=payload.location,
                priority=payload.priority,
                status="open",
                assignee=payload.assignee,
                reporter=payload.reporter,
                inspection_id=payload.inspection_id,
                due_at=due_at,
                acknowledged_at=None,
                completed_at=None,
                resolution_notes="",
                is_escalated=False,
                created_at=now,
                updated_at=now,
            )
        )
        work_order_id = result.inserted_primary_key[0]
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create work order")
    return _row_to_work_order_model(row)


@app.get("/api/work-orders", response_model=list[WorkOrderRead])
def list_work_orders(
    status: Annotated[str | None, Query()] = None,
    site: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[WorkOrderRead]:
    stmt = select(work_orders)
    if status is not None:
        stmt = stmt.where(work_orders.c.status == status)
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)

    stmt = stmt.order_by(work_orders.c.created_at.desc(), work_orders.c.id.desc()).limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_work_order_model(r) for r in rows]


@app.get("/api/work-orders/{work_order_id}", response_model=WorkOrderRead)
def get_work_order(work_order_id: int) -> WorkOrderRead:
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Work order not found")
    return _row_to_work_order_model(row)


@app.patch("/api/work-orders/{work_order_id}/ack", response_model=WorkOrderRead)
def ack_work_order(
    work_order_id: int,
    payload: WorkOrderAck,
    _: None = Depends(require_admin_token),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        if row["status"] == "completed":
            raise HTTPException(status_code=409, detail="Completed work order cannot be acked")

        assignee = payload.assignee if payload.assignee is not None else row["assignee"]
        conn.execute(
            update(work_orders)
            .where(work_orders.c.id == work_order_id)
            .values(
                status="acked",
                assignee=assignee,
                acknowledged_at=now,
                updated_at=now,
            )
        )
        updated_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to update work order")
    return _row_to_work_order_model(updated_row)


@app.patch("/api/work-orders/{work_order_id}/complete", response_model=WorkOrderRead)
def complete_work_order(
    work_order_id: int,
    payload: WorkOrderComplete,
    _: None = Depends(require_admin_token),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        if row["status"] == "completed":
            return _row_to_work_order_model(row)

        conn.execute(
            update(work_orders)
            .where(work_orders.c.id == work_order_id)
            .values(
                status="completed",
                completed_at=now,
                resolution_notes=payload.resolution_notes,
                updated_at=now,
            )
        )
        updated_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to complete work order")
    return _row_to_work_order_model(updated_row)


@app.post("/api/work-orders/escalations/run", response_model=SlaEscalationRunResponse)
def run_sla_escalation(
    payload: SlaEscalationRunRequest,
    _: None = Depends(require_admin_token),
) -> SlaEscalationRunResponse:
    return run_sla_escalation_job(
        site=payload.site,
        dry_run=payload.dry_run,
        limit=payload.limit,
    )


@app.get("/api/reports/monthly", response_model=MonthlyReportRead)
def get_monthly_report(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    _: None = Depends(require_admin_token),
) -> MonthlyReportRead:
    return build_monthly_report(month=month, site=site)


@app.get("/reports/monthly/print", response_class=HTMLResponse)
def print_monthly_report(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    _: None = Depends(require_admin_token),
) -> str:
    report = build_monthly_report(month=month, site=site)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Monthly Audit Report {report.month}</title>
  <style>
    @page {{ size: A4; margin: 12mm; }}
    body {{ font-family: Arial, sans-serif; color: #111; }}
    h1 {{ margin-bottom: 8px; font-size: 20px; }}
    h2 {{ margin-top: 14px; margin-bottom: 6px; font-size: 16px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 8px; }}
    td {{ border: 1px solid #ddd; padding: 6px; font-size: 13px; }}
    .k {{ width: 40%; background: #f7f7f7; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Monthly Audit Report ({report.month})</h1>
  <table>
    <tr><td class="k">Site</td><td>{report.site or "ALL"}</td></tr>
    <tr><td class="k">Generated At</td><td>{report.generated_at.isoformat()}</td></tr>
  </table>
  <h2>Inspection Summary</h2>
  <table>
    <tr><td class="k">Total</td><td>{report.inspections["total"]}</td></tr>
    <tr><td class="k">Risk Counts</td><td>{report.inspections["risk_counts"]}</td></tr>
    <tr><td class="k">Top Risk Flags</td><td>{report.inspections["top_risk_flags"]}</td></tr>
  </table>
  <h2>Work Order Summary</h2>
  <table>
    <tr><td class="k">Total</td><td>{report.work_orders["total"]}</td></tr>
    <tr><td class="k">Status Counts</td><td>{report.work_orders["status_counts"]}</td></tr>
    <tr><td class="k">Escalated Count</td><td>{report.work_orders["escalated_count"]}</td></tr>
    <tr><td class="k">Overdue Open Count</td><td>{report.work_orders["overdue_open_count"]}</td></tr>
    <tr><td class="k">Completion Rate (%)</td><td>{report.work_orders["completion_rate_percent"]}</td></tr>
    <tr><td class="k">Avg Resolution Hours</td><td>{report.work_orders["avg_resolution_hours"] or "-"}</td></tr>
  </table>
</body>
</html>
"""
