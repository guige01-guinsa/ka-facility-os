"""OPS reporting helpers extracted from app.main."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select

from app.runtime_bridge import export_main_symbols_with_prefixes
from app.schemas import (
    DashboardTrendPoint,
    DashboardTrendsRead,
    OpsHandoverBriefRead,
    OpsHandoverInspectionRead,
    OpsHandoverWorkOrderRead,
)

_REQUIRED_MAIN_NAMES = (
    "alert_deliveries",
    "get_conn",
    "inspections",
    "job_runs",
    "work_orders",
    "_as_datetime",
    "_as_optional_datetime",
    "_normalize_site_name",
)

export_main_symbols_with_prefixes(globals(), names=_REQUIRED_MAIN_NAMES)

def build_dashboard_trends(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> DashboardTrendsRead:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    inspections_stmt = select(inspections.c.inspected_at, inspections.c.site).where(inspections.c.inspected_at >= start)
    work_orders_stmt = select(
        work_orders.c.created_at,
        work_orders.c.completed_at,
        work_orders.c.site,
    ).where((work_orders.c.created_at >= start) | (work_orders.c.completed_at >= start))
    escalations_stmt = (
        select(job_runs.c.finished_at, job_runs.c.detail_json)
        .where(job_runs.c.job_name == "sla_escalation")
        .where(job_runs.c.finished_at >= start)
    )

    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return DashboardTrendsRead(generated_at=now, site=site, window_days=days, points=[])
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()
        escalation_rows = conn.execute(escalations_stmt).mappings().all()

    buckets: dict[str, dict[str, int]] = {}
    for i in range(days):
        bucket_day = (start + timedelta(days=i)).date().isoformat()
        buckets[bucket_day] = {
            "inspections_count": 0,
            "work_orders_created_count": 0,
            "work_orders_completed_count": 0,
            "work_orders_escalated_count": 0,
        }

    for row in inspection_rows:
        inspected_at = _as_optional_datetime(row["inspected_at"])
        if inspected_at is None:
            continue
        key = inspected_at.date().isoformat()
        if key in buckets:
            buckets[key]["inspections_count"] += 1

    for row in work_order_rows:
        created_at = _as_optional_datetime(row["created_at"])
        completed_at = _as_optional_datetime(row["completed_at"])
        if created_at is not None:
            key = created_at.date().isoformat()
            if key in buckets:
                buckets[key]["work_orders_created_count"] += 1
        if completed_at is not None:
            key = completed_at.date().isoformat()
            if key in buckets:
                buckets[key]["work_orders_completed_count"] += 1

    for row in escalation_rows:
        finished_at = _as_optional_datetime(row["finished_at"])
        if finished_at is None:
            continue
        key = finished_at.date().isoformat()
        if key not in buckets:
            continue

        detail = {}
        raw = str(row["detail_json"] or "{}")
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                detail = parsed
        except json.JSONDecodeError:
            detail = {}

        detail_site = detail.get("site")
        if site is not None and detail_site not in {site, None}:
            continue
        escalated_count = int(detail.get("escalated_count", 0) or 0)
        buckets[key]["work_orders_escalated_count"] += max(0, escalated_count)

    points = [
        DashboardTrendPoint(
            date=date_key,
            inspections_count=data["inspections_count"],
            work_orders_created_count=data["work_orders_created_count"],
            work_orders_completed_count=data["work_orders_completed_count"],
            work_orders_escalated_count=data["work_orders_escalated_count"],
        )
        for date_key, data in buckets.items()
    ]
    return DashboardTrendsRead(
        generated_at=now,
        site=site,
        window_days=days,
        points=points,
    )


def build_ops_handover_brief(
    *,
    site: str | None,
    window_hours: int,
    due_soon_hours: int,
    max_items: int,
    allowed_sites: list[str] | None = None,
) -> OpsHandoverBriefRead:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    due_soon_cutoff = now + timedelta(hours=due_soon_hours)
    alert_window_start = now - timedelta(hours=24)

    if site is None and allowed_sites is not None and not allowed_sites:
        return OpsHandoverBriefRead(
            generated_at=now,
            site=site,
            window_hours=window_hours,
            due_soon_hours=due_soon_hours,
            open_work_orders=0,
            overdue_open_work_orders=0,
            due_soon_work_orders=0,
            escalated_open_work_orders=0,
            unassigned_high_priority_open_work_orders=0,
            new_work_orders_in_window=0,
            high_risk_inspections_in_window=0,
            failed_alert_deliveries_24h=0,
            top_work_orders=[],
            recent_high_risk_inspections=[],
            recommended_actions=["No accessible sites in current principal scope."],
        )

    open_work_orders_stmt = select(work_orders).where(work_orders.c.status.in_(["open", "acked"]))
    new_work_orders_stmt = (
        select(work_orders.c.id, work_orders.c.site)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.created_at >= window_start)
    )
    high_risk_inspections_stmt = (
        select(inspections)
        .where(inspections.c.inspected_at >= window_start)
        .where(inspections.c.risk_level.in_(["warning", "danger"]))
    )
    alert_deliveries_stmt = (
        select(alert_deliveries.c.status, alert_deliveries.c.payload_json)
        .where(alert_deliveries.c.last_attempt_at >= alert_window_start)
        .where(alert_deliveries.c.status.in_(["failed", "warning"]))
    )

    if site is not None:
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site == site)
        new_work_orders_stmt = new_work_orders_stmt.where(work_orders.c.site == site)
        high_risk_inspections_stmt = high_risk_inspections_stmt.where(inspections.c.site == site)
    elif allowed_sites is not None:
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))
        new_work_orders_stmt = new_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))
        high_risk_inspections_stmt = high_risk_inspections_stmt.where(inspections.c.site.in_(allowed_sites))

    with get_conn() as conn:
        open_work_order_rows = conn.execute(open_work_orders_stmt).mappings().all()
        new_work_order_rows = conn.execute(new_work_orders_stmt).all()
        high_risk_inspection_rows = conn.execute(high_risk_inspections_stmt).mappings().all()
        alert_delivery_rows = conn.execute(alert_deliveries_stmt).mappings().all()

    priority_weights = {"low": 1, "medium": 2, "high": 4, "critical": 6}
    top_work_orders: list[OpsHandoverWorkOrderRead] = []
    overdue_open_work_orders = 0
    due_soon_work_orders = 0
    escalated_open_work_orders = 0
    unassigned_high_priority_open_work_orders = 0

    for row in open_work_order_rows:
        due_at = _as_optional_datetime(row["due_at"])
        created_at = _as_optional_datetime(row["created_at"]) or now
        priority = str(row["priority"] or "medium")
        is_escalated = bool(row["is_escalated"])
        is_overdue = due_at is not None and due_at < now
        is_due_soon = due_at is not None and now <= due_at <= due_soon_cutoff
        is_unassigned_high_priority = priority in {"high", "critical"} and not row["assignee"]

        if is_overdue:
            overdue_open_work_orders += 1
        if is_due_soon:
            due_soon_work_orders += 1
        if is_escalated:
            escalated_open_work_orders += 1
        if is_unassigned_high_priority:
            unassigned_high_priority_open_work_orders += 1

        urgency_score = priority_weights.get(priority, 2)
        reasons: list[str] = [f"{priority} priority"]
        if is_overdue:
            urgency_score += 6
            reasons.append("overdue")
        elif is_due_soon:
            urgency_score += 3
            reasons.append("due soon")
        if is_escalated:
            urgency_score += 4
            reasons.append("escalated")
        if is_unassigned_high_priority:
            urgency_score += 2
            reasons.append("unassigned high priority")

        age_hours = (now - created_at).total_seconds() / 3600
        if age_hours >= 72:
            urgency_score += 2
            reasons.append("open >72h")
        elif age_hours >= 24:
            urgency_score += 1
            reasons.append("open >24h")

        due_in_minutes = None
        if due_at is not None:
            due_in_minutes = int((due_at - now).total_seconds() // 60)

        top_work_orders.append(
            OpsHandoverWorkOrderRead(
                id=int(row["id"]),
                site=str(row["site"]),
                location=str(row["location"]),
                title=str(row["title"]),
                priority=priority,  # type: ignore[arg-type]
                status=str(row["status"]),  # type: ignore[arg-type]
                assignee=row["assignee"],
                due_at=due_at,
                created_at=created_at,
                is_escalated=is_escalated,
                is_overdue=is_overdue,
                due_in_minutes=due_in_minutes,
                urgency_score=urgency_score,
                reasons=reasons,
            )
        )

    far_future = now + timedelta(days=36500)
    top_work_orders.sort(
        key=lambda item: (
            -item.urgency_score,
            item.due_at or far_future,
            item.created_at,
            item.id,
        )
    )
    top_work_orders = top_work_orders[:max_items]

    risk_weights = {"danger": 2, "warning": 1}
    recent_high_risk_inspections: list[OpsHandoverInspectionRead] = []
    for row in high_risk_inspection_rows:
        risk_flags = [flag for flag in str(row["risk_flags"] or "").split(",") if flag]
        recent_high_risk_inspections.append(
            OpsHandoverInspectionRead(
                id=int(row["id"]),
                site=str(row["site"]),
                location=str(row["location"]),
                inspector=str(row["inspector"]),
                risk_level=str(row["risk_level"] or "warning"),
                inspected_at=_as_datetime(row["inspected_at"]),
                risk_flags=risk_flags,
            )
        )
    recent_high_risk_inspections.sort(
        key=lambda item: (
            risk_weights.get(item.risk_level, 0),
            item.inspected_at,
            item.id,
        ),
        reverse=True,
    )
    high_risk_inspections_in_window = len(recent_high_risk_inspections)
    recent_high_risk_inspections = recent_high_risk_inspections[:max_items]

    failed_alert_deliveries_24h = 0
    for row in alert_delivery_rows:
        payload_raw = str(row["payload_json"] or "{}")
        payload: dict[str, Any] = {}
        try:
            parsed_payload = json.loads(payload_raw)
            if isinstance(parsed_payload, dict):
                payload = parsed_payload
        except json.JSONDecodeError:
            payload = {}

        payload_site = _normalize_site_name(str(payload.get("site"))) if payload.get("site") is not None else None
        if site is not None:
            if payload_site != site:
                continue
        elif allowed_sites is not None and payload_site not in allowed_sites:
            continue
        failed_alert_deliveries_24h += 1

    recommended_actions: list[str] = []
    if overdue_open_work_orders > 0:
        recommended_actions.append(f"Resolve or reassign {overdue_open_work_orders} overdue open work orders.")
    if unassigned_high_priority_open_work_orders > 0:
        recommended_actions.append(
            f"Assign owners for {unassigned_high_priority_open_work_orders} unassigned high/critical work orders."
        )
    if high_risk_inspections_in_window > 0:
        recommended_actions.append(
            f"Review {high_risk_inspections_in_window} warning/danger inspections from last {window_hours} hours."
        )
    if due_soon_work_orders > 0:
        recommended_actions.append(f"Preempt {due_soon_work_orders} work orders due within next {due_soon_hours} hours.")
    if failed_alert_deliveries_24h > 0:
        recommended_actions.append(
            f"Investigate {failed_alert_deliveries_24h} failed/warning alert deliveries from last 24 hours."
        )
    if not recommended_actions:
        recommended_actions.append("No urgent blockers detected for this handover window.")

    return OpsHandoverBriefRead(
        generated_at=now,
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        open_work_orders=len(open_work_order_rows),
        overdue_open_work_orders=overdue_open_work_orders,
        due_soon_work_orders=due_soon_work_orders,
        escalated_open_work_orders=escalated_open_work_orders,
        unassigned_high_priority_open_work_orders=unassigned_high_priority_open_work_orders,
        new_work_orders_in_window=len(new_work_order_rows),
        high_risk_inspections_in_window=high_risk_inspections_in_window,
        failed_alert_deliveries_24h=failed_alert_deliveries_24h,
        top_work_orders=top_work_orders,
        recent_high_risk_inspections=recent_high_risk_inspections,
        recommended_actions=recommended_actions[:5],
    )


def _json_or_scalar(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    return str(value)




def _build_handover_brief_csv(report: OpsHandoverBriefRead) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["meta", "site", report.site or "ALL"])
    writer.writerow(["meta", "generated_at", report.generated_at.isoformat()])
    writer.writerow(["meta", "window_hours", report.window_hours])
    writer.writerow(["meta", "due_soon_hours", report.due_soon_hours])

    writer.writerow(["summary", "open_work_orders", report.open_work_orders])
    writer.writerow(["summary", "overdue_open_work_orders", report.overdue_open_work_orders])
    writer.writerow(["summary", "due_soon_work_orders", report.due_soon_work_orders])
    writer.writerow(["summary", "escalated_open_work_orders", report.escalated_open_work_orders])
    writer.writerow(
        [
            "summary",
            "unassigned_high_priority_open_work_orders",
            report.unassigned_high_priority_open_work_orders,
        ]
    )
    writer.writerow(["summary", "new_work_orders_in_window", report.new_work_orders_in_window])
    writer.writerow(["summary", "high_risk_inspections_in_window", report.high_risk_inspections_in_window])
    writer.writerow(["summary", "failed_alert_deliveries_24h", report.failed_alert_deliveries_24h])

    writer.writerow([])
    writer.writerow(
        [
            "top_work_orders",
            "id",
            "site",
            "location",
            "title",
            "priority",
            "status",
            "assignee",
            "due_at",
            "due_in_minutes",
            "is_overdue",
            "is_escalated",
            "urgency_score",
            "reasons",
        ]
    )
    for item in report.top_work_orders:
        writer.writerow(
            [
                "top_work_orders",
                item.id,
                item.site,
                item.location,
                item.title,
                item.priority,
                item.status,
                item.assignee or "",
                item.due_at.isoformat() if item.due_at is not None else "",
                item.due_in_minutes if item.due_in_minutes is not None else "",
                item.is_overdue,
                item.is_escalated,
                item.urgency_score,
                ", ".join(item.reasons),
            ]
        )

    writer.writerow([])
    writer.writerow(
        [
            "recent_high_risk_inspections",
            "id",
            "site",
            "location",
            "inspector",
            "risk_level",
            "inspected_at",
            "risk_flags",
        ]
    )
    for item in report.recent_high_risk_inspections:
        writer.writerow(
            [
                "recent_high_risk_inspections",
                item.id,
                item.site,
                item.location,
                item.inspector,
                item.risk_level,
                item.inspected_at.isoformat(),
                ", ".join(item.risk_flags),
            ]
        )

    writer.writerow([])
    writer.writerow(["recommended_actions", "index", "action"])
    for idx, action in enumerate(report.recommended_actions, start=1):
        writer.writerow(["recommended_actions", idx, action])

    return out.getvalue()


def _build_handover_brief_pdf(report: OpsHandoverBriefRead) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF generator dependency not installed") from exc

    lines = [
        "Ops Handover Brief",
        "",
        f"Site: {report.site or 'ALL'}",
        f"Generated At: {report.generated_at.isoformat()}",
        f"Window Hours: {report.window_hours}",
        f"Due Soon Hours: {report.due_soon_hours}",
        "",
        "[Summary]",
        f"Open Work Orders: {report.open_work_orders}",
        f"Overdue Open Work Orders: {report.overdue_open_work_orders}",
        f"Due Soon Work Orders: {report.due_soon_work_orders}",
        f"Escalated Open Work Orders: {report.escalated_open_work_orders}",
        f"Unassigned High Priority Open Work Orders: {report.unassigned_high_priority_open_work_orders}",
        f"New Work Orders In Window: {report.new_work_orders_in_window}",
        f"High Risk Inspections In Window: {report.high_risk_inspections_in_window}",
        f"Failed Alert Deliveries 24h: {report.failed_alert_deliveries_24h}",
        "",
        "[Top Work Orders]",
    ]
    for item in report.top_work_orders:
        due_text = item.due_at.isoformat() if item.due_at is not None else "-"
        lines.append(
            f"#{item.id} {item.priority}/{item.status} score={item.urgency_score} site={item.site} due={due_text}"
        )
        lines.append(f"  {item.title[:120]}")

    lines.append("")
    lines.append("[Recent High Risk Inspections]")
    for item in report.recent_high_risk_inspections:
        lines.append(f"#{item.id} {item.risk_level} site={item.site} inspected_at={item.inspected_at.isoformat()}")
        if item.risk_flags:
            lines.append(f"  flags={', '.join(item.risk_flags)[:140]}")

    lines.append("")
    lines.append("[Recommended Actions]")
    for idx, action in enumerate(report.recommended_actions, start=1):
        lines.append(f"{idx}. {action}")

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    _, height = A4
    margin_left = 36
    y = height - 40
    pdf.setFont("Helvetica", 10)
    for line in lines:
        if y < 40:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 40
        pdf.drawString(margin_left, y, line[:180])
        y -= 14
    pdf.save()
    return buf.getvalue()


