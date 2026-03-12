"""Utility billing routes for apartment electricity/water charging."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, insert, select

from app import main as main_module
from app.database import (
    get_conn,
    utility_billing_runs,
    utility_billing_statements,
    utility_billing_units,
    utility_common_charges,
    utility_meter_readings,
    utility_rate_policies,
)
from app.schemas import (
    UtilityBillingRunGenerateRequest,
    UtilityBillingRunRead,
    UtilityBillingRunResult,
    UtilityBillingStatementRead,
    UtilityBillingUnitCreate,
    UtilityBillingUnitRead,
    UtilityCommonChargeCreate,
    UtilityCommonChargeRead,
    UtilityMeterReadingCreate,
    UtilityMeterReadingRead,
    UtilityRatePolicyCreate,
    UtilityRatePolicyRead,
    UtilityRateTier,
)

router = APIRouter(prefix="/api/billing", tags=["billing"])

_allowed_sites_for_principal = main_module._allowed_sites_for_principal
_require_site_access = main_module._require_site_access
_to_json_text = main_module._to_json_text
_to_utc = main_module._to_utc
_write_audit_log = main_module._write_audit_log
get_current_admin = main_module.get_current_admin
require_permission = main_module.require_permission


def _validate_month_label(value: str, *, field_name: str) -> str:
    normalized = (value or "").strip()
    try:
        datetime.strptime(normalized, "%Y-%m")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be YYYY-MM") from exc
    return normalized


def _normalize_utility_type(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized not in {"electricity", "water"}:
        raise HTTPException(status_code=422, detail="utility_type must be electricity or water")
    return normalized


def _parse_tiers_json(value: Any) -> list[UtilityRateTier]:
    if isinstance(value, list):
        raw_items = value
    else:
        try:
            raw_items = json.loads(str(value or "[]"))
        except json.JSONDecodeError:
            raw_items = []
    tiers: list[UtilityRateTier] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        tiers.append(UtilityRateTier(**item))
    tiers.sort(key=lambda item: float("inf") if item.up_to is None else item.up_to)
    return tiers


def _row_to_unit_model(row: dict[str, Any]) -> UtilityBillingUnitRead:
    return UtilityBillingUnitRead(
        id=int(row["id"]),
        site=str(row["site"]),
        building=str(row["building"]),
        unit_number=str(row["unit_number"]),
        occupant_name=str(row["occupant_name"]) if row.get("occupant_name") else None,
        area_sqm=float(row["area_sqm"]) if row.get("area_sqm") is not None else None,
        is_active=bool(row["is_active"]),
        created_at=_to_utc(row["created_at"]),
        updated_at=_to_utc(row["updated_at"]),
    )


def _row_to_policy_model(row: dict[str, Any]) -> UtilityRatePolicyRead:
    return UtilityRatePolicyRead(
        id=int(row["id"]),
        site=str(row["site"]),
        utility_type=_normalize_utility_type(str(row["utility_type"])),
        effective_month=str(row["effective_month"]),
        basic_fee=float(row["basic_fee"] or 0),
        unit_rate=float(row["unit_rate"] or 0),
        sewage_rate_per_unit=float(row.get("sewage_rate_per_unit") or 0),
        service_fee=float(row.get("service_fee") or 0),
        vat_rate=float(row.get("vat_rate") or 0),
        tiers=_parse_tiers_json(row.get("tiers_json")),
        notes=str(row.get("notes") or ""),
        created_at=_to_utc(row["created_at"]),
        updated_at=_to_utc(row["updated_at"]),
    )


def _row_to_reading_model(row: dict[str, Any]) -> UtilityMeterReadingRead:
    return UtilityMeterReadingRead(
        id=int(row["id"]),
        site=str(row["site"]),
        building=str(row["building"]),
        unit_number=str(row["unit_number"]),
        utility_type=_normalize_utility_type(str(row["utility_type"])),
        reading_month=str(row["reading_month"]),
        previous_reading=float(row["previous_reading"] or 0),
        current_reading=float(row["current_reading"] or 0),
        usage=float(row["usage"] or 0),
        reader_name=str(row["reader_name"]),
        reading_at=_to_utc(row["reading_at"]),
        notes=str(row.get("notes") or ""),
        created_at=_to_utc(row["created_at"]),
    )


def _row_to_common_charge_model(row: dict[str, Any]) -> UtilityCommonChargeRead:
    return UtilityCommonChargeRead(
        id=int(row["id"]),
        site=str(row["site"]),
        billing_month=str(row["billing_month"]),
        utility_type=_normalize_utility_type(str(row["utility_type"])),
        charge_category=str(row["charge_category"]),
        amount=float(row["amount"] or 0),
        notes=str(row.get("notes") or ""),
        created_at=_to_utc(row["created_at"]),
    )


def _row_to_run_model(row: dict[str, Any]) -> UtilityBillingRunRead:
    return UtilityBillingRunRead(
        id=int(row["id"]),
        site=str(row["site"]),
        billing_month=str(row["billing_month"]),
        utility_type=_normalize_utility_type(str(row["utility_type"])),
        policy_id=int(row["policy_id"]),
        statement_count=int(row.get("statement_count") or 0),
        total_usage=float(row.get("total_usage") or 0),
        total_amount=float(row.get("total_amount") or 0),
        created_by=str(row.get("created_by") or "system"),
        created_at=_to_utc(row["created_at"]),
    )


def _row_to_statement_model(row: dict[str, Any]) -> UtilityBillingStatementRead:
    breakdown = row.get("breakdown_json")
    if isinstance(breakdown, str):
        try:
            parsed_breakdown = json.loads(breakdown or "{}")
        except json.JSONDecodeError:
            parsed_breakdown = {}
    elif isinstance(breakdown, dict):
        parsed_breakdown = breakdown
    else:
        parsed_breakdown = {}
    return UtilityBillingStatementRead(
        id=int(row["id"]),
        run_id=int(row["run_id"]),
        site=str(row["site"]),
        building=str(row["building"]),
        unit_number=str(row["unit_number"]),
        utility_type=_normalize_utility_type(str(row["utility_type"])),
        billing_month=str(row["billing_month"]),
        policy_id=int(row["policy_id"]),
        reading_id=int(row["reading_id"]),
        previous_reading=float(row["previous_reading"] or 0),
        current_reading=float(row["current_reading"] or 0),
        usage=float(row["usage"] or 0),
        basic_fee=float(row["basic_fee"] or 0),
        usage_fee=float(row["usage_fee"] or 0),
        common_fee=float(row.get("common_fee") or 0),
        sewage_fee=float(row.get("sewage_fee") or 0),
        service_fee=float(row.get("service_fee") or 0),
        vat_amount=float(row.get("vat_amount") or 0),
        total_amount=float(row["total_amount"] or 0),
        breakdown=parsed_breakdown,
        created_at=_to_utc(row["created_at"]),
    )


def _calculate_usage_fee(usage: float, *, unit_rate: float, tiers: list[UtilityRateTier]) -> tuple[float, list[dict[str, Any]]]:
    normalized_usage = max(float(usage or 0), 0.0)
    if not tiers:
        return round(normalized_usage * float(unit_rate or 0), 2), [
            {
                "from": 0,
                "to": None,
                "units": round(normalized_usage, 3),
                "rate": round(float(unit_rate or 0), 4),
                "amount": round(normalized_usage * float(unit_rate or 0), 2),
            }
        ]

    charge = 0.0
    consumed = 0.0
    breakdown: list[dict[str, Any]] = []
    for tier in tiers:
        upper = float(tier.up_to) if tier.up_to is not None else None
        if upper is None:
            tier_units = max(normalized_usage - consumed, 0.0)
        else:
            tier_units = max(min(normalized_usage, upper) - consumed, 0.0)
        if tier_units <= 0:
            consumed = upper if upper is not None else consumed
            continue
        amount = round(tier_units * float(tier.rate), 2)
        charge += amount
        breakdown.append(
            {
                "from": round(consumed, 3),
                "to": None if upper is None else round(upper, 3),
                "units": round(tier_units, 3),
                "rate": round(float(tier.rate), 4),
                "amount": amount,
            }
        )
        if upper is None:
            consumed = normalized_usage
            break
        consumed = upper
        if consumed >= normalized_usage:
            break
    return round(charge, 2), breakdown


def _resolve_policy(conn: Any, *, site: str, utility_type: str, billing_month: str) -> dict[str, Any] | None:
    return conn.execute(
        select(utility_rate_policies)
        .where(utility_rate_policies.c.site == site)
        .where(utility_rate_policies.c.utility_type == utility_type)
        .where(utility_rate_policies.c.effective_month <= billing_month)
        .order_by(utility_rate_policies.c.effective_month.desc(), utility_rate_policies.c.id.desc())
        .limit(1)
    ).mappings().first()


def _load_active_unit(conn: Any, *, site: str, building: str, unit_number: str) -> dict[str, Any] | None:
    return conn.execute(
        select(utility_billing_units)
        .where(utility_billing_units.c.site == site)
        .where(utility_billing_units.c.building == building)
        .where(utility_billing_units.c.unit_number == unit_number)
        .where(utility_billing_units.c.is_active.is_(True))
        .order_by(utility_billing_units.c.id.desc())
        .limit(1)
    ).mappings().first()


def _list_common_charge_rows(conn: Any, *, site: str, billing_month: str, utility_type: str) -> list[dict[str, Any]]:
    return conn.execute(
        select(utility_common_charges)
        .where(utility_common_charges.c.site == site)
        .where(utility_common_charges.c.billing_month == billing_month)
        .where(utility_common_charges.c.utility_type == utility_type)
        .order_by(utility_common_charges.c.charge_category.asc(), utility_common_charges.c.id.asc())
    ).mappings().all()


@router.get("/units", response_model=list[UtilityBillingUnitRead])
def list_billing_units(
    site: str | None = Query(default=None),
    building: str | None = Query(default=None),
    active_only: bool = Query(default=True),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: dict[str, Any] = Depends(require_permission("billing:read")),
) -> list[UtilityBillingUnitRead]:
    _require_site_access(principal, site)
    stmt = select(utility_billing_units)
    if site is not None:
        stmt = stmt.where(utility_billing_units.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(utility_billing_units.c.site.in_(allowed_sites))
    if building is not None:
        stmt = stmt.where(utility_billing_units.c.building == building)
    if active_only:
        stmt = stmt.where(utility_billing_units.c.is_active.is_(True))
    stmt = stmt.order_by(
        utility_billing_units.c.site.asc(),
        utility_billing_units.c.building.asc(),
        utility_billing_units.c.unit_number.asc(),
    ).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_unit_model(row) for row in rows]


@router.post("/units", response_model=UtilityBillingUnitRead, status_code=201)
def create_billing_unit(
    payload: UtilityBillingUnitCreate,
    principal: dict[str, Any] = Depends(require_permission("billing:write")),
) -> UtilityBillingUnitRead:
    _require_site_access(principal, payload.site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        existing = conn.execute(
            select(utility_billing_units)
            .where(utility_billing_units.c.site == payload.site)
            .where(utility_billing_units.c.building == payload.building)
            .where(utility_billing_units.c.unit_number == payload.unit_number)
            .limit(1)
        ).mappings().first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Billing unit already exists")
        result = conn.execute(
            insert(utility_billing_units).values(
                site=payload.site,
                building=payload.building,
                unit_number=payload.unit_number,
                occupant_name=payload.occupant_name,
                area_sqm=payload.area_sqm,
                is_active=payload.is_active,
                created_at=now,
                updated_at=now,
            )
        )
        unit_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(utility_billing_units).where(utility_billing_units.c.id == unit_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create billing unit")
    model = _row_to_unit_model(row)
    _write_audit_log(
        principal=principal,
        action="billing_unit_create",
        resource_type="billing_unit",
        resource_id=str(model.id),
        detail={"site": model.site, "building": model.building, "unit_number": model.unit_number},
    )
    return model


@router.get("/rate-policies", response_model=list[UtilityRatePolicyRead])
def list_rate_policies(
    site: str | None = Query(default=None),
    utility_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: dict[str, Any] = Depends(require_permission("billing:read")),
) -> list[UtilityRatePolicyRead]:
    normalized_utility_type = None if utility_type is None or not utility_type.strip() else _normalize_utility_type(utility_type)
    _require_site_access(principal, site)
    stmt = select(utility_rate_policies)
    if site is not None:
        stmt = stmt.where(utility_rate_policies.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(utility_rate_policies.c.site.in_(allowed_sites))
    if normalized_utility_type is not None:
        stmt = stmt.where(utility_rate_policies.c.utility_type == normalized_utility_type)
    stmt = stmt.order_by(
        utility_rate_policies.c.effective_month.desc(),
        utility_rate_policies.c.site.asc(),
        utility_rate_policies.c.utility_type.asc(),
        utility_rate_policies.c.id.desc(),
    ).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_policy_model(row) for row in rows]


@router.post("/rate-policies", response_model=UtilityRatePolicyRead, status_code=201)
def create_rate_policy(
    payload: UtilityRatePolicyCreate,
    principal: dict[str, Any] = Depends(require_permission("billing:write")),
) -> UtilityRatePolicyRead:
    _require_site_access(principal, payload.site)
    effective_month = _validate_month_label(payload.effective_month, field_name="effective_month")
    utility_type = _normalize_utility_type(payload.utility_type)
    now = datetime.now(timezone.utc)
    sorted_tiers = _parse_tiers_json([tier.model_dump() for tier in payload.tiers])
    with get_conn() as conn:
        result = conn.execute(
            insert(utility_rate_policies).values(
                site=payload.site,
                utility_type=utility_type,
                effective_month=effective_month,
                basic_fee=payload.basic_fee,
                unit_rate=payload.unit_rate,
                sewage_rate_per_unit=payload.sewage_rate_per_unit,
                service_fee=payload.service_fee,
                vat_rate=payload.vat_rate,
                tiers_json=_to_json_text([tier.model_dump() for tier in sorted_tiers]),
                notes=payload.notes,
                created_at=now,
                updated_at=now,
            )
        )
        policy_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(utility_rate_policies).where(utility_rate_policies.c.id == policy_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create rate policy")
    model = _row_to_policy_model(row)
    _write_audit_log(
        principal=principal,
        action="billing_rate_policy_create",
        resource_type="billing_rate_policy",
        resource_id=str(model.id),
        detail={"site": model.site, "utility_type": model.utility_type, "effective_month": model.effective_month},
    )
    return model


@router.get("/meter-readings", response_model=list[UtilityMeterReadingRead])
def list_meter_readings(
    site: str | None = Query(default=None),
    building: str | None = Query(default=None),
    utility_type: str | None = Query(default=None),
    reading_month: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: dict[str, Any] = Depends(require_permission("billing:read")),
) -> list[UtilityMeterReadingRead]:
    normalized_utility_type = None if utility_type is None or not utility_type.strip() else _normalize_utility_type(utility_type)
    normalized_month = None if reading_month is None or not reading_month.strip() else _validate_month_label(reading_month, field_name="reading_month")
    _require_site_access(principal, site)
    stmt = select(utility_meter_readings)
    if site is not None:
        stmt = stmt.where(utility_meter_readings.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(utility_meter_readings.c.site.in_(allowed_sites))
    if building is not None:
        stmt = stmt.where(utility_meter_readings.c.building == building)
    if normalized_utility_type is not None:
        stmt = stmt.where(utility_meter_readings.c.utility_type == normalized_utility_type)
    if normalized_month is not None:
        stmt = stmt.where(utility_meter_readings.c.reading_month == normalized_month)
    stmt = stmt.order_by(
        utility_meter_readings.c.reading_month.desc(),
        utility_meter_readings.c.site.asc(),
        utility_meter_readings.c.building.asc(),
        utility_meter_readings.c.unit_number.asc(),
        utility_meter_readings.c.id.desc(),
    ).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_reading_model(row) for row in rows]


@router.post("/meter-readings", response_model=UtilityMeterReadingRead, status_code=201)
def create_meter_reading(
    payload: UtilityMeterReadingCreate,
    principal: dict[str, Any] = Depends(require_permission("billing:write")),
) -> UtilityMeterReadingRead:
    _require_site_access(principal, payload.site)
    utility_type = _normalize_utility_type(payload.utility_type)
    reading_month = _validate_month_label(payload.reading_month, field_name="reading_month")
    previous_reading = float(payload.previous_reading)
    current_reading = float(payload.current_reading)
    if current_reading < previous_reading:
        raise HTTPException(status_code=422, detail="current_reading must be greater than or equal to previous_reading")
    usage = round(current_reading - previous_reading, 3)
    now = datetime.now(timezone.utc)
    reading_at = _to_utc(payload.reading_at or now)
    with get_conn() as conn:
        unit_row = _load_active_unit(
            conn,
            site=payload.site,
            building=payload.building,
            unit_number=payload.unit_number,
        )
        if unit_row is None:
            raise HTTPException(status_code=404, detail="Active billing unit not found")
        existing = conn.execute(
            select(utility_meter_readings)
            .where(utility_meter_readings.c.site == payload.site)
            .where(utility_meter_readings.c.building == payload.building)
            .where(utility_meter_readings.c.unit_number == payload.unit_number)
            .where(utility_meter_readings.c.utility_type == utility_type)
            .where(utility_meter_readings.c.reading_month == reading_month)
            .limit(1)
        ).mappings().first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Meter reading already exists for this month")
        result = conn.execute(
            insert(utility_meter_readings).values(
                site=payload.site,
                building=payload.building,
                unit_number=payload.unit_number,
                utility_type=utility_type,
                reading_month=reading_month,
                previous_reading=previous_reading,
                current_reading=current_reading,
                usage=usage,
                reader_name=payload.reader_name,
                reading_at=reading_at,
                notes=payload.notes,
                created_at=now,
            )
        )
        reading_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(utility_meter_readings).where(utility_meter_readings.c.id == reading_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create meter reading")
    model = _row_to_reading_model(row)
    _write_audit_log(
        principal=principal,
        action="billing_meter_reading_create",
        resource_type="billing_meter_reading",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "building": model.building,
            "unit_number": model.unit_number,
            "utility_type": model.utility_type,
            "reading_month": model.reading_month,
            "usage": model.usage,
        },
    )
    return model


@router.get("/common-charges", response_model=list[UtilityCommonChargeRead])
def list_common_charges(
    site: str | None = Query(default=None),
    billing_month: str | None = Query(default=None),
    utility_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: dict[str, Any] = Depends(require_permission("billing:read")),
) -> list[UtilityCommonChargeRead]:
    normalized_utility_type = None if utility_type is None or not utility_type.strip() else _normalize_utility_type(utility_type)
    normalized_month = None if billing_month is None or not billing_month.strip() else _validate_month_label(billing_month, field_name="billing_month")
    _require_site_access(principal, site)
    stmt = select(utility_common_charges)
    if site is not None:
        stmt = stmt.where(utility_common_charges.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(utility_common_charges.c.site.in_(allowed_sites))
    if normalized_month is not None:
        stmt = stmt.where(utility_common_charges.c.billing_month == normalized_month)
    if normalized_utility_type is not None:
        stmt = stmt.where(utility_common_charges.c.utility_type == normalized_utility_type)
    stmt = stmt.order_by(
        utility_common_charges.c.billing_month.desc(),
        utility_common_charges.c.site.asc(),
        utility_common_charges.c.utility_type.asc(),
        utility_common_charges.c.charge_category.asc(),
        utility_common_charges.c.id.desc(),
    ).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_common_charge_model(row) for row in rows]


@router.post("/common-charges", response_model=UtilityCommonChargeRead, status_code=201)
def create_common_charge(
    payload: UtilityCommonChargeCreate,
    principal: dict[str, Any] = Depends(require_permission("billing:write")),
) -> UtilityCommonChargeRead:
    _require_site_access(principal, payload.site)
    billing_month = _validate_month_label(payload.billing_month, field_name="billing_month")
    utility_type = _normalize_utility_type(payload.utility_type)
    category = (payload.charge_category or "").strip()
    if not category:
        raise HTTPException(status_code=422, detail="charge_category is required")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        result = conn.execute(
            insert(utility_common_charges).values(
                site=payload.site,
                billing_month=billing_month,
                utility_type=utility_type,
                charge_category=category,
                amount=float(payload.amount),
                notes=payload.notes,
                created_at=now,
            )
        )
        charge_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(utility_common_charges).where(utility_common_charges.c.id == charge_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create common charge")
    model = _row_to_common_charge_model(row)
    _write_audit_log(
        principal=principal,
        action="billing_common_charge_create",
        resource_type="billing_common_charge",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "billing_month": model.billing_month,
            "utility_type": model.utility_type,
            "charge_category": model.charge_category,
            "amount": model.amount,
        },
    )
    return model


@router.post("/runs/generate", response_model=UtilityBillingRunResult)
def generate_billing_run(
    payload: UtilityBillingRunGenerateRequest,
    principal: dict[str, Any] = Depends(require_permission("billing:write")),
) -> UtilityBillingRunResult:
    _require_site_access(principal, payload.site)
    billing_month = _validate_month_label(payload.billing_month, field_name="billing_month")
    utility_type = _normalize_utility_type(payload.utility_type)
    actor_username = str(principal.get("username") or "system")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        policy_row = _resolve_policy(conn, site=payload.site, utility_type=utility_type, billing_month=billing_month)
        if policy_row is None:
            raise HTTPException(status_code=404, detail="No rate policy found for billing month")
        existing_statement = conn.execute(
            select(utility_billing_statements.c.id)
            .where(utility_billing_statements.c.site == payload.site)
            .where(utility_billing_statements.c.billing_month == billing_month)
            .where(utility_billing_statements.c.utility_type == utility_type)
            .limit(1)
        ).first()
        if existing_statement is not None and not payload.replace_existing:
            raise HTTPException(status_code=409, detail="Billing statements already exist for this month")
        if existing_statement is not None and payload.replace_existing:
            conn.execute(
                delete(utility_billing_statements)
                .where(utility_billing_statements.c.site == payload.site)
                .where(utility_billing_statements.c.billing_month == billing_month)
                .where(utility_billing_statements.c.utility_type == utility_type)
            )
            conn.execute(
                delete(utility_billing_runs)
                .where(utility_billing_runs.c.site == payload.site)
                .where(utility_billing_runs.c.billing_month == billing_month)
                .where(utility_billing_runs.c.utility_type == utility_type)
            )

        readings = conn.execute(
            select(utility_meter_readings)
            .where(utility_meter_readings.c.site == payload.site)
            .where(utility_meter_readings.c.utility_type == utility_type)
            .where(utility_meter_readings.c.reading_month == billing_month)
            .order_by(utility_meter_readings.c.building.asc(), utility_meter_readings.c.unit_number.asc())
        ).mappings().all()
        if not readings:
            raise HTTPException(status_code=404, detail="No meter readings found for billing month")
        common_charge_rows = _list_common_charge_rows(
            conn,
            site=payload.site,
            billing_month=billing_month,
            utility_type=utility_type,
        )
        common_charge_total = round(sum(float(row.get("amount") or 0) for row in common_charge_rows), 2)
        unit_area_map: dict[tuple[str, str], float] = {}
        total_area = 0.0
        for reading_row in readings:
            unit_row = _load_active_unit(
                conn,
                site=payload.site,
                building=str(reading_row["building"]),
                unit_number=str(reading_row["unit_number"]),
            )
            if unit_row is None:
                raise HTTPException(status_code=404, detail="Active billing unit not found for billing run")
            area_sqm = unit_row.get("area_sqm")
            if common_charge_total > 0 and (area_sqm is None or float(area_sqm) <= 0):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "Area-based common charge allocation requires positive area_sqm for all billed units: "
                        + f"{reading_row['building']} {reading_row['unit_number']}"
                    ),
                )
            normalized_area = round(float(area_sqm or 0), 3)
            unit_area_map[(str(reading_row["building"]), str(reading_row["unit_number"]))] = normalized_area
            total_area += normalized_area
        if common_charge_total > 0 and total_area <= 0:
            raise HTTPException(status_code=422, detail="Total area_sqm must be positive for common charge allocation")
        common_rate_per_sqm = round(common_charge_total / total_area, 6) if common_charge_total > 0 else 0.0

        policy = _row_to_policy_model(policy_row)
        run_result = conn.execute(
            insert(utility_billing_runs).values(
                site=payload.site,
                billing_month=billing_month,
                utility_type=utility_type,
                policy_id=policy.id,
                statement_count=0,
                total_usage=0,
                total_amount=0,
                created_by=actor_username,
                created_at=now,
            )
        )
        run_id = int(run_result.inserted_primary_key[0])
        statements: list[UtilityBillingStatementRead] = []
        total_usage = 0.0
        total_amount = 0.0
        for reading_row in readings:
            usage = float(reading_row.get("usage") or 0)
            usage_fee, tier_breakdown = _calculate_usage_fee(usage, unit_rate=policy.unit_rate, tiers=policy.tiers)
            unit_area = unit_area_map[(str(reading_row["building"]), str(reading_row["unit_number"]))]
            common_fee = round(unit_area * common_rate_per_sqm, 2)
            basic_fee = round(policy.basic_fee, 2)
            sewage_fee = round(usage * policy.sewage_rate_per_unit, 2)
            service_fee = round(policy.service_fee, 2)
            vat_amount = round((basic_fee + usage_fee + common_fee + sewage_fee + service_fee) * policy.vat_rate, 2)
            total_statement_amount = round(basic_fee + usage_fee + common_fee + sewage_fee + service_fee + vat_amount, 2)
            breakdown = {
                "policy_effective_month": policy.effective_month,
                "tier_breakdown": tier_breakdown,
                "unit_area_sqm": unit_area,
                "common_charge_total": common_charge_total,
                "common_rate_per_sqm": common_rate_per_sqm,
                "common_charge_breakdown": [
                    {
                        "charge_category": str(item.get("charge_category") or ""),
                        "amount": round(float(item.get("amount") or 0), 2),
                    }
                    for item in common_charge_rows
                ],
                "vat_rate": policy.vat_rate,
                "notes": policy.notes,
            }
            statement_result = conn.execute(
                insert(utility_billing_statements).values(
                    run_id=run_id,
                    site=payload.site,
                    building=reading_row["building"],
                    unit_number=reading_row["unit_number"],
                    utility_type=utility_type,
                    billing_month=billing_month,
                    policy_id=policy.id,
                    reading_id=reading_row["id"],
                    previous_reading=reading_row["previous_reading"],
                    current_reading=reading_row["current_reading"],
                    usage=usage,
                    basic_fee=basic_fee,
                    usage_fee=usage_fee,
                    common_fee=common_fee,
                    sewage_fee=sewage_fee,
                    service_fee=service_fee,
                    vat_amount=vat_amount,
                    total_amount=total_statement_amount,
                    breakdown_json=_to_json_text(breakdown),
                    created_at=now,
                )
            )
            statement_id = int(statement_result.inserted_primary_key[0])
            statement_row = conn.execute(
                select(utility_billing_statements).where(utility_billing_statements.c.id == statement_id).limit(1)
            ).mappings().first()
            if statement_row is None:
                raise HTTPException(status_code=500, detail="Failed to create billing statement")
            statements.append(_row_to_statement_model(statement_row))
            total_usage += usage
            total_amount += total_statement_amount

        conn.execute(
            utility_billing_runs.update()
            .where(utility_billing_runs.c.id == run_id)
            .values(
                statement_count=len(statements),
                total_usage=round(total_usage, 3),
                total_amount=round(total_amount, 2),
            )
        )
        run_row = conn.execute(
            select(utility_billing_runs).where(utility_billing_runs.c.id == run_id).limit(1)
        ).mappings().first()

    if run_row is None:
        raise HTTPException(status_code=500, detail="Failed to finalize billing run")
    run_model = _row_to_run_model(run_row)
    summary = {
        "site": payload.site,
        "billing_month": billing_month,
        "utility_type": utility_type,
        "statement_count": len(statements),
        "total_usage": round(total_usage, 3),
        "total_amount": round(total_amount, 2),
        "common_charge_total": common_charge_total,
        "common_rate_per_sqm": common_rate_per_sqm,
        "common_charge_breakdown": [
            {
                "charge_category": str(item.get("charge_category") or ""),
                "amount": round(float(item.get("amount") or 0), 2),
            }
            for item in common_charge_rows
        ],
        "policy": {
            "id": policy.id,
            "effective_month": policy.effective_month,
            "basic_fee": policy.basic_fee,
            "unit_rate": policy.unit_rate,
            "sewage_rate_per_unit": policy.sewage_rate_per_unit,
            "service_fee": policy.service_fee,
            "vat_rate": policy.vat_rate,
        },
    }
    _write_audit_log(
        principal=principal,
        action="billing_run_generate",
        resource_type="billing_run",
        resource_id=str(run_model.id),
        detail=summary,
    )
    return UtilityBillingRunResult(run=run_model, statements=statements, summary=summary)


@router.get("/statements", response_model=list[UtilityBillingStatementRead])
def list_billing_statements(
    site: str | None = Query(default=None),
    billing_month: str | None = Query(default=None),
    utility_type: str | None = Query(default=None),
    building: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: dict[str, Any] = Depends(require_permission("billing:read")),
) -> list[UtilityBillingStatementRead]:
    normalized_utility_type = None if utility_type is None or not utility_type.strip() else _normalize_utility_type(utility_type)
    normalized_month = None if billing_month is None or not billing_month.strip() else _validate_month_label(billing_month, field_name="billing_month")
    _require_site_access(principal, site)
    stmt = select(utility_billing_statements)
    if site is not None:
        stmt = stmt.where(utility_billing_statements.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(utility_billing_statements.c.site.in_(allowed_sites))
    if normalized_month is not None:
        stmt = stmt.where(utility_billing_statements.c.billing_month == normalized_month)
    if normalized_utility_type is not None:
        stmt = stmt.where(utility_billing_statements.c.utility_type == normalized_utility_type)
    if building is not None:
        stmt = stmt.where(utility_billing_statements.c.building == building)
    stmt = stmt.order_by(
        utility_billing_statements.c.billing_month.desc(),
        utility_billing_statements.c.site.asc(),
        utility_billing_statements.c.building.asc(),
        utility_billing_statements.c.unit_number.asc(),
        utility_billing_statements.c.id.desc(),
    ).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_statement_model(row) for row in rows]
