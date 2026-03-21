"""OPS checklist runtime helpers extracted from app.main."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from os import getenv
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.database import (
    get_conn,
    ops_checklist_set_items,
    ops_checklist_sets,
    ops_equipment_assets,
    ops_qr_asset_revisions,
    ops_qr_assets,
)

OPS_QR_PLACEHOLDER_VALUES = {"설비", "위치", "점검항목"}
OPS_QR_MUTABLE_FIELDS = ("equipment", "location", "default_item")
OPS_MASTER_LIFECYCLE_ACTIVE = "active"
OPS_MASTER_LIFECYCLE_SET = {
    OPS_MASTER_LIFECYCLE_ACTIVE,
    "retired",
    "replaced",
}


def bind(namespace: dict[str, object]) -> None:
    return None


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


def _to_json_text(value: dict[str, Any] | None) -> str:
    return json.dumps(value or {}, ensure_ascii=False, default=str)


def _qr_asset_placeholder_flags(row: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    equipment = str(row.get("equipment") or "").strip()
    location = str(row.get("location") or "").strip()
    default_item = str(row.get("default_item") or "").strip()
    if not equipment:
        flags.append("missing_equipment")
    elif equipment in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_equipment")
    if not location:
        flags.append("missing_location")
    elif location in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_location")
    if not default_item:
        flags.append("missing_default_item")
    elif default_item in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_default_item")
    return flags


OPS_CHECKLIST_RESPONSE_SCHEMA = "ops_checklist_catalog_response"
OPS_CHECKLIST_RESPONSE_VERSION = "v1"


def _build_ops_checklist_response_meta(
    payload: dict[str, Any],
    *,
    endpoint: str,
) -> dict[str, Any]:
    checklist_version = str(payload.get("checklist_version") or payload.get("version") or "unknown")
    source = str(payload.get("source") or "unknown")
    applied_at = _as_optional_datetime(payload.get("applied_at"))
    applied_at_iso = applied_at.isoformat() if applied_at is not None else None
    return {
        "checklist_version": checklist_version,
        "source": source,
        "applied_at": applied_at_iso,
        "meta": {
            "schema": OPS_CHECKLIST_RESPONSE_SCHEMA,
            "schema_version": OPS_CHECKLIST_RESPONSE_VERSION,
            "endpoint": endpoint,
            "checklist_version": checklist_version,
            "source": source,
            "applied_at": applied_at_iso,
        },
    }


def _default_ops_special_checklists_payload() -> dict[str, Any]:
    return {
        "source_file": "fallback",
        "source": "fallback",
        "version": "fallback",
        "checklist_version": "fallback",
        "applied_at": None,
        "checklist_sets": [
            {
                "set_id": "electrical_60",
                "label": "전기직무고시60항목",
                "task_type": "전기점검",
                "items": [
                    {"seq": 1, "item": "수변전실 출입통제 상태 확인"},
                    {"seq": 2, "item": "변압기 외관 점검"},
                    {"seq": 3, "item": "수전반 차단기 동작 상태"},
                    {"seq": 4, "item": "분전반 누전차단기 상태"},
                    {"seq": 5, "item": "접지설비 연결 상태"},
                ],
            },
            {
                "set_id": "fire_legal",
                "label": "소방법정점검",
                "task_type": "소방점검",
                "items": [
                    {"seq": 1, "item": "소화기 압력 확인"},
                    {"seq": 2, "item": "옥내소화전 방수 시험"},
                    {"seq": 3, "item": "스프링클러 헤드 막힘 여부"},
                ],
            },
            {
                "set_id": "mechanical_ops",
                "label": "기계설비점검",
                "task_type": "기계점검",
                "items": [
                    {"seq": 1, "item": "급수펌프 외관 상태 확인"},
                    {"seq": 2, "item": "배수펌프 자동운전 상태 확인"},
                    {"seq": 3, "item": "저수조 수위 및 누수 확인"},
                ],
            },
            {
                "set_id": "building_ops",
                "label": "건축시설점검",
                "task_type": "건축점검",
                "items": [
                    {"seq": 1, "item": "외벽 균열 및 박락 여부 확인"},
                    {"seq": 2, "item": "옥상 방수층 손상 여부 확인"},
                    {"seq": 3, "item": "방화문 개폐 상태 확인"},
                ],
            },
            {
                "set_id": "safety_ops",
                "label": "안전시설점검",
                "task_type": "안전점검",
                "items": [
                    {"seq": 1, "item": "CCTV 전원 및 녹화 상태 확인"},
                    {"seq": 2, "item": "주차장 조명 점등 상태 확인"},
                    {"seq": 3, "item": "비상벨 작동 상태 확인"},
                ],
            },
        ],
        "ops_codes": [
            {"code": "E01", "category": "전기", "description": "수변전설비 점검"},
            {"code": "F01", "category": "소방", "description": "소화기 점검"},
            {"code": "M01", "category": "기계", "description": "급수펌프 점검"},
            {"code": "B01", "category": "건축", "description": "외벽 점검"},
            {"code": "S01", "category": "안전", "description": "CCTV 점검"},
        ],
        "qr_assets": [],
    }


def _resolve_ops_special_checklists_data_path() -> Path:
    raw_path = getenv(
        "OPS_SPECIAL_CHECKLISTS_DATA_PATH",
        "data/apartment_facility_special_checklists.json",
    ).strip() or "data/apartment_facility_special_checklists.json"
    target = Path(raw_path)
    if not target.is_absolute():
        target = Path(__file__).resolve().parent.parent / target
    return target


def _persist_ops_special_checklists_payload(payload: dict[str, Any]) -> Path:
    target = _resolve_ops_special_checklists_data_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)
    target.write_text(serialized + "\n", encoding="utf-8")
    return target


def _normalize_ops_equipment_key(equipment: Any, location: Any) -> str | None:
    equipment_text = str(equipment or "").strip()
    if not equipment_text:
        return None
    location_text = str(location or "").strip()
    return f"{equipment_text.lower()}::{location_text.lower()}"


def _normalize_ops_master_lifecycle_state(value: Any, *, default: str = OPS_MASTER_LIFECYCLE_ACTIVE) -> str:
    normalized = str(value or "").strip().lower() or default
    if normalized not in OPS_MASTER_LIFECYCLE_SET:
        return default
    return normalized


def _normalize_ops_checklist_sets(
    checklist_sets_raw: Any,
    *,
    fallback_sets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    checklist_sets: list[dict[str, Any]] = []
    if isinstance(checklist_sets_raw, list):
        for item in checklist_sets_raw:
            if not isinstance(item, dict):
                continue
            set_id = str(item.get("set_id") or "").strip()
            label = str(item.get("label") or "").strip()
            if not set_id or not label:
                continue
            task_type = str(item.get("task_type") or "점검").strip() or "점검"
            try:
                version_no = int(item.get("version_no") or 1)
            except (TypeError, ValueError):
                version_no = 1
            lifecycle_state = _normalize_ops_master_lifecycle_state(item.get("lifecycle_state"))
            items_raw = item.get("items")
            items: list[dict[str, Any]] = []
            if isinstance(items_raw, list):
                for idx, entry in enumerate(items_raw, start=1):
                    if not isinstance(entry, dict):
                        continue
                    text = str(entry.get("item") or "").strip()
                    if not text:
                        continue
                    seq_raw = entry.get("seq")
                    try:
                        seq = int(seq_raw)
                    except Exception:
                        seq = idx
                    items.append({"seq": max(1, seq), "item": text})
            if items:
                checklist_sets.append(
                    {
                        "set_id": set_id,
                        "label": label,
                        "task_type": task_type,
                        "version_no": max(1, version_no),
                        "lifecycle_state": lifecycle_state,
                        "items": items,
                    }
                )
    if checklist_sets:
        return checklist_sets
    return [
        {
            "set_id": str(row.get("set_id") or "").strip(),
            "label": str(row.get("label") or "").strip(),
            "task_type": str(row.get("task_type") or "점검").strip() or "점검",
            "version_no": max(1, int(row.get("version_no") or 1)),
            "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
            "items": [
                {
                    "seq": int(item.get("seq") or idx),
                    "item": str(item.get("item") or "").strip(),
                }
                for idx, item in enumerate(row.get("items") or [], start=1)
                if isinstance(item, dict) and str(item.get("item") or "").strip()
            ],
        }
        for row in fallback_sets
        if isinstance(row, dict)
        and str(row.get("set_id") or "").strip()
        and str(row.get("label") or "").strip()
        and isinstance(row.get("items"), list)
    ]


def _normalize_ops_special_ops_codes(ops_codes_raw: Any) -> list[dict[str, str]]:
    ops_codes: list[dict[str, str]] = []
    if isinstance(ops_codes_raw, list):
        for row in ops_codes_raw:
            if not isinstance(row, dict):
                continue
            code = str(row.get("code") or "").strip()
            category = str(row.get("category") or "").strip()
            description = str(row.get("description") or "").strip()
            if not code:
                continue
            ops_codes.append({"code": code, "category": category, "description": description})
    return ops_codes


def _normalize_ops_special_qr_assets(qr_assets_raw: Any) -> list[dict[str, str]]:
    qr_assets: list[dict[str, str]] = []
    if isinstance(qr_assets_raw, list):
        for row in qr_assets_raw:
            if not isinstance(row, dict):
                continue
            qr_id = str(row.get("qr_id") or "").strip()
            if not qr_id:
                continue
            qr_assets.append(
                {
                    "qr_id": qr_id,
                    "equipment": str(row.get("equipment") or "").strip(),
                    "location": str(row.get("location") or "").strip(),
                    "default_item": str(row.get("default_item") or "").strip(),
                    "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
                }
            )
    return qr_assets


def _read_ops_special_checklists_source_payload() -> dict[str, Any]:
    default_payload = _default_ops_special_checklists_payload()
    target = _resolve_ops_special_checklists_data_path()
    if not target.exists():
        return {
            "source_file": str(default_payload.get("source_file") or target.as_posix()),
            "source": str(default_payload.get("source") or "fallback"),
            "version": str(default_payload.get("version") or "fallback"),
            "checklist_version": str(default_payload.get("checklist_version") or default_payload.get("version") or "fallback"),
            "applied_at": default_payload.get("applied_at"),
            "checklist_sets": _normalize_ops_checklist_sets(
                default_payload.get("checklist_sets"),
                fallback_sets=list(default_payload.get("checklist_sets") or []),
            ),
            "ops_codes": _normalize_ops_special_ops_codes(default_payload.get("ops_codes")),
            "qr_assets": _normalize_ops_special_qr_assets(default_payload.get("qr_assets")),
        }
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        loaded = default_payload
    if not isinstance(loaded, dict):
        loaded = default_payload

    return {
        "source_file": str(loaded.get("source_file") or target.as_posix()),
        "source": str(loaded.get("source") or "file"),
        "version": str(loaded.get("version") or "unknown"),
        "checklist_version": str(loaded.get("checklist_version") or loaded.get("version") or "unknown"),
        "applied_at": (
            loaded.get("applied_at")
            or datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc).isoformat()
        ),
        "checklist_sets": _normalize_ops_checklist_sets(
            loaded.get("checklist_sets"),
            fallback_sets=list(default_payload.get("checklist_sets") or []),
        ),
        "ops_codes": _normalize_ops_special_ops_codes(loaded.get("ops_codes")),
        "qr_assets": _normalize_ops_special_qr_assets(loaded.get("qr_assets")),
    }


def _build_ops_checklist_item_to_set_map(payload: dict[str, Any]) -> dict[str, str]:
    checklist_sets = payload.get("checklist_sets") if isinstance(payload.get("checklist_sets"), list) else []
    item_to_set: dict[str, str] = {}
    for set_row in checklist_sets:
        if not isinstance(set_row, dict):
            continue
        set_id = str(set_row.get("set_id") or "").strip()
        if not set_id:
            continue
        items = set_row.get("items")
        if not isinstance(items, list):
            continue
        for item_row in items:
            if not isinstance(item_row, dict):
                continue
            item_text = str(item_row.get("item") or "").strip()
            if item_text and item_text not in item_to_set:
                item_to_set[item_text] = set_id
    return item_to_set


def _sync_ops_checklist_masters(payload: dict[str, Any]) -> bool:
    checklist_sets = payload.get("checklist_sets") if isinstance(payload.get("checklist_sets"), list) else []
    if not checklist_sets:
        return False

    source_name = str(payload.get("source") or "catalog_sync").strip() or "catalog_sync"
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            existing_sets = conn.execute(
                select(
                    ops_checklist_sets.c.id,
                    ops_checklist_sets.c.set_id,
                    ops_checklist_sets.c.label,
                    ops_checklist_sets.c.task_type,
                    ops_checklist_sets.c.version_no,
                    ops_checklist_sets.c.lifecycle_state,
                    ops_checklist_sets.c.source,
                )
            ).mappings().all()
            existing_set_by_id = {
                str(row.get("set_id") or "").strip(): dict(row)
                for row in existing_sets
                if str(row.get("set_id") or "").strip()
            }
            existing_item_rows = conn.execute(
                select(
                    ops_checklist_set_items.c.set_id,
                    ops_checklist_set_items.c.seq,
                    ops_checklist_set_items.c.item_text,
                )
            ).mappings().all()
            existing_items_by_set: dict[str, list[tuple[int, str]]] = {}
            for row in existing_item_rows:
                set_id = str(row.get("set_id") or "").strip()
                if not set_id:
                    continue
                existing_items_by_set.setdefault(set_id, []).append(
                    (
                        int(row.get("seq") or 0),
                        str(row.get("item_text") or "").strip(),
                    )
                )

            incoming_set_ids: list[str] = []
            for set_row in checklist_sets:
                if not isinstance(set_row, dict):
                    continue
                set_id = str(set_row.get("set_id") or "").strip()
                label = str(set_row.get("label") or "").strip()
                task_type = str(set_row.get("task_type") or "점검").strip() or "점검"
                existing = existing_set_by_id.get(set_id)
                try:
                    incoming_version_no = int(set_row.get("version_no") or (existing.get("version_no") if existing else 1) or 1)
                except (TypeError, ValueError, AttributeError):
                    incoming_version_no = int(existing.get("version_no") or 1) if isinstance(existing, dict) else 1
                incoming_version_no = max(1, incoming_version_no)
                lifecycle_state = _normalize_ops_master_lifecycle_state(
                    set_row.get("lifecycle_state"),
                    default=(
                        _normalize_ops_master_lifecycle_state(existing.get("lifecycle_state"))
                        if isinstance(existing, dict)
                        else OPS_MASTER_LIFECYCLE_ACTIVE
                    ),
                )
                items_raw = set_row.get("items") if isinstance(set_row.get("items"), list) else []
                if not set_id or not label or not items_raw:
                    continue
                if set_id not in incoming_set_ids:
                    incoming_set_ids.append(set_id)

                if existing is None:
                    conn.execute(
                        insert(ops_checklist_sets).values(
                            set_id=set_id,
                            label=label,
                            task_type=task_type,
                            version_no=incoming_version_no,
                            lifecycle_state=lifecycle_state,
                            source=source_name,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                elif (
                    str(existing.get("label") or "").strip() != label
                    or str(existing.get("task_type") or "").strip() != task_type
                    or int(existing.get("version_no") or 1) != incoming_version_no
                    or _normalize_ops_master_lifecycle_state(existing.get("lifecycle_state")) != lifecycle_state
                    or str(existing.get("source") or "").strip() != source_name
                ):
                    conn.execute(
                        update(ops_checklist_sets)
                        .where(ops_checklist_sets.c.set_id == set_id)
                        .values(
                            label=label,
                            task_type=task_type,
                            version_no=incoming_version_no,
                            lifecycle_state=lifecycle_state,
                            source=source_name,
                            updated_at=now,
                        )
                    )

                normalized_items: list[tuple[int, str]] = []
                for idx, item_row in enumerate(items_raw, start=1):
                    if not isinstance(item_row, dict):
                        continue
                    item_text = str(item_row.get("item") or "").strip()
                    if not item_text:
                        continue
                    try:
                        seq = int(item_row.get("seq"))
                    except Exception:
                        seq = idx
                    normalized_items.append((max(1, seq), item_text))

                current_items = sorted(existing_items_by_set.get(set_id, []), key=lambda row: (row[0], row[1]))
                next_items = sorted(normalized_items, key=lambda row: (row[0], row[1]))
                if current_items != next_items:
                    conn.execute(
                        delete(ops_checklist_set_items).where(ops_checklist_set_items.c.set_id == set_id)
                    )
                    if next_items:
                        conn.execute(
                            insert(ops_checklist_set_items),
                            [
                                {
                                    "set_id": set_id,
                                    "seq": seq,
                                    "item_text": item_text,
                                    "created_at": now,
                                    "updated_at": now,
                                }
                                for seq, item_text in next_items
                            ],
                        )

            stale_set_ids = [
                set_id
                for set_id in existing_set_by_id
                if set_id and set_id not in incoming_set_ids
            ]
            if stale_set_ids:
                conn.execute(
                    delete(ops_checklist_set_items).where(ops_checklist_set_items.c.set_id.in_(stale_set_ids))
                )
                conn.execute(
                    delete(ops_checklist_sets).where(ops_checklist_sets.c.set_id.in_(stale_set_ids))
                )
        return True
    except SQLAlchemyError:
        return False


def _load_ops_master_catalog_snapshot_from_db() -> dict[str, Any] | None:
    try:
        with get_conn() as conn:
            checklist_set_rows = conn.execute(
                select(
                    ops_checklist_sets.c.id,
                    ops_checklist_sets.c.set_id,
                    ops_checklist_sets.c.label,
                    ops_checklist_sets.c.task_type,
                    ops_checklist_sets.c.version_no,
                    ops_checklist_sets.c.lifecycle_state,
                    ops_checklist_sets.c.source,
                    ops_checklist_sets.c.updated_at,
                )
                .order_by(ops_checklist_sets.c.id.asc())
            ).mappings().all()
            checklist_item_rows = conn.execute(
                select(
                    ops_checklist_set_items.c.set_id,
                    ops_checklist_set_items.c.seq,
                    ops_checklist_set_items.c.item_text,
                )
                .order_by(
                    ops_checklist_set_items.c.set_id.asc(),
                    ops_checklist_set_items.c.seq.asc(),
                    ops_checklist_set_items.c.id.asc(),
                )
            ).mappings().all()
            equipment_rows = conn.execute(
                select(
                    ops_equipment_assets.c.id,
                    ops_equipment_assets.c.equipment_key,
                    ops_equipment_assets.c.equipment_name,
                    ops_equipment_assets.c.location_name,
                    ops_equipment_assets.c.lifecycle_state,
                    ops_equipment_assets.c.source,
                    ops_equipment_assets.c.updated_at,
                )
                .order_by(ops_equipment_assets.c.id.asc())
            ).mappings().all()
            qr_rows = conn.execute(
                select(
                    ops_qr_assets.c.id,
                    ops_qr_assets.c.qr_id,
                    ops_qr_assets.c.equipment_id,
                    ops_qr_assets.c.equipment_snapshot,
                    ops_qr_assets.c.equipment_location_snapshot,
                    ops_qr_assets.c.default_item,
                    ops_qr_assets.c.checklist_set_id,
                    ops_qr_assets.c.lifecycle_state,
                    ops_qr_assets.c.source,
                    ops_qr_assets.c.updated_at,
                )
                .order_by(ops_qr_assets.c.id.asc())
            ).mappings().all()
    except SQLAlchemyError:
        return None

    items_by_set: dict[str, list[dict[str, Any]]] = {}
    for row in checklist_item_rows:
        set_id = str(row.get("set_id") or "").strip()
        if not set_id:
            continue
        items_by_set.setdefault(set_id, []).append(
            {
                "seq": int(row.get("seq") or 0),
                "item": str(row.get("item_text") or "").strip(),
            }
        )

    checklist_sets: list[dict[str, Any]] = []
    item_to_set: dict[str, str] = {}
    for row in checklist_set_rows:
        set_id = str(row.get("set_id") or "").strip()
        if not set_id:
            continue
        items = [
            item
            for item in items_by_set.get(set_id, [])
            if str(item.get("item") or "").strip()
        ]
        for item in items:
            item_text = str(item.get("item") or "").strip()
            if item_text and item_text not in item_to_set:
                item_to_set[item_text] = set_id
        checklist_sets.append(
            {
                "checklist_master_id": int(row["id"]),
                "set_id": set_id,
                "label": str(row.get("label") or "").strip(),
                "task_type": str(row.get("task_type") or "").strip() or "점검",
                "version_no": max(1, int(row.get("version_no") or 1)),
                "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
                "source": str(row.get("source") or "").strip() or "catalog",
                "updated_at": (
                    _as_datetime(row.get("updated_at")).isoformat()
                    if row.get("updated_at") is not None
                    else None
                ),
                "item_count": len(items),
                "items": items,
            }
        )

    equipment_assets: list[dict[str, Any]] = []
    equipment_by_id: dict[int, dict[str, Any]] = {}
    for row in equipment_rows:
        equipment_id = int(row["id"])
        equipment_row = {
            "equipment_id": equipment_id,
            "equipment_key": str(row.get("equipment_key") or "").strip(),
            "equipment": str(row.get("equipment_name") or "").strip(),
            "location": str(row.get("location_name") or "").strip(),
            "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
            "source": str(row.get("source") or "").strip() or "catalog",
            "updated_at": (
                _as_datetime(row.get("updated_at")).isoformat()
                if row.get("updated_at") is not None
                else None
            ),
        }
        equipment_assets.append(equipment_row)
        equipment_by_id[equipment_id] = equipment_row

    qr_assets: list[dict[str, Any]] = []
    for row in qr_rows:
        equipment_id = int(row["equipment_id"]) if row.get("equipment_id") is not None else None
        equipment_master = equipment_by_id.get(equipment_id) if equipment_id is not None else None
        default_item = str(row.get("default_item") or "").strip()
        checklist_set_id = str(row.get("checklist_set_id") or "").strip()
        if not checklist_set_id and default_item:
            checklist_set_id = item_to_set.get(default_item, "")
        qr_assets.append(
            {
                "qr_asset_id": int(row["id"]),
                "qr_id": str(row.get("qr_id") or "").strip(),
                "equipment_id": equipment_id,
                "equipment": (
                    str(equipment_master.get("equipment") or "").strip()
                    if isinstance(equipment_master, dict)
                    else str(row.get("equipment_snapshot") or "").strip()
                ),
                "location": (
                    str(equipment_master.get("location") or "").strip()
                    if isinstance(equipment_master, dict)
                    else str(row.get("equipment_location_snapshot") or "").strip()
                ),
                "default_item": default_item,
                "checklist_set_id": checklist_set_id or None,
                "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
                "source": str(row.get("source") or "").strip() or "catalog",
                "updated_at": (
                    _as_datetime(row.get("updated_at")).isoformat()
                    if row.get("updated_at") is not None
                    else None
                ),
            }
        )

    return {
        "checklist_sets": checklist_sets,
        "equipment_assets": equipment_assets,
        "qr_assets": qr_assets,
    }


def _sync_ops_asset_masters(payload: dict[str, Any]) -> dict[str, Any] | None:
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    if not qr_assets:
        return {"equipment_id_by_key": {}, "qr_by_id": {}}

    item_to_set = _build_ops_checklist_item_to_set_map(payload)
    equipment_candidates: dict[str, dict[str, str]] = {}
    qr_candidates: list[dict[str, Any]] = []
    for raw_row in qr_assets:
        if not isinstance(raw_row, dict):
            continue
        qr_id = str(raw_row.get("qr_id") or "").strip()
        if not qr_id:
            continue
        equipment_name = str(raw_row.get("equipment") or "").strip()
        location_name = str(raw_row.get("location") or "").strip()
        default_item = str(raw_row.get("default_item") or "").strip()
        equipment_key = _normalize_ops_equipment_key(equipment_name, location_name)
        if equipment_key is not None and equipment_key not in equipment_candidates:
            equipment_candidates[equipment_key] = {
                "equipment_name": equipment_name,
                "location_name": location_name,
            }
        qr_candidates.append(
            {
                "qr_id": qr_id,
                "equipment_key": equipment_key,
                "equipment_snapshot": equipment_name or None,
                "equipment_location_snapshot": location_name or None,
                "default_item": default_item or None,
                "checklist_set_id": item_to_set.get(default_item),
            }
        )

    source_name = str(payload.get("source") or "catalog_sync").strip() or "catalog_sync"
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            equipment_rows = conn.execute(
                select(
                    ops_equipment_assets.c.id,
                    ops_equipment_assets.c.equipment_key,
                    ops_equipment_assets.c.equipment_name,
                    ops_equipment_assets.c.location_name,
                )
            ).mappings().all()
            equipment_id_by_key: dict[str, int] = {}
            equipment_row_by_key: dict[str, dict[str, Any]] = {}
            for row in equipment_rows:
                equipment_key = str(row.get("equipment_key") or "").strip()
                if equipment_key:
                    equipment_id_by_key[equipment_key] = int(row["id"])
                    equipment_row_by_key[equipment_key] = dict(row)

            for equipment_key, candidate in equipment_candidates.items():
                equipment_id = equipment_id_by_key.get(equipment_key)
                if equipment_id is None:
                    result = conn.execute(
                        insert(ops_equipment_assets).values(
                            equipment_key=equipment_key,
                            equipment_name=str(candidate.get("equipment_name") or "").strip(),
                            location_name=str(candidate.get("location_name") or "").strip() or None,
                            lifecycle_state=OPS_MASTER_LIFECYCLE_ACTIVE,
                            source=source_name,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                    inserted_id = result.inserted_primary_key[0] if result.inserted_primary_key else None
                    if inserted_id is None:
                        inserted_row = conn.execute(
                            select(ops_equipment_assets.c.id)
                            .where(ops_equipment_assets.c.equipment_key == equipment_key)
                            .limit(1)
                        ).first()
                        inserted_id = inserted_row[0] if inserted_row is not None else None
                    if inserted_id is None:
                        continue
                    equipment_id_by_key[equipment_key] = int(inserted_id)
                    equipment_row_by_key[equipment_key] = {
                        "id": int(inserted_id),
                        "equipment_name": str(candidate.get("equipment_name") or "").strip(),
                        "location_name": str(candidate.get("location_name") or "").strip() or None,
                    }
                    continue

                current = equipment_row_by_key.get(equipment_key) or {}
                next_equipment_name = str(candidate.get("equipment_name") or "").strip()
                next_location_name = str(candidate.get("location_name") or "").strip() or None
                if (
                    str(current.get("equipment_name") or "").strip() != next_equipment_name
                    or (str(current.get("location_name") or "").strip() or None) != next_location_name
                ):
                    conn.execute(
                        update(ops_equipment_assets)
                        .where(ops_equipment_assets.c.id == equipment_id)
                        .values(
                            equipment_name=next_equipment_name,
                            location_name=next_location_name,
                            source=source_name,
                            updated_at=now,
                        )
                    )
                    equipment_row_by_key[equipment_key] = {
                        "id": equipment_id,
                        "equipment_name": next_equipment_name,
                        "location_name": next_location_name,
                    }

            qr_rows = conn.execute(
                select(
                    ops_qr_assets.c.id,
                    ops_qr_assets.c.qr_id,
                    ops_qr_assets.c.equipment_id,
                    ops_qr_assets.c.equipment_snapshot,
                    ops_qr_assets.c.equipment_location_snapshot,
                    ops_qr_assets.c.default_item,
                    ops_qr_assets.c.checklist_set_id,
                )
            ).mappings().all()
            qr_by_id: dict[str, dict[str, Any]] = {}
            for row in qr_rows:
                qr_id = str(row.get("qr_id") or "").strip()
                if qr_id:
                    qr_by_id[qr_id] = {
                        "id": int(row["id"]),
                        "equipment_id": int(row["equipment_id"]) if row.get("equipment_id") is not None else None,
                        "equipment_snapshot": str(row.get("equipment_snapshot") or "").strip() or None,
                        "equipment_location_snapshot": str(row.get("equipment_location_snapshot") or "").strip() or None,
                        "default_item": str(row.get("default_item") or "").strip() or None,
                        "checklist_set_id": str(row.get("checklist_set_id") or "").strip() or None,
                    }

            for candidate in qr_candidates:
                qr_id = str(candidate.get("qr_id") or "").strip()
                if not qr_id:
                    continue
                equipment_key = candidate.get("equipment_key")
                equipment_id = (
                    equipment_id_by_key.get(str(equipment_key))
                    if isinstance(equipment_key, str)
                    else None
                )
                values = {
                    "equipment_id": equipment_id,
                    "equipment_snapshot": candidate.get("equipment_snapshot"),
                    "equipment_location_snapshot": candidate.get("equipment_location_snapshot"),
                    "default_item": candidate.get("default_item"),
                    "checklist_set_id": candidate.get("checklist_set_id"),
                    "source": source_name,
                    "updated_at": now,
                }
                existing = qr_by_id.get(qr_id)
                if existing is None:
                    result = conn.execute(
                        insert(ops_qr_assets).values(
                            qr_id=qr_id,
                            lifecycle_state=OPS_MASTER_LIFECYCLE_ACTIVE,
                            created_at=now,
                            **values,
                        )
                    )
                    inserted_id = result.inserted_primary_key[0] if result.inserted_primary_key else None
                    if inserted_id is None:
                        inserted_row = conn.execute(
                            select(ops_qr_assets.c.id).where(ops_qr_assets.c.qr_id == qr_id).limit(1)
                        ).first()
                        inserted_id = inserted_row[0] if inserted_row is not None else None
                    if inserted_id is None:
                        continue
                    qr_by_id[qr_id] = {
                        "id": int(inserted_id),
                        "equipment_id": equipment_id,
                        "equipment_snapshot": candidate.get("equipment_snapshot"),
                        "equipment_location_snapshot": candidate.get("equipment_location_snapshot"),
                        "default_item": candidate.get("default_item"),
                        "checklist_set_id": candidate.get("checklist_set_id"),
                    }
                    continue

                current_equipment_snapshot = str(existing.get("equipment_snapshot") or "").strip() or None
                current_location_snapshot = str(existing.get("equipment_location_snapshot") or "").strip() or None
                current_default_item = str(existing.get("default_item") or "").strip() or None
                current_checklist_set_id = str(existing.get("checklist_set_id") or "").strip() or None
                if (
                    existing.get("equipment_id") != equipment_id
                    or current_equipment_snapshot != candidate.get("equipment_snapshot")
                    or current_location_snapshot != candidate.get("equipment_location_snapshot")
                    or current_default_item != candidate.get("default_item")
                    or current_checklist_set_id != candidate.get("checklist_set_id")
                ):
                    conn.execute(
                        update(ops_qr_assets)
                        .where(ops_qr_assets.c.id == int(existing["id"]))
                        .values(**values)
                    )
                qr_by_id[qr_id] = {
                    "id": int(existing["id"]),
                    "equipment_id": equipment_id,
                    "equipment_snapshot": candidate.get("equipment_snapshot"),
                    "equipment_location_snapshot": candidate.get("equipment_location_snapshot"),
                    "default_item": candidate.get("default_item"),
                    "checklist_set_id": candidate.get("checklist_set_id"),
                }

        return {
            "equipment_id_by_key": equipment_id_by_key,
            "qr_by_id": qr_by_id,
        }
    except SQLAlchemyError:
        return None


def _attach_ops_asset_master_ids(payload: dict[str, Any]) -> dict[str, Any]:
    master_sync = _sync_ops_asset_masters(payload)
    if not isinstance(master_sync, dict):
        return payload

    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    equipment_id_by_key = (
        master_sync.get("equipment_id_by_key")
        if isinstance(master_sync.get("equipment_id_by_key"), dict)
        else {}
    )
    qr_by_id = master_sync.get("qr_by_id") if isinstance(master_sync.get("qr_by_id"), dict) else {}
    enriched_qr_assets: list[dict[str, Any]] = []
    for row in qr_assets:
        equipment_key = _normalize_ops_equipment_key(row.get("equipment"), row.get("location"))
        qr_id = str(row.get("qr_id") or "").strip()
        qr_master = qr_by_id.get(qr_id) if qr_id else None
        enriched_row = dict(row)
        enriched_row["equipment_id"] = (
            int(qr_master["equipment_id"])
            if isinstance(qr_master, dict) and qr_master.get("equipment_id") is not None
            else (
                int(equipment_id_by_key[equipment_key])
                if isinstance(equipment_key, str) and equipment_key in equipment_id_by_key
                else None
            )
        )
        enriched_row["qr_asset_id"] = (
            int(qr_master["id"])
            if isinstance(qr_master, dict) and qr_master.get("id") is not None
            else None
        )
        if not str(enriched_row.get("checklist_set_id") or "").strip():
            checklist_set_id = (
                str(qr_master.get("checklist_set_id") or "").strip()
                if isinstance(qr_master, dict)
                else ""
            )
            if checklist_set_id:
                enriched_row["checklist_set_id"] = checklist_set_id
        enriched_qr_assets.append(enriched_row)
    next_payload = dict(payload)
    next_payload["qr_assets"] = enriched_qr_assets
    return next_payload


def _build_ops_special_checklists_payload_from_masters(base_payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(base_payload)
    _sync_ops_checklist_masters(payload)

    master_snapshot = _load_ops_master_catalog_snapshot_from_db()
    if isinstance(master_snapshot, dict) and master_snapshot.get("checklist_sets"):
        payload["checklist_sets"] = master_snapshot["checklist_sets"]

    payload = _attach_ops_asset_master_ids(payload)

    master_snapshot = _load_ops_master_catalog_snapshot_from_db()
    if not isinstance(master_snapshot, dict):
        payload.setdefault("equipment_assets", [])
        return payload

    next_payload = dict(payload)
    if master_snapshot.get("checklist_sets"):
        next_payload["checklist_sets"] = master_snapshot["checklist_sets"]
    if master_snapshot.get("qr_assets"):
        next_payload["qr_assets"] = master_snapshot["qr_assets"]
    next_payload["equipment_assets"] = (
        master_snapshot.get("equipment_assets")
        if isinstance(master_snapshot.get("equipment_assets"), list)
        else []
    )
    return next_payload


def _load_ops_special_checklists_payload() -> dict[str, Any]:
    return _build_ops_special_checklists_payload_from_masters(
        _read_ops_special_checklists_source_payload()
    )


def _export_ops_special_checklists_payload_from_masters(*, source: str) -> Path:
    base_payload = _read_ops_special_checklists_source_payload()
    master_payload = _load_ops_master_catalog_snapshot_from_db() or {}
    now = datetime.now(timezone.utc)
    export_payload = {
        "source_file": str(base_payload.get("source_file") or _resolve_ops_special_checklists_data_path().as_posix()),
        "source": source,
        "version": now.strftime("%Y-%m-%d"),
        "checklist_version": now.strftime("%Y-%m-%d"),
        "applied_at": now.isoformat(),
        "checklist_sets": [
            {
                "set_id": str(row.get("set_id") or "").strip(),
                "label": str(row.get("label") or "").strip(),
                "task_type": str(row.get("task_type") or "점검").strip() or "점검",
                "version_no": max(1, int(row.get("version_no") or 1)),
                "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
                "items": [
                    {
                        "seq": int(item.get("seq") or idx),
                        "item": str(item.get("item") or "").strip(),
                    }
                    for idx, item in enumerate(row.get("items") or [], start=1)
                    if isinstance(item, dict) and str(item.get("item") or "").strip()
                ],
            }
            for row in (
                master_payload.get("checklist_sets")
                if isinstance(master_payload.get("checklist_sets"), list)
                else base_payload.get("checklist_sets", [])
            )
            if isinstance(row, dict) and str(row.get("set_id") or "").strip()
        ],
        "equipment_assets": [
            {
                "equipment_id": int(row.get("equipment_id") or 0),
                "equipment_key": str(row.get("equipment_key") or "").strip(),
                "equipment": str(row.get("equipment") or "").strip(),
                "location": str(row.get("location") or "").strip(),
                "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
            }
            for row in (
                master_payload.get("equipment_assets")
                if isinstance(master_payload.get("equipment_assets"), list)
                else []
            )
            if isinstance(row, dict) and int(row.get("equipment_id") or 0) > 0
        ],
        "ops_codes": [
            {
                "code": str(row.get("code") or "").strip(),
                "category": str(row.get("category") or "").strip(),
                "description": str(row.get("description") or "").strip(),
            }
            for row in base_payload.get("ops_codes", [])
            if isinstance(row, dict) and str(row.get("code") or "").strip()
        ],
        "qr_assets": [
            {
                "qr_id": str(row.get("qr_id") or "").strip(),
                "equipment": str(row.get("equipment") or "").strip(),
                "location": str(row.get("location") or "").strip(),
                "default_item": str(row.get("default_item") or "").strip(),
                "lifecycle_state": _normalize_ops_master_lifecycle_state(row.get("lifecycle_state")),
            }
            for row in (
                master_payload.get("qr_assets")
                if isinstance(master_payload.get("qr_assets"), list)
                else base_payload.get("qr_assets", [])
            )
            if isinstance(row, dict) and str(row.get("qr_id") or "").strip()
        ],
    }
    return _persist_ops_special_checklists_payload(export_payload)


def _append_ops_import_validation_issue(
    buckets: dict[tuple[str, str, str, str], dict[str, Any]],
    *,
    severity: str,
    category: str,
    code: str,
    message: str,
    reference: str = "",
) -> None:
    normalized_severity = str(severity or "warning").strip().lower() or "warning"
    normalized_category = str(category or "general").strip() or "general"
    normalized_code = str(code or "issue").strip() or "issue"
    normalized_message = str(message or "").strip() or "issue detected"
    normalized_reference = str(reference or "").strip()
    key = (normalized_severity, normalized_category, normalized_code, normalized_message)
    bucket = buckets.get(key)
    if bucket is None:
        bucket = {
            "severity": normalized_severity,
            "category": normalized_category,
            "code": normalized_code,
            "message": normalized_message,
            "count": 0,
            "references": [],
        }
        buckets[key] = bucket
    bucket["count"] = int(bucket["count"]) + 1
    references = bucket.get("references")
    if normalized_reference and isinstance(references, list) and len(references) < 5:
        references.append(normalized_reference)


def _build_ops_checklists_import_validation_report() -> dict[str, Any]:
    payload = _load_ops_special_checklists_payload()
    generated_at = datetime.now(timezone.utc)
    checklist_sets = payload.get("checklist_sets") if isinstance(payload.get("checklist_sets"), list) else []
    ops_codes = payload.get("ops_codes") if isinstance(payload.get("ops_codes"), list) else []
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    source_file = str(payload.get("source_file") or "")
    source_exists = False
    if source_file:
        source_path = Path(source_file)
        source_exists = source_path.exists()

    issue_buckets: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    task_types: set[str] = set()
    global_item_to_set: dict[str, str] = {}
    checklist_item_total = 0

    seen_set_ids: set[str] = set()
    for set_idx, set_row in enumerate(checklist_sets, start=1):
        if not isinstance(set_row, dict):
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_sets",
                code="invalid_set",
                message="checklist set row must be an object",
                reference=f"checklist_sets[{set_idx}]",
            )
            continue
        set_id = str(set_row.get("set_id") or "").strip()
        label = str(set_row.get("label") or "").strip()
        task_type = str(set_row.get("task_type") or "").strip()
        if not set_id:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_sets",
                code="missing_set_id",
                message="checklist set id is missing",
                reference=f"checklist_sets[{set_idx}]",
            )
        elif set_id in seen_set_ids:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_sets",
                code="duplicate_set_id",
                message=f"duplicate checklist set id: {set_id}",
                reference=f"checklist_sets[{set_idx}]",
            )
        else:
            seen_set_ids.add(set_id)
        if not label:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_sets",
                code="missing_label",
                message="checklist set label is missing",
                reference=f"checklist_sets[{set_idx}]",
            )
        if not task_type:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_sets",
                code="missing_task_type",
                message="checklist set task_type is missing",
                reference=f"checklist_sets[{set_idx}]",
            )
        else:
            task_types.add(task_type)

        items = set_row.get("items")
        if not isinstance(items, list) or len(items) == 0:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_items",
                code="empty_items",
                message="checklist set has no items",
                reference=f"checklist_sets[{set_idx}]",
            )
            continue

        if set_id == "electrical_60" and len(items) != 60:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_items",
                code="electrical_60_count_mismatch",
                message=f"electrical_60 expected 60 items, found {len(items)}",
                reference=f"checklist_sets[{set_idx}]",
            )
        if set_id == "fire_legal" and len(items) != 18:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_items",
                code="fire_legal_count_mismatch",
                message=f"fire_legal expected 18 items, found {len(items)}",
                reference=f"checklist_sets[{set_idx}]",
            )

        seen_seq: set[int] = set()
        seen_item_text: set[str] = set()
        for item_idx, item_row in enumerate(items, start=1):
            if not isinstance(item_row, dict):
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="error",
                    category="checklist_items",
                    code="invalid_item_row",
                    message="checklist item row must be an object",
                    reference=f"{set_id}.items[{item_idx}]",
                )
                continue
            checklist_item_total += 1
            item_text = str(item_row.get("item") or "").strip()
            seq_raw = item_row.get("seq")
            try:
                seq = int(seq_raw)
            except (TypeError, ValueError):
                seq = -1
            if seq <= 0:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="warning",
                    category="checklist_items",
                    code="invalid_seq",
                    message="item seq should be a positive integer",
                    reference=f"{set_id}.items[{item_idx}]",
                )
            elif seq in seen_seq:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="warning",
                    category="checklist_items",
                    code="duplicate_seq",
                    message=f"duplicate seq in set {set_id}: {seq}",
                    reference=f"{set_id}.items[{item_idx}]",
                )
            else:
                seen_seq.add(seq)

            if not item_text:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="error",
                    category="checklist_items",
                    code="missing_item_text",
                    message="item text is missing",
                    reference=f"{set_id}.items[{item_idx}]",
                )
                continue
            if item_text in seen_item_text:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="warning",
                    category="checklist_items",
                    code="duplicate_item_text",
                    message=f"duplicate item text in set {set_id}: {item_text}",
                    reference=f"{set_id}.items[{item_idx}]",
                )
            else:
                seen_item_text.add(item_text)
            global_item_to_set.setdefault(item_text, set_id)

    category_to_set: dict[str, str] = {}
    for set_row in checklist_sets:
        if not isinstance(set_row, dict):
            continue
        set_id = str(set_row.get("set_id") or "").strip()
        task_type = str(set_row.get("task_type") or "").strip()
        if set_id and task_type:
            if "전기" in task_type and "전기" not in category_to_set:
                category_to_set["전기"] = set_id
            if "소방" in task_type and "소방" not in category_to_set:
                category_to_set["소방"] = set_id
            if "기계" in task_type and "기계" not in category_to_set:
                category_to_set["기계"] = set_id
            if "건축" in task_type and "건축" not in category_to_set:
                category_to_set["건축"] = set_id
            if "안전" in task_type and "안전" not in category_to_set:
                category_to_set["안전"] = set_id

    seen_ops_codes: set[str] = set()
    for idx, row in enumerate(ops_codes, start=1):
        if not isinstance(row, dict):
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="ops_codes",
                code="invalid_code_row",
                message="ops code row must be an object",
                reference=f"ops_codes[{idx}]",
            )
            continue
        code = str(row.get("code") or "").strip()
        category = str(row.get("category") or "").strip()
        description = str(row.get("description") or "").strip()
        if not code:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="ops_codes",
                code="missing_code",
                message="ops code is missing",
                reference=f"ops_codes[{idx}]",
            )
            continue
        if code in seen_ops_codes:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="ops_codes",
                code="duplicate_code",
                message=f"duplicate ops code: {code}",
                reference=f"ops_codes[{idx}]",
            )
        else:
            seen_ops_codes.add(code)
        if not category:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="ops_codes",
                code="missing_category",
                message=f"ops code category is missing: {code}",
                reference=f"ops_codes[{idx}]",
            )
            continue
        normalized = f"{category} {description}".lower()
        mapped = False
        if "전기" in normalized and category_to_set.get("전기"):
            mapped = True
        if "소방" in normalized and category_to_set.get("소방"):
            mapped = True
        if "기계" in normalized and category_to_set.get("기계"):
            mapped = True
        if "건축" in normalized and category_to_set.get("건축"):
            mapped = True
        if "안전" in normalized and category_to_set.get("안전"):
            mapped = True
        if not mapped:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="ops_codes",
                code="unmapped_category",
                message=f"ops code category is not mapped to checklist set: {code}",
                reference=f"ops_codes[{idx}]",
            )

    seen_qr_ids: set[str] = set()
    for idx, row in enumerate(qr_assets, start=1):
        if not isinstance(row, dict):
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="qr_assets",
                code="invalid_qr_row",
                message="qr asset row must be an object",
                reference=f"qr_assets[{idx}]",
            )
            continue
        qr_id = str(row.get("qr_id") or "").strip()
        equipment = str(row.get("equipment") or "").strip()
        location = str(row.get("location") or "").strip()
        default_item = str(row.get("default_item") or "").strip()
        if not qr_id:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="qr_assets",
                code="missing_qr_id",
                message="qr_id is missing",
                reference=f"qr_assets[{idx}]",
            )
            continue
        if qr_id in seen_qr_ids:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="qr_assets",
                code="duplicate_qr_id",
                message=f"duplicate qr_id: {qr_id}",
                reference=f"qr_assets[{idx}]",
            )
        else:
            seen_qr_ids.add(qr_id)

        placeholder_flags = _qr_asset_placeholder_flags(
            {
                "equipment": equipment,
                "location": location,
                "default_item": default_item,
            }
        )
        for flag in placeholder_flags:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="qr_assets",
                code=flag,
                message=f"{flag.replace('_', ' ')} for {qr_id}",
                reference=f"qr_assets[{idx}]",
            )
        if default_item and default_item not in global_item_to_set:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="qr_assets",
                code="unknown_default_item",
                message=f"default_item is not registered in checklist sets for {qr_id}",
                reference=f"qr_assets[{idx}]",
            )

    if source_file and not source_exists:
        _append_ops_import_validation_issue(
            issue_buckets,
            severity="warning",
            category="source",
            code="source_file_not_found",
            message=f"source file path does not exist: {source_file}",
            reference="source_file",
        )

    severity_order = {"error": 0, "warning": 1, "info": 2}
    issues = sorted(
        issue_buckets.values(),
        key=lambda row: (
            severity_order.get(str(row.get("severity") or "warning"), 9),
            str(row.get("category") or ""),
            str(row.get("code") or ""),
            str(row.get("message") or ""),
        ),
    )

    error_count = sum(int(row.get("count") or 0) for row in issues if str(row.get("severity")) == "error")
    warning_count = sum(int(row.get("count") or 0) for row in issues if str(row.get("severity")) == "warning")
    status = "ok"
    if error_count > 0:
        status = "error"
    elif warning_count > 0:
        status = "warning"

    suggestions: list[str] = []
    issue_codes = {str(row.get("code") or "") for row in issues}
    if "placeholder_equipment" in issue_codes or "placeholder_location" in issue_codes or "placeholder_default_item" in issue_codes:
        suggestions.append("QR설비관리 시트의 placeholder 값(설비/위치/점검항목)을 실제 설비 데이터로 치환하세요.")
    if "unknown_default_item" in issue_codes:
        suggestions.append("QR default_item을 checklist set 항목명과 1:1로 맞추고 오탈자를 제거하세요.")
    if "unmapped_category" in issue_codes:
        suggestions.append("OPS코드 분류(기계/건축/안전 등)별 checklist_set을 추가하거나 category 매핑 규칙을 확정하세요.")
    if "duplicate_set_id" in issue_codes or "duplicate_code" in issue_codes or "duplicate_qr_id" in issue_codes:
        suggestions.append("중복 key(set_id/code/qr_id)를 제거하고 마스터키 유일성을 보장하세요.")
    if not suggestions:
        suggestions.append("치명적 정합성 이슈가 없으며 현재 데이터로 운영을 진행할 수 있습니다.")

    return {
        "generated_at": generated_at.isoformat(),
        "source_file": source_file,
        "source_file_exists": source_exists,
        "version": str(payload.get("version") or ""),
        **_build_ops_checklist_response_meta(payload, endpoint="/api/ops/inspections/checklists/import-validation"),
        "status": status,
        "summary": {
            "checklist_set_count": len(checklist_sets),
            "checklist_item_count": checklist_item_total,
            "ops_code_count": len(ops_codes),
            "qr_asset_count": len(qr_assets),
            "task_type_count": len(task_types),
            "error_count": error_count,
            "warning_count": warning_count,
            "issue_bucket_count": len(issues),
        },
        "task_types": sorted(task_types),
        "issues": issues,
        "suggestions": suggestions,
    }


def _build_ops_checklists_import_validation_csv(report: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["generated_at", str(report.get("generated_at") or "")])
    writer.writerow(["status", str(report.get("status") or "")])
    writer.writerow(["source_file", str(report.get("source_file") or "")])
    writer.writerow(["version", str(report.get("version") or "")])
    writer.writerow(["checklist_version", str(report.get("checklist_version") or "")])
    writer.writerow(["source", str(report.get("source") or "")])
    writer.writerow(["applied_at", str(report.get("applied_at") or "")])

    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    writer.writerow([])
    writer.writerow(["summary_key", "value"])
    for key in (
        "checklist_set_count",
        "checklist_item_count",
        "ops_code_count",
        "qr_asset_count",
        "task_type_count",
        "error_count",
        "warning_count",
        "issue_bucket_count",
    ):
        writer.writerow([key, summary.get(key, "")])

    writer.writerow([])
    writer.writerow(["severity", "category", "code", "count", "message", "references"])
    issues = report.get("issues") if isinstance(report.get("issues"), list) else []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        references = issue.get("references")
        if isinstance(references, list):
            references_text = " | ".join(str(item) for item in references if str(item).strip())
        else:
            references_text = str(references or "")
        writer.writerow(
            [
                issue.get("severity", ""),
                issue.get("category", ""),
                issue.get("code", ""),
                issue.get("count", ""),
                issue.get("message", ""),
                references_text,
            ]
        )

    suggestions = report.get("suggestions") if isinstance(report.get("suggestions"), list) else []
    writer.writerow([])
    writer.writerow(["suggestions"])
    for suggestion in suggestions:
        writer.writerow([str(suggestion or "")])
    return out.getvalue()


def _build_ops_checklist_item_set(payload: dict[str, Any]) -> set[str]:
    checklist_sets = payload.get("checklist_sets") if isinstance(payload.get("checklist_sets"), list) else []
    item_set: set[str] = set()
    for set_row in checklist_sets:
        if not isinstance(set_row, dict):
            continue
        items = set_row.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            text = str(item.get("item") or "").strip()
            if text:
                item_set.add(text)
    return item_set


def _build_ops_qr_placeholder_snapshot(payload: dict[str, Any]) -> list[dict[str, Any]]:
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    rows: list[dict[str, Any]] = []
    for row in qr_assets:
        if not isinstance(row, dict):
            continue
        qr_id = str(row.get("qr_id") or "").strip()
        if not qr_id:
            continue
        flags = _qr_asset_placeholder_flags(row)
        if not flags:
            continue
        rows.append(
            {
                "qr_id": qr_id,
                "equipment": str(row.get("equipment") or "").strip(),
                "location": str(row.get("location") or "").strip(),
                "default_item": str(row.get("default_item") or "").strip(),
                "flags": flags,
            }
        )
    rows.sort(key=lambda item: str(item.get("qr_id") or ""))
    return rows


def _coerce_request_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "y", "yes", "on"}:
        return True
    if normalized in {"0", "false", "n", "no", "off"}:
        return False
    return default


def _build_ops_qr_placeholder_report(payload: dict[str, Any]) -> dict[str, Any]:
    rows = _build_ops_qr_placeholder_snapshot(payload)
    flag_counts: dict[str, int] = {}
    for row in rows:
        flags = row.get("flags")
        if not isinstance(flags, list):
            continue
        for flag in flags:
            key = str(flag or "").strip()
            if not key:
                continue
            flag_counts[key] = flag_counts.get(key, 0) + 1
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(payload.get("source_file") or ""),
        "version": str(payload.get("version") or ""),
        **_build_ops_checklist_response_meta(payload, endpoint="/api/ops/inspections/checklists/qr-assets/placeholders"),
        "status": "warning" if rows else "ok",
        "summary": {
            "qr_asset_count": len(qr_assets),
            "placeholder_row_count": len(rows),
            "placeholder_flag_counts": flag_counts,
        },
        "rows": rows,
        "suggestions": (
            ["placeholder 행이 남아 있습니다. bulk-update API로 실제 설비값으로 치환하세요."]
            if rows
            else ["placeholder 행이 없습니다. 현재 QR 자산 데이터는 운영 가능한 상태입니다."]
        ),
    }


def _build_ops_qr_revision_snapshot_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    return {
        str(row.get("qr_id") or "").strip(): dict(row)
        for row in qr_assets
        if isinstance(row, dict) and str(row.get("qr_id") or "").strip()
    }


def _record_ops_qr_asset_revisions(revisions: list[dict[str, Any]]) -> int:
    rows_to_insert: list[dict[str, Any]] = []
    for revision in revisions:
        if not isinstance(revision, dict):
            continue
        qr_id = str(revision.get("qr_id") or "").strip()
        if not qr_id:
            continue
        before_row = revision.get("before") if isinstance(revision.get("before"), dict) else {}
        after_row = revision.get("after") if isinstance(revision.get("after"), dict) else {}
        quality_flags = revision.get("quality_flags") if isinstance(revision.get("quality_flags"), list) else []
        qr_asset_id_raw = revision.get("qr_asset_id")
        try:
            qr_asset_id = int(qr_asset_id_raw) if qr_asset_id_raw is not None else None
        except (TypeError, ValueError):
            qr_asset_id = None
        created_at = revision.get("created_at")
        if not isinstance(created_at, datetime):
            created_at = datetime.now(timezone.utc)
        rows_to_insert.append(
            {
                "qr_asset_id": qr_asset_id,
                "qr_id": qr_id,
                "change_source": str(revision.get("change_source") or "qr_asset_api").strip() or "qr_asset_api",
                "change_action": str(revision.get("change_action") or "updated").strip() or "updated",
                "change_note": str(revision.get("change_note") or "").strip(),
                "before_json": _to_json_text(before_row),
                "after_json": _to_json_text(after_row),
                "quality_flags_json": json.dumps(quality_flags, ensure_ascii=False, default=str),
                "created_by": str(revision.get("created_by") or "system").strip() or "system",
                "created_at": created_at,
            }
        )
    if not rows_to_insert:
        return 0
    with get_conn() as conn:
        conn.execute(insert(ops_qr_asset_revisions), rows_to_insert)
    return len(rows_to_insert)


def _apply_ops_qr_asset_bulk_update_request(request_payload: dict[str, Any]) -> dict[str, Any]:
    body = request_payload if isinstance(request_payload, dict) else {}
    updates_raw = body.get("updates")
    if not isinstance(updates_raw, list) or not updates_raw:
        raise HTTPException(status_code=422, detail="updates must be a non-empty array")

    dry_run = _coerce_request_bool(body.get("dry_run"), default=True)
    create_missing = _coerce_request_bool(body.get("create_missing"), default=False)
    allow_placeholder_values = _coerce_request_bool(body.get("allow_placeholder_values"), default=False)
    actor_username = str(body.get("_actor_username") or "system").strip() or "system"

    payload = _load_ops_special_checklists_payload()
    qr_assets_raw = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    qr_assets: list[dict[str, str]] = []
    for row in qr_assets_raw:
        if not isinstance(row, dict):
            continue
        qr_id = str(row.get("qr_id") or "").strip()
        if not qr_id:
            continue
        qr_assets.append(
            {
                "qr_id": qr_id,
                "equipment": str(row.get("equipment") or "").strip(),
                "location": str(row.get("location") or "").strip(),
                "default_item": str(row.get("default_item") or "").strip(),
            }
        )

    before_payload = {**payload, "qr_assets": [dict(row) for row in qr_assets]}
    before_placeholder_rows = _build_ops_qr_placeholder_snapshot(before_payload)
    checklist_item_set = _build_ops_checklist_item_set(payload)
    unknown_default_before = sum(
        1
        for row in qr_assets
        if str(row.get("default_item") or "").strip()
        and str(row.get("default_item") or "").strip() not in checklist_item_set
    )

    index_by_qr_id: dict[str, int] = {str(row.get("qr_id") or ""): idx for idx, row in enumerate(qr_assets)}
    seen_request_qr_ids: set[str] = set()
    changed_rows: list[dict[str, Any]] = []
    skipped_rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    updated_count = 0
    created_count = 0

    for idx, raw in enumerate(updates_raw, start=1):
        if not isinstance(raw, dict):
            invalid_rows.append({"index": idx, "reason": "invalid_row_type", "message": "row must be an object"})
            continue

        qr_id = str(raw.get("qr_id") or "").strip()
        if not qr_id:
            invalid_rows.append({"index": idx, "reason": "missing_qr_id", "message": "qr_id is required"})
            continue
        if qr_id in seen_request_qr_ids:
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": "duplicate_qr_id_in_request",
                    "message": "duplicate qr_id in updates array",
                }
            )
            continue
        seen_request_qr_ids.add(qr_id)

        requested_fields = [field for field in OPS_QR_MUTABLE_FIELDS if field in raw]
        update_fields: dict[str, str] = {}
        blocked_placeholder_fields: list[str] = []
        for field in requested_fields:
            value = str(raw.get(field) or "").strip()
            if not value:
                continue
            if (not allow_placeholder_values) and value in OPS_QR_PLACEHOLDER_VALUES:
                blocked_placeholder_fields.append(field)
                continue
            update_fields[field] = value
        if not update_fields:
            reason = "no_effective_fields"
            message = "no updatable non-empty fields"
            if blocked_placeholder_fields:
                reason = "blocked_placeholder_values"
                message = "placeholder values are blocked for fields: " + ", ".join(blocked_placeholder_fields)
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": reason,
                    "message": message,
                }
            )
            continue

        existing_index = index_by_qr_id.get(qr_id)
        if existing_index is None and not create_missing:
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": "qr_id_not_found",
                    "message": "qr_id does not exist (create_missing=false)",
                }
            )
            continue
        if existing_index is None and create_missing:
            missing_for_create = [field for field in OPS_QR_MUTABLE_FIELDS if field not in update_fields]
            if missing_for_create:
                skipped_rows.append(
                    {
                        "index": idx,
                        "qr_id": qr_id,
                        "reason": "missing_required_fields_for_create",
                        "message": "create_missing=true requires all fields: " + ", ".join(missing_for_create),
                    }
                )
                continue

        action = "updated" if existing_index is not None else "created"
        before_row = (
            dict(qr_assets[existing_index])
            if existing_index is not None
            else {"qr_id": qr_id, "equipment": "", "location": "", "default_item": ""}
        )
        after_row = dict(before_row)
        changed_fields: list[str] = []
        for field, value in update_fields.items():
            if str(after_row.get(field) or "").strip() == value:
                continue
            after_row[field] = value
            changed_fields.append(field)
        if not changed_fields:
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": "unchanged",
                    "message": "all provided values already match current row",
                }
            )
            continue

        if existing_index is not None:
            qr_assets[existing_index] = after_row
            updated_count += 1
        else:
            index_by_qr_id[qr_id] = len(qr_assets)
            qr_assets.append(after_row)
            created_count += 1

        quality_flags = _qr_asset_placeholder_flags(after_row)
        default_item = str(after_row.get("default_item") or "").strip()
        if default_item and default_item not in checklist_item_set:
            quality_flags.append("unknown_default_item")
        changed_rows.append(
            {
                "index": idx,
                "qr_id": qr_id,
                "action": action,
                "changed_fields": changed_fields,
                "before": before_row,
                "after": after_row,
                "quality_flags": quality_flags,
            }
        )

    after_payload = {**payload, "qr_assets": qr_assets}
    after_placeholder_rows = _build_ops_qr_placeholder_snapshot(after_payload)
    unknown_default_after = sum(
        1
        for row in qr_assets
        if str(row.get("default_item") or "").strip()
        and str(row.get("default_item") or "").strip() not in checklist_item_set
    )
    applied_count = updated_count + created_count

    saved = False
    saved_path = ""
    revision_saved_count = 0
    metadata_payload = after_payload
    if (not dry_run) and applied_count > 0:
        saved_at = datetime.now(timezone.utc)
        next_payload = {**after_payload}
        next_payload["version"] = saved_at.strftime("%Y-%m-%d")
        next_payload["checklist_version"] = next_payload["version"]
        next_payload["source"] = "qr_bulk_update_api"
        next_payload["applied_at"] = saved_at.isoformat()
        persisted = _persist_ops_special_checklists_payload(next_payload)
        metadata_payload = _load_ops_special_checklists_payload()
        before_revision_map = _build_ops_qr_revision_snapshot_map(before_payload)
        after_revision_map = _build_ops_qr_revision_snapshot_map(metadata_payload)
        revision_saved_count = _record_ops_qr_asset_revisions(
            [
                {
                    "qr_asset_id": (
                        (after_revision_map.get(str(row.get("qr_id") or "").strip()) or {}).get("qr_asset_id")
                        or (before_revision_map.get(str(row.get("qr_id") or "").strip()) or {}).get("qr_asset_id")
                    ),
                    "qr_id": str(row.get("qr_id") or "").strip(),
                    "change_source": "qr_bulk_update_api",
                    "change_action": str(row.get("action") or "updated").strip() or "updated",
                    "change_note": "qr placeholder bulk update",
                    "before": before_revision_map.get(str(row.get("qr_id") or "").strip()) or row.get("before") or {},
                    "after": after_revision_map.get(str(row.get("qr_id") or "").strip()) or row.get("after") or {},
                    "quality_flags": row.get("quality_flags") or [],
                    "created_by": actor_username,
                    "created_at": saved_at,
                }
                for row in changed_rows
                if str(row.get("qr_id") or "").strip()
            ]
        )
        saved = True
        saved_path = persisted.as_posix()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "create_missing": create_missing,
        "allow_placeholder_values": allow_placeholder_values,
        "saved": saved,
        "saved_path": saved_path,
        **_build_ops_checklist_response_meta(
            metadata_payload,
            endpoint="/api/ops/inspections/checklists/qr-assets/bulk-update",
        ),
        "summary": {
            "requested_count": len(updates_raw),
            "applied_count": applied_count,
            "updated_count": updated_count,
            "created_count": created_count,
            "skipped_count": len(skipped_rows),
            "invalid_count": len(invalid_rows),
            "placeholder_row_count_before": len(before_placeholder_rows),
            "placeholder_row_count_after": len(after_placeholder_rows),
            "placeholder_row_resolved": max(0, len(before_placeholder_rows) - len(after_placeholder_rows)),
            "unknown_default_item_count_before": unknown_default_before,
            "unknown_default_item_count_after": unknown_default_after,
            "revision_saved_count": revision_saved_count,
        },
        "changes": changed_rows,
        "skipped": skipped_rows,
        "invalid_rows": invalid_rows,
        "remaining_placeholder_rows": after_placeholder_rows[:20],
    }

