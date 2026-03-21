"""Inspection and evidence helpers extracted from app.main."""

from __future__ import annotations

import hashlib
import json
import secrets
import string
from datetime import datetime, timezone
from os import getenv
from pathlib import Path, PurePosixPath
from typing import Any

from app.domains.ops.schemas import InspectionCreate, InspectionEvidenceRead, InspectionRead

OPS_CHECKLIST_NOTE_TAGS = ("[OPS_CHECKLIST_V1]", "[OPS_ELECTRICAL_V1]")
EVIDENCE_ALLOWED_CONTENT_TYPES = {
    value.strip().lower()
    for value in getenv(
        "EVIDENCE_ALLOWED_CONTENT_TYPES",
        ",".join(
            [
                "application/pdf",
                "text/plain",
                "text/csv",
                "application/json",
                "image/png",
                "image/jpeg",
                "image/webp",
            ]
        ),
    ).split(",")
    if value.strip()
}
EVIDENCE_STORAGE_BACKEND = getenv("EVIDENCE_STORAGE_BACKEND", "fs").strip().lower() or "fs"
EVIDENCE_STORAGE_PATH = getenv("EVIDENCE_STORAGE_PATH", "data/evidence-objects").strip() or "data/evidence-objects"
EVIDENCE_SCAN_MODE = getenv("EVIDENCE_SCAN_MODE", "basic").strip().lower() or "basic"
EVIDENCE_SCAN_BLOCK_SUSPICIOUS = getenv("EVIDENCE_SCAN_BLOCK_SUSPICIOUS", "").strip().lower() in {"1", "true", "yes", "on"}

_SAMPLE_EVIDENCE_ARTIFACTS = {
    "w02-sample-sx-ins-01-proof.txt": (
        "W02 Sample Evidence\n"
        "Scenario: SX-INS-01\n"
        "Module: Inspection\n"
        "Result: PASS\n"
        "Checked Items:\n"
        "- risk_level warning/danger 검증 완료\n"
        "- risk_flags 임계치 검증 완료\n"
        "- print view 렌더링 정상\n"
    ).encode("utf-8"),
    "w02-sample-sx-wo-01-proof.txt": (
        "W02 Sample Evidence\n"
        "Scenario: SX-WO-01\n"
        "Module: Work-order + SLA\n"
        "Result: PASS\n"
        "Checked Items:\n"
        "- open->acked->completed 전이 검증 완료\n"
        "- escalation 배치 결과 타겟 포함 확인\n"
        "- timeline status_changed 이벤트 확인\n"
    ).encode("utf-8"),
    "w02-sample-sx-rpt-01-proof.txt": (
        "W02 Sample Evidence\n"
        "Scenario: SX-RPT-01\n"
        "Module: Reporting + Audit\n"
        "Result: PASS\n"
        "Checked Items:\n"
        "- monthly summary 수치 확인\n"
        "- csv/pdf 다운로드 확인\n"
        "- export audit 로그 기록 확인\n"
    ).encode("utf-8"),
}
SAMPLE_EVIDENCE_ARTIFACTS_BY_FILE = {
    file_name: {
        "bytes": content,
        "sha256": hashlib.sha256(content).hexdigest(),
        "file_size": len(content),
    }
    for file_name, content in _SAMPLE_EVIDENCE_ARTIFACTS.items()
}


def bind(namespace: dict[str, object]) -> None:
    return None


def _parse_ops_checklist_notes(note_text: str) -> dict[str, Any] | None:
    text = str(note_text or "")
    if not any(tag in text for tag in OPS_CHECKLIST_NOTE_TAGS):
        return None
    meta: dict[str, Any] = {}
    checklist: list[Any] = []
    memo = ""
    parse_errors: list[str] = []
    for line in text.splitlines():
        if line.startswith("meta="):
            raw = line[5:].strip()
            try:
                parsed = json.loads(raw)
            except Exception:
                parse_errors.append("meta JSON parse failed")
                continue
            if isinstance(parsed, dict):
                meta = parsed
            else:
                parse_errors.append("meta must be a JSON object")
            continue
        if line.startswith("checklist="):
            raw = line[10:].strip()
            try:
                parsed = json.loads(raw)
            except Exception:
                parse_errors.append("checklist JSON parse failed")
                continue
            if isinstance(parsed, list):
                checklist = parsed
            else:
                parse_errors.append("checklist must be a JSON list")
            continue
        if line.startswith("memo="):
            memo = line[5:]
    return {
        "meta": meta,
        "checklist": checklist,
        "memo": memo,
        "parse_errors": parse_errors,
    }


def _extract_ops_abnormal_count(parsed_ops_notes: dict[str, Any] | None) -> int:
    if not parsed_ops_notes:
        return 0
    meta = parsed_ops_notes.get("meta") if isinstance(parsed_ops_notes, dict) else None
    summary = meta.get("summary") if isinstance(meta, dict) else None
    if isinstance(summary, dict):
        try:
            return max(0, int(summary.get("abnormal", 0)))
        except (TypeError, ValueError):
            pass

    checklist_rows = parsed_ops_notes.get("checklist") if isinstance(parsed_ops_notes, dict) else None
    if isinstance(checklist_rows, list):
        total = 0
        for row in checklist_rows:
            if not isinstance(row, dict):
                continue
            result = str(row.get("result") or "").strip().lower()
            if result == "abnormal":
                total += 1
        return total
    return 0


def _calculate_risk(
    payload: InspectionCreate,
    *,
    parsed_ops_notes: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
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

    parsed_notes = parsed_ops_notes or _parse_ops_checklist_notes(str(payload.notes or ""))
    abnormal_count = _extract_ops_abnormal_count(parsed_notes)
    if abnormal_count > 0:
        flags.append("ops_check_abnormal")

    if "insulation_low" in flags or "temp_high" in flags:
        return "danger", flags
    if flags:
        return "warning", flags
    return "normal", flags


def _extract_optional_positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _extract_ops_snapshot_values(parsed_ops_notes: dict[str, Any] | None) -> dict[str, str | int | None]:
    meta = parsed_ops_notes.get("meta") if isinstance(parsed_ops_notes, dict) else None
    if not isinstance(meta, dict):
        return {
            "equipment_id": None,
            "qr_asset_id": None,
            "equipment_snapshot": None,
            "equipment_location_snapshot": None,
            "qr_id": None,
            "checklist_set_id": None,
            "checklist_version": None,
        }

    equipment_id = _extract_optional_positive_int(meta.get("equipment_id"))
    qr_asset_id = _extract_optional_positive_int(meta.get("qr_asset_id"))
    equipment_snapshot = str(meta.get("equipment") or "").strip() or None
    equipment_location_snapshot = str(meta.get("equipment_location") or "").strip() or None
    qr_id = str(meta.get("qr_id") or "").strip() or None
    checklist_set_id = str(meta.get("checklist_set_id") or "").strip() or None
    checklist_version = str(meta.get("checklist_data_version") or meta.get("checklist_version") or "").strip() or None
    return {
        "equipment_id": equipment_id,
        "qr_asset_id": qr_asset_id,
        "equipment_snapshot": equipment_snapshot,
        "equipment_location_snapshot": equipment_location_snapshot,
        "qr_id": qr_id,
        "checklist_set_id": checklist_set_id,
        "checklist_version": checklist_version,
    }


def _ops_snapshot_values_from_inspection_row(row: dict[str, Any] | None) -> dict[str, str | int | None]:
    if not row:
        return {
            "equipment_id": None,
            "qr_asset_id": None,
            "equipment_snapshot": None,
            "equipment_location_snapshot": None,
            "qr_id": None,
            "checklist_set_id": None,
            "checklist_version": None,
        }

    values = {
        "equipment_id": _extract_optional_positive_int(row.get("equipment_id")),
        "qr_asset_id": _extract_optional_positive_int(row.get("qr_asset_id")),
        "equipment_snapshot": str(row.get("equipment_snapshot") or "").strip() or None,
        "equipment_location_snapshot": str(row.get("equipment_location_snapshot") or "").strip() or None,
        "qr_id": str(row.get("qr_id") or "").strip() or None,
        "checklist_set_id": str(row.get("checklist_set_id") or "").strip() or None,
        "checklist_version": str(row.get("checklist_version") or "").strip() or None,
    }
    parsed_notes = _parse_ops_checklist_notes(str(row.get("notes") or ""))
    parsed_values = _extract_ops_snapshot_values(parsed_notes)
    for key, value in parsed_values.items():
        if values.get(key) is None and value is not None:
            values[key] = value
    if values["equipment_snapshot"] is not None and values["equipment_location_snapshot"] is None:
        values["equipment_location_snapshot"] = str(row.get("location") or "").strip() or None
    return values


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


def _safe_download_filename(raw_value: str, *, fallback: str = "download.bin", max_length: int = 120) -> str:
    allowed = set(string.ascii_letters + string.digits + "._-")
    candidate = (raw_value or "").replace("\x00", "").strip()
    sanitized_chars: list[str] = []
    for ch in candidate:
        if ch in allowed:
            sanitized_chars.append(ch)
        elif ch in {" ", "\t"}:
            sanitized_chars.append("_")
    sanitized = "".join(sanitized_chars).strip("._")
    if not sanitized:
        sanitized = fallback
    if max_length > 0 and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized or fallback


def _is_allowed_evidence_content_type(content_type: str) -> bool:
    normalized = content_type.strip().lower()
    if not normalized:
        return False
    if "*" in EVIDENCE_ALLOWED_CONTENT_TYPES:
        return True
    return normalized in EVIDENCE_ALLOWED_CONTENT_TYPES


def _normalize_evidence_storage_backend(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"fs", "filesystem", "file"}:
        return "fs"
    return "db"


def _evidence_storage_root() -> Path:
    candidate = Path(EVIDENCE_STORAGE_PATH)
    if candidate.is_absolute():
        return candidate
    project_root = Path(__file__).resolve().parents[3]
    return project_root / candidate


def _resolve_evidence_storage_abs_path(storage_key: str) -> Path | None:
    key = str(storage_key or "").strip().replace("\\", "/")
    if not key:
        return None
    if key.startswith("/") or key.startswith("\\"):
        return None
    if "\x00" in key:
        return None
    if ".." in PurePosixPath(key).parts:
        return None

    root = _evidence_storage_root().resolve()
    candidate = (root / key).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _ensure_evidence_storage_ready() -> None:
    backend = _normalize_evidence_storage_backend(EVIDENCE_STORAGE_BACKEND)
    if backend != "fs":
        return
    _evidence_storage_root().mkdir(parents=True, exist_ok=True)


def _scan_evidence_bytes(*, file_bytes: bytes, content_type: str) -> tuple[str, str, str | None]:
    if EVIDENCE_SCAN_MODE in {"off", "disabled", "none"}:
        return "skipped", "none", None

    eicar_signature = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    if eicar_signature in file_bytes:
        return "infected", "basic-signature", "eicar-signature-detected"

    if content_type in {"text/html", "application/javascript", "text/javascript"}:
        lowered = file_bytes[:4096].lower()
        if b"<script" in lowered:
            return "suspicious", "basic-pattern", "active-script-pattern-detected"

    return "clean", "basic-signature", None


def _write_evidence_blob(*, file_name: str, file_bytes: bytes, sha256_digest: str) -> tuple[str, str | None, bytes]:
    backend = _normalize_evidence_storage_backend(EVIDENCE_STORAGE_BACKEND)
    if backend != "fs":
        return "db", None, file_bytes

    _ensure_evidence_storage_ready()
    extension = ""
    if "." in file_name:
        extension = "." + file_name.rsplit(".", 1)[1][:16]
    now = datetime.now(timezone.utc)
    storage_key = (
        f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
        f"{sha256_digest[:20]}-{secrets.token_hex(8)}{extension}"
    )
    abs_path = _resolve_evidence_storage_abs_path(storage_key)
    if abs_path is None:
        raise RuntimeError("Invalid evidence storage key generated")
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_bytes(file_bytes)
    return "fs", storage_key, b""


def _resolve_sample_evidence_blob(*, row: dict[str, Any]) -> bytes | None:
    file_name = str(row.get("file_name") or "").strip()
    if not file_name:
        return None
    sample = SAMPLE_EVIDENCE_ARTIFACTS_BY_FILE.get(file_name)
    if sample is None:
        return None

    stored_sha = str(row.get("sha256") or "").strip().lower()
    if stored_sha and stored_sha != str(sample.get("sha256") or ""):
        return None

    try:
        file_size = int(row.get("file_size") or 0)
    except (TypeError, ValueError):
        file_size = 0
    if file_size > 0 and file_size != int(sample.get("file_size") or 0):
        return None

    blob = sample.get("bytes")
    return bytes(blob) if isinstance(blob, (bytes, bytearray)) else None


def _read_evidence_blob(*, row: dict[str, Any]) -> bytes | None:
    storage_backend = _normalize_evidence_storage_backend(str(row.get("storage_backend") or "db"))
    if storage_backend == "fs":
        storage_key = str(row.get("storage_key") or "").strip()
        abs_path = _resolve_evidence_storage_abs_path(storage_key) if storage_key else None
        if abs_path is not None and abs_path.exists() and abs_path.is_file():
            return abs_path.read_bytes()

        sample_blob = _resolve_sample_evidence_blob(row=row)
        if sample_blob is not None:
            if abs_path is not None:
                try:
                    abs_path.parent.mkdir(parents=True, exist_ok=True)
                    abs_path.write_bytes(sample_blob)
                except OSError:
                    pass
            return sample_blob
        return None

    raw = row.get("file_bytes") or b""
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, bytearray):
        return bytes(raw)
    try:
        return bytes(raw)
    except Exception:
        return None


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
        equipment_id=_extract_optional_positive_int(row.get("equipment_id")),
        qr_asset_id=_extract_optional_positive_int(row.get("qr_asset_id")),
        equipment_snapshot=str(row.get("equipment_snapshot") or "").strip() or None,
        equipment_location_snapshot=str(row.get("equipment_location_snapshot") or "").strip() or None,
        qr_id=str(row.get("qr_id") or "").strip() or None,
        checklist_set_id=str(row.get("checklist_set_id") or "").strip() or None,
        checklist_version=str(row.get("checklist_version") or "").strip() or None,
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


def _row_to_inspection_evidence_model(row: dict[str, Any]) -> InspectionEvidenceRead:
    return InspectionEvidenceRead(
        id=int(row["id"]),
        inspection_id=int(row["inspection_id"]),
        site=str(row["site"]),
        file_name=str(row["file_name"]),
        content_type=str(row.get("content_type") or "application/octet-stream"),
        file_size=int(row.get("file_size") or 0),
        storage_backend=_normalize_evidence_storage_backend(str(row.get("storage_backend") or "db")),
        sha256=str(row.get("sha256") or ""),
        malware_scan_status=str(row.get("malware_scan_status") or "unknown"),
        malware_scan_engine=row.get("malware_scan_engine"),
        malware_scanned_at=_as_optional_datetime(row.get("malware_scanned_at")),
        note=str(row.get("note") or ""),
        uploaded_by=str(row.get("uploaded_by") or "system"),
        uploaded_at=_as_datetime(row["uploaded_at"]),
    )


def _is_overdue(status: str, due_at: datetime | None) -> bool:
    if due_at is None:
        return False
    if status in {"completed", "canceled"}:
        return False
    return due_at < datetime.now(timezone.utc)
