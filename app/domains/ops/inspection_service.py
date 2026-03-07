"""Inspection and evidence helpers extracted from app.main."""

from __future__ import annotations

from app import main as main_module

globals().update(
    {
        key: value
        for key, value in main_module.__dict__.items()
        if key not in {"bind", "main_module", "_LOCAL_SYMBOLS"}
    }
)

_LOCAL_SYMBOLS = {
    'bind',
    'main_module',
    '_LOCAL_SYMBOLS',
    '_calculate_risk',
    '_to_utc',
    '_as_datetime',
    '_as_optional_datetime',
    '_safe_download_filename',
    '_is_allowed_evidence_content_type',
    '_normalize_evidence_storage_backend',
    '_evidence_storage_root',
    '_resolve_evidence_storage_abs_path',
    '_ensure_evidence_storage_ready',
    '_scan_evidence_bytes',
    '_write_evidence_blob',
    '_resolve_sample_evidence_blob',
    '_read_evidence_blob',
    '_row_to_read_model',
    '_row_to_inspection_evidence_model',
    '_is_overdue',
}


def bind(namespace: dict[str, object]) -> None:
    for key, value in namespace.items():
        if key not in _LOCAL_SYMBOLS:
            globals()[key] = value


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
    project_root = Path(__file__).resolve().parent.parent
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

    # EICAR test string detection provides deterministic malware-scan smoke coverage.
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
    # Keep DB rows lightweight when file-system backend is enabled.
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
