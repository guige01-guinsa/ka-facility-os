import importlib
import io
import json
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from tests.helpers.common import _assert_adoption_policy_response_shape, _owner_headers


def _issue_role_headers(
    app_client: TestClient,
    *,
    username: str,
    role: str,
    site_scope: list[str] | None = None,
) -> dict[str, str]:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": username,
            "display_name": username,
            "role": role,
            "permissions": [],
            "site_scope": site_scope or ["*"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]
    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": f"{username}-token"},
    )
    assert issued.status_code == 201
    return {"X-Admin-Token": issued.json()["token"]}


def _build_ops_notes_for_master_validation(
    *,
    equipment: str,
    location: str,
    checklist_set_id: str,
    qr_id: str | None = None,
) -> str:
    meta = {
        "task_type": "전기점검",
        "equipment": equipment,
        "equipment_location": location,
        "checklist_set_id": checklist_set_id,
        "summary": {"total": 2, "normal": 2, "abnormal": 0, "na": 0},
    }
    if qr_id:
        meta["qr_id"] = qr_id
    checklist = [
        {"group": "설비", "item": "외관 상태 확인", "result": "normal", "action": ""},
        {"group": "설비", "item": "운전 상태 확인", "result": "normal", "action": ""},
    ]
    return "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )


@pytest.mark.smoke
def test_inspection_evidence_upload_list_download(app_client: TestClient) -> None:
    headers = _owner_headers()
    inspected_at = datetime.now(timezone.utc).isoformat()
    created = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "Inspection Evidence Site",
            "location": "B1 수변전실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": inspected_at,
            "notes": "inspection evidence upload test",
        },
    )
    assert created.status_code == 201
    inspection_id = created.json()["id"]

    blocked_upload = app_client.post(
        f"/api/inspections/{inspection_id}/evidence",
        headers=headers,
        data={"note": "html not allowed"},
        files={"file": ("bad.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/inspections/{inspection_id}/evidence",
        headers=headers,
        data={"note": "inspection photo evidence"},
        files={"file": ("inspection-photo.txt", b"inspection evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["inspection_id"] == inspection_id
    assert evidence["site"] == "Inspection Evidence Site"
    assert evidence["file_name"] == "inspection-photo.txt"
    assert evidence["file_size"] == len(b"inspection evidence")
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    evidence_list = app_client.get(
        f"/api/inspections/{inspection_id}/evidence",
        headers=headers,
    )
    assert evidence_list.status_code == 200
    evidence_rows = evidence_list.json()
    assert len(evidence_rows) >= 1
    assert any(int(row["id"]) == int(evidence_id) for row in evidence_rows)

    downloaded = app_client.get(
        f"/api/inspections/evidence/{evidence_id}/download",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"inspection evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    missing_list = app_client.get(
        "/api/inspections/999999/evidence",
        headers=headers,
    )
    assert missing_list.status_code == 404

def test_ops_inspection_payload_validation_blocks_missing_required_fields(app_client: TestClient) -> None:
    headers = _owner_headers()
    inspected_at = datetime.now(timezone.utc).isoformat()
    invalid_meta = {
        "task_type": "전기점검",
        "equipment": "변압기",
        "equipment_location": "B1 수변전실",
        "summary": {"total": 1, "normal": 0, "abnormal": 1, "na": 0},
    }
    checklist = [
        {
            "group": "변압기",
            "item": "변압기 외관 점검",
            "result": "abnormal",
            "action": "",
        }
    ]
    notes = "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(invalid_meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )

    created = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "Validation Site",
            "location": "B1 수변전실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": inspected_at,
            "notes": notes,
        },
    )
    assert created.status_code == 422
    body = created.json()
    assert body["detail"]["message"] == "OPS checklist payload validation failed"
    errors = body["detail"]["errors"]
    assert any("meta.checklist_set_id is required" in msg for msg in errors)
    assert any("abnormal checklist rows require row action or meta.abnormal_action" in msg for msg in errors)

def test_ops_inspection_import_validation_report_endpoints(app_client: TestClient) -> None:
    headers = _owner_headers()
    report = app_client.get(
        "/api/ops/inspections/checklists/import-validation",
        headers=headers,
    )
    assert report.status_code == 200
    body = report.json()
    assert body["status"] in {"ok", "warning", "error"}
    assert body["checklist_version"]
    assert body["source"] in {"file", "fallback", "qr_bulk_update_api"}
    assert body["applied_at"] is not None
    assert body["meta"]["schema"] == "ops_checklist_catalog_response"
    assert body["meta"]["schema_version"] == "v1"
    assert body["meta"]["endpoint"] == "/api/ops/inspections/checklists/import-validation"
    assert body["summary"]["checklist_set_count"] >= 2
    assert body["summary"]["checklist_item_count"] >= 10
    assert body["summary"]["ops_code_count"] >= 1
    assert body["summary"]["qr_asset_count"] >= 1
    assert isinstance(body["issues"], list)
    assert isinstance(body["suggestions"], list)

    export = app_client.get(
        "/api/ops/inspections/checklists/import-validation.csv",
        headers=headers,
    )
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    assert "checklist_version," in export.text
    assert "applied_at," in export.text
    assert "severity,category,code,count,message,references" in export.text

def test_ops_inspection_qr_placeholder_snapshot_endpoint(app_client: TestClient) -> None:
    headers = _owner_headers()
    response = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    summary = body["summary"]
    assert body["status"] in {"ok", "warning"}
    assert body["checklist_version"]
    assert body["source"] in {"file", "fallback", "qr_bulk_update_api"}
    assert body["applied_at"] is not None
    assert body["meta"]["endpoint"] == "/api/ops/inspections/checklists/qr-assets/placeholders"
    assert summary["qr_asset_count"] >= 1
    assert summary["placeholder_row_count"] >= 0
    assert isinstance(summary["placeholder_flag_counts"], dict)
    assert isinstance(body["rows"], list)
    if body["rows"]:
        first = body["rows"][0]
        assert first["qr_id"]
        assert isinstance(first["flags"], list)


def test_ops_inspection_checklists_catalog_exposes_master_ids(app_client: TestClient) -> None:
    headers = _owner_headers()
    response = app_client.get(
        "/api/ops/inspections/checklists/catalog",
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["meta"]["endpoint"] == "/api/ops/inspections/checklists/catalog"
    assert body["summary"]["qr_asset_count"] >= 1
    assert body["summary"]["linked_qr_asset_count"] >= 1
    assert body["summary"]["linked_equipment_count"] >= 1
    assert body["summary"]["equipment_asset_count"] >= 1
    assert isinstance(body.get("equipment_assets"), list)
    qr_row = next(row for row in body["qr_assets"] if row["qr_id"] == "QR-002")
    assert int(qr_row["equipment_id"]) > 0
    assert int(qr_row["qr_asset_id"]) > 0
    assert qr_row["checklist_set_id"] == "electrical_60"


def test_ops_master_crud_roundtrip(app_client: TestClient) -> None:
    headers = _owner_headers()

    created_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": "night_safety_ops",
            "label": "야간안전점검",
            "task_type": "안전점검",
            "items": [
                {"seq": 1, "item": "보안등 점등 상태 확인"},
                {"seq": 2, "item": "비상벨 작동 상태 확인"},
            ],
        },
    )
    assert created_set.status_code == 200
    assert created_set.json()["row"]["set_id"] == "night_safety_ops"

    updated_set = app_client.patch(
        "/api/ops/inspections/checklists/sets/night_safety_ops",
        headers=headers,
        json={
            "label": "야간안전점검-개정",
            "task_type": "안전점검",
            "items": [
                {"seq": 1, "item": "보안등 점등 상태 확인"},
                {"seq": 2, "item": "비상벨 작동 상태 확인"},
                {"seq": 3, "item": "주차장 유도등 상태 확인"},
            ],
        },
    )
    assert updated_set.status_code == 200
    assert updated_set.json()["row"]["label"] == "야간안전점검-개정"
    assert int(updated_set.json()["row"]["item_count"]) == 3

    created_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "보안등 1호기",
            "location": "지상 1층 주차장",
        },
    )
    assert created_equipment.status_code == 200
    equipment_row = created_equipment.json()["row"]
    equipment_id = int(equipment_row["equipment_id"])

    updated_equipment = app_client.patch(
        f"/api/ops/inspections/checklists/equipment-assets/{equipment_id}",
        headers=headers,
        json={
            "equipment": "보안등 A",
            "location": "지상 1층 주차장",
        },
    )
    assert updated_equipment.status_code == 200
    assert updated_equipment.json()["row"]["equipment"] == "보안등 A"

    created_qr = app_client.post(
        "/api/ops/inspections/checklists/qr-assets",
        headers=headers,
        json={
            "qr_id": "QR-777",
            "equipment_id": equipment_id,
            "checklist_set_id": "night_safety_ops",
            "default_item": "보안등 점등 상태 확인",
        },
    )
    assert created_qr.status_code == 200
    qr_row = created_qr.json()["row"]
    qr_asset_id = int(qr_row["qr_asset_id"])
    assert qr_row["equipment"] == "보안등 A"

    updated_qr = app_client.patch(
        f"/api/ops/inspections/checklists/qr-assets/{qr_asset_id}",
        headers=headers,
        json={
            "qr_id": "QR-778",
            "equipment_id": equipment_id,
            "checklist_set_id": "night_safety_ops",
            "default_item": "비상벨 작동 상태 확인",
        },
    )
    assert updated_qr.status_code == 200
    assert updated_qr.json()["row"]["qr_id"] == "QR-778"
    assert updated_qr.json()["row"]["default_item"] == "비상벨 작동 상태 확인"

    catalog = app_client.get(
        "/api/ops/inspections/checklists/catalog",
        headers=headers,
    )
    assert catalog.status_code == 200
    catalog_body = catalog.json()
    assert any(row["set_id"] == "night_safety_ops" for row in catalog_body["checklist_sets"])
    assert any(int(row["equipment_id"]) == equipment_id for row in catalog_body["equipment_assets"])
    assert any(int(row["qr_asset_id"]) == qr_asset_id for row in catalog_body["qr_assets"])

    deleted_qr = app_client.delete(
        f"/api/ops/inspections/checklists/qr-assets/{qr_asset_id}",
        headers=headers,
    )
    assert deleted_qr.status_code == 200

    deleted_equipment = app_client.delete(
        f"/api/ops/inspections/checklists/equipment-assets/{equipment_id}",
        headers=headers,
    )
    assert deleted_equipment.status_code == 200

    deleted_set = app_client.delete(
        "/api/ops/inspections/checklists/sets/night_safety_ops",
        headers=headers,
    )
    assert deleted_set.status_code == 200


def test_ops_master_crud_supports_inspection_flow(app_client: TestClient) -> None:
    headers = _owner_headers()

    created_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": "generator_ops",
            "label": "발전기점검",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "발전기 외관 상태 확인"},
                {"seq": 2, "item": "연료 및 누유 상태 확인"},
            ],
        },
    )
    assert created_set.status_code == 200

    created_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "비상발전기 1호기",
            "location": "지상 1층 발전기실",
        },
    )
    assert created_equipment.status_code == 200
    equipment_id = int(created_equipment.json()["row"]["equipment_id"])

    created_qr = app_client.post(
        "/api/ops/inspections/checklists/qr-assets",
        headers=headers,
        json={
            "qr_id": "QR-880",
            "equipment_id": equipment_id,
            "checklist_set_id": "generator_ops",
            "default_item": "발전기 외관 상태 확인",
        },
    )
    assert created_qr.status_code == 200
    qr_asset_id = int(created_qr.json()["row"]["qr_asset_id"])

    inspected_at = datetime.now(timezone.utc).isoformat()
    notes = "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta="
            + json.dumps(
                {
                    "task_type": "기계점검",
                    "equipment": "비상발전기 1호기",
                    "equipment_location": "지상 1층 발전기실",
                    "qr_id": "QR-880",
                    "checklist_set_id": "generator_ops",
                    "summary": {"total": 2, "normal": 2, "abnormal": 0, "na": 0},
                },
                ensure_ascii=False,
            ),
            "checklist="
            + json.dumps(
                [
                    {"group": "발전기", "item": "발전기 외관 상태 확인", "result": "normal", "action": ""},
                    {"group": "발전기", "item": "연료 및 누유 상태 확인", "result": "normal", "action": ""},
                ],
                ensure_ascii=False,
            ),
        ]
    )
    inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "Generator Site",
            "location": "지상 1층 발전기실",
            "cycle": "monthly",
            "inspector": "owner_ci",
            "inspected_at": inspected_at,
            "equipment_id": equipment_id,
            "qr_asset_id": qr_asset_id,
            "notes": notes,
        },
    )
    assert inspection.status_code == 201
    inspection_body = inspection.json()
    assert inspection_body["checklist_set_id"] == "generator_ops"
    assert inspection_body["equipment_id"] == equipment_id
    assert inspection_body["qr_asset_id"] == qr_asset_id

    blocked_qr_delete = app_client.delete(
        f"/api/ops/inspections/checklists/qr-assets/{qr_asset_id}",
        headers=headers,
    )
    assert blocked_qr_delete.status_code == 409

    blocked_set_delete = app_client.delete(
        "/api/ops/inspections/checklists/sets/generator_ops",
        headers=headers,
    )
    assert blocked_set_delete.status_code == 409


def test_ops_master_lifecycle_states_are_exposed_and_enforced(app_client: TestClient) -> None:
    headers = _owner_headers()

    created_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": "lifecycle_ops",
            "label": "라이프사이클 점검",
            "task_type": "전기점검",
            "lifecycle_state": "active",
            "items": [
                {"seq": 1, "item": "외관 상태 확인"},
                {"seq": 2, "item": "운전 상태 확인"},
            ],
        },
    )
    assert created_set.status_code == 200
    assert created_set.json()["row"]["lifecycle_state"] == "active"
    assert created_set.json()["row"]["version_no"] == 1

    created_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "라이프사이클 펌프",
            "location": "지하 1층 기계실",
            "lifecycle_state": "active",
        },
    )
    assert created_equipment.status_code == 200
    equipment_id = int(created_equipment.json()["row"]["equipment_id"])
    assert created_equipment.json()["row"]["lifecycle_state"] == "active"

    retired_equipment = app_client.patch(
        f"/api/ops/inspections/checklists/equipment-assets/{equipment_id}",
        headers=headers,
        json={
            "equipment": "라이프사이클 펌프",
            "location": "지하 1층 기계실",
            "lifecycle_state": "retired",
        },
    )
    assert retired_equipment.status_code == 200
    assert retired_equipment.json()["row"]["lifecycle_state"] == "retired"

    inspection_retired_equipment = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "Lifecycle Site",
            "location": "지하 1층 기계실",
            "cycle": "monthly",
            "inspector": "owner_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
            "equipment_id": equipment_id,
            "notes": _build_ops_notes_for_master_validation(
                equipment="라이프사이클 펌프",
                location="지하 1층 기계실",
                checklist_set_id="lifecycle_ops",
            ),
        },
    )
    assert inspection_retired_equipment.status_code == 422
    assert inspection_retired_equipment.json()["detail"] == "equipment_id is not active"

    retired_set = app_client.patch(
        "/api/ops/inspections/checklists/sets/lifecycle_ops",
        headers=headers,
        json={
            "label": "라이프사이클 점검",
            "task_type": "전기점검",
            "lifecycle_state": "retired",
            "items": [
                {"seq": 1, "item": "외관 상태 확인"},
                {"seq": 2, "item": "운전 상태 확인"},
            ],
        },
    )
    assert retired_set.status_code == 200
    assert retired_set.json()["row"]["lifecycle_state"] == "retired"
    assert retired_set.json()["row"]["version_no"] == 2

    inspection_retired_set = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "Lifecycle Site",
            "location": "지하 1층 기계실",
            "cycle": "monthly",
            "inspector": "owner_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
            "notes": _build_ops_notes_for_master_validation(
                equipment="체크리스트 전용 설비",
                location="지하 1층 기계실",
                checklist_set_id="lifecycle_ops",
            ),
        },
    )
    assert inspection_retired_set.status_code == 422
    assert inspection_retired_set.json()["detail"] == "checklist_set_id is not active"

    catalog = app_client.get("/api/ops/inspections/checklists/catalog", headers=headers)
    assert catalog.status_code == 200
    body = catalog.json()
    lifecycle_row = next(row for row in body["checklist_sets"] if row["set_id"] == "lifecycle_ops")
    assert lifecycle_row["lifecycle_state"] == "retired"
    assert lifecycle_row["version_no"] == 2
    lifecycle_equipment = next(row for row in body["equipment_assets"] if int(row["equipment_id"]) == equipment_id)
    assert lifecycle_equipment["lifecycle_state"] == "retired"


def test_ops_checklist_revision_approval_flow(app_client: TestClient) -> None:
    headers = _owner_headers()
    manager_headers = _issue_role_headers(
        app_client,
        username="ops_revision_manager_ci",
        role="manager",
    )
    approver_headers = _issue_role_headers(
        app_client,
        username="ops_revision_owner_ci",
        role="owner",
    )
    release_note = "\n".join(
        [
            "Summary: submit pump checklist revision",
            "Impact: approvers can review the revised maintenance item set",
            "Rollback: keep the current live checklist if the revision is rejected",
        ]
    )

    base_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": "pump_revision_ops",
            "label": "펌프점검",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
            ],
        },
    )
    assert base_set.status_code == 200

    direct_manager_update = app_client.patch(
        "/api/ops/inspections/checklists/sets/pump_revision_ops",
        headers=manager_headers,
        json={
            "label": "manager live update should fail",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
            ],
        },
    )
    assert direct_manager_update.status_code == 403

    created_revision = app_client.post(
        "/api/ops/inspections/checklists/revisions",
        headers=manager_headers,
        json={
            "set_id": "pump_revision_ops",
            "label": "펌프점검-개정1",
            "task_type": "기계점검",
            "lifecycle_state": "active",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
                {"seq": 3, "item": "패킹 누수 상태 확인"},
            ],
            "note": "add leakage check",
        },
    )
    assert created_revision.status_code == 200
    revision = created_revision.json()["row"]
    revision_id = int(revision["id"])
    assert revision["status"] == "draft"
    assert revision["proposed_version_no"] == 2

    listed = app_client.get(
        "/api/ops/inspections/checklists/revisions?set_id=pump_revision_ops",
        headers=headers,
    )
    assert listed.status_code == 200
    assert any(int(row["id"]) == revision_id for row in listed.json()["rows"])

    submitted = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{revision_id}/submit",
        headers=manager_headers,
        json={"note": release_note},
    )
    assert submitted.status_code == 200
    assert submitted.json()["row"]["status"] == "pending"

    self_approve = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{revision_id}/approve",
        headers=manager_headers,
        json={"note": "self approve should fail"},
    )
    assert self_approve.status_code == 409

    approved = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{revision_id}/approve",
        headers=approver_headers,
        json={"note": "approved by second approver"},
    )
    assert approved.status_code == 200
    approved_row = approved.json()["row"]
    assert approved_row["status"] == "approved"
    assert approved_row["proposed_version_no"] == 2
    assert approved.json()["saved_path"].endswith(".json")

    catalog = app_client.get("/api/ops/inspections/checklists/catalog", headers=headers)
    assert catalog.status_code == 200
    catalog_row = next(row for row in catalog.json()["checklist_sets"] if row["set_id"] == "pump_revision_ops")
    assert catalog_row["label"] == "펌프점검-개정1"
    assert catalog_row["version_no"] == 2
    assert int(catalog_row["item_count"]) == 3

    approve_again = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{revision_id}/approve",
        headers=approver_headers,
        json={"note": "approve twice should fail"},
    )
    assert approve_again.status_code == 409

    rejected_revision = app_client.post(
        "/api/ops/inspections/checklists/revisions",
        headers=manager_headers,
        json={
            "set_id": "pump_revision_ops",
            "label": "펌프점검-개정2",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
                {"seq": 3, "item": "패킹 누수 상태 확인"},
                {"seq": 4, "item": "흡입압력 상태 확인"},
            ],
            "note": "secondary proposal",
        },
    )
    assert rejected_revision.status_code == 200
    rejected_revision_id = int(rejected_revision.json()["row"]["id"])

    rejected_submit = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{rejected_revision_id}/submit",
        headers=manager_headers,
        json={"note": release_note},
    )
    assert rejected_submit.status_code == 200

    rejected = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{rejected_revision_id}/reject",
        headers=approver_headers,
        json={"note": "not this sprint"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["row"]["status"] == "rejected"


def test_ops_master_search_and_lifecycle_filters(app_client: TestClient) -> None:
    headers = _owner_headers()
    active_token = "filter-ci-active"
    retired_token = "filter-ci-retired"

    active_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": active_token,
            "label": "Filter Active Checklist",
            "task_type": "전기점검",
            "lifecycle_state": "active",
            "items": [
                {"seq": 1, "item": "active item one"},
                {"seq": 2, "item": "active item two"},
            ],
        },
    )
    assert active_set.status_code == 200

    retired_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": retired_token,
            "label": "Filter Retired Checklist",
            "task_type": "전기점검",
            "lifecycle_state": "retired",
            "items": [
                {"seq": 1, "item": "retired item one"},
                {"seq": 2, "item": "retired item two"},
            ],
        },
    )
    assert retired_set.status_code == 200

    active_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "filter-ci active pump",
            "location": "B1 active room",
            "lifecycle_state": "active",
        },
    )
    assert active_equipment.status_code == 200
    active_equipment_id = int(active_equipment.json()["row"]["equipment_id"])

    retired_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "filter-ci retired pump",
            "location": "B2 retired room",
            "lifecycle_state": "retired",
        },
    )
    assert retired_equipment.status_code == 200
    retired_equipment_id = int(retired_equipment.json()["row"]["equipment_id"])

    active_qr = app_client.post(
        "/api/ops/inspections/checklists/qr-assets",
        headers=headers,
        json={
            "qr_id": "QR-FILTER-CI-ACTIVE",
            "equipment_id": active_equipment_id,
            "checklist_set_id": active_token,
            "default_item": "active item one",
            "lifecycle_state": "active",
        },
    )
    assert active_qr.status_code == 200

    retired_qr = app_client.post(
        "/api/ops/inspections/checklists/qr-assets",
        headers=headers,
        json={
            "qr_id": "QR-FILTER-CI-RETIRED",
            "equipment_id": retired_equipment_id,
            "checklist_set_id": retired_token,
            "default_item": "retired item one",
            "lifecycle_state": "retired",
        },
    )
    assert retired_qr.status_code == 200

    active_only_sets = app_client.get(
        "/api/ops/inspections/checklists/sets?q=filter-ci&include_inactive=false",
        headers=headers,
    )
    assert active_only_sets.status_code == 200
    active_only_set_ids = {str(row["set_id"]) for row in active_only_sets.json()["rows"]}
    assert active_token in active_only_set_ids
    assert retired_token not in active_only_set_ids
    assert active_only_sets.json()["summary"]["filters"]["include_inactive"] is False

    retired_equipment_rows = app_client.get(
        "/api/ops/inspections/checklists/equipment-assets?q=filter-ci&lifecycle_state=retired",
        headers=headers,
    )
    assert retired_equipment_rows.status_code == 200
    equipment_rows = retired_equipment_rows.json()["rows"]
    assert any(int(row["equipment_id"]) == retired_equipment_id for row in equipment_rows)
    assert all(str(row["lifecycle_state"]) == "retired" for row in equipment_rows)

    retired_qr_rows = app_client.get(
        "/api/ops/inspections/checklists/qr-assets?q=filter-ci&lifecycle_state=retired",
        headers=headers,
    )
    assert retired_qr_rows.status_code == 200
    qr_rows = retired_qr_rows.json()["rows"]
    assert any(str(row["qr_id"]) == "QR-FILTER-CI-RETIRED" for row in qr_rows)
    assert all(str(row["lifecycle_state"]) == "retired" for row in qr_rows)

    retired_catalog = app_client.get(
        "/api/ops/inspections/checklists/catalog?q=filter-ci&lifecycle_state=retired",
        headers=headers,
    )
    assert retired_catalog.status_code == 200
    catalog_body = retired_catalog.json()
    assert catalog_body["summary"]["filters"]["q"] == "filter-ci"
    assert catalog_body["summary"]["filters"]["lifecycle_state"] == "retired"
    assert any(str(row["set_id"]) == retired_token for row in catalog_body["checklist_sets"])
    assert any(int(row["equipment_id"]) == retired_equipment_id for row in catalog_body["equipment_assets"])
    assert any(str(row["qr_id"]) == "QR-FILTER-CI-RETIRED" for row in catalog_body["qr_assets"])
    assert all(str(row["lifecycle_state"]) == "retired" for row in catalog_body["checklist_sets"])
    assert all(str(row["lifecycle_state"]) == "retired" for row in catalog_body["equipment_assets"])
    assert all(str(row["lifecycle_state"]) == "retired" for row in catalog_body["qr_assets"])


def test_ops_checklist_revision_release_note_rules_and_diff(app_client: TestClient) -> None:
    headers = _owner_headers()
    manager_headers = _issue_role_headers(
        app_client,
        username="ops_revision_diff_manager_ci",
        role="manager",
    )
    approver_headers = _issue_role_headers(
        app_client,
        username="ops_revision_diff_owner_ci",
        role="owner",
    )

    base_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": "pump_revision_diff_ci",
            "label": "펌프점검 원본",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
            ],
        },
    )
    assert base_set.status_code == 200

    created_revision = app_client.post(
        "/api/ops/inspections/checklists/revisions",
        headers=manager_headers,
        json={
            "set_id": "pump_revision_diff_ci",
            "label": "펌프점검 개정안",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
                {"seq": 3, "item": "패킹 누수 상태 확인"},
            ],
            "note": "draft note only",
        },
    )
    assert created_revision.status_code == 200
    revision_id = int(created_revision.json()["row"]["id"])
    assert created_revision.json()["row"]["release_note_valid"] is False

    detail_before_submit = app_client.get(
        f"/api/ops/inspections/checklists/revisions/{revision_id}",
        headers=headers,
    )
    assert detail_before_submit.status_code == 200
    detail_body = detail_before_submit.json()
    assert detail_body["release_note_rules"]["required_sections"] == ["Summary", "Impact", "Rollback"]
    assert detail_body["row"]["diff"]["added_count"] == 1
    assert detail_body["row"]["diff"]["removed_count"] == 0
    assert detail_body["row"]["diff"]["label_changed"] is True
    assert detail_body["row"]["live_version_no"] == 1
    assert "Summary" in detail_body["row"]["release_note_missing_sections"]

    bad_submit = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{revision_id}/submit",
        headers=manager_headers,
        json={"note": "too short"},
    )
    assert bad_submit.status_code == 422
    assert bad_submit.json()["detail"]["missing_sections"] == ["Summary", "Impact", "Rollback"]

    valid_note = "\n".join(
        [
            "Summary: add leakage check to pump workflow",
            "Impact: operators review one more maintenance item during inspection",
            "Rollback: restore version 1 checklist if leakage validation is noisy",
        ]
    )
    submitted = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{revision_id}/submit",
        headers=manager_headers,
        json={"note": valid_note},
    )
    assert submitted.status_code == 200
    submitted_row = submitted.json()["row"]
    assert submitted_row["status"] == "pending"
    assert submitted_row["release_note_valid"] is True
    assert submitted_row["release_note_sections"]["summary"].startswith("add leakage check")

    listed = app_client.get(
        "/api/ops/inspections/checklists/revisions?status=pending&q=leakage",
        headers=headers,
    )
    assert listed.status_code == 200
    assert any(int(row["id"]) == revision_id for row in listed.json()["rows"])

    legacy_revision = app_client.post(
        "/api/ops/inspections/checklists/revisions",
        headers=manager_headers,
        json={
            "set_id": "pump_revision_diff_ci",
            "label": "펌프점검 개정안-legacy",
            "task_type": "기계점검",
            "items": [
                {"seq": 1, "item": "펌프 외관 상태 확인"},
                {"seq": 2, "item": "펌프 진동 상태 확인"},
                {"seq": 3, "item": "패킹 누수 상태 확인"},
                {"seq": 4, "item": "흡입압력 상태 확인"},
            ],
            "note": "legacy invalid note",
        },
    )
    assert legacy_revision.status_code == 200
    legacy_revision_id = int(legacy_revision.json()["row"]["id"])

    import app.database as db_module

    with db_module.get_conn() as conn:
        conn.execute(
            update(db_module.ops_checklist_set_revisions)
            .where(db_module.ops_checklist_set_revisions.c.id == legacy_revision_id)
            .values(
                status="pending",
                submitted_by="legacy-submit",
                submitted_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    legacy_approve = app_client.post(
        f"/api/ops/inspections/checklists/revisions/{legacy_revision_id}/approve",
        headers=approver_headers,
        json={"note": "attempt approval"},
    )
    assert legacy_approve.status_code == 422
    assert legacy_approve.json()["detail"]["missing_sections"] == ["Summary", "Impact", "Rollback"]


def test_ops_inspection_qr_bulk_update_dry_run_does_not_persist(app_client: TestClient) -> None:
    headers = _owner_headers()
    seed_placeholder = app_client.post(
        "/api/ops/inspections/checklists/qr-assets/bulk-update",
        headers=headers,
        json={
            "dry_run": False,
            "create_missing": False,
            "allow_placeholder_values": True,
            "updates": [
                {
                    "qr_id": "QR-001",
                    "equipment": "설비",
                    "location": "위치",
                    "default_item": "점검항목",
                }
            ],
        },
    )
    assert seed_placeholder.status_code == 200

    before = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert before.status_code == 200
    before_body = before.json()
    before_summary = before_body["summary"]
    assert before_summary["placeholder_row_count"] >= 1
    target_qr_id = "QR-001"

    result = app_client.post(
        "/api/ops/inspections/checklists/qr-assets/bulk-update",
        headers=headers,
        json={
            "dry_run": True,
            "create_missing": False,
            "updates": [
                {
                    "qr_id": target_qr_id,
                    "equipment": "변압기 1호기",
                    "location": "B1 수변전실",
                    "default_item": "변압기 외관 점검",
                },
                {
                    "qr_id": "QR-404",
                    "equipment": "비상발전기",
                    "location": "지상 1층 발전기실",
                    "default_item": "발전기 외관 상태 확인",
                },
            ],
        },
    )
    assert result.status_code == 200
    body = result.json()
    summary = body["summary"]
    assert body["dry_run"] is True
    assert body["saved"] is False
    assert body["checklist_version"]
    assert body["source"] in {"file", "fallback", "qr_bulk_update_api"}
    assert body["applied_at"] is not None
    assert body["meta"]["endpoint"] == "/api/ops/inspections/checklists/qr-assets/bulk-update"
    assert summary["requested_count"] == 2
    assert summary["applied_count"] == 1
    assert summary["updated_count"] == 1
    assert summary["created_count"] == 0
    assert summary["placeholder_row_count_before"] == before_summary["placeholder_row_count"]
    assert summary["placeholder_row_count_after"] == before_summary["placeholder_row_count"] - 1

    after = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert after.status_code == 200
    after_body = after.json()
    assert after_body["summary"]["placeholder_row_count"] == before_summary["placeholder_row_count"]
    assert after_body["summary"]["qr_asset_count"] == before_summary["qr_asset_count"]

def test_ops_inspection_qr_bulk_update_apply_persists(app_client: TestClient) -> None:
    headers = _owner_headers()
    seed_placeholder = app_client.post(
        "/api/ops/inspections/checklists/qr-assets/bulk-update",
        headers=headers,
        json={
            "dry_run": False,
            "create_missing": False,
            "allow_placeholder_values": True,
            "updates": [
                {
                    "qr_id": "QR-002",
                    "equipment": "설비",
                    "location": "위치",
                    "default_item": "점검항목",
                }
            ],
        },
    )
    assert seed_placeholder.status_code == 200

    before = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert before.status_code == 200
    before_body = before.json()
    before_summary = before_body["summary"]
    assert before_summary["placeholder_row_count"] >= 1
    target_qr_id = "QR-002"

    result = app_client.post(
        "/api/ops/inspections/checklists/qr-assets/bulk-update",
        headers=headers,
        json={
            "dry_run": False,
            "create_missing": True,
            "updates": [
                {
                    "qr_id": target_qr_id,
                    "equipment": "변압기 1호기",
                    "location": "B1 수변전실",
                    "default_item": "변압기 외관 점검",
                },
                {
                    "qr_id": "QR-900",
                    "equipment": "UPS 1호기",
                    "location": "전기실",
                    "default_item": "UPS 알람 상태 확인",
                },
            ],
        },
    )
    assert result.status_code == 200
    body = result.json()
    summary = body["summary"]
    assert body["dry_run"] is False
    assert body["saved"] is True
    assert body["saved_path"]
    assert body["checklist_version"]
    assert body["source"] == "qr_bulk_update_api"
    assert body["applied_at"] is not None
    assert summary["requested_count"] == 2
    assert summary["applied_count"] == 2
    assert summary["updated_count"] == 1
    assert summary["created_count"] == 1
    assert summary["placeholder_row_count_before"] == before_summary["placeholder_row_count"]
    assert summary["placeholder_row_count_after"] == before_summary["placeholder_row_count"] - 1
    assert summary["revision_saved_count"] == 2

    after = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert after.status_code == 200
    after_body = after.json()
    after_summary = after_body["summary"]
    assert after_body["source"] == "qr_bulk_update_api"
    assert after_body["applied_at"] is not None
    assert after_summary["placeholder_row_count"] == before_summary["placeholder_row_count"] - 1
    assert after_summary["qr_asset_count"] == before_summary["qr_asset_count"] + 1
    assert all(row["qr_id"] != target_qr_id for row in after_body["rows"])

    revisions = app_client.get(
        f"/api/ops/inspections/checklists/qr-assets/revisions?qr_id={target_qr_id}",
        headers=headers,
    )
    assert revisions.status_code == 200
    revision_rows = revisions.json()["rows"]
    assert len(revision_rows) >= 1
    latest_revision = revision_rows[0]
    assert latest_revision["change_source"] == "qr_bulk_update_api"
    assert latest_revision["change_action"] == "updated"
    assert latest_revision["created_by"] == "legacy-admin"
    assert latest_revision["before"]["equipment"] == "설비"
    assert latest_revision["after"]["equipment"] == "변압기 1호기"
    assert latest_revision["after"]["qr_id"] == target_qr_id


def test_ops_qr_asset_crud_records_revision_history(app_client: TestClient) -> None:
    headers = _owner_headers()

    created_set = app_client.post(
        "/api/ops/inspections/checklists/sets",
        headers=headers,
        json={
            "set_id": "qr_revision_set_ci",
            "label": "QR Revision Checklist",
            "task_type": "전기점검",
            "items": [
                {"seq": 1, "item": "revision item one"},
                {"seq": 2, "item": "revision item two"},
            ],
        },
    )
    assert created_set.status_code == 200

    created_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "qr revision pump",
            "location": "B1 revision room",
            "lifecycle_state": "active",
        },
    )
    assert created_equipment.status_code == 200
    equipment_id = int(created_equipment.json()["row"]["equipment_id"])

    created_qr = app_client.post(
        "/api/ops/inspections/checklists/qr-assets",
        headers=headers,
        json={
            "qr_id": "QR-REVISION-CI",
            "equipment_id": equipment_id,
            "checklist_set_id": "qr_revision_set_ci",
            "default_item": "revision item one",
            "lifecycle_state": "active",
        },
    )
    assert created_qr.status_code == 200
    qr_asset_id = int(created_qr.json()["row"]["qr_asset_id"])

    updated_qr = app_client.patch(
        f"/api/ops/inspections/checklists/qr-assets/{qr_asset_id}",
        headers=headers,
        json={
            "qr_id": "QR-REVISION-CI",
            "equipment_id": equipment_id,
            "checklist_set_id": "qr_revision_set_ci",
            "default_item": "revision item two",
            "lifecycle_state": "active",
        },
    )
    assert updated_qr.status_code == 200

    deleted_qr = app_client.delete(
        f"/api/ops/inspections/checklists/qr-assets/{qr_asset_id}",
        headers=headers,
    )
    assert deleted_qr.status_code == 200

    revisions = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/revisions?qr_id=QR-REVISION-CI",
        headers=headers,
    )
    assert revisions.status_code == 200
    revision_rows = revisions.json()["rows"]
    actions = [str(row["change_action"]) for row in revision_rows[:3]]
    assert actions == ["deleted", "updated", "created"]
    assert revision_rows[0]["before"]["qr_id"] == "QR-REVISION-CI"
    assert revision_rows[0]["after"] == {}
    assert revision_rows[1]["before"]["default_item"] == "revision item one"
    assert revision_rows[1]["after"]["default_item"] == "revision item two"
    assert revision_rows[2]["after"]["qr_id"] == "QR-REVISION-CI"

def test_ops_inspection_qr_bulk_update_create_missing_requires_all_fields(app_client: TestClient) -> None:
    headers = _owner_headers()
    before = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert before.status_code == 200
    before_summary = before.json()["summary"]

    result = app_client.post(
        "/api/ops/inspections/checklists/qr-assets/bulk-update",
        headers=headers,
        json={
            "dry_run": False,
            "create_missing": True,
            "updates": [
                {
                    "qr_id": "QR-998",
                    "equipment": "신규 설비",
                    "location": "신규 위치",
                }
            ],
        },
    )
    assert result.status_code == 200
    body = result.json()
    summary = body["summary"]
    assert summary["requested_count"] == 1
    assert summary["applied_count"] == 0
    assert summary["created_count"] == 0
    assert summary["skipped_count"] >= 1
    assert any(
        row.get("reason") == "missing_required_fields_for_create"
        for row in body.get("skipped", [])
        if isinstance(row, dict)
    )

    after = app_client.get(
        "/api/ops/inspections/checklists/qr-assets/placeholders",
        headers=headers,
    )
    assert after.status_code == 200
    after_summary = after.json()["summary"]
    assert after_summary["qr_asset_count"] == before_summary["qr_asset_count"]

def test_work_order_sla_rules_and_inspection_priority_floor(app_client: TestClient) -> None:
    headers = _owner_headers()

    rules = app_client.get("/api/work-orders/sla/rules", headers=headers)
    assert rules.status_code == 200
    rules_body = rules.json()
    assert rules_body["applies_when"]["inspection_id_provided"] is True
    assert rules_body["priority_floor_by_risk_level"]["danger"] == "critical"

    inspected_at = datetime.now(timezone.utc).isoformat()
    meta = {
        "task_type": "전기점검",
        "equipment": "변압기",
        "equipment_location": "B1 수변전실",
        "checklist_set_id": "electrical_60",
        "summary": {"total": 3, "normal": 0, "abnormal": 3, "na": 0},
        "abnormal_action": "단자 체결 상태 및 발열 재점검",
    }
    checklist = [
        {"group": "변압기", "item": "변압기 외관 점검", "result": "abnormal", "action": ""},
        {"group": "변압기", "item": "변압기 온도 상승 여부 확인", "result": "abnormal", "action": ""},
        {"group": "변압기", "item": "변압기 이상 소음 확인", "result": "abnormal", "action": ""},
    ]
    notes = "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )
    inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "SLA Rule Site",
            "location": "B1 수변전실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": inspected_at,
            "notes": notes,
        },
    )
    assert inspection.status_code == 201
    inspection_id = int(inspection.json()["id"])

    created = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": "Inspection-linked work order",
            "description": "auto priority floor check",
            "site": "SLA Rule Site",
            "location": "B1 수변전실",
            "priority": "low",
            "inspection_id": inspection_id,
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["priority"] == "critical"
    assert body["inspection_id"] == inspection_id
    assert body["due_at"] is not None

    events = app_client.get(
        f"/api/work-orders/{body['id']}/events",
        headers=headers,
    )
    assert events.status_code == 200
    created_event = events.json()[0]
    assert created_event["event_type"] == "created"
    assert created_event["detail"]["requested_priority"] == "low"
    assert created_event["detail"]["priority"] == "critical"
    assert created_event["detail"]["priority_upgraded"] is True

    mismatch = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": "Inspection site mismatch",
            "description": "should fail",
            "site": "Other Site",
            "location": "B1",
            "priority": "medium",
            "inspection_id": inspection_id,
        },
    )
    assert mismatch.status_code == 400
    assert "inspection_id site must match work order site" in mismatch.json()["detail"]


def test_ops_inspection_create_rejects_master_id_mismatch(app_client: TestClient) -> None:
    headers = _owner_headers()
    catalog = app_client.get(
        "/api/ops/inspections/checklists/catalog",
        headers=headers,
    )
    assert catalog.status_code == 200
    body = catalog.json()
    mismatch_row = next(row for row in body["qr_assets"] if row["qr_id"] == "QR-001")
    inspected_at = datetime.now(timezone.utc).isoformat()
    meta = {
        "task_type": "전기점검",
        "equipment": "변압기 1호기",
        "equipment_location": "B1 수변전실",
        "qr_id": "QR-002",
        "checklist_set_id": "electrical_60",
        "summary": {"total": 3, "normal": 0, "abnormal": 3, "na": 0},
        "abnormal_action": "단자 체결 상태 및 발열 재점검",
    }
    checklist = [
        {"group": "변압기", "item": "변압기 외관 점검", "result": "abnormal", "action": ""},
        {"group": "변압기", "item": "변압기 온도 상승 여부 확인", "result": "abnormal", "action": ""},
        {"group": "변압기", "item": "변압기 이상 소음 확인", "result": "abnormal", "action": ""},
    ]
    notes = "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )
    inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "Mismatch Site",
            "location": "B1 수변전실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": inspected_at,
            "equipment_id": int(mismatch_row["equipment_id"]),
            "qr_asset_id": int(mismatch_row["qr_asset_id"]),
            "notes": notes,
        },
    )
    assert inspection.status_code == 422
    assert inspection.json()["detail"] == "qr_asset_id does not match meta.qr_id"

def test_workflow_lock_matrix_enforcement(app_client: TestClient) -> None:
    def issue_token(
        *,
        username: str,
        display_name: str,
        role: str,
        permissions: list[str] | None = None,
        site_scope: list[str] | None = None,
    ) -> str:
        created = app_client.post(
            "/api/admin/users",
            headers=_owner_headers(),
            json={
                "username": username,
                "display_name": display_name,
                "role": role,
                "permissions": permissions or [],
                "site_scope": site_scope or ["WF Site"],
            },
        )
        assert created.status_code == 201
        user_id = created.json()["id"]
        issued = app_client.post(
            f"/api/admin/users/{user_id}/tokens",
            headers=_owner_headers(),
            json={"label": f"{username}-token"},
        )
        assert issued.status_code == 201
        return issued.json()["token"]

    operator_token = issue_token(
        username="wf_operator_ci",
        display_name="WF Operator",
        role="operator",
    )
    manager_token = issue_token(
        username="wf_manager_ci",
        display_name="WF Manager",
        role="manager",
    )
    owner_token = issue_token(
        username="wf_owner_ci",
        display_name="WF Owner",
        role="owner",
    )
    admin_token = issue_token(
        username="wf_admin_ci",
        display_name="WF Admin Override",
        role="manager",
        permissions=["workflow_locks:admin"],
    )
    auditor_token = issue_token(
        username="wf_auditor_ci",
        display_name="WF Auditor",
        role="auditor",
    )

    operator_headers = {"X-Admin-Token": operator_token}
    manager_headers = {"X-Admin-Token": manager_token}
    owner_headers = {"X-Admin-Token": owner_token}
    admin_headers = {"X-Admin-Token": admin_token}
    auditor_headers = {"X-Admin-Token": auditor_token}

    created = app_client.post(
        "/api/workflow-locks",
        headers=operator_headers,
        json={
            "site": "WF Site",
            "workflow_key": "inspection.approval",
            "content": {"step": "draft-v1"},
        },
    )
    assert created.status_code == 201
    workflow_lock_id = created.json()["id"]
    assert created.json()["status"] == "draft"

    manager_update_draft = app_client.patch(
        f"/api/workflow-locks/{workflow_lock_id}/draft",
        headers=manager_headers,
        json={"comment": "manager should not edit draft"},
    )
    assert manager_update_draft.status_code == 403

    owner_update_draft = app_client.patch(
        f"/api/workflow-locks/{workflow_lock_id}/draft",
        headers=owner_headers,
        json={"comment": "owner should not edit draft"},
    )
    assert owner_update_draft.status_code == 403

    operator_update_draft = app_client.patch(
        f"/api/workflow-locks/{workflow_lock_id}/draft",
        headers=operator_headers,
        json={
            "content": {"step": "draft-v2"},
            "requested_ticket": "REQ-1001",
            "comment": "operator update",
        },
    )
    assert operator_update_draft.status_code == 200
    assert operator_update_draft.json()["status"] == "draft"
    assert operator_update_draft.json()["content"]["step"] == "draft-v2"

    submitted = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/submit",
        headers=operator_headers,
        json={"comment": "submit for review"},
    )
    assert submitted.status_code == 200
    assert submitted.json()["status"] == "review"

    operator_approve = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/approve",
        headers=operator_headers,
        json={"comment": "operator cannot approve"},
    )
    assert operator_approve.status_code == 403

    approved = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/approve",
        headers=manager_headers,
        json={"comment": "manager approve"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    manager_lock = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/lock",
        headers=manager_headers,
        json={"reason": "manager cannot lock"},
    )
    assert manager_lock.status_code == 403

    locked = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/lock",
        headers=owner_headers,
        json={"reason": "owner lock", "requested_ticket": "REQ-1001"},
    )
    assert locked.status_code == 200
    assert locked.json()["status"] == "locked"

    owner_unlock = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/unlock",
        headers=owner_headers,
        json={"reason": "owner cannot unlock", "requested_ticket": "REQ-1002"},
    )
    assert owner_unlock.status_code == 403

    invalid_admin_unlock = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/unlock",
        headers=admin_headers,
        json={"comment": "missing reason and ticket"},
    )
    assert invalid_admin_unlock.status_code == 400

    unlocked = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/unlock",
        headers=admin_headers,
        json={
            "reason": "Emergency rollback",
            "requested_ticket": "REQ-1002",
            "comment": "admin override",
        },
    )
    assert unlocked.status_code == 200
    assert unlocked.json()["status"] == "approved"
    assert unlocked.json()["unlock_reason"] == "Emergency rollback"
    assert unlocked.json()["requested_ticket"] == "REQ-1002"

    auditor_read = app_client.get(
        f"/api/workflow-locks/{workflow_lock_id}",
        headers=auditor_headers,
    )
    assert auditor_read.status_code == 200
    assert auditor_read.json()["status"] == "approved"

def test_work_order_escalation_and_audit_log(app_client: TestClient) -> None:
    due_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    created = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Escalation test",
            "description": "SLA overdue",
            "site": "CI Site",
            "location": "B1",
            "priority": "high",
            "due_at": due_at,
        },
    )
    assert created.status_code == 201

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "limit": 100},
    )
    assert run.status_code == 200
    assert run.json()["escalated_count"] >= 1
    assert "alert_dispatched" in run.json()
    assert "alert_channels" in run.json()

    logs = app_client.get(
        "/api/admin/audit-logs?action=work_order_sla_escalation_run",
        headers=_owner_headers(),
    )
    assert logs.status_code == 200
    assert len(logs.json()) >= 1

def test_work_order_workflow_transitions_and_events(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Workflow test",
            "description": "initial",
            "site": "Workflow Site",
            "location": "B7",
            "priority": "medium",
        },
    )
    assert created.status_code == 201
    work_order_id = created.json()["id"]
    assert created.json()["status"] == "open"

    comment = app_client.post(
        f"/api/work-orders/{work_order_id}/comments",
        headers=_owner_headers(),
        json={"comment": "Needs vendor coordination"},
    )
    assert comment.status_code == 201
    assert comment.json()["event_type"] == "comment"

    ack = app_client.patch(
        f"/api/work-orders/{work_order_id}/ack",
        headers=_owner_headers(),
        json={"assignee": "Ops Team"},
    )
    assert ack.status_code == 200
    assert ack.json()["status"] == "acked"

    cancel = app_client.patch(
        f"/api/work-orders/{work_order_id}/cancel",
        headers=_owner_headers(),
        json={"reason": "Duplicate request"},
    )
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "canceled"

    invalid_complete = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=_owner_headers(),
        json={"resolution_notes": "Should fail from canceled"},
    )
    assert invalid_complete.status_code == 409

    reopen = app_client.patch(
        f"/api/work-orders/{work_order_id}/reopen",
        headers=_owner_headers(),
        json={"reason": "Not duplicate after review"},
    )
    assert reopen.status_code == 200
    assert reopen.json()["status"] == "open"

    complete = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=_owner_headers(),
        json={"resolution_notes": "Resolved after reopen"},
    )
    assert complete.status_code == 200
    assert complete.json()["status"] == "completed"

    events = app_client.get(
        f"/api/work-orders/{work_order_id}/events",
        headers=_owner_headers(),
    )
    assert events.status_code == 200
    body = events.json()
    assert len(body) >= 6
    event_types = [row["event_type"] for row in body]
    assert "created" in event_types
    assert "comment" in event_types
    status_changes = [row for row in body if row["event_type"] == "status_changed"]
    assert any(row["from_status"] == "open" and row["to_status"] == "acked" for row in status_changes)
    assert any(row["from_status"] == "acked" and row["to_status"] == "canceled" for row in status_changes)
    assert any(row["from_status"] == "canceled" and row["to_status"] == "open" for row in status_changes)
    assert any(row["from_status"] == "open" and row["to_status"] == "completed" for row in status_changes)

def test_sla_policy_auto_due_and_grace(app_client: TestClient) -> None:
    updated = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 96, "medium": 1, "high": 4, "critical": 2},
            "escalation_grace_minutes": 30,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["default_due_hours"]["medium"] == 1
    assert updated.json()["escalation_grace_minutes"] == 30

    wo_auto_due = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Auto due by policy",
            "description": "No due_at provided",
            "site": "Policy Site",
            "location": "B2",
            "priority": "medium",
        },
    )
    assert wo_auto_due.status_code == 201
    due_at = datetime.fromisoformat(wo_auto_due.json()["due_at"])
    now = datetime.now(timezone.utc)
    assert now + timedelta(minutes=50) <= due_at <= now + timedelta(minutes=70)

    due_not_ready = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    created_not_ready = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Within grace",
            "description": "Should not escalate yet",
            "site": "Policy Site",
            "location": "B2",
            "priority": "high",
            "due_at": due_not_ready,
        },
    )
    assert created_not_ready.status_code == 201

    run1 = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "site": "Policy Site", "limit": 100},
    )
    assert run1.status_code == 200
    assert run1.json()["escalated_count"] == 0

    due_over_grace = (datetime.now(timezone.utc) - timedelta(minutes=40)).isoformat()
    created_over_grace = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Over grace",
            "description": "Should escalate",
            "site": "Policy Site",
            "location": "B2",
            "priority": "high",
            "due_at": due_over_grace,
        },
    )
    assert created_over_grace.status_code == 201

    run2 = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "site": "Policy Site", "limit": 100},
    )
    assert run2.status_code == 200
    assert run2.json()["escalated_count"] >= 1

def test_sla_policy_site_override_and_fallback(app_client: TestClient) -> None:
    default_updated = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 0,
        },
    )
    assert default_updated.status_code == 200

    site_updated = app_client.put(
        "/api/admin/policies/sla?site=Site%20A",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 2, "high": 6, "critical": 1},
            "escalation_grace_minutes": 45,
        },
    )
    assert site_updated.status_code == 200
    assert site_updated.json()["source"] == "site"
    assert site_updated.json()["site"] == "Site A"
    assert site_updated.json()["default_due_hours"]["medium"] == 2

    get_site_a = app_client.get(
        "/api/admin/policies/sla?site=Site%20A",
        headers=_owner_headers(),
    )
    assert get_site_a.status_code == 200
    assert get_site_a.json()["source"] == "site"
    assert get_site_a.json()["policy_key"].startswith("site:")

    get_site_b = app_client.get(
        "/api/admin/policies/sla?site=Site%20B",
        headers=_owner_headers(),
    )
    assert get_site_b.status_code == 200
    assert get_site_b.json()["source"] == "default"
    assert get_site_b.json()["policy_key"] == "default"
    assert get_site_b.json()["default_due_hours"]["medium"] == 24

    now = datetime.now(timezone.utc)
    wo_a = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Site A auto due",
            "description": "site override",
            "site": "Site A",
            "location": "B4",
            "priority": "medium",
        },
    )
    assert wo_a.status_code == 201
    due_a = datetime.fromisoformat(wo_a.json()["due_at"])
    assert now + timedelta(minutes=100) <= due_a <= now + timedelta(minutes=140)

    wo_b = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Site B auto due",
            "description": "default fallback",
            "site": "Site B",
            "location": "B4",
            "priority": "medium",
        },
    )
    assert wo_b.status_code == 201
    due_b = datetime.fromisoformat(wo_b.json()["due_at"])
    assert now + timedelta(hours=23) <= due_b <= now + timedelta(hours=25)

def test_sla_escalation_uses_site_grace_on_global_run(app_client: TestClient) -> None:
    set_default = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 0,
        },
    )
    assert set_default.status_code == 200

    set_site = app_client.put(
        "/api/admin/policies/sla?site=Grace%20Site",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 60,
        },
    )
    assert set_site.status_code == 200

    due_30m = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    wo_grace = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Grace protected",
            "description": "should not escalate",
            "site": "Grace Site",
            "location": "B5",
            "priority": "high",
            "due_at": due_30m,
        },
    )
    assert wo_grace.status_code == 201
    grace_id = wo_grace.json()["id"]

    wo_default = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Default escalated",
            "description": "should escalate",
            "site": "No Grace Site",
            "location": "B5",
            "priority": "high",
            "due_at": due_30m,
        },
    )
    assert wo_default.status_code == 201
    default_id = wo_default.json()["id"]

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "limit": 100},
    )
    assert run.status_code == 200
    escalated_ids = set(run.json()["work_order_ids"])
    assert default_id in escalated_ids
    assert grace_id not in escalated_ids

def test_monthly_report_exports(app_client: TestClient) -> None:
    month = datetime.now(timezone.utc).strftime("%Y-%m")

    csv_resp = app_client.get(
        f"/api/reports/monthly/csv?month={month}",
        headers=_owner_headers(),
    )
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")

    pdf_resp = app_client.get(
        f"/api/reports/monthly/pdf?month={month}",
        headers=_owner_headers(),
    )
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"].startswith("application/pdf")

def test_ops_dashboard_summary(app_client: TestClient) -> None:
    inspected_at = datetime.now(timezone.utc).isoformat()
    inspection = app_client.post(
        "/api/inspections",
        headers=_owner_headers(),
        json={
            "site": "Ops Site",
            "location": "B3",
            "cycle": "monthly",
            "inspector": "CI Bot",
            "inspected_at": inspected_at,
        },
    )
    assert inspection.status_code == 201

    due_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    work_order = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Dashboard work order",
            "description": "for summary",
            "site": "Ops Site",
            "location": "B3",
            "priority": "high",
            "due_at": due_at,
        },
    )
    assert work_order.status_code == 201

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "site": "Ops Site", "limit": 50},
    )
    assert run.status_code == 200

    summary = app_client.get(
        "/api/ops/dashboard/summary?site=Ops+Site&days=30&job_limit=10",
        headers=_owner_headers(),
    )
    assert summary.status_code == 200
    body = summary.json()
    assert body["site"] == "Ops Site"
    assert body["inspections_total"] >= 1
    assert body["work_orders_total"] >= 1
    assert "inspection_risk_counts" in body
    assert "work_order_status_counts" in body
    assert "recent_job_runs" in body
    assert body["sla_recent_runs"] >= 1

def test_ops_dashboard_trends(app_client: TestClient) -> None:
    inspected_at = datetime.now(timezone.utc).isoformat()
    inspection = app_client.post(
        "/api/inspections",
        headers=_owner_headers(),
        json={
            "site": "Trend Site",
            "location": "B8",
            "cycle": "monthly",
            "inspector": "Trend Bot",
            "inspected_at": inspected_at,
        },
    )
    assert inspection.status_code == 201

    work_order = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Trend work order",
            "description": "for trends",
            "site": "Trend Site",
            "location": "B8",
            "priority": "high",
        },
    )
    assert work_order.status_code == 201
    work_order_id = work_order.json()["id"]

    completed = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=_owner_headers(),
        json={"resolution_notes": "done"},
    )
    assert completed.status_code == 200

    trends = app_client.get(
        "/api/ops/dashboard/trends?site=Trend+Site&days=7",
        headers=_owner_headers(),
    )
    assert trends.status_code == 200
    body = trends.json()
    assert body["site"] == "Trend Site"
    assert body["window_days"] == 7
    assert len(body["points"]) == 7
    assert sum(point["inspections_count"] for point in body["points"]) >= 1
    assert sum(point["work_orders_created_count"] for point in body["points"]) >= 1
    assert sum(point["work_orders_completed_count"] for point in body["points"]) >= 1

def test_ops_handover_brief_prioritization(app_client: TestClient) -> None:
    now = datetime.now(timezone.utc)

    inspection = app_client.post(
        "/api/inspections",
        headers=_owner_headers(),
        json={
            "site": "Handover Site",
            "location": "B2",
            "cycle": "monthly",
            "inspector": "Handover Bot",
            "inspected_at": now.isoformat(),
            "grounding_ohm": 30.0,
            "insulation_mohm": 0.1,
        },
    )
    assert inspection.status_code == 201
    assert inspection.json()["risk_level"] in {"warning", "danger"}

    overdue = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Critical overdue issue",
            "description": "handover priority",
            "site": "Handover Site",
            "location": "B2",
            "priority": "critical",
            "due_at": (now - timedelta(hours=2)).isoformat(),
        },
    )
    assert overdue.status_code == 201
    overdue_id = overdue.json()["id"]

    due_soon = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Due soon issue",
            "description": "needs prep",
            "site": "Handover Site",
            "location": "B2",
            "priority": "high",
            "assignee": "Ops Team",
            "due_at": (now + timedelta(minutes=45)).isoformat(),
        },
    )
    assert due_soon.status_code == 201

    normal = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Normal backlog",
            "description": "low risk",
            "site": "Handover Site",
            "location": "B3",
            "priority": "low",
        },
    )
    assert normal.status_code == 201

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"site": "Handover Site", "dry_run": False, "limit": 50},
    )
    assert run.status_code == 200

    brief = app_client.get(
        "/api/ops/handover/brief?site=Handover+Site&window_hours=24&due_soon_hours=2&max_items=5",
        headers=_owner_headers(),
    )
    assert brief.status_code == 200
    body = brief.json()
    assert body["site"] == "Handover Site"
    assert body["open_work_orders"] >= 3
    assert body["overdue_open_work_orders"] >= 1
    assert body["due_soon_work_orders"] >= 1
    assert body["high_risk_inspections_in_window"] >= 1
    assert len(body["top_work_orders"]) >= 1
    assert body["top_work_orders"][0]["id"] == overdue_id
    assert any("overdue" in action.lower() for action in body["recommended_actions"])

def test_ops_handover_brief_respects_site_scope(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "handover_scope_ci",
            "display_name": "Handover Scope CI",
            "role": "owner",
            "permissions": [],
            "site_scope": ["Scope Handover"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "handover-scope-token"},
    )
    assert issued.status_code == 201
    scoped_headers = {"X-Admin-Token": issued.json()["token"]}

    in_scope = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Scope visible",
            "description": "visible in scope",
            "site": "Scope Handover",
            "location": "B1",
            "priority": "high",
        },
    )
    assert in_scope.status_code == 201

    out_scope = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Scope hidden",
            "description": "hidden by scope",
            "site": "Outside Handover",
            "location": "B1",
            "priority": "high",
        },
    )
    assert out_scope.status_code == 201

    brief = app_client.get(
        "/api/ops/handover/brief?window_hours=24&due_soon_hours=6&max_items=10",
        headers=scoped_headers,
    )
    assert brief.status_code == 200
    body = brief.json()
    assert body["open_work_orders"] == 1
    assert all(item["site"] == "Scope Handover" for item in body["top_work_orders"])

    forbidden = app_client.get(
        "/api/ops/handover/brief?site=Outside+Handover",
        headers=scoped_headers,
    )
    assert forbidden.status_code == 403

def test_ops_handover_brief_exports(app_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    seeded = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Export target",
            "description": "for handover export",
            "site": "Export Site",
            "location": "B5",
            "priority": "high",
            "due_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert seeded.status_code == 201

    csv_resp = app_client.get(
        "/api/ops/handover/brief/csv?site=Export+Site&window_hours=24&due_soon_hours=4&max_items=10",
        headers=_owner_headers(),
    )
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "handover-brief-export_site" in csv_resp.headers.get("content-disposition", "").lower()
    assert "open_work_orders" in csv_resp.text

    pdf_resp = app_client.get(
        "/api/ops/handover/brief/pdf?site=Export+Site&window_hours=24&due_soon_hours=4&max_items=10",
        headers=_owner_headers(),
    )
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"].startswith("application/pdf")

    csv_logs = app_client.get(
        "/api/admin/audit-logs?action=report_handover_export_csv",
        headers=_owner_headers(),
    )
    assert csv_logs.status_code == 200
    assert len(csv_logs.json()) >= 1

    pdf_logs = app_client.get(
        "/api/admin/audit-logs?action=report_handover_export_pdf",
        headers=_owner_headers(),
    )
    assert pdf_logs.status_code == 200
    assert len(pdf_logs.json()) >= 1

def test_sla_simulator_what_if(app_client: TestClient) -> None:
    set_default = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 0,
        },
    )
    assert set_default.status_code == 200

    due_old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    wo = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Simulator target",
            "description": "simulate grace increase",
            "site": "Sim Site",
            "location": "B9",
            "priority": "high",
            "due_at": due_old,
        },
    )
    assert wo.status_code == 201

    simulated = app_client.post(
        "/api/ops/sla/simulate",
        headers=_owner_headers(),
        json={
            "site": "Sim Site",
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 60,
            },
            "limit": 500,
            "include_work_order_ids": True,
            "sample_size": 50,
            "recompute_due_from_policy": False,
        },
    )
    assert simulated.status_code == 200
    body = simulated.json()
    assert body["site"] == "Sim Site"
    assert body["baseline_escalate_count"] >= 1
    assert body["simulated_escalate_count"] == 0
    assert body["delta_escalate_count"] <= 0
    assert len(body["no_longer_escalated_ids"]) >= 1

def test_sla_policy_proposal_approval_flow(app_client: TestClient) -> None:
    due_old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    wo = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Proposal target",
            "description": "proposal approval flow",
            "site": "Approval Site",
            "location": "B10",
            "priority": "high",
            "due_at": due_old,
        },
    )
    assert wo.status_code == 201

    created = app_client.post(
        "/api/admin/policies/sla/proposals",
        headers=_owner_headers(),
        json={
            "site": "Approval Site",
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 60,
            },
            "note": "Increase grace for maintenance window",
            "simulation_limit": 500,
            "sample_size": 50,
            "include_work_order_ids": True,
            "recompute_due_from_policy": False,
        },
    )
    assert created.status_code == 201
    proposal = created.json()
    proposal_id = proposal["id"]
    assert proposal["status"] == "pending"
    assert proposal["site"] == "Approval Site"
    assert proposal["simulation"]["baseline_escalate_count"] >= 1
    assert proposal["simulation"]["simulated_escalate_count"] == 0

    listed = app_client.get(
        "/api/admin/policies/sla/proposals?status=pending&site=Approval+Site",
        headers=_owner_headers(),
    )
    assert listed.status_code == 200
    ids = [row["id"] for row in listed.json()]
    assert proposal_id in ids

    approver_user = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "proposal_approver_ci",
            "display_name": "Proposal Approver CI",
            "role": "owner",
            "permissions": [],
            "site_scope": ["*"],
        },
    )
    assert approver_user.status_code == 201
    approver_user_id = approver_user.json()["id"]
    approver_token_issue = app_client.post(
        f"/api/admin/users/{approver_user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "proposal-approver"},
    )
    assert approver_token_issue.status_code == 201
    approver_headers = {"X-Admin-Token": approver_token_issue.json()["token"]}

    self_approve = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal_id}/approve",
        headers=_owner_headers(),
        json={"note": "self approve should fail"},
    )
    assert self_approve.status_code == 409

    approved = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal_id}/approve",
        headers=approver_headers,
        json={"note": "Approved for next sprint"},
    )
    assert approved.status_code == 200
    approved_body = approved.json()
    assert approved_body["status"] == "approved"
    assert approved_body["applied_at"] is not None

    policy_after = app_client.get(
        "/api/admin/policies/sla?site=Approval+Site",
        headers=_owner_headers(),
    )
    assert policy_after.status_code == 200
    assert policy_after.json()["escalation_grace_minutes"] == 60

    approve_again = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal_id}/approve",
        headers=approver_headers,
        json={"note": "should fail"},
    )
    assert approve_again.status_code == 409

    created2 = app_client.post(
        "/api/admin/policies/sla/proposals",
        headers=_owner_headers(),
        json={
            "site": "Approval Site",
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 15,
            },
            "note": "Alternative proposal",
        },
    )
    assert created2.status_code == 201
    proposal2_id = created2.json()["id"]

    rejected = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal2_id}/reject",
        headers=approver_headers,
        json={"note": "Not needed"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

def test_site_scoped_admin_cannot_create_global_sla_proposal(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "proposal_scope_ci",
            "display_name": "Proposal Scope CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["Scoped Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "proposal-scope-token"},
    )
    assert issued.status_code == 201
    scoped_headers = {"X-Admin-Token": issued.json()["token"]}

    forbidden_global = app_client.post(
        "/api/admin/policies/sla/proposals",
        headers=scoped_headers,
        json={
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 5,
            },
            "note": "global proposal should be blocked",
        },
    )
    assert forbidden_global.status_code == 403

def test_sla_policy_revisions_and_restore(app_client: TestClient) -> None:
    set_v1 = app_client.put(
        "/api/admin/policies/sla?site=Revision+Site",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 5,
        },
    )
    assert set_v1.status_code == 200

    set_v2 = app_client.put(
        "/api/admin/policies/sla?site=Revision+Site",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 45,
        },
    )
    assert set_v2.status_code == 200

    listed = app_client.get(
        "/api/admin/policies/sla/revisions?site=Revision+Site&limit=50",
        headers=_owner_headers(),
    )
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) >= 2

    revision_v1 = None
    for row in rows:
        if row["policy"]["escalation_grace_minutes"] == 5:
            revision_v1 = row
            break
    assert revision_v1 is not None

    restored = app_client.post(
        f"/api/admin/policies/sla/revisions/{revision_v1['id']}/restore",
        headers=_owner_headers(),
        json={"note": "rollback for test"},
    )
    assert restored.status_code == 200
    assert restored.json()["escalation_grace_minutes"] == 5

    policy_after = app_client.get(
        "/api/admin/policies/sla?site=Revision+Site",
        headers=_owner_headers(),
    )
    assert policy_after.status_code == 200
    assert policy_after.json()["escalation_grace_minutes"] == 5

    restore_rows = app_client.get(
        "/api/admin/policies/sla/revisions?site=Revision+Site&source_action=revision_restore&limit=20",
        headers=_owner_headers(),
    )
    assert restore_rows.status_code == 200
    assert len(restore_rows.json()) >= 1
