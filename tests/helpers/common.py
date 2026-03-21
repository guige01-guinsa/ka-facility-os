import json
from pathlib import Path


def _seed_ops_special_checklists_json(target_path: Path) -> None:
    payload = {
        "source_file": "tests-fixture",
        "version": "tests-fixture",
        "checklist_sets": [
            {
                "set_id": "electrical_60",
                "label": "전기직무고시60항목",
                "task_type": "전기점검",
                "items": [
                    {"seq": 1, "item": "수변전실 출입통제 상태 확인"},
                    {"seq": 2, "item": "변압기 외관 점검"},
                    {"seq": 3, "item": "변압기 온도 상승 여부 확인"},
                    {"seq": 4, "item": "변압기 이상 소음 확인"},
                    {"seq": 5, "item": "수전반 차단기 동작 상태"},
                    {"seq": 6, "item": "분전반 누전차단기 상태"},
                    {"seq": 7, "item": "접지설비 연결 상태"},
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
        ],
        "ops_codes": [
            {"code": "E01", "category": "전기", "description": "수변전설비 점검"},
            {"code": "F01", "category": "소방", "description": "소화기 점검"},
            {"code": "M01", "category": "기계", "description": "급수펌프 점검"},
        ],
        "qr_assets": [
            {"qr_id": "QR-001", "equipment": "설비", "location": "위치", "default_item": "점검항목"},
            {
                "qr_id": "QR-002",
                "equipment": "변압기 1호기",
                "location": "B1 수변전실",
                "default_item": "변압기 외관 점검",
            },
        ],
    }
    target_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _owner_headers() -> dict[str, str]:
    return {"X-Admin-Token": "test-owner-token"}


def _build_ops_checklist_notes() -> str:
    meta = {
        "task_type": "전기점검",
        "equipment": "변압기 1호기",
        "equipment_location": "B1 수변전실",
        "qr_id": "QR-002",
        "checklist_set_id": "electrical_60",
        "checklist_data_version": "tests-fixture",
        "summary": {"total": 3, "normal": 0, "abnormal": 3, "na": 0},
        "abnormal_action": "단자 체결 상태 및 발열 재점검",
    }
    checklist = [
        {"group": "변압기", "item": "변압기 외관 점검", "result": "abnormal", "action": ""},
        {"group": "변압기", "item": "변압기 온도 상승 여부 확인", "result": "abnormal", "action": ""},
        {"group": "변압기", "item": "변압기 이상 소음 확인", "result": "abnormal", "action": ""},
    ]
    return "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )


def _assert_adoption_policy_response_shape(
    body: dict[str, object],
    *,
    phase: str,
    policy_kind: str,
    endpoint: str,
    site: str,
    policy_key_prefix: str,
) -> None:
    assert body["version"] == "v1"
    assert body["site"] == site
    assert body["applies_to"] == site
    assert str(body["policy_key"]).startswith(policy_key_prefix)
    assert isinstance(body.get("policy"), dict)

    scope = body.get("scope")
    assert isinstance(scope, dict)
    assert scope["type"] == "site"
    assert scope["site"] == site
    assert scope["policy_key"] == body["policy_key"]

    meta = body.get("meta")
    assert isinstance(meta, dict)
    assert meta["schema"] == "adoption_policy_response"
    assert meta["schema_version"] == "v1"
    assert meta["phase"] == phase
    assert meta["policy_kind"] == policy_kind
    assert meta["endpoint"] == endpoint
    assert meta["scope_type"] == "site"
    assert meta["version"] == "v1"
    assert meta["scope"] == "site"
    assert meta["applies_to"] == site
    assert meta["policy_key"] == body["policy_key"]
    assert meta["updated_at"] == body["updated_at"]
