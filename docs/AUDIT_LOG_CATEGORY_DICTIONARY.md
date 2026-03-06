# Audit Log Category Dictionary

기준일: 2026-03-07
기준 커밋: `29110e0`
스캔 기준: `app/main.py`, `app/domains/**/*.py`의 `_write_audit_log(...)` 호출부

## 목적

이 문서는 감사로그 `action`, `resource_type`, `status` 값을 새로 추가하거나 검토할 때 사용하는 기준 사전입니다.
목표는 다음 3가지입니다.

- 같은 의미의 이벤트가 서로 다른 이름으로 중복 기록되지 않게 한다.
- 운영/감사/분석 화면에서 prefix 단위 집계가 가능하도록 한다.
- 신규 기능 추가 시 기존 분류 체계를 벗어나지 않도록 한다.

## 현재 스캔 결과

- `action`: 231개
- `resource_type`: 96개
- `status`: 16개

## Naming Rules

### action

형식 원칙:

- 권장 형식: `<domain>_<object>_<verb>` 또는 `<domain>_<verb>`
- 예외 허용: 워크플로우 상태전이형 단축 verb (`submit`, `approve`, `reject`, `lock`, `unlock`, `read`, `create`, `updated`)

도메인 prefix:

- `auth_*`: 로그인/로그아웃/본인 프로필
- `admin_user_*`: 관리자 사용자 생성/수정/삭제/활성화
- `admin_token_*`: 토큰 발급/회전/폐기/자동정리
- `admin_audit_*`: 감사 무결성/아카이브/재기준화
- `inspection_*`: 점검/증빙 업로드/다운로드
- `work_order_*`: 작업지시 생성/상태전이/SLA
- `workflow_lock_*`: 승인잠금 흐름
- `ops_*`: 운영 스모크/런북/보안/품질/DR/거버넌스
- `sla_policy_*`: SLA 정책 시뮬레이션/제안/복원/업데이트
- `alert_*`: 알림 재시도/전송/보관정책
- `w02_*` ~ `w15_*`: adoption 단계별 실행 트래커 및 정책
- `report_*`: 월간보고서/인수인계 출력

verb 원칙:

- 조회: `*_view`, `*_latest_view`, `*_history_view`, `*_summary_view`
- 실행: `*_run`, `*_sync`, `*_check`, `*_bootstrap`, `*_complete`
- 변경: `*_create`, `*_update`, `*_restore`, `*_approve`, `*_reject`, `*_revoke`, `*_rotate`
- 출력: `*_csv_export`, `*_pdf_export`, `*_download`, `*_upload`

### resource_type

형식 원칙:

- 권장 형식: 단수형 도메인 자원명
- 세부 자원은 suffix로 분리: `_item`, `_site`, `_policy`, `_evidence`, `_session`

주요 resource_type 카테고리:

| Category | resource_type prefix / key | 의미 |
| --- | --- | --- |
| IAM | `admin_user`, `admin_token`, `admin_audit_log` | 사용자/토큰/감사 아카이브 |
| OPS Core | `workflow_lock`, `inspection`, `inspection_evidence`, `work_order`, `work_order_sla`, `report` | 점검/작업지시/월간리포트 |
| OPS Reliability | `ops_runbook`, `ops_security`, `ops_preflight`, `ops_integrity`, `ops_performance`, `ops_deploy`, `ops_dr`, `ops_quality_report` | 운영 안정성/품질/배포/복구 |
| OPS Governance | `ops_governance_gate`, `ops_governance_remediation_tracker`, `ops_governance_remediation_tracker_item` | 거버넌스 게이트 및 시정조치 |
| OPS Alerting | `alert_delivery`, `alert_policy`, `ops_alerting`, `ops_admin_security` | 알림/보안/전송채널 |
| OPS Checklist | `ops_inspection_checklists` | 점검 마스터/QR 자산/import validation |
| Tutorial | `ops_tutorial_simulator_session` | 튜토리얼 세션 |
| SLA Policy | `sla_policy`, `sla_policy_proposal`, `sla_policy_revision` | SLA 정책 본문/제안/리비전 |
| Adoption | `adoption_w02_*` ~ `adoption_w15_*` | 단계별 tracker/policy/evidence/site/item |

### status

status는 두 층으로 해석합니다.

운영 결과 상태:

- `success`: 정상 완료
- `warning`: 부분 경고 또는 후속 조치 필요
- `error`: 처리 실패 또는 오류 발생
- `denied`: 권한/정책에 의해 거부
- `fail`: 체크 실패
- `pass`: 체크 통과
- `ok`: 스냅샷/상태 조회 결과 정상
- `critical`: 치명 상태
- `missing`: 필수 데이터/첨부 누락

업무 상태 스냅샷:

- `open`, `acked`, `completed`, `canceled`: 작업지시 상태
- `deactivated`: 계정 비활성화 결과
- `logged_out`: 로그아웃 결과
- `healthy`: 상태 확인 정상

규칙:

- 상태전이 엔터티는 도메인 상태를 그대로 기록할 수 있다.
- 그 외 대부분의 감사 이벤트는 `success|warning|error|denied` 중 하나를 우선 사용한다.
- 신규 `status` 추가는 문서와 테스트를 같이 갱신한다.

## Canonical Categories

### IAM

대표 action:

- `auth_login_success`, `auth_login_failed`, `auth_logout`
- `admin_user_create`, `admin_user_update`, `admin_user_delete`
- `admin_token_issue`, `admin_token_rotate`, `admin_token_revoke`
- `admin_audit_integrity_check`, `admin_audit_archive_export_json`, `admin_audit_archive_export_csv`

대표 resource_type:

- `admin_user`
- `admin_token`
- `admin_audit_log`

### OPS Core

대표 action:

- `inspection_create`, `inspection_evidence_upload`, `inspection_evidence_download`
- `work_order_create`, `work_order_ack`, `work_order_complete`, `work_order_reopen`
- `work_order_sla_rules_view`, `work_order_sla_escalation_run`
- `workflow_lock_create`, `workflow_lock_submit`, `workflow_lock_approve`
- `report_monthly_export_csv`, `report_monthly_export_pdf`

대표 resource_type:

- `inspection`, `inspection_evidence`
- `work_order`, `work_order_sla`
- `workflow_lock`
- `report`

### OPS Reliability / Governance

대표 action:

- `ops_runbook_daily_check_run`, `ops_runbook_daily_check_latest_view`
- `ops_quality_report_run`, `ops_quality_report_weekly_view`
- `ops_dr_rehearsal_run`, `ops_governance_gate_run`
- `ops_governance_remediation_tracker_sync`, `ops_governance_remediation_tracker_complete`
- `ops_deploy_checklist_view`, `ops_deploy_smoke_record`

대표 resource_type:

- `ops_runbook`, `ops_quality_report`, `ops_dr`, `ops_deploy`
- `ops_governance_gate`, `ops_governance_remediation_tracker`

### Alerting / SLA

대표 action:

- `alert_retry_batch_run`, `alert_delivery_retry`
- `ops_alert_retention_run`, `ops_alert_noise_policy_view`
- `sla_policy_update`, `sla_policy_simulation_run`, `sla_policy_restore`
- `sla_policy_proposal_create`, `sla_policy_proposal_approve`, `sla_policy_proposal_reject`

대표 resource_type:

- `alert_delivery`, `alert_policy`
- `sla_policy`, `sla_policy_proposal`, `sla_policy_revision`

### Adoption

대표 action 패턴:

- `wNN_tracker_bootstrap`
- `wNN_tracker_item_update`
- `wNN_tracker_evidence_upload`
- `wNN_tracker_complete`
- `wNN_*_policy_view`, `wNN_*_policy_update`

대표 resource_type 패턴:

- `adoption_wNN_tracker`
- `adoption_wNN_tracker_item`
- `adoption_wNN_tracker_site`
- `adoption_wNN_evidence`
- `adoption_wNN_*_policy`

## Change Rules

새 감사로그 추가 시 체크리스트:

1. 기존 prefix에 들어갈 수 있으면 새 prefix를 만들지 않는다.
2. `resource_type`는 복수형 대신 단수형을 사용한다.
3. 조회는 `*_view`, 배치는 `*_run`, 출력은 `*_export_*` 규칙을 우선 사용한다.
4. 성공/경고/실패 여부를 해석해야 하는 이벤트는 `status`를 명시한다.
5. 새 `action`, `resource_type`, `status`를 추가하면 이 문서와 관련 테스트를 같이 갱신한다.

## 운영 참고

월간 감사 아카이브 JSON(`build_monthly_audit_archive`)은 2026-03-07부터 `format_version=v2`와 `attachment_schema_version=v2`를 사용합니다.
기존 top-level attachment 키는 호환성 때문에 유지하지만, 신규 소비자는 아래 경로를 우선 사용합니다.

- `attachments.dr_rehearsal`
- `attachments.ops_checklists_import_validation`
