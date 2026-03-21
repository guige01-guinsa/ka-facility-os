# KA Facility OS Next Roadmap (2026 Q2-Q3)

기준일: 2026-03-15 (OPS remediation / adoption tracker bridge split 반영)

## 2026-03-15 시스템 구조 점검 결과

- 코드 규모
  - `app/main.py`: 16,454 lines (직접 route decorator는 제거됐고, OPS checklist/runtime + inspection/workflow + governance/alert/remediation helper의 역의존도와 adoption tracker helper bind도 줄였지만 여전히 공개/웹 + adoption + ops + billing + official documents 조립 허브 역할을 수행)
  - `tests/api/*.py`: 15 files, 전체 회귀 130 tests (`billing`, `official_documents`, `acceptance_a1~a3`, `acceptance_role_matrix`, `smoke_a1_lite`, `smoke_a2_lite`, checklist catalog/master-id/CRUD/lifecycle/revision/search-filter/diff/qr-revision-history/integrated asset scope 검증 포함)
  - `app/schemas.py`: 1,597 lines, `app/database.py`: 1,000 lines
  - 신규 분리 모듈: `app/domains/ops/checklist_runtime.py` 1,933 lines, `app/domains/ops/tables.py` 236 lines, `app/domains/ops/schemas.py` 196 lines, `app/domains/iam/core.py`
- 라우팅 상태
  - `ops/admin/adoption/public` 라우터 분리는 진행됨
  - `service-info`, `/`, `/web/*`, `/api/public/*` 공개 진입 경로는 `app.domains.public.router`로 이동
  - `W02~W15 adoption tracker`는 `app.domains.adoption.router_tracker`로 이동
  - `W04~W15 adoption KPI/policy`는 `app.domains.adoption.router_ops`로 이동
  - `ops governance/alert/SLA policy`는 `app.domains.ops.router_governance`, `router_alerts`로 이동
  - `utility billing`은 `app.domains.ops.router_billing`으로 이동
  - `official documents / integrated reports`는 `app.domains.ops.router_official_documents`로 이동
  - `tutorial simulator`, `dashboard trends`, `handover brief`는 `app.domains.ops.router_tutorial`, `router_reporting`으로 이동
  - `app/main.py`에는 직접 route decorator가 없고, 앱 부트스트랩/미들웨어/호환 helper만 남아 있음
- 운영 자동화 상태
  - 배포/스모크/런북/거버넌스/리메디에이션 자동화는 운영 가능한 수준
  - cron job 블루프린트도 다수 구성됨
- 최근 운영 반영 상태(2026-03-07)
  - IAM 토큰/감사로그 콘솔 기능 반영
  - 메뉴탭 툴팁(영문 용어 + 한글 설명) 반영
  - OPS 체크리스트/권한/토큰/감사 응답 메타 규약 1차 반영
  - 감사로그 카테고리 사전 문서화 (`docs/AUDIT_LOG_CATEGORY_DICTIONARY.md`)
  - 월간 감사 아카이브 `format_version=v2`, `attachment_schema_version=v2` 고정
  - R4 운영 신뢰성 강화 반영
    - 운영 스모크 UI 핵심 경로(`/ ?tab=iam`) 추가
    - runbook critical 월간 review loop API/배치 추가
    - governance gate DR 가중치/가중 점수 반영
    - 배포 체크리스트 자동 버전(`current_utc_month + deploy_smoke signature sequence`) 반영
  - audit chain write 직렬화 + 운영 rebaseline 완료
    - 런타임 커밋 `1ed4f4c`
    - 운영 배포 `dep-d6llg3ea2pns73b434sg` + `SMOKE_OK`
    - `/api/admin/audit-integrity` `chain_ok=true`
    - `/api/ops/governance/gate` `decision=go`
  - 비차단 운영 경고 오탐 정리 + 샘플 증빙 복구 반영
    - 런타임 커밋 `7b7835d`
    - 운영 배포 `dep-d6lmemkhg0os73aske20` + `SMOKE_OK`
    - `alert_retry_recent`, `alert_retention_recent`, `ops_quality_weekly_report_streak`, `api_latency_p95`, `api_burn_rate`, `evidence_archive_integrity_batch` 정상화
    - 샘플 증빙 누락 blob 다운로드 self-heal 적용
    - 당시 남은 실경고: `w07_quality_alert_channel` (webhook target 미구성)
  - W07 품질 알림 내부 webhook 채널 운영 연결 완료
    - 런타임 커밋 `aec572a`
    - 운영 배포 `dep-d6ln61p5pdvs73a7b54g`(route 반영), `dep-d6ln7engi27c73dne7dg`(env 적용) + `SMOKE_OK`
    - internal webhook API `/api/ops/alerts/webhook/internal` 추가
    - guard recover probe `probe_status=success`
    - `/api/ops/runbook/checks` `overall_status=ok`
    - `/api/ops/governance/gate` `weighted_score_percent=100.0`
  - Slack/Teams 외부 채널 adapter 지원 배포
    - 런타임 커밋 `9b9679b`
    - 운영 배포 `dep-d6lnmsi4d50c73ceirt0` + `SMOKE_OK`
    - host auto-detect(`hooks.slack.com`, `logic.azure.com`, `office.com`) + explicit prefix(`slack::`, `teams::`, `generic::`) 지원
    - 현재 운영 target은 내부 webhook 유지, 실제 외부 secret URL만 추가하면 확장 가능
  - 배포 환경변수 정합성 수정 + helper/service 추가 추출
    - 사용자 환경변수 `RENDER_SERVICE_ID`를 실제 운영 웹서비스 `srv-d6g57jbuibrs739g5mvg`로 정정
    - 런타임 커밋 `7c17db2`
    - 운영 배포 `dep-d6m0ctk50q8c73abg7l0` + `SMOKE_OK`
    - `app.domains.ops.service`로 ops quality/DR rehearsal/governance gate-remediation helper 추출
    - 검증: split test run total `101 passed` (`16 + 36 + 20 + 29`)
  - remediation/autopilot helper 추가 추출
    - 런타임 커밋 `4bfea9f`
    - 운영 배포 `dep-d6m0pkp4tr6s7386n830` + `SMOKE_OK`
    - `app.domains.ops.remediation_service`로 W21~W30 remediation/autopilot helper 추출
    - 검증: split test run total `101 passed` (`16 + 36 + 20 + 29`)
  - inspection/evidence helper 추가 추출
    - 런타임 커밋 `48019cd`
    - 운영 배포 `dep-d6m133bh46gs73bc4ke0` + `SMOKE_OK`
    - `app.domains.ops.inspection_service`로 inspection/evidence helper 추출
    - 검증: split test run total `101 passed` (`16 + 36 + 49`)
  - workflow/work-order helper 추가 추출 + privileged smoke 자동 복구
    - 런타임 커밋 `d6d43dc`
    - 운영 배포 `dep-d6m23q7gi27c73ds4gk0` + `SMOKE_OK`
    - `app.domains.ops.workflow_service`로 work-order/workflow helper 추출
    - `scripts/render_env_utils.ps1` 추가, `post_deploy_smoke.ps1`가 Render env의 `ADMIN_TOKEN`을 자동 조회
    - `deploy_and_verify.ps1`는 deploy hook 없이도 Render API로 직접 배포 가능
    - live 검증: `/api/auth/me` `role=owner`, `/api/ops/runbook/checks` `overall_status=ok`
  - adoption tracker helper 추가 추출 + smoke marker 도입
    - 런타임 커밋 `bc434c6`
    - 운영 배포 `dep-d6m2ga450q8c73ac79bg` + `SMOKE_OK`
    - `app.domains.adoption.tracker_service`로 `W02~W15` tracker/catalog/readiness/load/reset helper 추출
    - `pytest.ini`에 `smoke` marker 추가, 배포 핵심 회귀 5개를 `pytest -m smoke`로 분리
    - 검증: `pytest -q -m smoke` `5 passed, 96 deselected`, split test run total `101 passed`
    - live 검증: `/api/adoption/w15/tracker/overview?site=HQ` `200 OK`, `/api/ops/runbook/checks` `overall_status=ok`
  - ops record/model helper 추가 추출 + deploy 사전 smoke 강제
    - 런타임 커밋 `0e38087`
    - 운영 배포 `dep-d6m2o6h5pdvs738nsk80` + `SMOKE_OK`
    - `app.domains.ops.record_service`로 `job_runs`, `alert_deliveries`, `sla_policy_*` helper 추출
    - `deploy_and_verify.ps1`가 기본적으로 `python -m pytest -q -m smoke`를 먼저 실행하고 통과 시에만 배포
    - 실제 검증: `PRE_DEPLOY_SMOKE_OK -> SMOKE_OK -> DEPLOY_AND_SMOKE_OK`
    - live 검증: deploy commit `0e38087`, `/api/auth/me role=owner`, `/api/ops/runbook/checks overall_status=ok`
  - alert policy/dispatch/analytics helper 추가 추출 + deploy commit 정합성 재시도
    - 런타임 커밋 `0d1507e`
    - 운영 배포 `dep-d6m39ep5pdvs738o2qc0` + `SMOKE_OK`
    - `app.domains.ops.alert_service`로 MTTR policy, alert target/render, guard, retention, dispatch, KPI/MTTR snapshot helper 추출
    - `deploy_and_verify.ps1`가 기대 commit(`git rev-parse HEAD`)과 live deploy commit 불일치 시 자동 재시도
    - stale process env의 `RENDER_SERVICE_ID`가 예상 서비스와 다르면 user env `srv-d6g57jbuibrs739g5mvg`로 자동 fallback
    - 실제 검증: `TARGET_SERVICE_FALLBACK`, `DEPLOY_COMMIT_MATCH`, `PRE_DEPLOY_SMOKE_OK`, `SMOKE_OK`, `DEPLOY_AND_SMOKE_OK`

## 앞으로의 로드맵 재설계 (2026-03-15 기준)

기존 R0~R5는 대부분 완료되어, 이제 로드맵의 초점은 “기능 추가”보다 “현업 전환 가능한 운영 제품 완성”으로 바꿔야 한다.

### 재설계 원칙

- 기능 축은 아래 5개로 고정한다.
  - 전기직무고시 법정 점검 관리
  - 소방 법정 점검 관리
  - OPS 입력 관리
  - QR 설비관리
  - 시설관리 데이터 축적
- 앞으로의 작업은 아래 3가지 완료 조건을 동시에 만족해야 한다.
  - 코드/테스트 완료
  - 운영 배포 및 smoke 완료
  - 실제 사용자 흐름 기준 검증 완료
- 신규 주차형 기능(W16+)을 계속 늘리기보다, 지금 있는 기능을 현장 운영 수준으로 마감하는 쪽을 우선한다.
- 기존 완료 이력은 하단 레퍼런스로 유지하고, 상단은 앞으로 90일 실행 계획만 다룬다.

## 2026-03-14 단계 1 완료 상태

- [x] 로컬 검증환경 복구
  - `.venv`에 테스트 런타임 의존성(`pytest`, `httpx`, `alembic` 등) 정합화 완료
  - `pytest.ini`에 `testpaths`, `norecursedirs`를 추가해 임시 디렉터리 재수집을 차단
  - `scripts/run_pytest.ps1` 추가로 `.venv` + 안전한 Temp 기반 `pytest` 실행 경로 표준화
- [x] 로컬 검증 결과 고정
  - smoke: `9 passed, 121 deselected`
  - acceptance: `6 passed, 124 deselected`
  - full regression: `130 passed`
- [x] 단계 2 착수 조건 충족
  - acceptance 시나리오를 문서 기준이 아니라 실행 기준으로 고정할 수 있는 상태 확보

## 2026-03-14 단계 2 진행 상태

- [x] A1 owner acceptance 고정
  - 문서: `docs/ACCEPTANCE_A1_LEGAL_INSPECTION_FLOW.md`
  - 테스트: `tests/api/test_acceptance_a1.py`
- [x] A2 owner acceptance 고정
  - 문서: `docs/ACCEPTANCE_A2_OFFICIAL_DOCUMENT_FLOW.md`
  - 테스트: `tests/api/test_acceptance_a2.py`
- [x] A3 owner acceptance 고정
  - 문서: `docs/ACCEPTANCE_A3_BILLING_FLOW.md`
  - 테스트: `tests/api/test_acceptance_a3.py`
- [x] A1~A3 role matrix 고정
  - 문서: `docs/ACCEPTANCE_ROLE_MATRIX.md`
  - 테스트: `tests/api/test_acceptance_role_matrix.py`
- [x] 운영 smoke 승격 후보 선정
  - 문서: `docs/ACCEPTANCE_SMOKE_PROMOTION.md`
  - 결정:
    - `A1-lite` -> privileged post-deploy smoke 1순위
    - `A2-lite` -> privileged smoke 확장 2순위
    - `A3-lite` -> nightly/non-blocking smoke 후보
- [x] `A1-lite` 실제 smoke/CI 편입
  - 스크립트: `scripts/post_deploy_smoke.ps1`, `scripts/deploy_and_verify.ps1`
  - 테스트: `tests/api/test_smoke_a1_lite.py`
  - CI: `.github/workflows/ci.yml`에 `pytest -q -m smoke` 단계 반영
- [x] `A2-lite` opt-in smoke 확장 구현
  - 스크립트: `scripts/post_deploy_smoke.ps1`, `scripts/deploy_and_verify.ps1` (`RunA2Lite`)
  - 테스트: `tests/api/test_smoke_a2_lite.py`
- [x] inspection/work-order key snapshot 1차 반영
  - migration: `migrations/versions/20260314_0030_ops_key_snapshots.py`
  - 적용 범위: `equipment_snapshot`, `equipment_location_snapshot`, `qr_id`, `checklist_set_id`, `checklist_version`
- [x] relational equipment/QR master 1차 반영
  - migration: `migrations/versions/20260314_0031_ops_asset_masters.py`
  - 적용 범위: `ops_equipment_assets`, `ops_qr_assets`, `inspections.equipment_id/qr_asset_id`, `work_orders.equipment_id/qr_asset_id`
- [x] inspection UI/API를 `master id + snapshot` 제출 방식으로 전환
  - API: `/api/ops/inspections/checklists/catalog`, `POST /api/inspections`
  - UI: `app/web/main_tabs.py`가 `equipment_id`, `qr_asset_id`를 note/meta와 payload에 함께 제출
- [x] 운영 evidence template 초안 작성
  - 문서: `docs/ACCEPTANCE_EVIDENCE_TEMPLATE.md`
- [x] 기준키 연결표 작성
  - 문서: `docs/ACCEPTANCE_KEY_LINKAGE_TABLE.md`
- [x] 설비/QR/checklist_set_id 코드 기준 gap 분석 작성
  - 문서: `docs/OPS_KEY_NORMALIZATION_GAP_ANALYSIS.md`
- [x] migration backfill 검증 추가
  - 테스트: `tests/test_migration_ops_key_snapshots.py`, `tests/test_migration_ops_asset_masters.py`
- [x] 운영 검증 artifact/evidence와 privileged smoke 결과 아카이브 자동화
  - env/path: `DEPLOY_SMOKE_ARCHIVE_PATH`
  - API: `/api/ops/deploy/smoke/record` detail에 `artifact_archive` 기록
  - 테스트: `tests/api/test_ops_governance.py`
- [x] checklist_set relational master 1차 반영
  - migration: `migrations/versions/20260314_0032_ops_checklist_masters.py`
  - 적용 범위: `ops_checklist_sets`, `ops_checklist_set_items`
- [x] equipment/QR/checklist master CRUD 화면과 API 추가
  - API: `/api/ops/inspections/checklists/equipment-assets`, `/api/ops/inspections/checklists/sets`, `/api/ops/inspections/checklists/qr-assets`
  - UI: `app/web/main_tabs.py`의 `OPS 마스터 관리` 박스 + inspection 입력용 `설비마스터` selector
- [x] checklist master CRUD/inspection linkage 검증 추가
  - 테스트: `tests/api/test_ops_core.py`, `tests/test_migration_ops_checklist_masters.py`
- [x] QR/equipment/checklist master lifecycle state 1차 반영
  - migration: `migrations/versions/20260314_0033_ops_master_lifecycle_and_checklist_revisions.py`
  - 적용 범위: `ops_equipment_assets.lifecycle_state`, `ops_qr_assets.lifecycle_state`, `ops_checklist_sets.lifecycle_state`
- [x] checklist set version/approval workflow 1차 반영
  - table/API: `ops_checklist_set_revisions`, `/api/ops/inspections/checklists/revisions`, `/submit`, `/approve`, `/reject`
  - UI: `app/web/main_tabs.py`의 `OPS 마스터 관리`에 revision draft/submit/approve/reject 추가
- [x] QR/equipment/checklist master 검색/필터 정책 확정
  - API: `/api/ops/inspections/checklists/catalog`, `/equipment-assets`, `/sets`, `/qr-assets`에 `q`, `lifecycle_state`, `include_inactive` 반영
  - UI: `app/web/main_tabs.py`의 `OPS 마스터 관리`에 search + lifecycle/revision status filter 반영
- [x] checklist revision diff/release 정책 확정
  - API: `/api/ops/inspections/checklists/revisions/{id}` detail + diff/release note validation
  - 규칙: submit/approve 전 `Summary`, `Impact`, `Rollback` release note 섹션 필수
  - UI: revision diff 패널 + release note template placeholder 추가
- [x] QR placeholder 정리 이후 변경 이력(audit + revision) 저장
  - migration/table: `migrations/versions/20260314_0034_ops_qr_asset_revisions.py`, `ops_qr_asset_revisions`
  - API: `GET /api/ops/inspections/checklists/qr-assets/revisions`
  - 적용 범위: QR CRUD + placeholder bulk-update가 before/after + actor + source를 revision row로 저장
  - 증빙 export: 월간 감사 아카이브가 `ops_qr_asset_revisions_attachment`를 함께 내보냄
- [x] `app/main.py` / `app/schemas.py` / `app/database.py` 2차 분해 1차 착수
  - 분리 모듈: `app/domains/ops/checklist_runtime.py`, `app/domains/ops/schemas.py`, `app/domains/ops/tables.py`
  - 적용 방식: `app/main.py`는 checklist runtime wrapper 위임, `app/schemas.py`와 `app/database.py`는 OPS core re-export 구조로 축소
  - 추가 정리: `checklist_runtime.py`는 더 이상 `app.main`을 import하지 않음
- [x] 통합 리포트 asset scope pivot 반영
  - API: 월간/연간 integrated report, csv/pdf/print가 `equipment_id`, `qr_asset_id` query를 수용
  - 동작: inspection/work-order/official-document 섹션은 자산 scope로 좁혀지고, billing은 `scope_applicable=false`로 명시적 제외
  - 테스트: `tests/api/test_official_documents.py`
- [x] `inspection_service` / `workflow_service` / `iam.service` standalone import 정리
  - 추가 모듈: `app/domains/iam/core.py`
  - 적용 방식: 세 서비스가 더 이상 `app.main`을 직접 import하지 않고, `app/main.py`도 inspection/workflow service에 `bind(globals())`를 호출하지 않음
  - 회귀 검증: `tests/api/test_auth_iam.py`, `tests/api/test_ops_core.py`, `tests/api/test_official_documents.py`, `tests/api/test_adoption.py`
- [x] `iam.security` / `record_service` standalone import 정리
  - 적용 범위: `app/domains/iam/security.py`, `app/domains/ops/record_service.py`
  - 추가 정리: `app/main.py`가 더 이상 `record_service.bind(globals())`를 호출하지 않음
  - 회귀 검증: `tests/api/test_auth_iam.py`, `tests/api/test_ops_governance.py`, `tests/api/test_alerts.py`
- [x] `ops.service` / `alert_service` standalone import 정리
  - 적용 범위: `app/domains/ops/service.py`, `app/domains/ops/alert_service.py`
  - 추가 모듈: `app/domains/ops/config.py`
  - 적용 방식: 두 서비스가 더 이상 `app.main`을 직접 import하거나 `bind(globals())`에 의존하지 않고, `config.runtime` proxy로 현재 `app.main` 설정 override를 읽음
  - 회귀 검증: `tests/api/test_alerts.py`, `tests/api/test_ops_governance.py`, `tests/api/test_platform.py`
- [x] `ops.remediation_service` / `adoption.tracker_service` direct main import 정리
  - 적용 범위: `app/domains/ops/remediation_service.py`, `app/domains/adoption/tracker_service.py`
  - 추가 모듈: `app/runtime_bridge.py`
  - 적용 방식: `remediation_service`는 standalone import + `ops.config.runtime`로 정리했고, `tracker_service`는 `app.main` 직접 import 대신 runtime bridge로 adoption payload/status/content 심볼을 읽음
  - 추가 정리: `app/main.py`가 더 이상 `remediation_service.bind(globals())`, `tracker_service.bind(globals())`를 호출하지 않음
  - 회귀 검증: `tests/api/test_ops_governance.py`, `tests/api/test_adoption.py`
- [x] lifecycle/revision 회귀 검증 추가
  - 테스트: `tests/api/test_ops_core.py`, `tests/test_migration_ops_master_lifecycle_and_revisions.py`, `tests/test_migration_ops_qr_asset_revisions.py`
- [x] 실행 기준 재검증
  - `.\scripts\run_pytest.ps1 -q -m smoke` -> `9 passed, 121 deselected`
  - `.\scripts\run_pytest.ps1 -q -m acceptance` -> `6 passed, 124 deselected`
  - `.\scripts\run_pytest.ps1 -q` -> `130 passed`
- [x] CI smoke + acceptance 실행 추가
  - `.github/workflows/ci.yml`에 `pytest -q -m smoke`, `pytest -q -m acceptance`, `pytest -q` 단계 반영

## 현재 판정

### 이미 운영 가능한 축

- [x] 전기/소방 법정점검 입력과 점검 이력 조회
- [x] 작업지시 생성, SLA 정책, 에스컬레이션, 타임라인
- [x] IAM 권한관리, 토큰 운영, 감사로그 조회
- [x] QR placeholder 탐지와 bulk update API
- [x] 공문 접수/첨부/기한초과 sync/월간-연간 리포트
- [x] 전기/수도 검침, 공용요금 배부, 청구 생성
- [x] 튜토리얼, 온보딩, 콘솔 가이드, IAM 가이드
- [x] 배포 smoke, runbook, governance gate, privileged smoke 자동 복구
- [x] 로컬 smoke/full regression 실행 경로 복구

### 아직 약한 축

- [ ] `A2-lite`를 default privileged smoke로 승격할지 운영 비용 기준 확정
- [ ] `A3-lite`를 nightly/non-blocking smoke로 연결
- [ ] 전기/소방 점검 결과의 출력물/보고서/증빙 패키지 표준화
- [ ] 공문 처리와 법정점검/작업지시 간 기준키 연결 명확화
- [ ] asset-scoped integrated report에서 billing 섹션을 어떤 규칙으로 연결할지 확정
- [ ] `app.main` 역의존 제거와 remaining helper/service 분리까지 포함한 구조 2차 분해 마감 (`inspection_service`, `workflow_service`, `iam.service`, `iam.security`, `record_service`, `ops.service`, `alert_service`, `ops.remediation_service`까지는 정리 완료. `adoption.tracker_service`는 direct import/bind 제거 완료, 남은 직접 대상은 일부 router helper와 adoption content/payload 본체 이동`)

## 90일 목표

### G1. 현업 전환

- 관리소 기준으로 아래 3개 acceptance 시나리오를 사람 손으로 실제 수행할 수 있게 만든다.
  - A1. 법정점검 -> 이상조치 작업지시 -> SLA -> 감사로그 -> 월간 통합 리포트
  - A2. 공문 접수 -> 첨부 저장 -> 기한초과 sync -> 작업지시 -> 공문 리포트
  - A3. 검침 -> 공용요금 배부 -> 청구 생성 -> 청구 조회

### G2. 데이터 기준선

- 사이트, 설비, QR, 점검, 작업지시, 증빙이 서로 일관된 키와 버전으로 연결되게 만든다.

### G3. 운영 신뢰성

- `code -> test -> deploy -> smoke -> runbook -> gate` 흐름을 사람 개입 없이 재현 가능하게 만든다.

### G4. 구조 안정화

- `app/main.py`를 더 줄이고, 남은 대형 모듈을 도메인 단위로 분리해 이후 유지보수 비용을 낮춘다.

## 새 실행 로드맵

### F1. acceptance 시나리오 3개 고정 (우선순위 1, 다음 2주)

- [x] A1. 법정점검 흐름 고정
  - 전기/소방 점검 저장 -> 이상조치 작업지시 생성 -> SLA 확인 -> 감사로그 조회 -> 월간 통합 리포트까지 1개 흐름으로 묶는다.
  - owner 기준 문서/pytest acceptance 고정 완료 (`docs/ACCEPTANCE_A1_LEGAL_INSPECTION_FLOW.md`, `tests/api/test_acceptance_a1.py`)
- [x] A2. 공문 처리 흐름 고정
  - 공문 접수 -> 첨부 업로드 -> overdue sync -> 연계 작업지시 -> 월간/연간 공문 리포트까지 1개 흐름으로 묶는다.
  - owner 기준 문서/pytest acceptance 고정 완료 (`docs/ACCEPTANCE_A2_OFFICIAL_DOCUMENT_FLOW.md`, `tests/api/test_acceptance_a2.py`)
- [x] A3. 검침/청구 흐름 고정
  - 세대/요율/검침/공용요금 입력 -> billing run -> 청구서 조회까지 1개 흐름으로 묶는다.
  - owner 기준 문서/pytest acceptance 고정 완료 (`docs/ACCEPTANCE_A3_BILLING_FLOW.md`, `tests/api/test_acceptance_a3.py`)
- [x] 3개 시나리오 모두에 대해 owner/manager/operator/auditor 권한 매트릭스를 실제 API 기준으로 점검한다.
- [x] 3개 시나리오 모두를 acceptance test 대상으로 확정한다.

완료 기준:
- 3개 시나리오가 문서 없이 API/UI만으로 재현 가능
- 각 시나리오별 입력 데이터, 기대 결과, 검증 포인트가 문서와 테스트로 남아 있음
- 최소 1회 로컬 full regression + smoke 이후에도 시나리오 정의가 유지됨

### F2. 설비/QR 마스터 운영 완성 (우선순위 1, 2~4주)

- [x] QR/설비/checklist master CRUD 화면과 관리자 API 세트 추가
- [x] 설비코드, 설비위치, QR ID, 기본점검항목의 기준키를 명시적으로 정리
- [x] QR/설비/checklist master lifecycle state 1차 추가
- [x] checklist set 변경 승인/버전 관리 1차 추가
- [x] QR/설비/checklist master 검색 정책 추가
- [x] checklist revision diff/release 정책 확정
- [x] QR placeholder 정리 이후의 변경 이력(audit + revision) 저장
- [ ] QR 선택 시 점검 입력 화면 자동채움 로직을 “운영 규칙”으로 문서화
- [ ] 신규 설비 등록부터 점검 연결까지의 seed/import 절차 정리

완료 기준:
- QR 자산을 수동 JSON 수정 없이 운영 UI/API만으로 관리 가능
- 설비/QR 기준정보 변경이 감사 추적 가능

### F3. 법정점검 도메인 완성 (우선순위 1, 4~6주)

- [ ] 전기직무고시 체크리스트 버전 관리 체계 확정
- [ ] 소방 법정점검 체크리스트 버전 관리 체계 확정
- [ ] 점검 유형별 필수항목, 출력양식, 증빙요건을 정책화
- [ ] 월간/분기별 법정점검 패키지(점검결과, 조치이력, 증빙목록) 생성 API 추가
- [ ] 법정점검 누락/지연/미조치 항목을 한 눈에 보는 운영 대시보드 추가

완료 기준:
- 전기/소방 점검이 단순 입력이 아니라 “법정 기록 패키지”로 재구성 가능
- 월간 감사 또는 대내 보고 자료로 바로 활용 가능

### F4. 시설관리 데이터 축적/리포트 (우선순위 2, 6~8주)

- [ ] 사이트별 시설 데이터 snapshot 테이블 또는 export 규격 정의
- [ ] 점검, 작업지시, SLA, 증빙, QR 자산을 묶는 월간 KPI 스냅샷 저장
- [ ] 반복 이상 설비, 미조치 설비, 점검누락 설비, SLA 초과 설비 집계 추가
- [ ] 운영 리포트 API를 “실시간 조회”와 “월간 고정본”으로 분리
- [ ] 장기 추세 분석용 CSV/JSON export 규격 정리

완료 기준:
- “데이터가 쌓인다”는 말을 화면과 export 결과로 확인 가능
- 월간 운영회의 자료를 시스템에서 바로 뽑을 수 있음

### F5. 구조 2차 분해 (우선순위 2, 8~10주)

- [x] OPS core tables/schema/checklist runtime 1차 분리
- [ ] `app/main.py`를 12k lines 이하로 축소
- [ ] `app/schemas.py`를 도메인별 schema 모듈로 분리
- [ ] `app/database.py`의 테이블/헬퍼를 관심사별로 분리
- [ ] governance snapshot, adoption policy, remaining row-model helper를 별도 서비스로 분리
- [ ] import dependency 방향을 점검해 `app.main -> domain` 단방향 조립 구조를 강화 (`inspection_service`, `workflow_service`, `iam.service`, `iam.security`, `record_service` 정리는 완료)

완료 기준:
- 신규 기능 추가 시 `app/main.py`를 직접 수정하지 않는 비율이 높아짐
- 도메인 테스트와 코드 탐색 비용이 눈에 띄게 줄어듦

### F6. 배포/검증 자동화 2차 (우선순위 2, 10~12주)

- [ ] `deploy_and_verify.ps1` 결과를 JSON summary로 저장
- [ ] smoke, full regression, privileged smoke의 실행 정책을 명문화
- [ ] 환경변수 drift check와 service-id validation을 배포 전 강제
- [ ] CI에서 smoke/acceptance/full 결과 artifact와 주요 split 회귀를 자동 실행
- [ ] 운영 배포 후 핵심 API/HTML marker 검증 결과를 아카이브

완료 기준:
- 운영 배포 결과를 사람이 콘솔 로그로 읽지 않아도 JSON/문서로 추적 가능
- “잘못된 서비스에 배포”와 “오래된 commit 배포”를 자동 차단

## 바로 착수할 2주 실행 순서

### Week 1

- [x] Day 1: A1~A3 acceptance 중 운영 smoke 승격 후보 선정
- [x] Day 2: 3개 시나리오 공통 기준키(site/equipment/qr/work_order/document/unit) 연결표 작성
- [ ] Day 3: 공문/청구/통합리포트 기준키 gap 정리
- [x] Day 4: 운영 검증 체크리스트 + evidence template 초안
- [x] Day 5: 로컬 full/acceptance/smoke 재검증

### Week 2

- [x] Day 1: acceptance 결과를 smoke/runbook 후보와 연결
- [ ] Day 2: CI acceptance 결과 artifact/summary 저장 방식 정리
- [x] Day 3: OPS key master / smoke archive 반영 후 로컬 재검증
- [ ] Day 4: 구조 2차 분해 우선 대상(router_official_documents, router_tracker, router_governance) 확정
- [ ] Day 5: F1 완료 판정 및 F2/F3 우선순위 재조정

## 이번 재설계에서 보류할 것

- [ ] 신규 W16+ 주차형 기능 확장
- [ ] 대규모 UI 재디자인
- [ ] 외부 알림 채널 2개 이상 동시 연결
- [ ] 비핵심 시각화 추가

## 운영 규칙

- 모든 완료 항목은 아래 3가지를 함께 기록
  - commit SHA
  - deploy ID
  - smoke 결과(`SMOKE_OK` 여부)
- 목표 추가 시 아래 2가지를 같이 적는다.
  - 사용자 시나리오 기준 효과
  - 운영 지표 기준 효과
- 완료된 계획은 상단에서 제거하지 말고, 하단 레퍼런스 이력으로 이동한다.

---

아래 기존 섹션(W16~W31 및 과거 완료 이력)은 추적 목적의 레퍼런스로 유지합니다.

## 즉시 실행 체크리스트 (2026-03-04 착수)

### 1. 필수값 강제 + 누락 방지
- [x] OPS 점검 저장 API(`POST /api/inspections`)에 서버측 필수검증 추가
  - 태그: `[OPS_CHECKLIST_V1]`, `[OPS_ELECTRICAL_V1]` 모두 인식
  - 필수 메타: `task_type`, `equipment`, `equipment_location`, `checklist_set_id`
  - 필수 구조: `checklist` 배열/행 `group,item,result`
- [x] 이상(`abnormal`) 항목에 조치 누락 시 저장 차단
  - 행 조치(`row.action`) 또는 `meta.abnormal_action` 중 최소 1개 필수
- [x] 체크리스트-요약 정합성 검증
  - `summary.total/normal/abnormal/na`와 실제 행 집계 불일치 시 422 반환

### 2. 엑셀 Import 검증 리포트
- [x] Import 검증 API 추가
  - `GET /api/ops/inspections/checklists/import-validation`
- [x] Import 검증 CSV Export API 추가
  - `GET /api/ops/inspections/checklists/import-validation.csv`
- [x] 검증 규칙 적용
  - checklist set/item 중복/누락
  - OPS 코드 중복/분류-세트 매핑 불일치
  - QR 자산 중복/placeholder/기본점검항목 매핑 누락
- [x] 메인 점검 화면에 검증 리포트 조회 UI 추가

### 3. 점검 -> 작업지시 SLA 자동화 룰 확정
- [x] 룰 공개 API 추가
  - `GET /api/work-orders/sla/rules`
- [x] 점검 연계 작업지시 생성 시 자동 우선순위 하한 적용
  - 입력: `inspection_id`가 있는 `POST /api/work-orders`
  - 룰: 위험도(`risk_level`) + 이상건수(`abnormal`) 기반 `priority` 상향
- [x] 사이트 정합성 강제
  - `inspection.site`와 `work_order.site` 불일치 시 생성 차단(400)
- [x] due_at 자동 계산 시 상향된 우선순위 기준으로 SLA 시간 반영

### 남은 후속 작업
- [x] QR placeholder 탐지/일괄치환 API 추가
  - `GET /api/ops/inspections/checklists/qr-assets/placeholders`
  - `POST /api/ops/inspections/checklists/qr-assets/bulk-update` (`dry_run`, `create_missing` 지원)
- [x] QR설비관리 원본 placeholder 데이터(`설비/위치/점검항목`) 실제값 대량 치환 실행
- [x] OPS코드 `기계/건축/안전` 카테고리 매핑 규칙 확장(Import 검증룰 + fallback checklist_set)
- [x] 원본 데이터셋(`data/apartment_facility_special_checklists.json`)에 `기계/건축/안전` checklist_set 전량 반영
- [x] Import 검증 결과를 월간 감사 리포트와 자동 연동

## 최근 완료(2026-03-01)
- 안정화 스프린트 3대 과제 완료
  - 성능: 주요 API P95 지연 모니터/런북 체크 반영
  - 신뢰성: 배포 스모크 + 롤백 체크리스트 API/스크립트 표준화
  - 데이터: 증빙/감사 아카이브 무결성 배치 점검 강화
- W17-3 착수 완료
  - `ops_daily_check` 결과 요약 자동 JSON/CSV 아카이브 발행
  - 최신 요약 및 이력 JSON/CSV API 추가
- W17-4 + W18 준비 구현
  - 운영 품질 리포트 주간/월간 템플릿 API + 배치 잡 추가
  - startup preflight, DR rehearsal, 관리자 보안 대시보드 API 추가
  - 배포 스모크에 롤백 가이드 존재/체크섬 검증 연결
- W18-2~4 구현 고도화
  - 관리자 보안 대시보드에 리스크 점수/권한 이상징후/권고안/민감이벤트 피드 추가
  - 월간 감사 아카이브에 DR 리허설 결과 자동 첨부(`dr_rehearsal_attachment`) 연계
  - deploy smoke record에 롤백 가이드 경로/체크섬 바인딩 검증(detail) 추가
- W19 착수 완료: Governance Release Gate Automation
  - `GO/NO-GO` 자동 판정 API/배치(`ops_governance_gate`) 구현
  - preflight/runbook/security risk/deploy binding/DR/streak 규칙 기반 판정 표준화
  - 일일 거버넌스 게이트 Cron(`ka-facility-os-ops-governance-gate`) 블루프린트 추가
- W20 착수 완료: Governance Remediation Pack
  - 게이트 규칙 결과를 실행 가능한 조치계획으로 변환(`owner_role`, `sla_hours`, `due_at`, `action`)
  - `/api/ops/governance/gate/remediation` + CSV export API 추가
  - 운영자가 즉시 후속 작업을 배정할 수 있는 우선순위 목록 자동 생성
- W21 착수 완료: Governance Remediation Execution Tracker
  - 리메디에이션 항목 동기화(sync) + 담당자/상태/완료체크 추적 API 추가
  - readiness/overview/completion 판정 API 추가
  - 완료 후 재동기화 시 자동 재오픈/자동 해소 로직 반영
- W22 착수 완료: Governance Remediation SLA Escalation
  - 리메디에이션 SLA 스냅샷 API(`.../tracker/sla`) 추가
  - 에스컬레이션 실행/최신조회 API(`.../tracker/escalate/run|latest`) 추가
  - 시간단위 Cron 잡(`ops_governance_remediation_escalation`) 연동 준비
- W23 착수 완료: Governance Remediation Auto Assignment
  - 워크로드/추천 API(`.../tracker/workload`) 추가
  - 자동할당 실행/최신조회 API(`.../tracker/auto-assign/run|latest`) 추가
  - 시간단위 Cron 잡(`ops_governance_remediation_auto_assign`) 연동 준비
- W24 착수 완료: Governance Remediation KPI Pulse
  - KPI 스냅샷 API(`.../tracker/kpi`) 추가
  - KPI 실행/최신조회 API(`.../tracker/kpi/run|latest`) 추가
  - 시간단위 Cron 잡(`ops_governance_remediation_kpi`) 연동 준비
- W25 착수 완료: Governance Remediation Autopilot
  - 자동조치 실행/최신조회 API(`.../tracker/autopilot/run|latest`) 추가
  - KPI 기반 auto-assign/escalation 연계 오케스트레이션 추가
  - 시간단위 Cron 잡(`ops_governance_remediation_autopilot`) 연동 준비
- W26 착수 완료: Governance Remediation Autopilot Policy and Preview
  - 자동조치 정책 조회/수정 API(`.../tracker/autopilot/policy`) 추가
  - 실행 전 판정 API(`.../tracker/autopilot/preview`) 추가
  - 정책 기반 임계치/윈도우/알림 설정 런타임 반영
- W27 착수 완료: Governance Remediation Autopilot Guardrails
  - 쿨다운/실행차단 가드 API(`.../tracker/autopilot/guard`) 추가
  - autopilot 실행 응답에 `planned_actions`/`guard`/`skipped` 정보 표준화
  - 정책(`cooldown_minutes`, `skip_if_no_action`) 기반 중복 실행 억제 적용
- W28 착수 완료: Governance Remediation Autopilot Analytics
  - autopilot 이력 API(`.../tracker/autopilot/history`) 추가
  - autopilot 요약 API(`.../tracker/autopilot/summary`) 추가
  - 실행/스킵/쿨다운 차단 추세를 운영 지표로 집계
- W29 착수 완료: Governance Remediation Autopilot Reporting Export
  - autopilot 이력 CSV API(`.../tracker/autopilot/history.csv`) 추가
  - autopilot 요약 CSV API(`.../tracker/autopilot/summary.csv`) 추가
  - 운영 리포팅용 다운로드 포맷(지표/최신 실행 상태) 표준화
- W30 착수 완료: Governance Remediation Autopilot Health Signals
  - autopilot 이상징후 API(`.../tracker/autopilot/anomalies`) 추가
  - autopilot 이상징후 CSV API(`.../tracker/autopilot/anomalies.csv`) 추가
  - 성공률/스킵률/쿨다운 차단/에러런 기반 건강상태 자동 판정
- W31 착수 완료: Tutorial Simulator for New Users
  - 공개 튜토리얼 허브(`/api/public/tutorial-simulator`, `/web/tutorial-simulator`) 추가
  - 검증 샘플데이터 기반 세션 시작/조회/체크/실행 API(`.../ops/tutorial-simulator/sessions/*`) 추가
  - 점검→작업지시 ACK→완료→리포트 준비 조건을 실습/자동판정으로 제공
- 운영 전환 사전 안정화(2026-03-05)
  - `AdminToken` 포함 post-deploy smoke 1회 실행 완료(`SMOKE_OK`, deploy `dep-d6knu61aae7s73ahu5k0`)
  - 월간 감사 아카이브 해시/서명 검증 로직 보정(`archive_sha_ok/signature_ok` 일치)
  - API 지연 P95 계산을 모니터 윈도우 기준으로 보정(과거 샘플 과반영 제거)
  - smoke 스크립트에서 이전 실패이력(`deploy_smoke_checklist`) 자기참조 차단 로직 제거
  - 최신 반영 배포+스모크 성공(`SMOKE_OK`, deploy `dep-d6kogr3h46gs73d30ptg`, commit `0a1109f`)

## W16 진행상황 (2026-03-05)
- [x] 정책 API 공통 응답 메타 필드 표준화 1차 적용
  - 대상: `/api/ops/governance/gate/remediation/tracker/autopilot/policy` (GET/PUT)
  - 대상: `/api/ops/alerts/mttr-slo/policy` (GET/PUT)
  - 공통 메타: `meta.version`, `meta.scope`, `meta.applies_to`, `meta.policy_key`, `meta.updated_at`
- [x] W10/W11/W15 Adoption KPI 점검 화면 JS 공통화
  - 공통 함수: `runSharedAdoptionKpiOperation(phaseCode)`, `getSharedAdoptionKpiConfig(phaseCode)`
  - 공통 컬럼/요약 매핑: KPI/반복이슈/권고안/정책 테이블 렌더 중복 제거
  - 결과: `runW10KpiOperation`, `runW11KpiOperation`, `runW15KpiOperation`이 공통 실행 경로 사용
- [x] Tracker CRUD/evidence UI 템플릿 공통화 2차 적용
  - 대상: `W02/W03/W04` 실행추적 입력 박스
  - 공통 템플릿: `_build_shared_tracker_execution_box_html(phase_code, phase_label)`
  - 결과: `W02~W04/W09~W11/W15`가 동일 HTML/ID 규약으로 렌더링
- [x] 도메인 라우터 분리 1차 착수 (`ops/admin/adoption/public`)
  - `/api/ops/*` -> `ops_router`
  - `/api/admin/*` -> `admin_router`
  - `/api/adoption/*` -> `adoption_router`
  - `/api/public/*` -> `public_router`
  - 비고: `/`, `/web/*`, `/health`, `/meta`, `/api/auth/*`는 현재 `app` 직결 유지
- [x] W16 1~2번 운영 반영 배포 + AdminToken 스모크 완료 (2026-03-06)
  - deploy: `dep-d6krog7tskes73ar8n70` (`live`)
  - commit: `5863cc5` (`Consolidate tracker UI templates and route API domains via routers`)
  - smoke: `SMOKE_OK`
- [x] 정책 API(W09~W15) 메타 스키마 표준화 2차 적용
  - 공통 메타 확장: `meta.version`, `meta.scope`, `meta.applies_to`, `meta.policy_key`, `meta.updated_at`
  - 적용 경로: `/api/ops/adoption/w09~w15/*-policy` GET/PUT
  - 테스트: `test_w09_to_w15_policy_response_schema_standardized`에서 메타 필드 검증 강화
- [x] 정책 API 표준화 2차 운영 반영 배포 + AdminToken 스모크 완료 (2026-03-06)
  - deploy: `dep-d6ks12fpm1nc73f6a3t0` (`live`)
  - commit: `2082005` (`Standardize W09-W15 policy meta fields and tighten schema tests`)
  - smoke: `SMOKE_OK`
- [x] 메인/레거시 콘솔 토큰 저장키 통일 + 호환 마이그레이션 적용 (2026-03-06)
  - 공통 키: `kaFacilityAdminToken` (레거시 `kaFacilityMainToken` 자동 흡수)
  - deploy: `dep-d6ksecvpm1nc73f6j71g` (`live`), smoke: `SMOKE_OK`
- 관련 API
  - `/api/ops/performance/api-latency`
  - `/api/ops/deploy/checklist`
  - `/api/ops/deploy/smoke/record`
  - `/api/ops/integrity/evidence-archive`
  - `/api/ops/runbook/checks/latest/summary.json`
  - `/api/ops/runbook/checks/latest/summary.csv`
  - `/api/ops/runbook/checks/archive.json`
  - `/api/ops/runbook/checks/archive.csv`
  - `/api/ops/preflight`
  - `/api/ops/reports/quality/weekly`
  - `/api/ops/reports/quality/monthly`
  - `/api/ops/reports/quality/run`
  - `/api/ops/dr/rehearsal/run`

## 다음 목표
- W15 이후 운영을 "기능 확대"보다 "운영비용 절감 + 안정성 + 거버넌스 자동화"로 전환
- 신규 개발은 KPI 향상, 장애감소, 인수인계 단순화 효과가 확인되는 항목만 우선

## W16: Platform Consolidation (우선순위 1)
목표:
- W07~W15 실행추적 UI/JS 공통 컴포넌트화
- 정책 API(W09~W15) 응답 스키마 표준화
- `app/main.py` 모듈 분리 시작(도메인별 라우터 분리)

주요 작업:
1. `web/console`의 반복 JS 로직을 공통 함수로 추출
2. 트래커 CRUD/evidence 업로드 UI 블록 템플릿화
3. 정책 API 공통 응답 필드(메타/버전/적용범위) 통일
4. 단계별 라우터 분리(`ops`, `adoption`, `admin`, `public`)

완료 기준:
- 중복 JS/HTML 코드 30% 이상 축소
- 정책 API 응답 구조 일관성 테스트 추가
- 기존 58개 회귀 테스트 100% 유지

## W17: Observability and SLO Automation (우선순위 2)
목표:
- 지연/오류/SLO 지표의 영속화 및 추세 기반 경보 고도화
- 운영 주간 리포트 자동 발행

주요 작업:
1. 요청 지연 샘플의 DB 영속화(인메모리 보완)
2. 오류율/지연 P95/P99 기반 burn-rate 경보 추가
3. `ops_daily_check` 결과 요약 자동 CSV/JSON 발행
4. 월간/주간 운영 품질 리포트 템플릿 고정

완료 기준:
- 재시작 이후에도 지연추세 보존
- 경보 오탐/누락 기준 문서화
- 주간 리포트 생성 배치 4주 연속 성공

## W18: Governance and DR Automation (우선순위 3)
목표:
- 운영 안전장치(환경설정, 권한, 복구) 자동 점검
- 장애 복구 리허설을 정기 운영으로 전환

주요 작업:
1. startup preflight(필수 ENV 누락/오설정 탐지) 구현 [완료]
2. 관리자 권한/토큰 사용 감사 대시보드 강화 [완료]
3. 백업/복구 리허설 배치 자동 실행 및 결과 적재 [완료]
4. 마이그레이션 롤백 가이드와 배포 파이프라인 체크 연결 [완료]

완료 기준:
- preflight 실패 시 명확한 차단/경고 동작
- DR 리허설 결과를 월간 감사에 자동 첨부
- 권한/토큰 이상징후 탐지 규칙 운영

## W19: Release Governance Gate Automation (우선순위 4)
목표:
- 배포/운영 승인 판단을 정량 규칙으로 자동화
- 일일 거버넌스 점검 결과를 이력으로 남겨 감사 추적성 강화

주요 작업:
1. `GET/POST /api/ops/governance/gate*` API 도입(스냅샷/실행/최신/이력)
2. preflight + runbook critical + 보안 리스크 + DR/배포 바인딩 규칙 통합
3. `ops_governance_gate` Cron 배치로 일일 자동 판정 기록
4. 서비스 정보/문서/테스트/배포 설정 동기화

완료 기준:
- 최신 판정 기준으로 `GO/NO-GO`가 일관되게 계산됨
- 최소 1회 수동 실행 + 이력 조회 가능
- 회귀 테스트 전체 통과

## W20: Governance Remediation Automation (우선순위 5)
목표:
- `NO-GO/WARNING` 판정 이후 실행 항목을 자동 생성해 조치 리드타임 단축
- 운영자가 보고/회의 없이 바로 할당 가능한 형식(CSV) 제공

주요 작업:
1. 게이트 규칙 -> 조치계획 매핑(우선순위, 담당역할, SLA, 액션 문구)
2. `GET /api/ops/governance/gate/remediation` API 제공
3. `GET /api/ops/governance/gate/remediation/csv` API 제공
4. 서비스 정보/문서/테스트 동기화

완료 기준:
- remediation item 생성 규칙이 일관되고 우선순위가 안정적으로 정렬됨
- CSV 출력으로 현장 실행표로 바로 사용 가능
- 회귀 테스트 전체 통과

## W21: Governance Remediation Execution Tracker (우선순위 6)
목표:
- 리메디에이션 계획을 실행 추적 가능한 운영 보드로 전환
- 담당자/상태/완료체크를 API에서 일관되게 관리

주요 작업:
1. `POST /api/ops/governance/gate/remediation/tracker/sync`로 최신 remediation plan 동기화
2. `GET/PATCH /api/ops/governance/gate/remediation/tracker/items*`로 항목 운영
3. `GET /api/ops/governance/gate/remediation/tracker/overview|readiness` 제공
4. `GET/POST /api/ops/governance/gate/remediation/tracker/completion|complete` 완료 판정 제공

완료 기준:
- 항목별 assignee/status/completion_checked 추적 가능
- readiness 기반 완료 판정(강제 완료 포함) 지원
- 회귀 테스트 전체 통과

## W22: Governance Remediation SLA Escalation (우선순위 7)
목표:
- 리메디에이션 항목의 SLA 위험(기한임박/기한초과)을 상시 감시
- 경고 상태를 배치/알림으로 자동 확산해 조치 지연을 줄임

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/sla` 스냅샷 API 제공
2. `POST /api/ops/governance/gate/remediation/tracker/escalate/run` 실행 API 제공
3. `GET /api/ops/governance/gate/remediation/tracker/escalate/latest` 최신 이력 API 제공
4. Cron 잡 `python -m app.jobs.ops_governance_remediation_escalation` 추가

완료 기준:
- dry-run/실행 모드 모두에서 후보/critical 집계가 일관됨
- 최근 실행 이력(job_run) 조회 가능
- 회귀 테스트 전체 통과

## W23: Governance Remediation Auto Assignment (우선순위 8)
목표:
- 미배정 리메디에이션 항목을 역할기반 후보군으로 자동 배정
- 담당자 워크로드를 정량화해 운영 병목을 줄임

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/workload` 워크로드/추천 API 제공
2. `POST /api/ops/governance/gate/remediation/tracker/auto-assign/run` 실행 API 제공
3. `GET /api/ops/governance/gate/remediation/tracker/auto-assign/latest` 최신 이력 API 제공
4. Cron 잡 `python -m app.jobs.ops_governance_remediation_auto_assign` 추가

완료 기준:
- dry-run/실행 모드 모두에서 추천/배정 집계가 일관됨
- 최근 실행 이력(job_run) 조회 가능
- 회귀 테스트 전체 통과

## W24: Governance Remediation KPI Pulse (우선순위 9)
목표:
- 리메디에이션 백로그를 일/주 단위 KPI로 표준화해 운영 상태를 즉시 판단
- 기한초과/미배정/처리량 정체를 한 화면 지표로 드러내고 자동점검 이력화

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/kpi` 스냅샷 API 제공
2. `POST /api/ops/governance/gate/remediation/tracker/kpi/run` 실행 API 제공
3. `GET /api/ops/governance/gate/remediation/tracker/kpi/latest` 최신 이력 API 제공
4. Cron 잡 `python -m app.jobs.ops_governance_remediation_kpi` 추가

완료 기준:
- window/due-soon 파라미터별 지표 계산이 일관됨
- 최근 실행 이력(job_run) 조회 가능
- 회귀 테스트 전체 통과

## W25: Governance Remediation Autopilot (우선순위 10)
목표:
- KPI 상태를 기준으로 자동 배정/에스컬레이션을 일괄 실행해 MTTR 단축
- 수동 운영 편차를 줄이고 시간단위 자동 대응 루프를 확립

주요 작업:
1. `POST /api/ops/governance/gate/remediation/tracker/autopilot/run` 실행 API 제공
2. `GET /api/ops/governance/gate/remediation/tracker/autopilot/latest` 최신 이력 API 제공
3. KPI 지표(`overdue/critical/unassigned`) 기반 auto-assign + escalation 연계
4. Cron 잡 `python -m app.jobs.ops_governance_remediation_autopilot` 추가

완료 기준:
- dry-run/실행 모드에서 action 결정 로직이 일관됨
- 최근 실행 이력(job_run) 조회 가능
- 회귀 테스트 전체 통과

## W26: Governance Remediation Autopilot Policy and Preview (우선순위 11)
목표:
- Autopilot 임계치/윈도우/알림 설정을 API로 안전하게 조정
- 실행 전 영향(planned actions)을 미리 검토해 운영 리스크를 낮춤

주요 작업:
1. `GET/PUT /api/ops/governance/gate/remediation/tracker/autopilot/policy` 제공
2. `POST /api/ops/governance/gate/remediation/tracker/autopilot/preview` 제공
3. autopilot 실행시 정책(sla_policies) 기반으로 동작하도록 연결
4. 서비스 정보/문서/테스트 동기화

완료 기준:
- 정책 변경 후 다음 실행부터 설정이 반영됨
- preview 결과와 실행 decision이 같은 규칙으로 계산됨
- 회귀 테스트 전체 통과

## W27: Governance Remediation Autopilot Guardrails (우선순위 12)
목표:
- 짧은 간격의 중복 autopilot 실행을 제한해 노이즈/과잉조치 방지
- 실행 전/후 decision 근거를 guard 상태로 명시해 감사 추적성 강화

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/autopilot/guard` 제공
2. autopilot 정책에 `cooldown_minutes`, `skip_if_no_action` 추가
3. autopilot 실행 응답에 `planned_actions`, `guard`, `skipped`, `skip_reason` 추가
4. 서비스 정보/문서/테스트 동기화

완료 기준:
- cooldown 활성 시 force=false 실행이 안전하게 차단됨
- preview/guard/run이 동일 규칙으로 action 판단
- 회귀 테스트 전체 통과

## W28: Governance Remediation Autopilot Analytics (우선순위 13)
목표:
- autopilot 운영 품질(성공률/스킵률/실행행동 분포)을 기간 단위로 가시화
- 운영자가 API만으로 최근 실행흐름과 병목(쿨다운 차단/오류)을 빠르게 파악

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/autopilot/history` 제공
2. `GET /api/ops/governance/gate/remediation/tracker/autopilot/summary` 제공
3. run payload(`planned_actions/actions/skipped/skip_reason/metrics`) 기반 집계 로직 추가
4. 서비스 정보/문서/테스트 동기화

완료 기준:
- 최근 N회 이력 조회와 window 요약 값이 일관됨
- summary가 최소 성공률/스킵률/행동 집계를 반환함
- 회귀 테스트 전체 통과

## W29: Governance Remediation Autopilot Reporting Export (우선순위 14)
목표:
- autopilot 분석 데이터를 다운로드 가능한 CSV로 표준 제공
- 운영회의/감사보고에서 JSON 가공 없이 즉시 활용 가능하도록 보강

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/autopilot/history.csv` 제공
2. `GET /api/ops/governance/gate/remediation/tracker/autopilot/summary.csv` 제공
3. 실행 이력/요약 지표를 CSV 컬럼으로 정규화
4. 서비스 정보/문서/테스트 동기화

완료 기준:
- history/summary JSON과 CSV 수치가 일관됨
- CSV 다운로드 파일명/헤더가 운영 리포팅 용도에 맞게 고정됨
- 회귀 테스트 전체 통과

## W30: Governance Remediation Autopilot Health Signals (우선순위 15)
목표:
- autopilot 운영 상태를 건강신호(healthy/warning/critical)로 자동 분류
- 반복 쿨다운 차단/성공률 저하/에러 증가를 조기 감지해 선제 대응

주요 작업:
1. `GET /api/ops/governance/gate/remediation/tracker/autopilot/anomalies` 제공
2. `GET /api/ops/governance/gate/remediation/tracker/autopilot/anomalies.csv` 제공
3. summary/history 기반 이상징후 규칙(성공률/스킵률/쿨다운/에러/최신 critical) 추가
4. 서비스 정보/문서/테스트 동기화

완료 기준:
- 동일 window에서 anomalies JSON과 CSV 결과가 일관됨
- health_status(healthy/warning/critical)가 규칙 기반으로 재현 가능
- 회귀 테스트 전체 통과

## W31: Tutorial Simulator for New Users (우선순위 16)
목표:
- 신규 사용자가 운영 API를 실제처럼 실습하면서 첫 성공을 빠르게 달성
- 검증된 샘플데이터와 완료 조건을 표준화해 교육 품질 편차를 축소

주요 작업:
1. `GET /api/public/tutorial-simulator` + `GET /web/tutorial-simulator` 공개 허브 제공
2. `POST /api/ops/tutorial-simulator/sessions/start`로 시나리오/샘플데이터 세션 시작
3. `GET/POST /api/ops/tutorial-simulator/sessions/{session_id}(/check)`로 진행률/완료판정 조회
4. `POST /api/ops/tutorial-simulator/sessions/{session_id}/actions/{action}`로 ACK/완료/리셋 실습 지원
5. 서비스 정보/문서/테스트/모듈 허브 동기화

완료 기준:
- 세션 시작 후 단계별 조건(ACK/완료/리포트 준비) 판정이 API로 재현 가능
- completion_percent=100 완료 흐름이 자동 검증됨
- 회귀 테스트 전체 통과

## 기술부채 정리 원칙(지속)
- 제외:
  - 단기 데모/실험 파일 재사용 금지(`_share.html`, `_render_public_api.json`)
  - 로컬 캐시/임시 DB/실행 산출물 소스관리 제외
- 유지:
  - 마이그레이션, 테스트, 운영 스크립트, 공식 문서
- 삭제 전 확인:
  - `git ls-files` 기준 추적 파일 보호

## 운영 점검 기준(릴리스 게이트)
1. 정적 점검
- `python -m py_compile app/main.py app/schemas.py app/database.py tests/test_api.py`

2. 회귀 테스트
- `pytest -q tests/test_api.py`

3. 핵심 엔드포인트 점검
- `/`
- `/api/public/modules`
- `/api/service-info`
- `/api/ops/runbook/checks`
- `/api/ops/security/posture`

4. 배포 점검
- `scripts/deploy_and_verify.ps1` 실행 후 `DEPLOY_AND_SMOKE_OK` 확인
