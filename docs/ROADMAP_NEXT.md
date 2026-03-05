# KA Facility OS Next Roadmap (2026 Q2-Q3)

기준일: 2026-03-01

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
