# KA Facility OS Next Roadmap (2026 Q2-Q3)

기준일: 2026-03-01

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
