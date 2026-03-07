# KA Facility OS Development Report

기준일: 2026-03-01
추가 업데이트: 2026-03-07
대상: `main` 브랜치, Render 운영 서비스(`ops.ka-part.com`)

## 1. 요약
- 시설관리 시스템을 API 중심 MVP에서 운영형 플랫폼으로 확장했다.
- W01~W15 주차형 실행추적 모듈과 공개형 운영/교육 페이지를 구축했다.
- 보안(RBAC, 토큰 정책, 레이트리밋, 감사무결성)과 운영자동화(Cron, 스모크, 런북)를 내재화했다.
- 최신 안정화 스프린트(성능/신뢰성/데이터 무결성) 항목을 운영 API로 반영했다.
- 2026-03-07 기준 runbook 오탐 경고를 정리하고 샘플 증빙 누락 blob 복구 로직을 운영에 반영했다.
- 2026-03-07 기준 W07 품질 알림 내부 webhook 채널을 운영에 연결해 runbook `overall_status=ok` 상태를 만들었다.
- 2026-03-07 기준 Slack/Teams 외부 채널 payload adapter를 배포해 실제 webhook URL secret만 추가하면 외부 운영 채널로 확장 가능한 상태를 만들었다.
- 2026-03-07 기준 신규 사용자용 `처음 1일 운영 체크리스트`, 역할별 시작 가이드, 운영 용어집 API/UI를 튜토리얼 탭에 반영했다.

## 2. 단계별 개발 내역

### Phase 0: 기반 구축
- 서비스 분리 배포 전략 정립(기존 서비스와 신규 서비스 도메인 분리 운영).
- FastAPI + SQLAlchemy + Alembic 기반 구조 정착.
- Render 배포 훅/운영 스크립트 기반 CI/CD 루프 정리.

### W01: Role Workflow Lock
- 워크플로 상태(`draft/review/approved/locked`) 및 역할별 권한 제어 구현.
- 잠금/해제 승인 흐름 및 감사로그 연동 구현.
- 운영 중 문서/체크리스트 무단 변경 방지 기반 확보.

### W02: Scheduled SOP + Sandbox
- 주차 실행표/체크리스트/ICS/CSV 공개 패키지 제공.
- 실행추적(담당자/상태/완료 체크/증빙 업로드) API 및 UI 구현.
- 샘플 증빙 다운로드/검증 플로우 구축.

### W03: 실행추적 모듈 고도화
- W02 패턴을 확장해 사이트 단위 readiness/completion 판정 체계 정립.
- 토큰 기반 쓰기 제어, 사이트 스코프 강제, 증빙 검증 일관화.

### W04: First Success Acceleration
- 퍼널 지표 API(첫 성공 시간/전환율) 및 대시보드 연결.
- 상위 블로커 추출, 코칭 트래커, Common Mistakes 공개 페이지 구현.

### W05: Usage Consistency
- 유지사용 지표(활성/유지율/과다 지연 항목) 스냅샷 구축.
- 실행 미션/교육 문서/주간 루틴 기반 정착 플로우 반영.

### W06: Operational Rhythm
- 운영 리듬 지표(주간 활동/핸드오버 루틴/토큰 상태) API 구현.
- 스케줄 이벤트와 실행 추적을 연결해 운영 습관화 구조 적용.

### W07: SLA Quality
- SLA 품질 대시보드/주간 자동화/트렌드/아카이브 API 구현.
- W07 완료 패키지 ZIP(증빙 포함), 자동 알림/품질 경보 체계 구현.
- Automation Readiness 카드 및 실행추적 UI 고도화.

### W08: Report Discipline
- 보고 품질/정시성/데이터 품질 지표 및 벤치마크 API 구현.
- 리포팅 SOP 공개 패키지와 실행 추적 연결.

### W09: KPI Operation
- KPI 운영 정책 API, 실행추적, 공개 체크리스트 패키지 구현.
- 사이트/전체 정책 관리를 RBAC와 결합.

### W10: Self-Serve Support
- 셀프서브 지원 지표/정책 API와 실행추적 모듈 구현.
- 가이드/런북/증빙 관리 플로우를 운영 탭에 통합.

### W11: Scale Readiness
- 확장 준비도(guide/runbook/정책) 측정 API 구현.
- 실행추적 및 완료판정 모델을 동일 프레임으로 확장.

### W12: Closure Handoff
- 마감 인수인계 지표/정책/트래커/API 구현.
- 완료 판정, 예외 처리, 증빙 연계 표준화.

### W13: Continuous Improvement
- 개선 백로그 운영 및 거버넌스 추적 모듈 구현.
- W12 패턴 기반으로 정책/추적/증빙 체계를 확장.

### W14: Stability Sprint
- 안정화 지표/정책/트래커/API 구현.
- 성능/신뢰성/무결성 점검 운영 루틴을 제품 흐름에 반영.

### R5: 신규 사용자 온보딩
- 튜토리얼 탭에서 `처음 1일 운영 체크리스트`와 역할별 시작 가이드를 바로 조회할 수 있게 구성.
- 공개 API `GET /api/public/onboarding/day1`, `GET /api/public/glossary` 추가.
- 영문 메뉴/용어를 한글 업무 의미와 함께 설명하는 운영 용어집 UI 제공.

### W15: Ops Efficiency
- 운영 효율 지표/정책/트래커/API 구현.
- W07~W14 운영 흐름을 상위 운영효율 관점으로 집계/관리.

### 안정화 스프린트(2026-03-01 반영)
- 성능: 주요 API P95 지연 모니터 API 추가
  - `GET /api/ops/performance/api-latency`
- 신뢰성: 배포 스모크/롤백 체크리스트 표준 API 및 기록 API 추가
  - `GET /api/ops/deploy/checklist`
  - `POST /api/ops/deploy/smoke/record`
  - 배포 스크립트(`deploy_and_verify.ps1`, `post_deploy_smoke.ps1`) 연동
- 데이터 무결성: 증빙/감사 아카이브 배치 무결성 점검 API 추가
  - `GET /api/ops/integrity/evidence-archive`
- 런북 통합 체크 추가:
  - `api_latency_p95`
  - `deploy_smoke_checklist`
  - `evidence_archive_integrity_batch`

### 운영 보정 업데이트(2026-03-07 반영)
- runbook warning 오탐 억제 로직 추가
  - retry/retention 대상이 0건이면 `alert_retry_recent`, `alert_retention_recent`를 `ok`로 판정
  - 주간 품질 리포트 streak는 최근 성공 주차를 anchor로 사용하고 ramp-up target을 적용
  - stale endpoint와 저트래픽 burn-rate는 idle로 분리해 `api_latency_p95`, `api_burn_rate` 오탐 제거
- 샘플 증빙 self-heal 추가
  - W02/W03/W04/W07/W11 샘플 증빙 blob이 파일시스템에서 누락돼도 canonical sample payload로 다운로드 복구
  - 복구 시 파일을 재생성해 이후 무결성 배치가 정상화되도록 처리
- 운영 배포 결과
  - 커밋: `7b7835d`
  - 배포: `dep-d6lmemkhg0os73aske20`
  - post-deploy smoke: `SMOKE_OK`
  - live runbook 결과: `alert_retry_recent`, `alert_retention_recent`, `ops_quality_weekly_report_streak`, `api_latency_p95`, `api_burn_rate`, `evidence_archive_integrity_batch` 정상화
  - 당시 남은 실경고: `w07_quality_alert_channel` (품질 알림 webhook target 미설정)

### 알림 채널 연결 업데이트(2026-03-07 반영)
- 내부 webhook sink API 추가
  - `POST /api/ops/alerts/webhook/internal`
  - `X-Alert-Webhook-Token` shared token 검증 방식 적용
- alert dispatcher 공통 헤더 보강
  - outbound webhook 요청에 shared token 헤더 자동 포함
- 운영 채널 연결 결과
  - 커밋: `aec572a`
  - 배포: `dep-d6ln61p5pdvs73a7b54g`(internal route), `dep-d6ln7engi27c73dne7dg`(운영 env 적용)
  - post-deploy smoke: `SMOKE_OK`
  - direct webhook probe: HTTP `202`
  - guard recover probe: `probe_status=success`
  - live runbook 결과: `overall_status=ok`, `w07_quality_alert_channel=status=ok`
  - live governance gate: `decision=go`, `weighted_score_percent=100.0`

### 외부 채널 확장 업데이트(2026-03-07 반영)
- Slack/Teams adapter 지원 추가
  - host auto-detect: `hooks.slack.com`, `logic.azure.com`, `office.com`
  - explicit prefix: `slack::`, `teams::`, `generic::`
  - 현재 운영 기본 target은 내부 webhook 유지
- 운영 배포 결과
  - 커밋: `9b9679b`
  - 배포: `dep-d6lnmsi4d50c73ceirt0`
  - post-deploy smoke: `SMOKE_OK`
  - internal webhook probe 및 guard recover는 기존과 동일하게 `success`
  - 실제 Slack/Teams 전환에는 고객측 secret webhook URL 추가만 필요

## 3. 공통 보안/운영 고도화(횡단영역)
- RBAC 사용자/권한/사이트 스코프 모델 운영화.
- 관리자 토큰 수명/회전/유휴 정책 강화.
- API rate limit(memory/redis/auto) 및 헤더 표준화.
- 증빙 파일 무결성(SHA-256), 악성패턴 차단, 경로 우회 차단.
- 감사로그 해시체인 + 월간 서명 아카이브 + 재기준화 도구 제공.
- 운영잡 관측(`job_runs`)과 런북/보안 posture API 운영.

## 4. 배포/운영 상태(기준일 시점)
- 운영 배포 최신 커밋 반영 및 스모크 통과.
- 배포 스모크 결과 기록이 런북 체크에 직접 반영되도록 구성.
- W15 마이그레이션은 forward-only 정책이며 롤백 가이드 문서화 완료:
  - `docs/W15_MIGRATION_ROLLBACK.md`
- 2026-03-07 운영 기준 거버넌스 게이트는 `go`, runbook overall status는 `warning`이며 원인은 `w07_quality_alert_channel` 1건이다.
- 2026-03-07 후속 운영 기준 내부 webhook 연결까지 완료되어 runbook overall status는 `ok`, governance gate는 `go`(`weighted_score_percent=100.0`)다.

## 5. 잔여 리스크 및 개선 필요 포인트
- `app/main.py` 단일 파일 규모가 커 유지보수/리스크 증가.
- W07~W15 UI/JS 중복으로 변경 비용이 상승.
- 지표 수집 일부가 인메모리 기반(프로세스 재시작 시 초기화)이라 장기 추세 분석 정확도 개선 여지.
- 운영 정책 API 응답 스키마의 일관성 추가 정리가 필요.

## 6. 다음 확장 우선순위(요약)
1. 모듈 공통화: 트래커 UI/JS 공통 컴포넌트로 리팩터링
2. 관측 강화: 지연/오류/SLO 지표 영속 저장 + 주간 요약 자동 발행
3. 거버넌스: startup preflight + DR 리허설 자동화 + 권한 감사 대시보드 강화
4. 알림 운영: 실제 Slack/Teams/사내 알림 secret URL 등록 및 채널별 운영 책임자 지정
