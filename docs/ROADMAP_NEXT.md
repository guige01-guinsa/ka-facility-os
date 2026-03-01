# KA Facility OS Next Roadmap (2026 Q2-Q3)

기준일: 2026-03-01

## 최근 완료(2026-03-01)
- 안정화 스프린트 3대 과제 완료
  - 성능: 주요 API P95 지연 모니터/런북 체크 반영
  - 신뢰성: 배포 스모크 + 롤백 체크리스트 API/스크립트 표준화
  - 데이터: 증빙/감사 아카이브 무결성 배치 점검 강화
- 관련 API
  - `/api/ops/performance/api-latency`
  - `/api/ops/deploy/checklist`
  - `/api/ops/deploy/smoke/record`
  - `/api/ops/integrity/evidence-archive`

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
1. startup preflight(필수 ENV 누락/오설정 탐지) 구현
2. 관리자 권한/토큰 사용 감사 대시보드 강화
3. 백업/복구 리허설 배치 자동 실행 및 결과 적재
4. 마이그레이션 롤백 가이드와 배포 파이프라인 체크 연결

완료 기준:
- preflight 실패 시 명확한 차단/경고 동작
- DR 리허설 결과를 월간 감사에 자동 첨부
- 권한/토큰 이상징후 탐지 규칙 운영

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
