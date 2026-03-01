# KA Facility OS Next Roadmap (2026 Q2)

## 목표
- W13 이후 운영을 "기능 추가"보다 "품질/안정/운영 자동화" 중심으로 전환한다.
- 신규 기능은 KPI 개선 효과가 명확한 항목만 우선 반영한다.

## 다음 개발 단계
1. 안정화 스프린트 (우선)
- 성능: 주요 API P95 지연시간 측정/경보 기준 확정
- 신뢰성: 배포 후 자동 스모크 + 롤백 체크리스트 고정
- 데이터: 증빙/감사 아카이브 무결성 검증 배치 점검 강화

2. 운영 효율화
- W07~W13 실행추적 UI 공통 컴포넌트화(중복 JS/HTML 축소)
- 정책 API(W09~W13) 응답 구조 표준화
- 주간 운영 리포트 자동 발행(요약 + 예외 항목)

3. 거버넌스/보안 고도화
- 관리자 권한/토큰 사용 감사 대시보드 강화
- 환경변수 누락 감지(startup preflight) 및 경고 표준화
- 재해복구 리허설(백업/복구) 정기 실행 자동화

## 앞으로 "개발에서 제외"할 항목
- 단기 데모/실험용 산출물 파일(`_share.html`, `_render_public_api.json`) 재사용 금지
- 로컬 실행 캐시/임시 DB/테스트 산출물을 소스관리 대상에서 제외
- 중복된 주차별 코드 복사 방식의 신규 확장 지양(공통화 우선)

## 불필요 항목 정리 원칙
- 삭제 대상: 캐시, 임시 파일, 로컬 아카이브, 실행 중 생성 파일
- 유지 대상: 마이그레이션, 테스트, 운영 스크립트, 공식 문서
- 삭제 전 확인: `git ls-files`에 없는 파일만 우선 정리

## 시스템 점검 기준
1. 정적 점검
- `python -m py_compile app/main.py app/schemas.py app/database.py tests/test_api.py`

2. 회귀 테스트
- `pytest -q tests/test_api.py`

3. 핵심 엔드포인트 점검
- `/`
- `/api/public/adoption-plan/w13`
- `/api/public/modules`
- `/api/service-info`

4. 배포 점검
- Render deploy hook 호출 후 W13 JSON/CSV/ICS 200 확인
