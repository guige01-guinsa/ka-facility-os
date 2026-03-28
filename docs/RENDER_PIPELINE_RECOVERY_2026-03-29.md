# Render Pipeline Recovery Runbook

## 목적

`Render` 워크스페이스의 `pipeline minutes` 소진으로 자동 배포가 차단된 상태에서,
가장 적은 비용으로 운영 복구를 진행하기 위한 실행 순서를 정리한다.

대상 이슈:

- `14d0a46` 커밋의 알림 작업 래퍼 복구가 아직 운영 반영되지 않음
- Render 메시지: workspace pipeline usage exhausted

## 현재 상태

- 알림 cron import 오류는 코드에서 이미 수정됨
  - 커밋: `14d0a46`
  - 수정 위치: [app/main.py](/C:/ka-facility-os/app/main.py)
- 아직 운영 반영되지 않은 이유는 코드 오류가 아니라 Render 빌드 차단
- 현재 [render.yaml](/C:/ka-facility-os/render.yaml)은 다음 원칙으로 조정됨
  - web 2개: `autoDeployTrigger: commit`
  - cron 16개: `autoDeployTrigger: off`

## 핵심 판단

지금은 `전체 Blueprint sync`가 우선이 아니다.

먼저 해야 할 일:

1. Render에서 빌드를 다시 허용
2. 오류 난 cron만 수동 배포
3. 운영 web 서비스 배포
4. 나머지 cron은 필요 시에만 배포

이 순서가 맞는 이유:

- 현재 장애는 `alert_guard_recover` 계열 cron import 실패가 직접 원인
- web 서비스와 모든 cron을 한 번에 다시 빌드하면 pipeline minutes를 다시 크게 소모함
- 이 저장소는 cron 수가 많아서 자동 배포를 유지하면 같은 문제가 반복될 가능성이 높음

## 즉시 확인 항목

Render Dashboard에서 아래를 먼저 확인한다.

1. `Workspace Settings -> Build Pipeline`
   - 남은 Starter pipeline minutes
   - spend limit
   - payment method 존재 여부
2. `Billing`
   - 이번 달 pipeline 사용량
   - 추가 과금 차단 여부
3. `Blueprint Settings`
   - Auto Sync 상태

공식 참고:

- https://render.com/docs/build-pipeline
- https://render.com/docs/infrastructure-as-code

## 복구 실행 순서

### 1. 빌드 차단 해제

둘 중 하나를 선택한다.

- 가장 빠른 방법:
  `payment method` 추가 후 `spend limit` 상향
- 비용을 당장 늘리지 않을 방법:
  다음 월 pipeline minutes 리셋까지 대기

Render 공식 문서 기준으로, 분을 모두 사용했고 spend limit 또는 결제수단 조건을 만족하지 않으면
그 달 남은 기간 동안 pipeline tasks가 중단된다.

## 2. 가장 먼저 수동 배포할 서비스

아래 3개 cron을 먼저 수동 배포한다.

1. `ka-facility-os-alert-guard-recover`
2. `ka-facility-os-alert-retention`
3. `ka-facility-os-alert-retry`

이유:

- 현재 직접적으로 깨진 로그가 확인된 범위
- 모두 [app/main.py](/C:/ka-facility-os/app/main.py)의 레거시 wrapper 복구 영향을 받음

## 3. 그다음 배포할 서비스

1. `ka-facility-os`
2. `ka-platform-admin`

이유:

- 운영 web 서비스가 최신 코드와 `render.yaml` 변경을 함께 반영해야 함
- main web 반영 후 admin을 올리는 편이 운영 확인이 단순함

## 4. 마지막에 검토할 cron

아래 cron은 장애와 직접 관련이 없으므로 마지막에 본다.

- `ka-facility-os-ops-governance-gate`
- `ka-facility-os-ops-governance-remediation-escalation`
- `ka-facility-os-ops-governance-remediation-auto-assign`
- `ka-facility-os-ops-governance-remediation-kpi`
- `ka-facility-os-ops-governance-remediation-autopilot`
- `ka-facility-os-ops-quality-weekly`
- `ka-facility-os-ops-quality-monthly`
- `ka-facility-os-dr-rehearsal`
- `ka-facility-os-sla-escalation`
- `ka-facility-os-audit-archive`
- `ka-facility-os-ops-daily-check`
- `ka-facility-os-alert-mttr-slo`
- `ka-facility-os-adoption-w07-weekly`

운영에 당장 필요하지 않으면 다음 배포 주기까지 미뤄도 된다.

## 배포 후 확인 체크리스트

### cron

- `ka-facility-os-alert-guard-recover` 최근 실행 성공
- `ka-facility-os-alert-retention` import 오류 없음
- `ka-facility-os-alert-retry` import 오류 없음

### web

- `https://ka-facility-os.onrender.com/api/service-info`
- `https://ka-facility-os.onrender.com/web/complaints`
- `https://ka-platform-admin.onrender.com/api/service-info`

확인 기준:

- HTTP 200
- 최근 deploy commit이 `14d0a46` 이상

## 재발 방지 원칙

### 1. cron 자동 배포 유지 금지

이 저장소는 현재 web 2개 + cron 16개 구조다.
cron까지 모두 `autoDeployTrigger: commit`이면, push 한 번에 너무 많은 build가 같이 발생한다.

따라서 원칙은 다음과 같다.

- web: 자동 배포 유지
- cron: 수동 배포 유지

## 2. Blueprint sync는 필요할 때만

Render 공식 문서 기준으로 Blueprint는 `Auto Sync`를 끄고 필요할 때 수동 동기화할 수 있다.

권장:

- 평소 `Auto Sync = No`
- 실제 배포 시점에만 `Manual Sync`

## 3. 큰 기능 추가 직후에는 cron 전부 재배포하지 않기

아래 중 하나에 해당할 때만 cron을 수동 배포한다.

- 해당 cron start command 변경
- 해당 cron이 직접 import하는 job 함수 변경
- 해당 cron 실행 경로의 핵심 service 로직 변경

그 외 변경은 web만 먼저 올리고, cron은 필요 시점에만 올린다.

## 운영자용 짧은 실행 순서

1. Render에서 spend limit 또는 payment method 확인
2. Build 차단 해제
3. 아래 스크립트 실행
4. 200 응답과 cron 성공 로그 확인
5. 나머지 cron은 필요 시에만 배포

실행 스크립트:

```powershell
.\scripts\recover_render_minimal.ps1
```

스크립트 순서:

1. `ka-facility-os-alert-guard-recover`
2. `ka-facility-os-alert-retention`
3. `ka-facility-os-alert-retry`
4. `ka-facility-os`
5. `ka-platform-admin`

## 메모

- `render.yaml` 변경은 다음 successful sync부터 비용 절감 효과가 난다
- 현재 문제의 직접 원인은 코드보다 Render pipeline 한도
- `14d0a46`은 배포만 되면 cron import 오류를 해소하는 수정이다
