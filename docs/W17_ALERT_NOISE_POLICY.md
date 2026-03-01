# W17 Alert Noise Policy

기준일: 2026-03-01

## 목적
- 경보 오탐(false positive) / 누락(false negative)을 정량 기준으로 관리합니다.
- 운영팀 주간 점검 시 동일 기준으로 재현 가능한 판단을 보장합니다.

## 기준값
- review window: 최근 14일
- false positive threshold: 5.0%
- false negative threshold: 1.0%

## 정의
- false positive:
  - 경보가 발송되었으나 실제 조치가 필요하지 않았던 케이스
  - 예: 정상 상태를 경고로 오판, 이미 해소된 이벤트의 중복 발송
- false negative:
  - 실제 장애/위험 사건이 있었으나 경보가 발송되지 않은 케이스
  - 예: SLA 초과 사건 존재 + alert delivery 기록 부재

## 운영 규칙
1. false positive > 5.0% 이면 채널/임계치 튜닝 액션 발행
2. false negative > 1.0% 이면 즉시 임계치 재검토 + 탐지 로직 보정
3. 연속 2주 초과 시 runbook `critical`로 승격

## 감사 로그 연계
- 정책 조회: `ops_alert_noise_policy_view`
- 주간 품질 리포트와 함께 정책 기준값이 기록됩니다.
