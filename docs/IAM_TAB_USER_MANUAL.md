# IAM 탭 사용자 매뉴얼

대상 화면: 메인 운영 셸 `/?tab=iam`  
대상 역할: `owner`, `manager`

## 목적

IAM 탭에서 아래 3가지를 한 순서로 처리하기 위한 운영 매뉴얼입니다.

1. 내 권한과 토큰 정책 확인
2. 사용자 생성/수정/비활성화
3. 토큰 발급/회전/폐기 후 감사 로그 확인

## 먼저 알아둘 제약

- `owner`는 전체 사용자/IAM 기능을 관리할 수 있습니다.
- `manager`는 자기 `site_scope` 안의 사용자만 관리할 수 있습니다.
- `manager`는 `owner` 계정을 관리할 수 없습니다.
- `manager`는 `owner` 역할을 새로 부여할 수 없습니다.
- `manager`는 `admins:*` 성격의 관리자 제어 권한을 다른 사용자에게 줄 수 없습니다.
- 활성 `owner`는 항상 최소 1명 이상 남아 있어야 합니다.
- 현재 로그인한 자기 자신은 비활성화할 수 없습니다.
- 현재 로그인 중인 자기 사용자 토큰은 서버에서 폐기할 수 없습니다.
- `legacy env token`은 서버 revoke 대상이 아닙니다.
- 신규 토큰 평문은 발급/회전 직후 1회만 표시됩니다.

## 권장 운영 순서

1. `내 세션 / 권한 / 로그아웃`
2. `사용자 목록`
3. 필요하면 `사용자 생성`
4. 또는 `사용자 수정 / 비활성화 / 삭제`
5. `토큰 발급 / 회전 / 폐기`
6. `감사 로그 조회`

이 순서를 지키면 “권한 확인 -> 계정 변경 -> 토큰 처리 -> 감사 검증”이 한 흐름으로 끝납니다.

## 1. 내 세션 / 권한 / 로그아웃

사용 버튼:

- `내 권한 조회`
- `로그아웃`
- `토큰 정책 조회`

권장 절차:

1. IAM 탭에 들어오면 먼저 `내 권한 조회`를 누릅니다.
2. 현재 `username`, `display_name`, `role`, `permissions`, `site_scope`를 확인합니다.
3. 이어서 `토큰 정책 조회`를 눌러 아래 값을 확인합니다.
4. `require_expiry`
5. `max_ttl_days`
6. `rotate_after_days`
7. `rotate_warning_days`
8. `max_idle_days`
9. `max_active_per_user`

운영 판단 기준:

- 토큰 발급 전에 `max_ttl_days`와 `max_active_per_user`를 먼저 확인합니다.
- `token_must_rotate=true`가 보이면 새 토큰 발급 또는 회전을 바로 진행합니다.
- 작업 종료 후 브라우저 세션을 닫기 전에 `로그아웃`을 실행하는 편이 안전합니다.

## 2. 사용자 목록

사용 필드:

- `role filter (optional)`
- `active: all/true/false`
- `username/display search`
- `사용자 조회`

권장 절차:

1. 기본은 `active: all`로 시작합니다.
2. 필요한 경우 `role filter`로 `operator`, `auditor`, `manager`, `owner` 중 하나를 넣습니다.
3. `username/display search`에 이름 일부를 넣고 `사용자 조회`를 누릅니다.
4. 결과 표에서 `선택`을 눌러 아래 수정 폼과 토큰 폼에 연동합니다.

운영 원칙:

- `manager`는 자기 범위 밖 사용자와 `owner` 계정을 목록에서 다루지 못합니다.
- 사용자 수정이나 토큰 발급은 먼저 목록에서 대상을 선택한 뒤 진행하는 것이 안전합니다.

## 3. 사용자 생성

사용 필드:

- `username`
- `password (8+)`
- `display_name (optional)`
- `role`
- `site_scope comma`
- `custom permissions comma (optional)`
- `is_active=true`
- `사용자 생성`

권장 절차:

1. `username`을 입력합니다.
2. 초기 비밀번호를 넣습니다.
3. `display_name`이 있으면 같이 입력합니다.
4. 기본 역할을 선택합니다.
5. `site_scope`를 쉼표로 입력합니다. 전체 범위면 `*`를 사용합니다.
6. 별도 권한이 정말 필요할 때만 `custom permissions`를 입력합니다.
7. `사용자 생성`을 실행합니다.

운영 원칙:

- 처음에는 역할 기반 권한만 쓰고, `custom permissions`는 최소화합니다.
- 같은 permission 문자열은 중복 없이 입력하는 편이 좋습니다.
- 현장 운영자는 `operator`, 조회/감사 전용은 `auditor`, 운영 조정자는 `manager`, 최상위 관리자는 `owner`가 기본입니다.

## 4. 사용자 수정 / 비활성화 / 삭제

사용 버튼:

- `사용자 선택`
- `사용자 수정`
- `비밀번호 변경`
- `비활성화`
- `사용자 삭제`

권장 절차:

1. 먼저 `사용자 목록`에서 대상을 `선택`합니다.
2. 또는 `user_id`를 직접 넣고 `사용자 선택`을 누릅니다.
3. `display_name`, `role`, `site_scope`, `permissions`, `is_active`를 수정합니다.
4. 속성 변경이면 `사용자 수정`
5. 비밀번호만 바꾸면 `비밀번호 변경`
6. 더 이상 사용하지 않으면 `비활성화`
7. 완전 제거가 필요할 때만 `사용자 삭제`

운영 원칙:

- 삭제보다 `비활성화`가 우선입니다.
- 비활성화하면 해당 사용자의 활성 토큰도 함께 비활성화됩니다.
- `owner` 변경이나 비활성화 전에 활성 `owner`가 최소 1명 남는지 확인합니다.
- `manager`는 `owner` 계정 대상 수정/삭제를 할 수 없습니다.

## 5. 토큰 발급 / 회전 / 폐기

사용 버튼:

- `토큰 조회`
- `토큰 발급`
- `토큰 선택`
- `토큰 회전`
- `토큰 폐기`

### 5-1. 토큰 조회

사용 필드:

- `user_id filter (optional)`
- `active: all/true/false`

권장 절차:

1. 대상 사용자를 먼저 선택한 뒤 `토큰 조회`를 누릅니다.
2. 필요하면 `active=true`로 활성 토큰만 봅니다.
3. 목록에서 대상 행의 `선택`을 눌러 회전/폐기 대상으로 지정합니다.

확인 포인트:

- `label`
- `is_active`
- `site_scope`
- `expires_at`
- `last_used_at`
- `created_at`

### 5-2. 토큰 발급

사용 필드:

- `issue user_id`
- `token label`
- `expires_at (ISO-8601, optional)`
- `token site_scope comma (optional)`

권장 절차:

1. 대상 사용자를 먼저 선택합니다.
2. `issue user_id`는 비워두거나 직접 넣습니다.
3. `token label`에 목적을 적습니다. 예: `console-issued`, `mobile-shift-a`
4. 필요할 때만 `expires_at`과 `token site_scope`를 좁혀 입력합니다.
5. `토큰 발급`을 실행합니다.
6. 발급 직후 표시된 평문 토큰을 안전한 방법으로 전달합니다.

운영 원칙:

- 토큰은 사람/기기/용도별로 label을 구분하는 편이 추적에 좋습니다.
- 사용자 `site_scope`보다 넓은 토큰 범위는 주지 않습니다.
- 활성 토큰 개수가 정책 한도를 넘으면 오래된 토큰이 자동 정리될 수 있습니다.

### 5-3. 토큰 회전

권장 상황:

- 분실 의심
- 정기 교체
- `token_must_rotate=true`
- 외부 공유 위험이 있었던 경우

절차:

1. `토큰 조회`로 대상 토큰을 찾습니다.
2. 목록에서 `선택`을 누릅니다.
3. `토큰 회전`을 실행합니다.
4. 새 평문 토큰이 1회 표시되면 즉시 전달/보관합니다.

주의:

- 회전 즉시 기존 토큰은 비활성화됩니다.
- 비활성 사용자 토큰은 회전할 수 없습니다.

### 5-4. 토큰 폐기

권장 상황:

- 사용 중지
- 기기 반납
- 계정 종료
- 테스트 토큰 정리

절차:

1. `토큰 조회`로 대상 토큰을 찾습니다.
2. 목록에서 `선택`을 누릅니다.
3. `토큰 폐기`를 실행합니다.

주의:

- 현재 로그인 중인 자기 사용자의 토큰은 폐기할 수 없습니다.
- `legacy env token`은 이 화면에서 폐기되지 않습니다.

## 6. 감사 로그 조회

사용 필드:

- `action filter (optional)`
- `actor_username filter (optional)`
- `limit`
- `offset`
- `감사 로그 조회`

권장 절차:

1. 사용자/토큰 변경 작업 직후 바로 `감사 로그 조회`를 누릅니다.
2. 특정 작업만 보고 싶으면 `action filter`를 사용합니다.
3. 특정 관리자만 보고 싶으면 `actor_username filter`를 사용합니다.
4. 목록에서 `상세`를 눌러 아래 `detail JSON`을 확인합니다.

자주 보는 action 예시:

- `admin_user_create`
- `admin_user_update`
- `admin_user_delete`
- `admin_token_issue`
- `admin_token_rotate`
- `admin_token_revoke`
- `admin_audit_integrity_check`
- `admin_audit_archive_export_json`
- `admin_audit_archive_export_csv`

운영 원칙:

- 사용자 생성/수정/삭제 후에는 감사 로그를 반드시 1회 확인합니다.
- 토큰 회전/폐기 후에는 대상 `token_id`와 `user_id`가 detail JSON에 맞는지 확인합니다.
- 월간 보관이 필요하면 별도 감사 아카이브 API와 월간 리포트 절차를 사용합니다.

## 실무 권장 시나리오

### 신규 운영자 등록

1. `내 권한 조회`
2. `사용자 생성`
3. `사용자 목록`에서 새 사용자 확인
4. `토큰 발급`
5. `감사 로그 조회`로 `admin_user_create`, `admin_token_issue` 확인

### 운영자 퇴사/권한 종료

1. `사용자 목록`에서 대상 선택
2. `비활성화`
3. 필요하면 남은 토큰 `토큰 폐기`
4. `감사 로그 조회`로 변경 이력 확인

### 토큰 분실 신고

1. `토큰 조회`
2. 대상 토큰 `선택`
3. `토큰 회전`
4. 새 토큰 안전 전달
5. `감사 로그 조회`로 회전 이력 확인

## 실패 메시지별 바로 조치

- `User management requires owner or manager role`
  - 현재 계정은 IAM 사용자 관리 권한이 없습니다.
- `Manager cannot manage owner accounts`
  - `manager`는 `owner` 계정을 수정할 수 없습니다.
- `Manager cannot assign owner role`
  - `owner` 승격은 `owner`가 직접 처리해야 합니다.
- `At least one active owner must remain`
  - 마지막 활성 owner를 비활성화/삭제하려고 한 상태입니다.
- `Cannot revoke token of current admin user`
  - 현재 로그인 중인 자기 토큰은 폐기 대상이 아닙니다.
- `Inactive user cannot rotate token`
  - 먼저 사용자 상태를 확인해야 합니다.

## 운영 체크리스트

1. 작업 전 `내 권한 조회`
2. 작업 전 `토큰 정책 조회`
3. 사용자 변경 전 목록에서 대상 확인
4. 삭제보다 비활성화 우선
5. 토큰 평문은 발급/회전 직후만 확인
6. 변경 후 감사 로그 1회 검증
