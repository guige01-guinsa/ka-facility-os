# Complaint SMS Provider Setup

`2026-03-22` 기준 민원 문자 발송은 `stub`, `webhook`, `solapi` provider를 지원한다.

## 권장 운영값

- `COMPLAINT_MESSAGE_PROVIDER=solapi`
- `COMPLAINT_MESSAGE_SOLAPI_API_KEY`
- `COMPLAINT_MESSAGE_SOLAPI_API_SECRET`
- `COMPLAINT_MESSAGE_SOLAPI_SENDER`

현장별 발신번호가 다르면 아래 JSON을 추가한다.

```json
{"연산더샵":"010-1234-5678","다른단지":"010-9999-0000"}
```

- `COMPLAINT_MESSAGE_SOLAPI_SITE_SENDERS=<위 JSON>`

## 선택값

- `COMPLAINT_MESSAGE_TIMEOUT_SEC=10`
- `COMPLAINT_MESSAGE_SOLAPI_APP_ID`
- `COMPLAINT_MESSAGE_SOLAPI_ALLOW_DUPLICATES=false`
- `COMPLAINT_MESSAGE_SOLAPI_SHOW_MESSAGE_LIST=true`

## 동작 방식

- `/api/complaints/{id}/messages` 호출 시 provider가 실행된다.
- `solapi`는 `https://api.solapi.com/messages/v4/send-many/detail`로 발송 등록한다.
- 성공 시 DB에는 `provider_name=solapi`, `delivery_status=accepted`, `provider_message_id`가 저장된다.
- 발신번호 미설정, 인증 오류, 공급자 응답 오류는 `delivery_status=failed`와 `error`에 남는다.

## 적용 순서

1. Render 환경변수에 Solapi 값을 입력한다.
2. `COMPLAINT_MESSAGE_PROVIDER`를 `solapi`로 설정한다.
3. `/web/complaints`에서 테스트 민원을 열고 문자 발송을 실행한다.
4. `/api/complaints/{id}` 또는 상세 화면의 문자 이력에서 결과를 확인한다.

## 참고

- Solapi SDK for Python: https://github.com/solapi/solapi-python
- Solapi endpoint article: https://solapi.zendesk.com/hc/ko/articles/360052545813-%EB%A7%88%EC%9D%B4%EC%82%AC%EC%9D%B4%ED%8A%B8%EC%97%90%EC%84%9C-API-%ED%98%B8%EC%B6%9C-%EB%B0%A9%EB%B2%95
