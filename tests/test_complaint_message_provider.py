from __future__ import annotations

from app.domains.complaints import message_provider


class _MockResponse:
    def __init__(self, status_code: int, payload: dict[str, object]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, object]:
        return self._payload


class _MockClient:
    def __init__(self, response: _MockResponse, capture: dict[str, object], **_: object) -> None:
        self._response = response
        self._capture = capture

    def __enter__(self) -> _MockClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def post(self, url: str, *, headers: dict[str, str], json: dict[str, object]) -> _MockResponse:
        self._capture["url"] = url
        self._capture["headers"] = headers
        self._capture["json"] = json
        return self._response


def test_solapi_provider_accepts_registered_message(monkeypatch) -> None:
    monkeypatch.setenv("COMPLAINT_MESSAGE_PROVIDER", "solapi")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_KEY", "api-key")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_SECRET", "api-secret")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_SENDER", "010-1111-2222")
    captured: dict[str, object] = {}
    response = _MockResponse(
        200,
        {
            "groupInfo": {
                "groupId": "G-001",
                "count": {"registeredSuccess": 1, "registeredFailed": 0},
            },
            "messageList": [{"messageId": "M-001"}],
        },
    )
    monkeypatch.setattr(
        message_provider.httpx,
        "Client",
        lambda *args, **kwargs: _MockClient(response=response, capture=captured, **kwargs),
    )

    result = message_provider.send_message(
        site="연산더샵",
        complaint_id=101,
        recipient="010-9999-8888",
        body="민원 접수되었습니다.",
        template_key="intake_ack",
    )

    assert result["provider_name"] == "solapi"
    assert result["delivery_status"] == "accepted"
    assert result["provider_message_id"] == "M-001"
    assert result["error"] is None
    assert captured["url"] == "https://api.solapi.com/messages/v4/send-many/detail"
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert str(headers["Authorization"]).startswith("HMAC-SHA256 ApiKey=api-key")
    payload = captured["json"]
    assert isinstance(payload, dict)
    messages = payload["messages"]
    assert isinstance(messages, list)
    assert messages[0]["to"] == "01099998888"
    assert messages[0]["from"] == "01011112222"
    assert messages[0]["customFields"]["complaintId"] == "101"
    assert messages[0]["customFields"]["site"] == "연산더샵"


def test_solapi_provider_uses_site_sender_map(monkeypatch) -> None:
    monkeypatch.setenv("COMPLAINT_MESSAGE_PROVIDER", "solapi")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_KEY", "api-key")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_SECRET", "api-secret")
    monkeypatch.setenv(
        "COMPLAINT_MESSAGE_SOLAPI_SITE_SENDERS",
        '{"연산더샵":"010-1234-5678","다른현장":"010-0000-0000"}',
    )
    captured: dict[str, object] = {}
    response = _MockResponse(
        200,
        {
            "groupInfo": {
                "groupId": "G-002",
                "count": {"registeredSuccess": 1, "registeredFailed": 0},
            },
            "messageList": [],
        },
    )
    monkeypatch.setattr(
        message_provider.httpx,
        "Client",
        lambda *args, **kwargs: _MockClient(response=response, capture=captured, **kwargs),
    )

    result = message_provider.send_message(
        site="연산더샵",
        complaint_id=102,
        recipient="010-7777-6666",
        body="방문 예정입니다.",
    )

    assert result["provider_message_id"] == "G-002"
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["messages"][0]["from"] == "01012345678"


def test_solapi_provider_returns_failure_for_client_error(monkeypatch) -> None:
    monkeypatch.setenv("COMPLAINT_MESSAGE_PROVIDER", "solapi")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_KEY", "api-key")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_SECRET", "api-secret")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_SENDER", "010-1111-2222")
    response = _MockResponse(
        400,
        {"errorCode": "ValidationError", "errorMessage": "Invalid sender"},
    )
    monkeypatch.setattr(
        message_provider.httpx,
        "Client",
        lambda *args, **kwargs: _MockClient(response=response, capture={}, **kwargs),
    )

    result = message_provider.send_message(
        site="연산더샵",
        complaint_id=103,
        recipient="010-7777-6666",
        body="처리 완료되었습니다.",
    )

    assert result["provider_name"] == "solapi"
    assert result["delivery_status"] == "failed"
    assert "ValidationError" in str(result["error"])


def test_solapi_provider_requires_sender(monkeypatch) -> None:
    monkeypatch.setenv("COMPLAINT_MESSAGE_PROVIDER", "solapi")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_KEY", "api-key")
    monkeypatch.setenv("COMPLAINT_MESSAGE_SOLAPI_API_SECRET", "api-secret")
    monkeypatch.delenv("COMPLAINT_MESSAGE_SOLAPI_SENDER", raising=False)
    monkeypatch.delenv("COMPLAINT_MESSAGE_SOLAPI_SITE_SENDERS", raising=False)

    result = message_provider.send_message(
        site="연산더샵",
        complaint_id=104,
        recipient="010-7777-6666",
        body="처리 완료되었습니다.",
    )

    assert result["provider_name"] == "solapi"
    assert result["delivery_status"] == "failed"
    assert result["error"] == "COMPLAINT_MESSAGE_SOLAPI_SENDER is required"
