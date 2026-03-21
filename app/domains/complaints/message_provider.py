"""Complaint message delivery adapters."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from os import getenv
from typing import Any
from uuid import uuid1

import httpx


def _provider_name() -> str:
    return getenv("COMPLAINT_MESSAGE_PROVIDER", "stub").strip().lower() or "stub"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _normalize_phone_number(value: str) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if digits.startswith("82") and len(digits) >= 11:
        digits = "0" + digits[2:]
    return digits


def _solapi_sender_for_site(site: str) -> str:
    raw_map = getenv("COMPLAINT_MESSAGE_SOLAPI_SITE_SENDERS", "").strip()
    if raw_map:
        try:
            parsed = json.loads(raw_map)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            site_sender = str(parsed.get(site) or "").strip()
            if site_sender:
                return _normalize_phone_number(site_sender)
    return _normalize_phone_number(getenv("COMPLAINT_MESSAGE_SOLAPI_SENDER", "").strip())


def _solapi_auth_header(*, api_key: str, api_secret: str) -> str:
    date_label = datetime.now().astimezone().isoformat()
    salt = uuid1().hex
    signature = hmac.new(
        api_secret.encode("utf-8"),
        f"{date_label}{salt}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"HMAC-SHA256 ApiKey={api_key}, Date={date_label}, salt={salt}, signature={signature}"


def _send_via_webhook(
    *,
    site: str,
    complaint_id: int,
    recipient: str,
    body: str,
    template_key: str | None,
) -> dict[str, Any]:
    url = getenv("COMPLAINT_MESSAGE_WEBHOOK_URL", "").strip()
    if not url:
        return {
            "provider_name": "webhook",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": "COMPLAINT_MESSAGE_WEBHOOK_URL is required",
            "sent_at": None,
        }
    token = getenv("COMPLAINT_MESSAGE_WEBHOOK_TOKEN", "").strip()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {
        "site": site,
        "complaint_id": complaint_id,
        "recipient": recipient,
        "body": body,
        "template_key": template_key,
    }
    timeout_sec = float(getenv("COMPLAINT_MESSAGE_TIMEOUT_SEC", "10").strip() or "10")
    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=timeout_sec)
        if response.status_code >= 400:
            return {
                "provider_name": "webhook",
                "provider_message_id": None,
                "delivery_status": "failed",
                "error": f"webhook status {response.status_code}",
                "sent_at": None,
            }
        return {
            "provider_name": "webhook",
            "provider_message_id": response.headers.get("x-message-id") or None,
            "delivery_status": "sent",
            "error": None,
            "sent_at": _now(),
        }
    except Exception as exc:
        return {
            "provider_name": "webhook",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": str(exc),
            "sent_at": None,
        }


def _send_via_solapi(
    *,
    site: str,
    complaint_id: int,
    recipient: str,
    body: str,
    template_key: str | None,
) -> dict[str, Any]:
    api_key = getenv("COMPLAINT_MESSAGE_SOLAPI_API_KEY", "").strip()
    api_secret = getenv("COMPLAINT_MESSAGE_SOLAPI_API_SECRET", "").strip()
    sender = _solapi_sender_for_site(site)
    if not api_key:
        return {
            "provider_name": "solapi",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": "COMPLAINT_MESSAGE_SOLAPI_API_KEY is required",
            "sent_at": None,
        }
    if not api_secret:
        return {
            "provider_name": "solapi",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": "COMPLAINT_MESSAGE_SOLAPI_API_SECRET is required",
            "sent_at": None,
        }
    if not sender:
        return {
            "provider_name": "solapi",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": "COMPLAINT_MESSAGE_SOLAPI_SENDER is required",
            "sent_at": None,
        }

    api_base_url = getenv("COMPLAINT_MESSAGE_SOLAPI_BASE_URL", "https://api.solapi.com").strip() or "https://api.solapi.com"
    timeout_sec = float(getenv("COMPLAINT_MESSAGE_TIMEOUT_SEC", "10").strip() or "10")
    request_payload: dict[str, Any] = {
        "messages": [
            {
                "to": _normalize_phone_number(recipient),
                "from": sender,
                "text": body,
                "autoTypeDetect": True,
                "customFields": {
                    "complaintId": str(complaint_id),
                    "site": site,
                    "templateKey": template_key or "",
                },
            }
        ],
        "allowDuplicates": _env_flag("COMPLAINT_MESSAGE_SOLAPI_ALLOW_DUPLICATES", default=False),
        "showMessageList": _env_flag("COMPLAINT_MESSAGE_SOLAPI_SHOW_MESSAGE_LIST", default=True),
        "agent": {
            "sdkVersion": "ka-facility-os",
            "osPlatform": "complaints-message-provider",
        },
    }
    app_id = getenv("COMPLAINT_MESSAGE_SOLAPI_APP_ID", "").strip()
    if app_id:
        request_payload["appId"] = app_id

    headers = {
        "Authorization": _solapi_auth_header(api_key=api_key, api_secret=api_secret),
        "Content-Type": "application/json",
        "Connection": "keep-alive",
    }
    transport = httpx.HTTPTransport(retries=3)
    try:
        with httpx.Client(transport=transport, timeout=timeout_sec) as client:
            response = client.post(
                f"{api_base_url.rstrip('/')}/messages/v4/send-many/detail",
                headers=headers,
                json=request_payload,
            )
        try:
            payload = response.json()
        except Exception:
            payload = {}
        if 400 <= response.status_code < 500:
            return {
                "provider_name": "solapi",
                "provider_message_id": None,
                "delivery_status": "failed",
                "error": f"{payload.get('errorCode', 'ClientError')}: {payload.get('errorMessage', 'request failed')}",
                "sent_at": None,
            }
        if response.status_code >= 500:
            return {
                "provider_name": "solapi",
                "provider_message_id": None,
                "delivery_status": "failed",
                "error": f"Solapi server error {response.status_code}",
                "sent_at": None,
            }
        group_info = payload.get("groupInfo") or {}
        message_list = payload.get("messageList") or []
        count = group_info.get("count") or {}
        registered_success = int(count.get("registeredSuccess") or 0)
        registered_failed = int(count.get("registeredFailed") or 0)
        provider_message_id = None
        if message_list:
            provider_message_id = message_list[0].get("messageId")
        if not provider_message_id:
            provider_message_id = group_info.get("groupId")
        if registered_success <= 0 and registered_failed > 0:
            failed_rows = payload.get("failedMessageList") or []
            first_failed = failed_rows[0] if failed_rows else {}
            error_message = str(first_failed.get("statusMessage") or "message registration failed")
            return {
                "provider_name": "solapi",
                "provider_message_id": provider_message_id,
                "delivery_status": "failed",
                "error": error_message,
                "sent_at": None,
            }
        return {
            "provider_name": "solapi",
            "provider_message_id": provider_message_id,
            "delivery_status": "accepted",
            "error": None,
            "sent_at": _now(),
        }
    except httpx.HTTPError as exc:
        return {
            "provider_name": "solapi",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": str(exc),
            "sent_at": None,
        }
    except Exception as exc:
        return {
            "provider_name": "solapi",
            "provider_message_id": None,
            "delivery_status": "failed",
            "error": str(exc),
            "sent_at": None,
        }


def send_message(
    *,
    site: str,
    complaint_id: int,
    recipient: str,
    body: str,
    template_key: str | None = None,
) -> dict[str, Any]:
    provider = _provider_name()
    now = _now()
    if provider in {"stub", "mock", "test"}:
        return {
            "provider_name": "stub",
            "provider_message_id": f"stub-{complaint_id}-{int(now.timestamp())}",
            "delivery_status": "sent",
            "error": None,
            "sent_at": now,
        }
    if provider == "webhook":
        return _send_via_webhook(
            site=site,
            complaint_id=complaint_id,
            recipient=recipient,
            body=body,
            template_key=template_key,
        )
    if provider == "solapi":
        return _send_via_solapi(
            site=site,
            complaint_id=complaint_id,
            recipient=recipient,
            body=body,
            template_key=template_key,
        )
    return {
        "provider_name": provider,
        "provider_message_id": None,
        "delivery_status": "failed",
        "error": f"Unsupported complaint message provider: {provider}",
        "sent_at": None,
    }
