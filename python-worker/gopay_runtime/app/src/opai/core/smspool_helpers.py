"""SMSPool adapter used by the embedded GoPay module.

The adapter deliberately mirrors the small interface used by SMSBower in the
GoPay flow.  It keeps provider-specific order IDs and API payloads out of the
registration/payment managers.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Collection

import tls_client

log = logging.getLogger(__name__)

SMSPOOL_DEFAULT_BASE_URL = "https://api.smspool.net"
SMSPOOL_DEFAULT_COUNTRY = "9"
SMSPOOL_DEFAULT_SERVICE = "392"
SMSPOOL_TIMEOUT = 180
SMSPOOL_CANCEL_RETRY_ATTEMPTS = 3
SMSPOOL_CANCEL_RETRY_DELAY_SECONDS = 30.0


def _load_env() -> None:
    path = (os.environ.get("OPAI_GOPAY_SMS_ENV_FILE") or "").strip()
    candidates = [Path(path)] if path else [Path.cwd() / "config" / "sms.env"]
    for env_path in candidates:
        if not env_path.is_file():
            continue
        try:
            for raw in env_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if key.startswith("OPAI_SMSPOOL_") and not os.environ.get(key):
                    os.environ[key] = value.strip().strip('"').strip("'")
        except OSError:
            log.debug("Could not read SMSPool env file", exc_info=True)
        if path:
            break


def smspool_api_key(value: str = "") -> str:
    _load_env()
    return str(value or os.environ.get("OPAI_SMSPOOL_API_KEY") or "").strip()


def smspool_base_url() -> str:
    _load_env()
    return (os.environ.get("OPAI_SMSPOOL_API_BASE_URL") or SMSPOOL_DEFAULT_BASE_URL).strip().rstrip("/")


def smspool_config() -> dict[str, str]:
    _load_env()
    return {
        "api_key": smspool_api_key(),
        "api_base_url": smspool_base_url(),
        "country": (os.environ.get("OPAI_SMSPOOL_COUNTRY") or SMSPOOL_DEFAULT_COUNTRY).strip(),
        "service": (os.environ.get("OPAI_SMSPOOL_SERVICE") or SMSPOOL_DEFAULT_SERVICE).strip(),
        "pool": (os.environ.get("OPAI_SMSPOOL_POOL") or "").strip(),
        "max_price": (os.environ.get("OPAI_SMSPOOL_MAX_PRICE") or "").strip(),
    }


def _post(path: str, data: dict[str, Any] | None = None, *, timeout: int = 30) -> dict[str, Any]:
    config = smspool_config()
    key = config["api_key"]
    if not key:
        raise RuntimeError("SMSPool API key is not configured")
    payload = {"key": key}
    payload.update({k: v for k, v in (data or {}).items() if v is not None and v != ""})
    session = tls_client.Session(client_identifier="chrome_120")
    response = session.post(
        f"{config['api_base_url']}{path}",
        data=payload,
        headers={"Accept": "application/json", "Authorization": f"Bearer {key}"},
        timeout_seconds=timeout,
    )
    text = str(getattr(response, "text", "") or "").strip()
    status = int(getattr(response, "status_code", 200) or 200)
    if status >= 400:
        raise RuntimeError(f"SMSPool HTTP {status}: {text[:300]}")
    try:
        body = response.json()
    except Exception as exc:
        try:
            body = json.loads(text)
        except Exception:
            raise RuntimeError(f"SMSPool returned non-JSON: {text[:300]}") from exc
    if not isinstance(body, dict):
        return {"data": body}
    if str(body.get("success") or "") in {"0", "false", "False"}:
        raise RuntimeError(str(body.get("message") or body.get("type") or text[:300]))
    return body


def smspool_balance() -> dict[str, Any]:
    return _post("/request/balance")


def smspool_get_number() -> tuple[str | None, str | None]:
    config = smspool_config()
    data: dict[str, Any] = {
        "country": config["country"] or SMSPOOL_DEFAULT_COUNTRY,
        "service": config["service"] or SMSPOOL_DEFAULT_SERVICE,
        "quantity": "1",
        "activation_type": "SMS",
        "create_token": "0",
    }
    if config["pool"]:
        data["pool"] = config["pool"]
    if config["max_price"]:
        data["max_price"] = config["max_price"]
    body = _post("/purchase/sms", data, timeout=45)
    order_id = str(body.get("order_id") or body.get("orderid") or body.get("id") or "").strip()
    raw_phone = str(body.get("phonenumber") or body.get("phone") or body.get("number") or "").strip()
    cc = str(body.get("cc") or body.get("country_code") or "").strip().lstrip("+")
    if raw_phone and not raw_phone.startswith("+"):
        raw_phone = f"+{cc}{raw_phone}" if cc and not raw_phone.startswith(cc) else f"+{raw_phone}"
    if not order_id or not raw_phone:
        raise RuntimeError(str(body.get("message") or "SMSPool did not return an order and phone"))
    return raw_phone, order_id


def smspool_check(order_id: str) -> dict[str, Any]:
    return _post("/sms/check", {"orderid": order_id}, timeout=20)


def smspool_wait_code(
    order_id: str,
    timeout: int = SMSPOOL_TIMEOUT,
    *,
    ignore_code_hashes: Collection[str] | None = None,
) -> str | None:
    from .sms_helpers import sms_code_sha256

    ignored = {str(value).lower() for value in (ignore_code_hashes or ())}
    deadline = time.time() + max(1, timeout)
    while time.time() < deadline:
        body = smspool_check(order_id)
        status = str(body.get("status") or "")
        if status == "3":
            code = str(body.get("sms") or "").strip()
            if not code:
                match = re.search(r"\b(\d{4,8})\b", str(body.get("full_sms") or ""))
                code = match.group(1) if match else ""
            if code and sms_code_sha256(code).lower() not in ignored:
                return code
        if status == "6":
            return None
        time.sleep(min(3, max(0, deadline - time.time())))
    return None


def smspool_resend(order_id: str) -> bool:
    try:
        _post("/sms/resend", {"orderid": order_id}, timeout=20)
        return True
    except Exception:
        log.debug("SMSPool resend failed for %s", order_id, exc_info=True)
        return False


def smspool_reactivate(order_id: str) -> str | None:
    try:
        body = _post("/sms/reactivate", {"orderid": order_id}, timeout=20)
        return str(body.get("order_id") or body.get("orderid") or body.get("id") or order_id).strip() or None
    except Exception:
        log.debug("SMSPool reactivate failed for %s", order_id, exc_info=True)
        return None


def smspool_cancel(order_id: str) -> bool:
    if not order_id:
        return False
    try:
        _post("/sms/cancel", {"orderid": order_id}, timeout=20)
        return True
    except Exception:
        log.debug("SMSPool cancel failed for %s", order_id, exc_info=True)
        return False


def schedule_smspool_cancel_retry(
    order_id: str,
    *,
    retry_attempts: int | None = None,
    delay_seconds: float | None = None,
    on_success: Callable[[], None] | None = None,
) -> threading.Thread | None:
    """Retry a failed cancellation without changing the single-call API."""
    normalized_order_id = str(order_id or "").strip()
    if not normalized_order_id:
        return None

    if retry_attempts is None:
        raw_attempts = os.environ.get(
            "OPAI_SMSPOOL_CANCEL_RETRY_ATTEMPTS",
            str(SMSPOOL_CANCEL_RETRY_ATTEMPTS),
        )
        try:
            retry_attempts = int(raw_attempts)
        except (TypeError, ValueError):
            retry_attempts = SMSPOOL_CANCEL_RETRY_ATTEMPTS
    retry_attempts = max(0, min(int(retry_attempts), 20))
    if retry_attempts == 0:
        return None

    if delay_seconds is None:
        raw_delay = os.environ.get(
            "OPAI_SMSPOOL_CANCEL_RETRY_DELAY_SEC",
            str(SMSPOOL_CANCEL_RETRY_DELAY_SECONDS),
        )
        try:
            delay_seconds = float(raw_delay)
        except (TypeError, ValueError):
            delay_seconds = SMSPOOL_CANCEL_RETRY_DELAY_SECONDS
    delay_seconds = max(0.0, min(float(delay_seconds), 3600.0))

    def retry() -> None:
        for attempt in range(1, retry_attempts + 1):
            if delay_seconds:
                time.sleep(delay_seconds)
            if not smspool_cancel(normalized_order_id):
                continue
            log.info(
                "SMSPool cancellation retry succeeded for %s on attempt %d",
                normalized_order_id,
                attempt,
            )
            if on_success is not None:
                try:
                    on_success()
                except Exception:
                    log.warning(
                        "SMSPool cancellation success callback failed for %s",
                        normalized_order_id,
                        exc_info=True,
                    )
            return
        log.warning(
            "SMSPool cancellation retries exhausted for %s after %d attempts",
            normalized_order_id,
            retry_attempts,
        )

    thread = threading.Thread(
        target=retry,
        daemon=True,
        name=f"smspool-cancel-{normalized_order_id[:24]}",
    )
    thread.start()
    return thread


def smspool_activate(order_id: str) -> bool:
    try:
        _post("/sms/activate", {"orderid": order_id}, timeout=20)
        return True
    except Exception:
        log.debug("SMSPool activate failed for %s", order_id, exc_info=True)
        return False
