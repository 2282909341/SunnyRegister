from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any


GOPAY_SRC = Path(__file__).resolve().parents[1] / "gopay_runtime" / "app" / "src"
if str(GOPAY_SRC) not in sys.path:
    sys.path.insert(0, str(GOPAY_SRC))

try:
    import tls_client  # noqa: F401
except ModuleNotFoundError:
    tls_client_stub = types.ModuleType("tls_client")
    tls_client_stub.Session = None  # type: ignore[attr-defined]
    sys.modules["tls_client"] = tls_client_stub

from opai.core import gopay_payment_protocol as protocol  # noqa: E402
from opai.core.payment_fingerprint import (  # noqa: E402
    build_payment_fingerprint,
    ensure_account_payment_fingerprint,
    payment_fingerprint_headers,
)


def test_payment_fingerprint_matches_latest_successful_har() -> None:
    profile = build_payment_fingerprint(
        phone="+628123456789",
        local="8123456789",
        account_id="account-1",
    )

    assert profile["version"] == 2
    assert profile["locale"] == "zh-CN"
    assert profile["timezone"] == "Asia/Shanghai"
    assert profile["viewport"] == {
        "width": 787,
        "height": 586,
        "device_scale_factor": 1,
    }
    assert "Android 15; Pixel 9" in profile["user_agent"]
    assert "Chrome/151.0.0.0 Mobile" in profile["user_agent"]
    assert profile["sec_ch_ua_mobile"] == "?1"
    assert profile["sec_ch_ua_platform"] == '"Android"'

    headers = payment_fingerprint_headers(profile)
    assert headers["Accept-Language"].startswith("zh-CN,zh;q=0.9")
    assert headers["Sec-CH-UA-Mobile"] == "?1"
    assert headers["Sec-CH-UA-Platform"] == '"Android"'
    assert "X-Timezone" not in headers
    assert "Viewport-Width" not in headers


def test_version_one_account_fingerprint_migrates_stably_across_reload() -> None:
    account = {
        "phone": "+628123456789",
        "local": "8123456789",
        "account_id": "account-1",
    }
    expected = build_payment_fingerprint(
        phone=account["phone"],
        local=account["local"],
        account_id=account["account_id"],
    )
    old_profile_id = "0123456789abcdef"
    account["payment_fingerprint"] = {
        "version": 1,
        "profile_id": old_profile_id,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "locale": "id-ID",
        "timezone": "Asia/Jakarta",
        "viewport": {"width": 1366, "height": 768, "device_scale_factor": 1},
        "sec_ch_ua": '"Chromium";v="120"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
    }

    migrated = ensure_account_payment_fingerprint(account)
    reloaded = json.loads(json.dumps(account))
    migrated_after_reload = ensure_account_payment_fingerprint(reloaded)

    assert migrated == {**expected, "profile_id": old_profile_id}
    assert migrated["profile_id"] == old_profile_id
    assert migrated_after_reload == migrated
    assert migrated_after_reload["profile_id"] == migrated["profile_id"]


class _FakeResponse:
    status_code = 200
    text = ""

    @staticmethod
    def json() -> dict[str, Any]:
        return {"data": {"token": "pin-token"}}


class _RecordingSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def post(self, url: str, *, headers: dict[str, str], **_kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, headers))
        return _FakeResponse()

    def get(self, url: str, *, headers: dict[str, str], **_kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, headers))
        return _FakeResponse()


def test_gwa_and_pin_headers_follow_the_payment_fingerprint(monkeypatch: Any) -> None:
    session = _RecordingSession()
    monkeypatch.setattr(protocol.tls_client, "Session", lambda **_kwargs: session)

    profile = build_payment_fingerprint(seed="header-test")
    payment = protocol.GoPayPayment(payment_fingerprint=profile)
    payment._gwa_post("/v1/linking/user-consent", {"reference_id": "ref"})
    payment._gwa_get("/v1/payment/validate?reference_id=ref")
    assert payment._pin_verify("challenge-id", "147258", protocol.PIN_CLIENT_PAYMENT) == "pin-token"

    gwa_headers = [headers for _method, url, headers in session.calls if "gwa.gopayapi.com" in url]
    assert len(gwa_headers) == 2
    assert all(headers["X-User-Locale"] == "zh-CN" for headers in gwa_headers)
    assert all(headers["Sec-CH-UA-Mobile"] == "?1" for headers in gwa_headers)
    assert all(headers["Sec-CH-UA-Platform"] == '"Android"' for headers in gwa_headers)

    pin_headers = next(headers for _method, url, headers in session.calls if "customer.gopayapi.com" in url)
    assert pin_headers["X-User-Locale"] == "id"
    assert pin_headers["X-Is-Mobile"] == "false"
    assert pin_headers["X-Platform"] == "Android 15"
    assert "Chrome/151.0.0.0 Mobile" in pin_headers["User-Agent"]
