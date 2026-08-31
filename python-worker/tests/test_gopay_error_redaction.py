from __future__ import annotations

import io
import sys
import threading
import urllib.error
from pathlib import Path
from types import ModuleType

import pytest


RUNTIME_SRC = Path(__file__).resolve().parents[1] / "gopay_runtime" / "app" / "src"
if str(RUNTIME_SRC) not in sys.path:
    sys.path.insert(0, str(RUNTIME_SRC))


def _payment_inbox_module():
    from opai.core import payment_inbox

    return payment_inbox


def test_legacy_captcha_error_does_not_expose_request_payload() -> None:
    from opai.core import captcha_provider

    unsafe = captcha_provider._legacy_error(
        {"status": 0, "request": "api_key=legacy-secret bearer legacy-token"},
        "submit",
    )
    assert "legacy-secret" not in str(unsafe)
    assert "legacy-token" not in str(unsafe)
    assert "PROVIDER_ERROR" in str(unsafe)

    known = captcha_provider._legacy_error(
        {"status": 0, "request": "ERROR_CAPTCHA_UNSOLVABLE"},
        "result",
    )
    assert "ERROR_CAPTCHA_UNSOLVABLE" in str(known)


def test_web_payment_progress_persists_charge_reference_only_in_internal_field() -> None:
    payment_inbox = _payment_inbox_module()
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._lock = threading.RLock()
    manager._jobs = {"job": {"id": "job", "logs": []}}
    manager._save_state_locked = lambda: None

    manager._append_log(
        "job",
        "linking reference=link-secret linking challenge_id=link-challenge "
        "charge challenge_ref=charge-secret payment challenge_id=payment-challenge",
    )

    job = manager._jobs["job"]
    assert job["challenge_ref"] == "charge-secret"
    assert job["payment_phase"] == "charged"
    public_text = f"{job['message']} {job['logs'][-1]['message']}"
    for secret in (
        "link-secret",
        "link-challenge",
        "charge-secret",
        "payment-challenge",
    ):
        assert secret not in public_text
    assert public_text.count("[已隐藏]") == 8


def test_midtrans_metadata_error_does_not_expose_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payment_inbox = _payment_inbox_module()
    snap = "123e4567-e89b-12d3-a456-426614174000"

    class FakeResponse:
        status_code = 403
        text = "access_token=midtrans-text-secret"

        @staticmethod
        def json():
            return {
                "error": "forbidden",
                "client_key": "midtrans-client-secret",
                "challenge_ref": "midtrans-challenge-secret",
            }

    class FakeSession:
        def __init__(self, **_kwargs):
            self.proxies = {}

        def get(self, *_args, **_kwargs):
            return FakeResponse()

    fake_tls_client = ModuleType("tls_client")
    fake_tls_client.Session = FakeSession
    monkeypatch.setitem(sys.modules, "tls_client", fake_tls_client)

    with pytest.raises(RuntimeError) as raised:
        payment_inbox._midtrans_transaction_meta(
            f"https://app.midtrans.com/snap/v4/redirection/{snap}"
        )

    message = str(raised.value)
    assert "HTTP 403" in message
    assert "midtrans-client-secret" not in message
    assert "midtrans-challenge-secret" not in message
    assert "midtrans-text-secret" not in message


def test_payment_inbox_client_error_does_not_expose_api_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payment_inbox = _payment_inbox_module()
    response = io.BytesIO(
        b'{"error":"denied","access_token":"api-response-secret"}'
    )

    def raise_http_error(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=response,
        )

    monkeypatch.setattr(payment_inbox.urllib.request, "urlopen", raise_http_error)
    client = payment_inbox.PaymentInboxClient(
        "http://127.0.0.1:19480",
        token="request-token-secret",
    )

    with pytest.raises(RuntimeError) as raised:
        client._req("GET", "/api/jobs")

    message = str(raised.value)
    assert "HTTP 401" in message
    assert "api-response-secret" not in message
    assert "request-token-secret" not in message
