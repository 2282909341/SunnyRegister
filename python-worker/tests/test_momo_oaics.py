from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch


PAY153_DIR = Path(__file__).parents[1] / "tools" / "pay153_checkout"
if str(PAY153_DIR) not in sys.path:
    sys.path.insert(0, str(PAY153_DIR))

import app as checkout_app  # noqa: E402


def test_momo_stage1_requests_custom_oaics_and_defers_trial_campaign() -> None:
    payload = checkout_app.checkout_payload(
        {
            "plan": "plus",
            "link_type": "momo",
            "country": "VN",
            "currency": "VND",
            "checkout_country": "VN",
            "checkout_currency": "VND",
            "use_promo": True,
            "promo_campaign": "plus-1-month-free",
            "promo_on_create": False,
            "checkout_ui_mode": "custom",
        },
        {},
    )

    assert payload["checkout_ui_mode"] == "custom"
    assert payload["billing_details"] == {"country": "VN", "currency": "VND"}
    assert "promo_campaign" not in payload


def test_momo_authorization_url_accepts_expected_stripe_handoff() -> None:
    url = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_V9sheJQ8YBaT9uRLR4gw2ilYZiC8pWl"
    )

    assert checkout_app.is_valid_momo_authorization_url(url)
    assert checkout_app.momo_authorization_url({"next_action": {"url": url}}) == url


def test_momo_authorization_url_rejects_checkout_and_other_provider_urls() -> None:
    assert not checkout_app.is_valid_momo_authorization_url(
        "https://chatgpt.com/checkout/openai_ie/oaics_example"
    )
    assert not checkout_app.is_valid_momo_authorization_url(
        "https://pm-redirects.stripe.com/authorize/acct_test/not_a_nonce"
    )


def test_momo_attempts_request_custom_oaics_and_keep_cs_live_fallback() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    strategies: list[tuple[str, str, bool]] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, _message: None
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        strategies.append((
            str(attempt_options["checkout_ui_mode"]),
            str(attempt_options["local_method_strategy"]),
            bool(attempt_options["promo_on_create"]),
        ))
        if len(strategies) >= 4:
            state.update(status="done", result={})
        else:
            state.update(status="error", error="MOMO_METHOD_UNAVAILABLE: oaics_test")

    store._run_single = run_single
    store._run_locked("job-momo", {
        "retry_count": 3,
        "link_type": "momo",
        "use_promo": True,
        "country": "VN",
        "checkout_country": "VN",
        "entry_proxies": ["http://promotion:8001"],
        "exit_proxies": ["http://checkout:9001"],
        "paired_proxy_rotation": True,
    })

    assert strategies == [
        ("custom", "late_promo", False),
        ("custom", "late_promo", False),
        ("custom", "late_promo", False),
        ("custom", "late_promo", False),
    ]


def test_momo_native_method_detection_reads_har_observed_oaics_shapes() -> None:
    payload = {
        "checkout_session": {
            "payment_method_types": ["link", "card", "momo"],
            "available_payment_methods": [{"type": "momo"}],
            "custom_payment_methods": [{"id": "cpmt_unrelated", "type": "wallet"}],
        },
    }

    assert checkout_app.oaics_native_payment_method_types(payload) == ["link", "card", "momo"]


def test_momo_discounted_amount_accepts_har_threshold() -> None:
    assert checkout_app.is_momo_promo_amount(0, "VND")
    assert checkout_app.is_momo_promo_amount(50, "vnd")
    assert not checkout_app.is_momo_promo_amount(51, "VND")
    assert not checkout_app.is_momo_promo_amount(0, "IDR")


def test_momo_oaics_error_redacts_confirmation_and_intent_secrets() -> None:
    rendered = checkout_app._redact_oaics_payment_error(
        "ctoken_private seti_fixture_secret_private pi_fixture_secret_private"
    )

    assert "private" not in rendered
    assert rendered.count("[PAYMENT_SECRET]") == 3


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = "{}"

    def json(self) -> dict:
        return self._payload


class _RecordingHttp:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def post(self, url: str, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    def get(self, url: str, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


def test_momo_confirmation_token_uses_payment_method_without_leaking_it_to_logs() -> None:
    http = _RecordingHttp([_FakeResponse({"id": "ctoken_fixture"})])

    token_id = checkout_app.create_oaics_confirmation_token(
        http, "pk_live_fixture", "pm_fixture",
    )

    assert token_id == "ctoken_fixture"
    method, url, request = http.calls[0]
    assert method == "POST"
    assert url.endswith("/v1/confirmation_tokens")
    assert request["data"]["payment_method"] == "pm_fixture"
    assert request["data"]["key"] == "pk_live_fixture"


def test_momo_native_checkout_confirm_uses_confirm_token_contract() -> None:
    redirect = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_VA3BRLWr6svCcb3IbJQljuUq2OZpfPW"
    )
    http = _RecordingHttp([
        _FakeResponse({"ok": True}),
        _FakeResponse({
            "status": "success",
            "setup_intent": {"next_action": {"redirect_to_url": {"url": redirect}}},
        }),
    ])

    with patch.object(
        checkout_app,
        "resolve_payment_sentinel_headers",
        return_value={"OpenAI-Sentinel-Token": "sentinel-fixture"},
    ):
        result = checkout_app.confirm_oaics_native_payment_method(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "momo",
            "ctoken_fixture",
            "http://vn-proxy",
            "device-fixture",
            "did-fixture",
        )

    assert checkout_app.momo_authorization_url(result) == redirect
    assert http.calls[0][1].endswith("/backend-api/sentinel/ping")
    _, url, request = http.calls[1]
    assert url.endswith("/backend-api/payments/checkout/confirm")
    assert request["json"] == {
        "checkout_session_id": "oaics_fixture",
        "selected_payment_method_type": "momo",
        "confirm_token": "ctoken_fixture",
    }


def test_momo_intent_fallback_confirms_setup_intent_with_created_payment_method() -> None:
    redirect = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_VA3BRLWr6svCcb3IbJQljuUq2OZpfPW"
    )
    http = _RecordingHttp([_FakeResponse({
        "id": "seti_fixture",
        "status": "requires_action",
        "next_action": {"redirect_to_url": {"url": redirect}},
    })])

    result = checkout_app.confirm_oaics_momo_intent(
        http,
        "pk_live_fixture",
        "pm_fixture",
        {"setup_intent": {"client_secret": "seti_fixture_secret_value"}},
        "oaics_fixture",
        "openai_llc",
    )

    assert checkout_app.momo_authorization_url(result) == redirect
    _, url, request = http.calls[0]
    assert url.endswith("/v1/setup_intents/seti_fixture/confirm")
    assert request["data"]["payment_method"] == "pm_fixture"
    assert "confirmation_token" not in request["data"]


def test_momo_intent_poll_reads_redirect_after_approval() -> None:
    redirect = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_VA3BRLWr6svCcb3IbJQljuUq2OZpfPW"
    )
    http = _RecordingHttp([
        _FakeResponse({"id": "seti_fixture", "status": "processing"}),
        _FakeResponse({
            "id": "seti_fixture",
            "status": "requires_action",
            "next_action": {"redirect_to_url": {"url": redirect}},
        }),
    ])

    with patch.object(checkout_app.time, "sleep"):
        result = checkout_app.poll_oaics_momo_intent(
            http,
            "pk_live_fixture",
            {"setup_intent": {"client_secret": "seti_fixture_secret_value"}},
            attempts=2,
        )

    assert checkout_app.momo_authorization_url(result) == redirect
    assert [call[0] for call in http.calls] == ["GET", "GET"]
