from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import pytest


PAY153_DIR = Path(__file__).parents[1] / "tools" / "pay153_checkout"
if str(PAY153_DIR) not in sys.path:
    sys.path.insert(0, str(PAY153_DIR))

import app as checkout_app  # noqa: E402
import provider_checkout as provider_checkout_module  # noqa: E402
from provider_checkout import (  # noqa: E402
    PROVIDER_DEFAULTS,
    default_billing,
    extract_provider_result,
    is_gopay_promo_amount,
    stripe_to_provider,
)


MIDTRANS_V3 = "https://app.midtrans.com/snap/v3/redirection/123e4567-e89b-12d3-a456-426614174000"
MIDTRANS_V4 = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174001"
MIDTRANS_V4_LINKING = MIDTRANS_V4 + "#/gopay-tokenization/linking"


def test_gopay_midtrans_url_accepts_reference_snap_versions() -> None:
    assert checkout_app.is_valid_gopay_midtrans_url(MIDTRANS_V3)
    assert checkout_app.is_valid_gopay_midtrans_url(MIDTRANS_V4 + "?source=chatgpt")
    assert checkout_app.is_valid_gopay_midtrans_url(MIDTRANS_V4_LINKING)


def test_gopay_midtrans_url_rejects_non_provider_and_lookalike_urls() -> None:
    assert not checkout_app.is_valid_gopay_midtrans_url(
        "https://app.midtrans.com.evil.example/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174001"
    )
    assert not checkout_app.is_valid_gopay_midtrans_url(
        "https://app.midtrans.com/snap/v4/redirection/not-a-uuid"
    )
    assert not checkout_app.is_valid_gopay_midtrans_url(
        "https://chatgpt.com/checkout/openai_ie/oaics_example"
    )


def test_gopay_midtrans_url_finds_nested_and_encoded_handoff() -> None:
    payload = {
        "next_action": {"url": "https://chatgpt.com/checkout/verify"},
        "provider_data": {"redirect_url": quote(MIDTRANS_V4, safe="")},
    }
    assert checkout_app.gopay_midtrans_url(payload) == MIDTRANS_V4


def test_generic_gopay_result_preserves_midtrans_linking_fragment() -> None:
    result = checkout_app.require_gopay_midtrans_result({
        "provider_redirect_url": MIDTRANS_V4_LINKING,
        "next_action_type": "redirect_to_url",
    })
    assert result["provider_redirect_url"] == MIDTRANS_V4_LINKING
    assert result["gopay_midtrans_url"] == MIDTRANS_V4_LINKING
    assert result["checkout_url"] == MIDTRANS_V4_LINKING


def test_generic_gopay_result_rejects_non_midtrans_redirect() -> None:
    try:
        checkout_app.require_gopay_midtrans_result({
            "provider_redirect_url": "https://chatgpt.com/checkout/verify",
        })
    except RuntimeError as exc:
        assert str(exc).startswith("GOPAY_MIDTRANS_LINK_MISSING")
    else:
        raise AssertionError("普通 Checkout 链接不应被判定为 GoPay 成功结果")


def test_generic_provider_result_reads_redirect_to_url() -> None:
    result = extract_provider_result({
        "next_action": {
            "type": "redirect_to_url",
            "redirect_to_url": {"url": MIDTRANS_V4_LINKING},
        },
    }, "gopay")
    assert result["provider_redirect_url"] == MIDTRANS_V4_LINKING


def test_gopay_method_selection_prefers_gopay_cpmt() -> None:
    payload = {
        "custom_payment_methods": [
            {"id": "cpmt_paypal", "name": "PayPal"},
            {"id": "cpmt_gopay", "name": "GoPay wallet"},
        ],
    }
    assert checkout_app.custom_payment_method_id_for(payload, "gopay") == "cpmt_gopay"


def test_gopay_method_selection_accepts_protocol_aliases_but_not_other_cpmt() -> None:
    payload = {
        "custom_payment_methods": [
            {"id": "cpmt_unknown", "name": "wallet"},
            {"id": "cpmt_alias", "paymentMethodType": "gopay-tokenization"},
            {"id": "cpmt_p24", "name": "Przelewy24"},
        ],
    }
    assert checkout_app.custom_payment_method_id_for(payload, "gopay") == "cpmt_alias"
    assert checkout_app.custom_payment_methods_for(payload, "gopay") == [payload["custom_payment_methods"][1]]


def test_gopay_confirm_retries_only_blocked_responses() -> None:
    responses = [
        RuntimeError("CUSTOM_CONFIRM_BLOCKED: transient"),
        RuntimeError("CUSTOM_CONFIRM_BLOCKED: transient"),
        {"status": "success"},
    ]

    def fake_confirm(*_args, **_kwargs):
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    with patch.object(checkout_app, "confirm_custom_checkout_method", side_effect=fake_confirm) as confirm:
        result = checkout_app.confirm_custom_checkout_method_with_retry(
            object(), "token", "oaics_test", "openai_ie", "cpmt_gopay",
            "http://proxy:1", "device", "did", max_retries=2,
        )
    assert result == {"status": "success"}
    assert confirm.call_count == 3


def test_gopay_confirm_does_not_retry_non_blocked_errors() -> None:
    with patch.object(
        checkout_app,
        "confirm_custom_checkout_method",
        side_effect=RuntimeError("确认 GoPay 支付方式失败：HTTP 400"),
    ) as confirm:
        try:
            checkout_app.confirm_custom_checkout_method_with_retry(
                object(), "token", "oaics_test", "openai_ie", "cpmt_gopay",
                "http://proxy:1", "device", "did", max_retries=3,
            )
        except RuntimeError as exc:
            assert "HTTP 400" in str(exc)
        else:
            raise AssertionError("非 blocked 错误不应重试")
    assert confirm.call_count == 1


def test_gopay_approval_blocked_invalidates_current_checkout() -> None:
    logs: list[str] = []
    with patch.object(
        checkout_app,
        "approve_checkout",
        side_effect=RuntimeError("manual_approval approve blocked: result=blocked"),
    ) as approve:
        with pytest.raises(RuntimeError, match="GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED"):
            checkout_app.approve_gopay_checkout_or_rebuild(
                "token", "cs_live_test", "openai_ie", "http://proxy", "device", "did",
                log=logs.append, allow_sentinel_fallback=True,
            )

    approve.assert_called_once()
    assert approve.call_args.kwargs["allow_sentinel_fallback"] is True
    assert any("停止复用并重建完整支付提链" in message for message in logs)


def test_gopay_approval_does_not_retry_non_blocked_errors() -> None:
    with patch.object(
        checkout_app,
        "approve_checkout",
        side_effect=RuntimeError("Checkout approve HTTP 400"),
    ) as approve:
        try:
            checkout_app.approve_gopay_checkout_or_rebuild(
                "token", "cs_live_test", "openai_ie", "http://proxy", "device", "did",
                log=lambda _message: None,
            )
        except RuntimeError as exc:
            assert "HTTP 400" in str(exc)
        else:
            raise AssertionError("非 blocked approval 错误不应重试")
    assert approve.call_count == 1


def test_gopay_approval_success_returns_after_one_submission() -> None:
    with patch.object(checkout_app, "approve_checkout", return_value={"result": "approved"}) as approve:
        result = checkout_app.approve_gopay_checkout_or_rebuild(
            "token", "cs_live_test", "openai_ie", "http://proxy", "device", "did",
            log=lambda _message: None,
        )

    assert result == {"result": "approved"}
    approve.assert_called_once()


def test_gopay_checkout_preserves_method_from_creation_response() -> None:
    creation = {
        "custom_payment_methods": [
            {"id": "cpmt_card", "name": "Card"},
            {"id": "cpmt_gopay", "name": "GoPay"},
        ],
    }
    refreshed = {
        "amount_total": 0,
        "currency": "IDR",
        "custom_payment_methods": [{"id": "cpmt_card", "name": "Card"}],
    }
    with patch.object(
        checkout_app,
        "fetch_custom_checkout_session",
        return_value=refreshed,
    ) as fetch:
        result = checkout_app.fetch_custom_checkout_session_with_retry(
            object(), "token", "oaics_test", "openai_ie", "device",
            attempts=3,
            required_provider="gopay",
            preserve_payment_methods_from=creation,
        )

    fetch.assert_called_once()
    assert checkout_app.custom_payment_method_id_for(result, "gopay") == "cpmt_gopay"
    assert result["amount_total"] == 0


def test_gopay_checkout_payload_delays_promo_until_method_is_published() -> None:
    options = {
        "plan": "plus",
        "link_type": "gopay",
        "country": "ID",
        "currency": "IDR",
        "checkout_country": "ID",
        "checkout_currency": "IDR",
        "use_promo": True,
        "promo_campaign": "plus-1-month-free",
        "promo_on_create": False,
        "checkout_ui_mode": "redirect",
    }
    payload = checkout_app.checkout_payload(options, {})
    assert "promo_campaign" not in payload
    assert payload["checkout_ui_mode"] == "redirect"


def test_gopay_cs_live_creation_rebuilds_oaics_with_fresh_identity() -> None:
    closed: list[str] = []

    class FakeHttp:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            closed.append(self.name)

    responses = [
        {"data": {"checkout_session_id": "oaics_first"}, "http": FakeHttp("first")},
        {"data": {"checkout_session_id": "oaics_second"}, "http": FakeHttp("second")},
        {"data": {"checkout_session_id": "cs_live_success"}, "http": FakeHttp("success")},
    ]
    calls: list[tuple[str, str, bool]] = []

    def fake_create(_token, _payload, _proxy, device_id, did, _log, **kwargs):
        calls.append((device_id, did, bool(kwargs.get("allow_sentinel_fallback"))))
        return responses.pop(0)

    generated_ids = iter(["identity-2", "identity-3"])
    with (
        patch.object(checkout_app, "create_checkout", side_effect=fake_create),
        patch.object(checkout_app.uuid, "uuid4", side_effect=lambda: next(generated_ids)),
    ):
        created, device_id, did = checkout_app.create_gopay_cs_live_checkout(
            "token", {"checkout_ui_mode": "redirect"}, "http://proxy",
            "device-1", "did-1", lambda _message: None, attempts=3,
        )

    assert created["data"]["checkout_session_id"] == "cs_live_success"
    assert (device_id, did) == ("identity-3", "identity-3")
    assert calls == [
        ("device-1", "device-1", False),
        ("identity-2", "identity-2", False),
        ("identity-3", "identity-3", False),
    ]
    assert closed == ["first", "second"]


def test_gopay_merges_checkout_init_and_elements_method_sources() -> None:
    logs: list[str] = []
    stage1 = {
        "custom_payment_methods": [
            {"id": "cpmt_gopay", "name": "GoPay wallet"},
        ],
    }
    ctx = {"payment_method_types": ["card"]}

    def fetch_elements(_http, _pk, _session_id, current, _version, _profile, _log):
        assert current["payment_method_types"] == ["gopay", "card"]
        current["elements_payment_method_types"] = ["card", "gopay"]
        current["payment_method_types"] = ["card", "gopay"]
        return {"payment_method_specs": [{"type": "card"}, {"type": "gopay"}]}

    with patch.object(checkout_app.sc, "fetch_elements_session", side_effect=fetch_elements):
        methods = provider_checkout_module._prepare_gopay_payment_methods(
            object(), "pk_live", "cs_live_test", stage1, ctx, "2026-test", {}, logs.append,
            phase="initial",
        )

    assert methods == ["gopay", "card"]
    assert ctx["payment_method_types"] == ["gopay", "card"]
    assert any("checkout=['gopay']" in message and "elements=['card', 'gopay']" in message for message in logs)


@pytest.mark.parametrize(
    ("response_text", "expected_code"),
    [
        ('{"error":"sentinel proof blocked"}', "SENTINEL_PROOF_REJECTED"),
        ('{"error":"oai-did device mismatch"}', "DEVICE_SESSION_MISMATCH"),
    ],
)
def test_gopay_checkout_classifies_proof_and_identity_rejections(
    response_text: str,
    expected_code: str,
) -> None:
    class FakeResponse:
        status_code = 403
        text = response_text

    class FakeCookies:
        def set(self, *_args, **_kwargs) -> None:
            pass

    class FakeHttp:
        cookies = FakeCookies()

        def get(self, *_args, **_kwargs) -> FakeResponse:
            return FakeResponse()

        def post(self, *_args, **_kwargs) -> FakeResponse:
            return FakeResponse()

    with (
        patch.object(checkout_app.sc, "build_http", return_value=FakeHttp()),
        patch.object(
            checkout_app,
            "resolve_payment_sentinel_headers",
            return_value={"OpenAI-Sentinel-Token": "proof"},
        ),
        pytest.raises(RuntimeError, match=expected_code),
    ):
        checkout_app.create_checkout(
            "token", {}, "http://proxy", "identity", "identity", lambda _message: None,
            diagnostic_label="GoPay",
        )


def test_gopay_cs_live_creation_stops_after_rebuild_budget() -> None:
    class FakeHttp:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    sessions = [FakeHttp(), FakeHttp(), FakeHttp()]
    with patch.object(
        checkout_app,
        "create_checkout",
        side_effect=[
            {"data": {"checkout_session_id": f"oaics_{index}"}, "http": http}
            for index, http in enumerate(sessions)
        ],
    ) as create:
        try:
            checkout_app.create_gopay_cs_live_checkout(
                "token", {"checkout_ui_mode": "redirect"}, "http://proxy",
                "device", "did", lambda _message: None, attempts=3,
            )
        except RuntimeError as exc:
            assert str(exc).startswith("GOPAY_CS_LIVE_REBUILD_EXHAUSTED")
        else:
            raise AssertionError("连续 OAICS 应耗尽 GoPay CS Live 重建预算")

    assert create.call_count == 3
    assert all(http.closed for http in sessions)


def test_gopay_cs_live_creation_defaults_to_ten_rebuilds() -> None:
    class FakeHttp:
        def close(self) -> None:
            pass

    responses = [
        {"data": {"checkout_session_id": f"oaics_{index}"}, "http": FakeHttp()}
        for index in range(9)
    ]
    responses.append({"data": {"checkout_session_id": "cs_live_tenth"}, "http": FakeHttp()})
    with patch.object(checkout_app, "create_checkout", side_effect=responses) as create:
        created, _device_id, _did = checkout_app.create_gopay_cs_live_checkout(
            "token", {"checkout_ui_mode": "redirect"}, "http://proxy",
            "device", "did", lambda _message: None,
        )

    assert created["data"]["checkout_session_id"] == "cs_live_tenth"
    assert create.call_count == 10


def test_gopay_blocked_approval_rebuilds_inside_one_outer_attempt() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    calls = 0
    strategies: list[tuple[bool, str]] = []
    routes: list[tuple[str, str]] = []
    logs: list[str] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, message: logs.append(message)
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        nonlocal calls
        calls += 1
        strategies.append((
            bool(attempt_options["promo_on_create"]),
            str(attempt_options["checkout_ui_mode"]),
        ))
        routes.append((
            str(attempt_options["fixed_entry_proxy"]),
            str(attempt_options["fixed_exit_proxy"]),
        ))
        if calls >= 2:
            state.update(status="done", result={})
        else:
            state.update(
                status="error",
                error="GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED: rebuild current checkout",
            )

    store._run_single = run_single
    with patch.object(checkout_app.time, "sleep"):
        store._run_locked("job-gopay", {
            "retry_count": 0,
            "link_type": "gopay",
            "use_promo": True,
            "country": "ID",
            "checkout_country": "ID",
            "entry_proxies": ["http://promotion-1:8001"],
            "exit_proxies": ["http://checkout-1:9001"],
            "paired_proxy_rotation": True,
        })

    assert strategies == [(False, "redirect")] * 2
    assert routes == [("http://promotion-1:8001", "http://checkout-1:9001")] * 2
    assert state["result"] == {"attempt": 1, "max_attempts": 1}
    assert any("重建完整链路 2/10" in message for message in logs)


def test_gopay_ten_blocked_chains_consume_one_outer_attempt() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    routes: list[tuple[str, str]] = []
    logs: list[str] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, message: logs.append(message)
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        routes.append((
            str(attempt_options["fixed_entry_proxy"]),
            str(attempt_options["fixed_exit_proxy"]),
        ))
        if len(routes) >= 11:
            state.update(status="done", result={})
        else:
            state.update(
                status="error",
                error="GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED: rebuild current checkout",
            )

    store._run_single = run_single
    with patch.object(checkout_app.time, "sleep"):
        store._run_locked("job-gopay", {
            "retry_count": 1,
            "link_type": "gopay",
            "use_promo": True,
            "country": "ID",
            "checkout_country": "ID",
            "entry_proxies": ["http://promotion-1:8001", "http://promotion-2:8002"],
            "exit_proxies": ["http://checkout-1:9001", "http://checkout-2:9002"],
            "paired_proxy_rotation": True,
        })

    assert routes[:10] == [("http://promotion-1:8001", "http://checkout-1:9001")] * 10
    assert routes[10:] == [("http://promotion-2:8002", "http://checkout-2:9002")]
    assert state["result"] == {"attempt": 2, "max_attempts": 2}
    assert any("顺序创建并尝试的 10 个 CS Live 均被 blocked" in message for message in logs)
    assert any("下一次账户任务将更换代理" in message for message in logs)


def test_gopay_defaults_use_indonesia_billing() -> None:
    assert PROVIDER_DEFAULTS["gopay"] == {"country": "ID", "currency": "IDR"}
    billing = default_billing("ID", "user@example.com")
    assert billing["email"] == "user@example.com"
    assert billing["address"]["country"] == "ID"
    assert billing["address"]["city"] == "Jakarta"
    assert billing["address"]["postal_code"] == "10310"


@pytest.mark.parametrize("amount", [0, 1, 49, "1", "49.0"])
def test_gopay_promo_amount_accepts_idr_below_fifty(amount) -> None:
    assert is_gopay_promo_amount(amount, "IDR")


@pytest.mark.parametrize("amount", [50, 51, -1, None, "", "unknown", True])
def test_gopay_promo_amount_rejects_invalid_or_out_of_range_values(amount) -> None:
    assert not is_gopay_promo_amount(amount, "IDR")


def test_gopay_promo_amount_rejects_non_idr_currency() -> None:
    assert not is_gopay_promo_amount(1, "USD")


def test_gopay_cs_live_accepts_one_idr_without_reapplying_promo() -> None:
    logs: list[str] = []
    promo_calls: list[str] = []
    ctx = {
        "checkout_amount": 1,
        "currency": "idr",
        "payment_method_types": ["card", "gopay"],
    }
    confirmation = {
        "next_action": {
            "type": "redirect_to_url",
            "redirect_to_url": {"url": MIDTRANS_V4_LINKING},
        },
    }
    billing = default_billing("ID", "user@example.com")

    with (
        patch.object(checkout_app.sc, "init_checkout", return_value=({}, "2026-test", ctx)),
        patch.object(checkout_app.sc, "fetch_elements_session"),
        patch.object(checkout_app.sc, "update_tax_region"),
        patch.object(checkout_app.sc, "snapshot_billing"),
        patch("provider_checkout.confirm_provider_payment", return_value=confirmation),
    ):
        result = stripe_to_provider(
            object(),
            "cs_live_test",
            "gopay",
            billing=billing,
            country="ID",
            stage1={"publishable_key": "pk_live_test", "processor_entity": "openai_llc"},
            apply_promo_callback=promo_calls.append,
            require_zero_due=True,
            log=logs.append,
        )

    assert promo_calls == []
    assert result["provider_redirect_url"] == MIDTRANS_V4_LINKING
    assert result["checkout_amount"] == 1
    assert result["checkout_currency"] == "IDR"
    assert result["promo_applied"] is True
    assert any("小于 50 IDR" in message for message in logs)


def test_gopay_cs_live_rejects_fifty_idr_after_promo_refresh() -> None:
    ctx = {
        "checkout_amount": 50,
        "currency": "idr",
        "payment_method_types": ["card", "gopay"],
    }
    billing = default_billing("ID", "user@example.com")

    with (
        patch.object(checkout_app.sc, "init_checkout", return_value=({}, "2026-test", ctx)),
        patch.object(checkout_app.sc, "fetch_elements_session"),
        patch.object(checkout_app.sc, "update_tax_region"),
        patch.object(checkout_app.sc, "snapshot_billing"),
        pytest.raises(RuntimeError, match="GOPAY_PROMO_AMOUNT_REQUIRED"),
    ):
        stripe_to_provider(
            object(),
            "cs_live_test",
            "gopay",
            billing=billing,
            country="ID",
            stage1={"publishable_key": "pk_live_test", "processor_entity": "openai_llc"},
            apply_promo_callback=lambda _processor: None,
            require_zero_due=True,
            log=lambda _message: None,
        )
