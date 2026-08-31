from __future__ import annotations

import asyncio
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


def bound_gopay_context(
    http: object,
    proxy: str = "http://proxy",
) -> checkout_app.CheckoutClientContext:
    return checkout_app.CheckoutClientContext(
        payment_provider="gopay",
        device_id="device",
        did="device",
        user_agent="Mozilla/5.0 test-agent",
        proxy_route=proxy,
        session_owner=f"checkout-http:{id(http)}",
        cookies={"oai-did": "device"},
    )


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


@pytest.mark.parametrize(
    "candidate",
    [
        "https://checkout.stripe.com.evil.example/c/pay/cs_live_expected",
        "https://checkout.stripe.com/c/pay/cs_live_stale",
        "http://checkout.stripe.com/c/pay/cs_live_expected",
    ],
)
def test_hosted_checkout_url_rebuilds_untrusted_or_cross_session_urls(
    candidate: str,
) -> None:
    assert checkout_app.normalize_hosted_checkout_url(
        candidate,
        "cs_live_expected",
    ) == "https://pay.openai.com/c/pay/cs_live_expected"


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
    http = object()
    context = bound_gopay_context(http)
    with patch.object(
        checkout_app,
        "approve_checkout",
        side_effect=checkout_app.CheckoutApprovalBlockedError(
            "MANUAL_APPROVAL_BLOCKED: result=blocked"
        ),
    ) as approve:
        with pytest.raises(RuntimeError, match="GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED"):
            checkout_app.approve_gopay_checkout_or_rebuild(
                "token", "cs_live_test", "openai_ie", "http://proxy", "device", "device",
                http=http,
                client_context=context,
                log=logs.append,
                allow_sentinel_fallback=True,
            )

    approve.assert_called_once()
    assert approve.call_args.kwargs["allow_sentinel_fallback"] is False
    assert any("停止复用并重建完整支付提链" in message for message in logs)


def test_gopay_approval_does_not_retry_non_blocked_errors() -> None:
    http = object()
    context = bound_gopay_context(http)
    with patch.object(
        checkout_app,
        "approve_checkout",
        side_effect=RuntimeError("Checkout approve HTTP 400"),
    ) as approve:
        try:
            checkout_app.approve_gopay_checkout_or_rebuild(
                "token", "cs_live_test", "openai_ie", "http://proxy", "device", "device",
                http=http,
                client_context=context,
                log=lambda _message: None,
            )
        except RuntimeError as exc:
            assert "HTTP 400" in str(exc)
        else:
            raise AssertionError("非 blocked approval 错误不应重试")
    assert approve.call_count == 1


def test_gopay_approval_success_returns_after_one_submission() -> None:
    http = object()
    context = bound_gopay_context(http)
    with patch.object(checkout_app, "approve_checkout", return_value={"result": "approved"}) as approve:
        result = checkout_app.approve_gopay_checkout_or_rebuild(
            "token", "cs_live_test", "openai_ie", "http://proxy", "device", "device",
            http=http,
            client_context=context,
            log=lambda _message: None,
        )

    assert result == {"result": "approved"}
    approve.assert_called_once()


@pytest.mark.parametrize("missing", ["context", "http"])
def test_gopay_approval_fails_closed_without_creation_context_or_session(
    missing: str,
) -> None:
    http = object()
    context = bound_gopay_context(http)
    kwargs = {"http": http, "client_context": context}
    kwargs.pop("client_context" if missing == "context" else "http")

    with pytest.raises(checkout_app.PaymentFlowError) as caught:
        checkout_app.approve_gopay_checkout_or_rebuild(
            "token",
            "cs_live_test",
            "openai_ie",
            "http://proxy",
            "device",
            "device",
            **kwargs,
        )

    assert caught.value.code == "CHECKOUT_CLIENT_CONTEXT_REQUIRED"


def test_gopay_proof_options_cannot_disable_required_sen_or_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSentinel:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def get_token_pair(self, flow: str, device_id: str):
            return (
                {"p": "proof", "c": "challenge", "id": device_id, "flow": flow},
                {"so": "observer", "c": "challenge", "id": device_id, "flow": flow},
                {},
            )

        async def close(self) -> None:
            pass

    http = object()
    context = bound_gopay_context(http)
    monkeypatch.setattr(checkout_app, "ProxySentinel", FakeSentinel)

    headers = asyncio.run(checkout_app.sentinel_headers(
        context.proxy_route,
        "chatgpt_checkout",
        context.device_id,
        context.did,
        use_sen=False,
        use_so=False,
        client_context=context,
        proof_policy=checkout_app.ProofPolicy.strict_gopay(),
        payment_endpoint=checkout_app.PaymentEndpoint.CHECKOUT_CREATE,
    ))

    assert set(headers) == {
        "OpenAI-Sentinel-Token",
        "OpenAI-Sentinel-SO-Token",
    }


def test_provider_payment_flow_error_is_not_rewrapped() -> None:
    expected = checkout_app.PaymentFlowError(
        "PROOF_BINDING_MISMATCH",
        "provider returned a proof for a different client",
    )

    class FailingProvider:
        name = checkout_app.ProofProviderKind.SUPPORTED_BROWSER.value

        async def issue(self, _request):
            raise expected

    http = object()
    base = bound_gopay_context(http)
    context = checkout_app.CheckoutClientContext(
        payment_provider=base.payment_provider,
        device_id=base.device_id,
        did=base.did,
        user_agent=base.user_agent,
        proxy_route=base.proxy_route,
        session_owner=base.session_owner,
        proof_provider=FailingProvider.name,
        cookies=base.cookies,
        proof_issuer=FailingProvider(),
    )

    with pytest.raises(checkout_app.PaymentFlowError) as caught:
        asyncio.run(checkout_app.sentinel_headers(
            context.proxy_route,
            "chatgpt_checkout",
            context.device_id,
                context.did,
                client_context=context,
                proof_policy=checkout_app.ProofPolicy.strict_gopay(),
                payment_endpoint=checkout_app.PaymentEndpoint.CHECKOUT_CREATE,
            ))

    assert caught.value is expected


def test_gopay_confirm_proof_uses_the_confirm_endpoint_contract() -> None:
    captured = []

    class RecordingProvider:
        name = checkout_app.ProofProviderKind.SUPPORTED_BROWSER.value

        async def issue(self, request):
            captured.append(request)
            return checkout_app.ProofBundle(
                endpoint=request.endpoint,
                flow=request.flow,
                payment_provider=request.payment_provider,
                proof_provider=request.proof_provider,
                device_id=request.device_id,
                did=request.did,
                user_agent=request.user_agent,
                proxy_route=request.proxy_route,
                session_owner=request.session_owner,
                cookie_identity=request.cookie_identity,
                headers={
                    "OpenAI-Sentinel-Token": (
                        '{"p":"proof","id":"device",'
                        '"flow":"checkout_session_approval"}'
                    ),
                },
            )

    http = object()
    context = checkout_app.CheckoutClientContext(
        payment_provider="gopay",
        device_id="device",
        did="device",
        user_agent="Mozilla/5.0 test-agent",
        proxy_route="http://proxy",
        session_owner=f"checkout-http:{id(http)}",
        proof_provider=RecordingProvider.name,
        cookies={"oai-did": "device"},
        proof_issuer=RecordingProvider(),
    )

    asyncio.run(checkout_app.sentinel_headers(
        context.proxy_route,
        "checkout_session_approval",
        context.device_id,
        context.did,
        client_context=context,
        proof_policy=checkout_app.ProofPolicy.strict_gopay(),
        payment_endpoint=checkout_app.PaymentEndpoint.CHECKOUT_CONFIRM,
    ))

    assert len(captured) == 1
    assert captured[0].endpoint is checkout_app.PaymentEndpoint.CHECKOUT_CONFIRM
    assert captured[0].flow is checkout_app.SentinelFlow.CHECKOUT_SESSION_APPROVAL


def test_gopay_proof_rejects_endpoint_flow_mismatch() -> None:
    http = object()
    context = bound_gopay_context(http)

    with pytest.raises(checkout_app.PaymentFlowError) as caught:
        asyncio.run(checkout_app.sentinel_headers(
            context.proxy_route,
            "chatgpt_checkout",
            context.device_id,
            context.did,
            client_context=context,
            proof_policy=checkout_app.ProofPolicy.strict_gopay(),
            payment_endpoint=checkout_app.PaymentEndpoint.CHECKOUT_CONFIRM,
        ))

    assert caught.value.code == "ENDPOINT_FLOW_MISMATCH"


def test_gopay_proof_requires_explicit_endpoint() -> None:
    http = object()
    context = bound_gopay_context(http)

    with pytest.raises(checkout_app.PaymentFlowError) as caught:
        asyncio.run(checkout_app.sentinel_headers(
            context.proxy_route,
            "chatgpt_checkout",
            context.device_id,
            context.did,
            client_context=context,
            proof_policy=checkout_app.ProofPolicy.strict_gopay(),
        ))

    assert caught.value.code == "PAYMENT_ENDPOINT_REQUIRED"


def test_gopay_checkout_preserves_method_when_refresh_omits_method_fields() -> None:
    creation = {
        "custom_payment_methods": [
            {"id": "cpmt_card", "name": "Card"},
            {"id": "cpmt_gopay", "name": "GoPay"},
        ],
    }
    refreshed = {
        "amount_total": 0,
        "currency": "IDR",
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


def test_gopay_checkout_does_not_revive_stale_method_from_explicit_snapshot() -> None:
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
            attempts=1,
            required_provider="gopay",
            preserve_payment_methods_from=creation,
        )

    fetch.assert_called_once()
    assert checkout_app.custom_payment_methods_for(result, "gopay") == []
    assert checkout_app.custom_payment_method_id_for(result, "gopay") == ""
    assert result["custom_payment_methods"] == refreshed["custom_payment_methods"]


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


def test_gopay_checkout_payload_uses_verified_query_coupon_on_create() -> None:
    options = {
        "plan": "plus",
        "link_type": "gopay",
        "country": "ID",
        "currency": "IDR",
        "checkout_country": "ID",
        "checkout_currency": "IDR",
        "use_promo": True,
        "promo_campaign": "plus-1-month-free",
        "promo_on_create": True,
        "promo_from_query_param": True,
        "checkout_ui_mode": "redirect",
    }

    payload = checkout_app.checkout_payload(options, {})

    assert payload["promo_campaign"] == {
        "promo_campaign_id": "plus-1-month-free",
        "is_coupon_from_query_param": True,
    }


def test_gopay_preflight_falls_back_to_account_management_coupon_protocol() -> None:
    calls: list[tuple[str, dict]] = []

    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.status_code = 200
            self._payload = payload

        def json(self) -> dict:
            return self._payload

    class FakeCookies:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}

        def set(self, name: str, value: str, **_kwargs) -> None:
            self.values[name] = value

        def get_dict(self) -> dict[str, str]:
            return dict(self.values)

    class FakeHttp:
        cookies = FakeCookies()
        closed = False

        def get(self, url: str, **kwargs):
            calls.append((url, kwargs))
            if "accounts/check" in url:
                return FakeResponse({
                    "accounts": {
                        "account-1": {"eligible_promo_campaigns": {}},
                    },
                })
            return FakeResponse({"state": "eligible"})

        def close(self) -> None:
            self.closed = True

    http = FakeHttp()
    logs: list[str] = []
    with (
        patch.dict("os.environ", {"PAY153_RUST_URL": ""}),
        patch.object(checkout_app.sc, "build_http", return_value=http),
    ):
        result = checkout_app.preflight_trial_eligibility(
            "token", "account-1", "http://id-proxy", "identity", "identity", logs.append,
            coupon_fallback=True,
        )

    assert result["one_click_trial_eligible"] is True
    assert result["promo_campaign_id"] == "plus-1-month-free"
    assert result["promotion_source"] == "coupon_check"
    assert result["is_coupon_from_query_param"] is True
    assert calls[1][1]["params"]["is_coupon_from_query_param"] == "true"
    assert calls[1][1]["headers"]["OAI-Device-Id"] == "identity"
    assert http.closed is True
    assert any("state=eligible" in message for message in logs)


def test_gopay_promo_update_submits_query_coupon_semantics() -> None:
    captured: dict = {}

    class FakeResponse:
        status_code = 200
        text = '{"success":true}'

        def json(self) -> dict:
            return {"success": True}

    class FakeHttp:
        def post(self, _url: str, **kwargs) -> FakeResponse:
            captured.update(kwargs)
            return FakeResponse()

    result = checkout_app.update_checkout_promo(
        FakeHttp(), "token", "cs_live_test", "openai_llc", "plus-1-month-free",
        lambda _message: None,
        device_id="identity",
        is_coupon_from_query_param=True,
    )

    assert result == {"success": True}
    assert captured["json"]["promo_campaign"] == {
        "promo_campaign_id": "plus-1-month-free",
        "is_coupon_from_query_param": True,
    }


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


def test_gopay_initial_missing_current_method_fields_falls_back_to_stage1() -> None:
    stage1 = {
        "custom_payment_methods": [
            {"id": "cpmt_gopay", "name": "GoPay wallet"},
        ],
    }
    ctx = {"payment_method_types": []}

    def fetch_elements(_http, _pk, _session_id, current, _version, _profile, _log):
        assert current["payment_method_types"] == ["gopay"]
        return {"session_id": "elements_without_method_fields"}

    with patch.object(checkout_app.sc, "fetch_elements_session", side_effect=fetch_elements):
        methods = provider_checkout_module._prepare_gopay_payment_methods(
            object(), "pk_live", "cs_live_test", stage1, ctx, "2026-test", {},
            lambda _message: None,
            phase="initial",
            init_payload={
                "currency": "idr",
                "customer": {"payment_methods": [{"type": "card", "id": "pm_saved"}]},
            },
        )

    assert methods == ["gopay"]


@pytest.mark.parametrize("phase", ["initial", "post_promo", "post_taxes"])
def test_gopay_current_explicit_empty_methods_do_not_revive_stage1(phase: str) -> None:
    stage1 = {
        "payment_method_types": ["card", "gopay"],
    }
    ctx = {"payment_method_types": ["card", "gopay"]}

    with patch.object(
        checkout_app.sc,
        "fetch_elements_session",
        return_value={"payment_method_specs": []},
    ):
        methods = provider_checkout_module._prepare_gopay_payment_methods(
            object(), "pk_live", "cs_live_test", stage1, ctx, "2026-test", {},
            lambda _message: None,
            phase=phase,
            init_payload={"payment_method_types": ["card", "gopay"]},
        )

    assert methods == []
    assert ctx["payment_method_types"] == []


def test_gopay_post_taxes_explicit_current_list_without_gopay_wins() -> None:
    stage1 = {"payment_method_types": ["card", "gopay"]}
    ctx = {"payment_method_types": ["card"]}

    with patch.object(
        checkout_app.sc,
        "fetch_elements_session",
        return_value={"session_id": "elements_without_method_fields"},
    ):
        methods = provider_checkout_module._prepare_gopay_payment_methods(
            object(), "pk_live", "cs_live_test", stage1, ctx, "2026-test", {},
            lambda _message: None,
            phase="post_taxes",
            init_payload={"payment_method_types": ["card"]},
        )

    assert methods == ["card"]


def test_gopay_method_normalization_excludes_disabled_and_unavailable_entries() -> None:
    payload = {
        "custom_payment_methods": [
            {"type": "gopay", "enabled": False},
            {"type": "gopay", "available": "false"},
            {"name": "GoPay", "status": "disabled"},
            {"label": "GoPay unavailable"},
            {"type": "card", "available": True, "status": "available"},
            {"type": "link", "enabled": "true"},
        ],
        "available_payment_methods": {
            "gopay": {"availability": "unavailable_by_country"},
            "card": {"available": True},
        },
    }

    methods = provider_checkout_module._published_payment_method_types(payload)

    assert methods == ["card", "link"]
    assert "gopay" not in methods


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"paymentMethodTypes": ["card", "gopay"]}, ["card", "gopay"]),
        ({"customPaymentMethods": [{"type": "gopay"}]}, ["gopay"]),
        ({"checkoutSession": {"paymentMethodTypes": ["gopay"]}}, ["gopay"]),
        ({"legacyCustomer": {"paymentMethods": [{"type": "gopay"}]}}, []),
        ({"checkoutCustomer": {"paymentMethods": [{"type": "gopay"}]}}, []),
        (
            {"payment_method_types": [], "paymentMethodTypes": ["gopay"]},
            ["gopay"],
        ),
    ],
)
def test_gopay_method_snapshot_handles_camel_case_and_saved_method_boundaries(
    payload: dict,
    expected: list[str],
) -> None:
    assert provider_checkout_module._published_payment_method_types(payload) == expected


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {
                "payment_method_types": ["card"],
                "history": [{"payment_method_types": ["card", "gopay"]}],
            },
            (["card"], True),
        ),
        (
            {
                "payment_method_types": [],
                "previous": {"payment_method_types": ["gopay"]},
            },
            ([], True),
        ),
        (
            {
                "checkout_session": {"payment_method_types": []},
                "previous_checkout_session": {
                    "payment_method_types": ["gopay"],
                },
            },
            ([], True),
        ),
        (
            {
                "data": {
                    "checkout_session": {"payment_method_types": ["card"]},
                },
                "history": {"payment_method_types": ["gopay"]},
            },
            (["card"], True),
        ),
    ],
)
def test_gopay_current_snapshot_overrides_stale_nested_methods(
    payload: dict,
    expected: tuple[list[str], bool],
) -> None:
    assert provider_checkout_module.published_payment_method_snapshot(payload) == expected


def test_gopay_snapshot_uses_stale_data_only_when_current_fields_are_missing() -> None:
    payload = {
        "checkout_session": {"currency": "idr", "amount_total": 0},
        "previous": {"payment_method_types": ["card", "gopay"]},
    }

    assert provider_checkout_module.published_payment_method_snapshot(payload) == (
        ["card", "gopay"],
        True,
    )


@pytest.mark.parametrize(
    ("scenario", "expected_code", "expected_phase"),
    [
        ("initial", "GOPAY_METHOD_UNAVAILABLE", "checkout"),
        ("post_promo", "GOPAY_PROMO_METHOD_INCOMPATIBLE", "promotion"),
        ("post_taxes", "GOPAY_METHOD_UNAVAILABLE_AFTER_TAXES", "taxes"),
        ("amount", "GOPAY_PROMO_AMOUNT_REQUIRED", "promotion"),
    ],
)
def test_gopay_provider_failures_expose_structured_retry_metadata(
    scenario: str,
    expected_code: str,
    expected_phase: str,
) -> None:
    methods_by_scenario = {
        "initial": [[]],
        "post_promo": [["gopay"], []],
        "post_taxes": [["gopay"], []],
        "amount": [["gopay"], ["gopay"]],
    }
    init_responses = [
        (
            {"return_url": ""},
            "2026-test",
            {"checkout_amount": 100, "currency": "idr"},
        ),
        (
            {"return_url": ""},
            "2026-test",
            {"checkout_amount": 100, "currency": "idr"},
        ),
    ]
    apply_promo = (lambda _processor: None) if scenario == "post_promo" else None

    with (
        patch.object(provider_checkout_module.sc, "_profile", return_value={}),
        patch.object(
            provider_checkout_module.sc,
            "init_checkout",
            side_effect=init_responses,
        ),
        patch.object(provider_checkout_module.sc, "update_tax_region"),
        patch.object(
            provider_checkout_module,
            "_prepare_gopay_payment_methods",
            side_effect=methods_by_scenario[scenario],
        ),
        pytest.raises(provider_checkout_module.PaymentFlowError) as caught,
    ):
        stripe_to_provider(
            object(),
            "cs_live_fixture",
            "gopay",
            billing={"address": {"country": "ID"}},
            country="ID",
            stage1={
                "publishable_key": "pk_live_fixture",
                "processor_entity": "openai_llc",
            },
            apply_promo_callback=apply_promo,
            require_zero_due=scenario == "amount",
        )

    error = caught.value
    assert error.code == expected_code
    assert error.phase == expected_phase
    assert error.http_status is None
    assert error.retryable is True
    assert error.rebuild_checkout is True


def test_gopay_method_snapshot_treats_null_container_as_missing() -> None:
    for malformed in (None, "", "gopay"):
        snapshot = provider_checkout_module._published_payment_method_snapshot({
            "paymentMethodTypes": malformed,
        })
        assert snapshot == ([], False)


@pytest.mark.parametrize(
    "status",
    ["not_enabled", "not_eligible", "removed", "deprecated"],
)
def test_gopay_method_snapshot_rejects_explicit_unavailable_status(status: str) -> None:
    methods = provider_checkout_module._published_payment_method_types({
        "paymentMethodTypes": [{"type": "gopay", "status": status}],
    })

    assert methods == []


@pytest.mark.parametrize(
    "availability",
    [
        {"availability": False},
        {"eligible": False},
        {"isEligible": False},
        {"supported": "false"},
    ],
)
def test_gopay_method_snapshot_rejects_false_availability_flags(
    availability: dict,
) -> None:
    methods = provider_checkout_module._published_payment_method_types({
        "availablePaymentMethods": {"gopay": availability},
    })

    assert methods == []


def test_gopay_method_snapshot_handles_boolean_availability_map() -> None:
    methods = provider_checkout_module._published_payment_method_types({
        "availablePaymentMethods": {
            "gopay": False,
            "card": True,
            "link": {"eligible": False},
        },
    })

    assert methods == ["card"]


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "gopay", "blocked": True},
        {"type": "gopay", "isUnavailable": True},
        {"type": "gopay", "status": "temporarilyUnavailableByCountry"},
        {"type": "gopay", "eligibility": "not_eligible"},
        {"type": "gopay", "provider": {"isAvailable": False}},
    ],
)
def test_gopay_method_snapshot_rejects_negative_entry_markers(entry: dict) -> None:
    assert provider_checkout_module._published_payment_method_types({
        "paymentMethodTypes": [entry],
    }) == []


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
        def __init__(self) -> None:
            self.values: dict[str, str] = {}

        def set(self, name: str, value: str, **_kwargs) -> None:
            self.values[name] = value

        def get_dict(self) -> dict[str, str]:
            return dict(self.values)

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
                payment_error={
                    "code": "GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED",
                    "retryable": True,
                    "rebuild_checkout": True,
                },
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


def test_gopay_retries_unchanged_amount_with_coupon_on_checkout_create() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    strategies: list[tuple[bool, bool]] = []
    logs: list[str] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, message: logs.append(message)
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        strategies.append((
            bool(attempt_options["promo_on_create"]),
            bool(attempt_options["promo_from_query_param"]),
        ))
        if len(strategies) == 1:
            state.update(
                status="error",
                error="GOPAY_PROMO_AMOUNT_REQUIRED: amount=34900000 currency=IDR",
            )
        else:
            state.update(status="done", result={})

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

    assert strategies == [(False, True), (True, True)]
    assert state["result"] == {"attempt": 2, "max_attempts": 2}
    assert any("确认 GoPay 后" in message for message in logs)
    assert any("Checkout 创建时携带" in message for message in logs)


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
                payment_error={
                    "code": "GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED",
                    "retryable": True,
                    "rebuild_checkout": True,
                },
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
        pytest.raises(RuntimeError, match="GOPAY_PROMO_ACCEPTED_WITHOUT_DISCOUNT"),
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
