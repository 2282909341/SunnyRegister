from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

# Keep this test runnable both from ``python-worker`` and the repository root.
WORKER_DIR = Path(__file__).parents[1]
PAY153_DIR = WORKER_DIR / "tools" / "pay153_checkout"
for import_path in (WORKER_DIR, PAY153_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from tools.pay153_checkout.payment_proof_contracts import (
    CheckoutClientContext,
    PaymentEndpoint,
    PaymentFlowError,
    ProofBundle,
    ProofPolicy,
    ProofProviderKind,
    ProofRequest,
    SentinelFlow,
    SentinelProofProvider,
    flow_for_endpoint,
    render_payment_diagnostic_event,
)


def client_context() -> CheckoutClientContext:
    return CheckoutClientContext(
        payment_provider="GoPay",
        device_id="device-123",
        did="device-123",
        user_agent="Mozilla/5.0 test-agent",
        proxy_route="id-checkout-route",
        session_owner="checkout-session-owner-1",
        proof_provider=ProofProviderKind.SUPPORTED_BROWSER.value,
        cookies={"oai-did": "device-123"},
    )


def proof_bundle(
    request: ProofRequest,
    *,
    proof_provider: str = ProofProviderKind.SUPPORTED_BROWSER.value,
    sentinel: bool = True,
    observer: bool = True,
    turnstile_required: bool = False,
    session_observer_required: bool = False,
) -> ProofBundle:
    headers: dict[str, str] = {}
    if sentinel:
        headers["OpenAI-Sentinel-Token"] = json.dumps({
            "p": "proof",
            "t": "turnstile" if turnstile_required else "",
            "c": "challenge",
            "id": request.device_id,
            "flow": request.flow.value,
        })
    if observer:
        headers["openai-sentinel-so-token"] = json.dumps({
            "so": "observer",
            "c": "challenge",
            "id": request.device_id,
            "flow": request.flow.value,
        })
    return ProofBundle(
        endpoint=request.endpoint,
        flow=request.flow,
        payment_provider=request.payment_provider,
        proof_provider=proof_provider,
        device_id=request.device_id,
        did=request.did,
        user_agent=request.user_agent,
        proxy_route=request.proxy_route,
        session_owner=request.session_owner,
        headers=headers,
        turnstile_required=turnstile_required,
        session_observer_required=session_observer_required,
        cookie_identity=request.cookie_identity,
    )


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (PaymentEndpoint.CHECKOUT_CREATE, SentinelFlow.CHATGPT_CHECKOUT),
        (PaymentEndpoint.CHECKOUT_CONFIRM, SentinelFlow.CHECKOUT_SESSION_APPROVAL),
        (PaymentEndpoint.CHECKOUT_APPROVE, SentinelFlow.CHECKOUT_SESSION_APPROVAL),
        (PaymentEndpoint.SENTINEL_PING, SentinelFlow.CHECKOUT_SESSION_APPROVAL),
        (
            "https://chatgpt.com/backend-api/payments/checkout?source=test",
            SentinelFlow.CHATGPT_CHECKOUT,
        ),
    ],
)
def test_endpoint_flow_mapping_is_explicit(endpoint, expected: SentinelFlow) -> None:
    assert flow_for_endpoint(endpoint) is expected


def test_unknown_endpoint_and_flow_fail_closed() -> None:
    with pytest.raises(PaymentFlowError) as endpoint_error:
        flow_for_endpoint("/backend-api/payments/checkout/unknown")
    assert endpoint_error.value.code == "UNKNOWN_PAYMENT_ENDPOINT"

    context = client_context()
    with pytest.raises(PaymentFlowError) as flow_error:
        ProofRequest(
            endpoint=PaymentEndpoint.CHECKOUT_CREATE,
            flow="default",
            payment_provider=context.payment_provider,
            device_id=context.device_id,
            did=context.did,
            user_agent=context.user_agent,
            proxy_route=context.proxy_route,
            session_owner=context.session_owner,
        )
    assert flow_error.value.code == "UNKNOWN_SENTINEL_FLOW"


def test_endpoint_rejects_a_valid_but_incorrect_flow() -> None:
    context = client_context()
    with pytest.raises(PaymentFlowError) as caught:
        ProofRequest(
            endpoint=PaymentEndpoint.CHECKOUT_CREATE,
            flow=SentinelFlow.CHECKOUT_SESSION_APPROVAL,
            payment_provider=context.payment_provider,
            device_id=context.device_id,
            did=context.did,
            user_agent=context.user_agent,
            proxy_route=context.proxy_route,
            session_owner=context.session_owner,
        )
    assert caught.value.code == "ENDPOINT_FLOW_MISMATCH"


def test_checkout_context_requires_one_device_identity() -> None:
    with pytest.raises(PaymentFlowError) as caught:
        CheckoutClientContext(
            payment_provider="gopay",
            device_id="device-a",
            did="device-b",
            user_agent="test-agent",
            proxy_route="route",
            session_owner="owner",
        )
    assert caught.value.code == "CLIENT_IDENTITY_MISMATCH"


def test_gopay_checkout_context_requires_cookie_identity() -> None:
    with pytest.raises(PaymentFlowError) as caught:
        CheckoutClientContext(
            payment_provider="gopay",
            device_id="device-a",
            did="device-a",
            user_agent="test-agent",
            proxy_route="route",
            session_owner="owner",
        )
    assert caught.value.code == "CLIENT_COOKIE_IDENTITY_REQUIRED"


def test_checkout_context_builds_bound_request_and_safe_identity_hash() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)

    assert request.flow is SentinelFlow.CHATGPT_CHECKOUT
    assert request.payment_provider == "gopay"
    assert context.identity_hash == client_context().identity_hash
    assert len(context.identity_hash) == 12
    assert context.device_id not in context.identity_hash


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("payment_provider", "paypal"),
        ("user_agent", "different-agent"),
        ("proxy_route", "different-route"),
        ("session_owner", "different-owner"),
    ],
)
def test_checkout_context_rejects_request_binding_changes(
    field_name: str,
    replacement: str,
) -> None:
    context = client_context()
    request = replace(
        context.proof_request(PaymentEndpoint.CHECKOUT_CREATE),
        **{field_name: replacement},
    )

    with pytest.raises(PaymentFlowError) as caught:
        context.validate_request(request)
    assert caught.value.code == "CLIENT_CONTEXT_MISMATCH"
    assert field_name in caught.value.message


def test_strict_gopay_policy_accepts_a_fully_bound_bundle() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)
    bundle = proof_bundle(
        request,
        turnstile_required=True,
        session_observer_required=True,
    )
    policy = ProofPolicy.strict_gopay(
        allowed_proof_providers=frozenset({ProofProviderKind.SUPPORTED_BROWSER.value}),
    )

    assert policy.validate(context, request, bundle) is bundle
    assert bundle.http_headers().keys() == {
        "OpenAI-Sentinel-Token",
        "OpenAI-Sentinel-SO-Token",
    }
    with pytest.raises(TypeError):
        bundle.headers["openai-sentinel-token"] = "changed"  # type: ignore[index]


def test_strict_gopay_policy_never_accepts_an_empty_fallback() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)

    with pytest.raises(PaymentFlowError) as caught:
        ProofPolicy.strict_gopay().validate(context, request, None)
    assert caught.value.code == "SENTINEL_PROOF_REQUIRED"


def test_strict_gopay_policy_rejects_bundle_without_cookie_identity() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)
    bundle = replace(proof_bundle(request), cookie_identity="")

    with pytest.raises(PaymentFlowError) as caught:
        ProofPolicy.strict_gopay().validate(context, request, bundle)
    assert caught.value.code == "CLIENT_CONTEXT_MISMATCH"


@pytest.mark.parametrize(
    ("bundle_kwargs", "expected_code"),
    [
        ({"sentinel": False}, "SENTINEL_PROOF_REQUIRED"),
        (
            {"sentinel": True, "observer": False, "session_observer_required": True},
            "SESSION_OBSERVER_PROOF_REQUIRED",
        ),
    ],
)
def test_strict_policy_rejects_missing_required_proofs(
    bundle_kwargs: dict,
    expected_code: str,
) -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)

    with pytest.raises(PaymentFlowError) as caught:
        ProofPolicy.strict_gopay().validate(
            context,
            request,
            proof_bundle(request, **bundle_kwargs),
        )
    assert caught.value.code == expected_code


def test_strict_policy_rejects_missing_turnstile_proof() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)
    bundle = proof_bundle(request)
    bundle = replace(bundle, turnstile_required=True)

    with pytest.raises(PaymentFlowError) as caught:
        ProofPolicy.strict_gopay().validate(context, request, bundle)
    assert caught.value.code == "TURNSTILE_PROOF_REQUIRED"


@pytest.mark.parametrize("field_name", ["flow", "id"])
def test_strict_policy_rejects_token_binding_mismatch(field_name: str) -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)
    token = {
        "p": "proof",
        "c": "challenge",
        "id": request.device_id,
        "flow": request.flow.value,
    }
    token[field_name] = "wrong-binding"
    bundle = proof_bundle(request)
    bundle = replace(
        bundle,
        headers={
            "openai-sentinel-token": json.dumps(token),
            "openai-sentinel-so-token": bundle.headers["openai-sentinel-so-token"],
        },
    )

    with pytest.raises(PaymentFlowError) as caught:
        ProofPolicy.strict_gopay().validate(context, request, bundle)
    assert caught.value.code == "PROOF_BINDING_MISMATCH"


def test_strict_policy_rejects_disallowed_proof_provider() -> None:
    context = replace(client_context(), proof_provider="legacy_protocol")
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)
    bundle = proof_bundle(request, proof_provider="legacy_protocol")
    policy = ProofPolicy.strict_gopay(
        allowed_proof_providers=frozenset({ProofProviderKind.SUPPORTED_BROWSER.value}),
    )

    with pytest.raises(PaymentFlowError) as caught:
        policy.validate(context, request, bundle)
    assert caught.value.code == "PROOF_PROVIDER_NOT_ALLOWED"


def test_proof_bundle_rejects_non_proof_headers() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)

    with pytest.raises(PaymentFlowError) as caught:
        replace(proof_bundle(request), headers={"Authorization": "secret"})
    assert caught.value.code == "PROOF_HEADER_NOT_ALLOWED"


def test_payment_flow_error_exposes_typed_retry_metadata() -> None:
    error = PaymentFlowError(
        "sentinel transport failed",
        "proof runtime was unavailable",
        retryable=True,
        rebuild_checkout=True,
        http_status=503,
    )

    assert error.as_dict() == {
        "code": "SENTINEL_TRANSPORT_FAILED",
        "message": "proof runtime was unavailable",
        "phase": "proof",
        "retryable": True,
        "rebuild_checkout": True,
        "http_status": 503,
    }


def test_sentinel_provider_protocol_is_async_and_structural() -> None:
    context = client_context()
    request = context.proof_request(PaymentEndpoint.CHECKOUT_CREATE)

    class FakeProvider:
        name = ProofProviderKind.SUPPORTED_BROWSER.value

        async def issue(self, issued_request: ProofRequest) -> ProofBundle:
            return proof_bundle(issued_request)

    provider = FakeProvider()
    assert isinstance(provider, SentinelProofProvider)
    assert asyncio.run(provider.issue(request)).proof_provider == provider.name


def test_payment_diagnostic_event_excludes_credentials_and_proof_material() -> None:
    access_token = "eyJ.secret-access-token"
    cookie_secret = "session-cookie-secret"
    sentinel_token = "sentinel-proof-secret"
    context = replace(
        client_context(),
        proxy_route="socks5h://proxy-user:proxy-password@example.test:1080",
        user_agent="Mozilla/5.0 private-agent-value",
        cookies={"oai-did": "device-123", "session": cookie_secret},
    )
    rendered = render_payment_diagnostic_event(
        context,
        phase="failure",
        flow=SentinelFlow.CHATGPT_CHECKOUT,
        sen_present=True,
        so_present=True,
        checkout_type="cs_live",
        payment_method_source="elements_explicit",
        failure=PaymentFlowError(
            "SENTINEL_REJECTED",
            f"AT={access_token}; cookie={cookie_secret}; token={sentinel_token}",
        ),
        elapsed_ms=12.8,
        proxy_round=2,
    )

    assert access_token not in rendered
    assert cookie_secret not in rendered
    assert sentinel_token not in rendered
    assert "proxy-password" not in rendered
    assert "private-agent-value" not in rendered
    assert context.device_id not in rendered
    assert '"failure_type":"SENTINEL_REJECTED"' in rendered


def test_payment_diagnostic_event_never_derives_failure_type_from_free_text() -> None:
    secret = "eyJ.free-form-secret"
    rendered = render_payment_diagnostic_event(
        client_context(),
        phase="failure",
        failure=f"UPSTREAM_FAILURE_{secret}",
    )

    assert secret not in rendered
    assert '"failure_type":"UNCLASSIFIED"' in rendered
