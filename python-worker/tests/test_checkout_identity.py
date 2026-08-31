from __future__ import annotations

import sys
from pathlib import Path

import pytest


PAY153_DIR = Path(__file__).parents[1] / "tools" / "pay153_checkout"
if str(PAY153_DIR) not in sys.path:
    sys.path.insert(0, str(PAY153_DIR))

from checkout_identity import (  # noqa: E402
    CheckoutSessionIdentityConflictError,
    classify_checkout_session_identity,
)


def test_checkout_identity_prefers_explicit_id_over_lower_priority_evidence() -> None:
    result = classify_checkout_session_identity({
        "checkoutSessionId": "oaics_primary",
        "url": "https://pay.openai.com/c/pay/cs_live_url",
        "diagnostic": "previous cs_live_text",
    })

    assert result is not None
    assert (result.session_id, result.kind, result.source) == (
        "oaics_primary",
        "oaics",
        "explicit_id",
    )
    assert result.checkout_session_id == result.session_id == "oaics_primary"


def test_checkout_identity_prefers_trusted_url_over_full_text_noise() -> None:
    result = classify_checkout_session_identity({
        "checkoutUrl": "https://chatgpt.com/checkout/openai_ie/oaics_current",
        "message": "previous cs_live_old",
    })

    assert result is not None
    assert (result.session_id, result.kind, result.source) == (
        "oaics_current",
        "oaics",
        "trusted_url",
    )


def test_checkout_identity_accepts_encoded_trusted_url() -> None:
    result = classify_checkout_session_identity({
        "redirectUrl": "https%3A%2F%2Fpay.openai.com%2Fc%2Fpay%2Fcs_live_encoded"
    })

    assert result is not None
    assert result.session_id == "cs_live_encoded"
    assert result.source == "trusted_url"


def test_checkout_identity_ignores_response_text_candidate() -> None:
    assert classify_checkout_session_identity(
        {"message": "Checkout created"},
        "response contains cs_test_only",
    ) is None


def test_checkout_identity_rejects_conflicting_explicit_ids() -> None:
    with pytest.raises(CheckoutSessionIdentityConflictError) as raised:
        classify_checkout_session_identity({
            "checkout_session_id": "oaics_primary",
            "checkoutSessionId": "cs_live_other",
        })

    assert raised.value.source == "explicit_id"
    assert raised.value.candidates == ("cs_live_other", "oaics_primary")
    assert str(raised.value).startswith("CHECKOUT_SESSION_ID_CONFLICT")


def test_checkout_identity_rejects_conflicting_trusted_urls() -> None:
    with pytest.raises(CheckoutSessionIdentityConflictError) as raised:
        classify_checkout_session_identity({
            "checkout_url": "https://pay.openai.com/c/pay/cs_live_primary",
            "sourceCheckoutUrl": "https://chatgpt.com/checkout/openai_ie/oaics_other",
        })

    assert raised.value.source == "trusted_url"
    assert raised.value.candidates == ("cs_live_primary", "oaics_other")


def test_checkout_identity_ignores_diagnostic_text_candidates() -> None:
    assert classify_checkout_session_identity({
        "message": "created oaics_first after cs_live_previous",
        "diagnostic": {"detail": "last checkout was cs_test_stale"},
    }) is None


def test_checkout_identity_does_not_treat_untrusted_url_as_trusted_evidence() -> None:
    assert classify_checkout_session_identity({
        "url": "https://checkout.stripe.com.evil.example/c/pay/cs_live_fake",
    }) is None


@pytest.mark.parametrize("url", [
    "https://pay.openai.com.evil.example/c/pay/cs_live_fake",
    "https://checkout-stripe.com/c/pay/cs_live_fake",
    "https://checkout.stripe.com@evil.example/c/pay/cs_live_fake",
    "https://checkout.stripe.com:444/c/pay/cs_live_fake",
])
def test_checkout_identity_rejects_lookalike_or_noncanonical_checkout_url(
    url: str,
) -> None:
    assert classify_checkout_session_identity({"checkout_url": url}) is None


def test_checkout_identity_ignores_generic_id_even_when_checkout_shaped() -> None:
    assert classify_checkout_session_identity({
        "diagnostic": {"id": "cs_live_untrusted"},
    }) is None


def test_checkout_identity_ignores_malformed_trusted_url() -> None:
    assert classify_checkout_session_identity({"checkout_url": "https://[invalid"}) is None


def test_checkout_identity_returns_none_without_a_candidate() -> None:
    assert classify_checkout_session_identity({"message": "Checkout created"}) is None
