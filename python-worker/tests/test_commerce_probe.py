from contextlib import nullcontext
from types import ModuleType
from unittest.mock import MagicMock, patch

from sunny_core.commerce_probe import (
    _checkout_probe_options,
    _payment_methods,
    _task_style_checkout_probe,
    probe_commerce,
    probe_payment_methods,
    probe_trial,
)


def response(status: int, payload=None, content_type: str = "application/json"):
    value = MagicMock()
    value.status_code = status
    value.headers = {"content-type": content_type}
    if payload is None:
        value.json.side_effect = ValueError("not json")
    else:
        value.json.return_value = payload
    return value


def test_probe_commerce_parses_trial_checkout_and_payment_methods() -> None:
    session = MagicMock()
    session.get.return_value = response(200, {"state": "eligible"})
    with (
        patch("sunny_core.commerce_probe.curl_requests.Session", return_value=session),
        patch(
            "sunny_core.commerce_probe._task_style_checkout_probe",
            return_value={"kind": "oaics", "payment_methods": ["card", "paypal"], "http": 200, "error": ""},
        ),
    ):
        result = probe_commerce("token")

    assert result["trial"] == {"state": "eligible", "http": 200, "error": ""}
    assert result["checkout"]["kind"] == "oaics"
    assert result["checkout"]["payment_methods"] == ["card", "paypal"]


def test_probe_trial_does_not_run_checkout() -> None:
    session = MagicMock()
    session.get.return_value = response(200, {"state": "eligible"})
    with (
        patch("sunny_core.commerce_probe.curl_requests.Session", return_value=session),
        patch("sunny_core.commerce_probe._task_style_checkout_probe") as checkout_probe,
    ):
        result = probe_trial("token", "http://register-proxy")

    assert result["trial"] == {"state": "eligible", "http": 200, "error": ""}
    assert session.proxies == {
        "http": "http://register-proxy",
        "https": "http://register-proxy",
    }
    checkout_probe.assert_not_called()


def test_probe_commerce_reports_html_challenge_without_leaking_body() -> None:
    session = MagicMock()
    session.get.return_value = response(403, None, "text/html; charset=UTF-8")
    with (
        patch("sunny_core.commerce_probe.curl_requests.Session", return_value=session),
        patch(
            "sunny_core.commerce_probe._task_style_checkout_probe",
            side_effect=RuntimeError("HTTP 403 returned text/html content"),
        ),
    ):
        result = probe_commerce("token")

    assert result["trial"]["error"] == "HTTP 403 returned text/html content"
    assert result["checkout"]["error"] == "RuntimeError: HTTP 403 returned text/html content"


def test_trial_network_failure_does_not_skip_checkout() -> None:
    session = MagicMock()
    session.get.side_effect = ConnectionError("trial interrupted")
    with (
        patch("sunny_core.commerce_probe.curl_requests.Session", return_value=session),
        patch("sunny_core.commerce_probe._task_style_checkout_probe", return_value={"kind": "cs_live", "payment_methods": [], "http": 200, "error": ""}),
        patch("sunny_core.commerce_probe.time.sleep"),
    ):
        result = probe_commerce("token")

    assert result["trial"]["http"] == 0
    assert "trial interrupted" in result["trial"]["error"]
    assert result["checkout"]["kind"] == "cs_live"
    assert session.get.call_count == 2


def test_probe_commerce_uses_separate_promotion_and_checkout_proxies() -> None:
    promotion_session = MagicMock()
    promotion_session.get.return_value = response(200, {"state": "eligible"})
    with (
        patch("sunny_core.commerce_probe.curl_requests.Session", return_value=promotion_session),
        patch("sunny_core.commerce_probe._task_style_checkout_probe", return_value={"kind": "cs_live", "payment_methods": [], "http": 200, "error": ""}) as checkout_probe,
    ):
        result = probe_commerce(
            "token",
            promotion_proxy_url="http://promotion-proxy",
            checkout_proxy_url="http://checkout-proxy",
        )

    assert result["trial"]["state"] == "eligible"
    assert result["checkout"]["kind"] == "cs_live"
    assert promotion_session.proxies == {
        "http": "http://promotion-proxy",
        "https": "http://promotion-proxy",
    }
    checkout_probe.assert_called_once_with("token", "DE", "EUR", "http://checkout-proxy")
    assert promotion_session.trust_env is False


def test_probe_commerce_returns_worker_proxy_traffic_summary() -> None:
    session = MagicMock()
    session.get.return_value = response(200, {"state": "eligible"})

    class FakeMeter:
        snapshots = iter(({"requests": 2, "total_bytes": 120}, {"requests": 3, "total_bytes": 340}))

        def __init__(self, **_kwargs):
            self.snapshot_value = next(self.snapshots)

        def snapshot(self):
            return self.snapshot_value

    with (
        patch("sunny_core.commerce_probe.curl_requests.Session", return_value=session),
        patch("sunny_core.commerce_probe.ProxyTrafficMeter", side_effect=FakeMeter),
        patch("sunny_core.commerce_probe.use_traffic_meter", side_effect=lambda meter: nullcontext(meter)),
        patch(
            "sunny_core.commerce_probe._task_style_checkout_probe",
            return_value={"kind": "oaics", "payment_methods": [], "http": 200, "error": ""},
        ),
    ):
        result = probe_commerce(
            "token",
            promotion_proxy_url="http://promotion-proxy",
            checkout_proxy_url="http://checkout-proxy",
        )

    assert result["traffic"] == {"requests": 5, "total_bytes": 460}


def test_probe_payment_methods_only_runs_checkout_for_requested_country() -> None:
    class FakeMeter:
        def __init__(self, **_kwargs):
            pass

        def snapshot(self):
            return {"requests": 2, "total_bytes": 240}

    with (
        patch("sunny_core.commerce_probe.ProxyTrafficMeter", side_effect=FakeMeter),
        patch("sunny_core.commerce_probe.use_traffic_meter", side_effect=lambda meter: nullcontext(meter)),
        patch(
            "sunny_core.commerce_probe._task_style_checkout_probe",
            return_value={"kind": "oaics", "payment_methods": ["card", "momo"], "http": 200, "error": ""},
        ) as checkout_probe,
    ):
        result = probe_payment_methods("token", "http://vn-proxy", "VN", "VND")

    checkout_probe.assert_called_once_with("token", "VN", "VND", "http://vn-proxy", False)
    assert result["checkout"]["payment_methods"] == ["card", "momo"]
    assert result["traffic"] == {"requests": 2, "total_bytes": 240}


def test_payment_methods_merge_standard_custom_and_future_fields() -> None:
    payload = {
        "payment_method_types": ["card"],
        "custom_payment_methods": [{"id": "cpmt_gopay"}],
        "available_payment_methods": [{"type": "bank_transfer_x"}],
        "payment_method_specs": [{"type": "future_wallet_v2"}],
    }
    assert _payment_methods(payload) == ["card", "cpmt_gopay", "bank_transfer_x", "future_wallet_v2"]


def test_indonesia_payment_probe_matches_gopay_cs_live_mode() -> None:
    options = _checkout_probe_options("ID", "IDR")
    assert options["link_type"] == "gopay"
    assert options["checkout_ui_mode"] == "redirect"
    assert options["use_promo"] is False


def test_payment_probe_can_include_free_trial_promotion() -> None:
    options = _checkout_probe_options("JP", "JPY", True)
    assert options["use_promo"] is True
    assert options["promo_campaign"] == "plus-1-month-free"
    assert options["promo_on_create"] is True
    assert options["promo_from_query_param"] is True


def test_local_stripe_payment_countries_use_hosted_checkout_mode() -> None:
    countries = {
        "SG": "SGD", "MY": "MYR", "TH": "THB", "IN": "INR", "JP": "JPY",
        "BR": "BRL", "NL": "EUR", "PL": "PLN", "PT": "EUR",
    }
    for country, currency in countries.items():
        options = _checkout_probe_options(country, currency)
        assert options["checkout_ui_mode"] == "redirect"
        assert options["checkout_country"] == country
        assert options["checkout_currency"] == currency


def test_task_style_probe_reads_stripe_init_and_elements_payment_methods() -> None:
    http = MagicMock()
    app = ModuleType("app")
    app.checkout_payload = MagicMock(return_value={"billing_details": {"country": "PL", "currency": "PLN"}})
    app.create_checkout = MagicMock(return_value={
        "data": {"checkout_session_id": "cs_live_test", "payment_method_types": ["card"]},
        "http": http,
    })
    app.fetch_custom_checkout_session_with_retry = MagicMock()

    stripe = ModuleType("stripe_checkout")
    stripe._profile = MagicMock(return_value={"browser_locale": "pl-PL"})
    stripe.verify_pk = MagicMock(return_value="pk_live_test")
    stripe.init_checkout = MagicMock(return_value=(
        {"payment_method_types": ["card", "blik"]},
        "2025-03-31.basil",
        {"payment_method_types": ["card", "blik"], "elements_payment_method_types": ["card", "blik", "p24"]},
    ))
    stripe.fetch_elements_session = MagicMock(return_value={
        "payment_method_specs": [{"type": "card"}, {"type": "blik"}, {"type": "p24"}],
    })

    with patch.dict("sys.modules", {"app": app, "stripe_checkout": stripe}):
        result = _task_style_checkout_probe("token", "PL", "PLN", "http://pl-proxy", True)

    assert result["kind"] == "cs_live"
    assert result["payment_methods"] == ["card", "blik", "p24"]
    app.checkout_payload.assert_called_once()
    probe_options = app.checkout_payload.call_args.args[0]
    assert probe_options["use_promo"] is True
    assert probe_options["promo_campaign"] == "plus-1-month-free"
    assert probe_options["promo_on_create"] is True
    assert probe_options["promo_from_query_param"] is True
    stripe.init_checkout.assert_called_once()
    stripe.fetch_elements_session.assert_called_once()
    http.close.assert_called_once()
