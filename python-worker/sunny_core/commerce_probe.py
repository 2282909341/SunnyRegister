from __future__ import annotations

import time
import uuid
import sys
from pathlib import Path
from typing import Any

from curl_cffi import requests as curl_requests

from .browser_traffic import ProxyTrafficMeter, use_traffic_meter
from .ca_bundle import ca_bundle_path

try:
    from tools.pay153_checkout.paypal_routing import session_checkout_kind
except ImportError:  # pragma: no cover - direct module execution compatibility
    from paypal_routing import session_checkout_kind


TRIAL_URL = (
    "https://chatgpt.com/backend-api/promo_campaign/check_coupon"
    "?coupon=plus-1-month-free&is_coupon_from_query_param=true"
)
CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"
STRIPE_HOSTED_PAYMENT_COUNTRIES = {"SG", "MY", "TH", "IN", "JP", "BR", "NL", "PL", "PT"}


def _headers(token: str) -> dict[str, str]:
    return {
        "authorization": f"Bearer {token}",
        "referer": "https://chatgpt.com/",
        "user-agent": USER_AGENT,
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "oai-language": "en-US",
    }


def _safe_json(response: Any) -> tuple[dict[str, Any], str]:
    try:
        payload = response.json() or {}
        if isinstance(payload, dict):
            return payload, ""
    except Exception:
        pass
    content_type = str(response.headers.get("content-type") or "").split(";", 1)[0]
    return {}, f"HTTP {response.status_code} returned {content_type or 'non-JSON'} content"


def _payment_methods(payload: dict[str, Any]) -> list[str]:
    methods: list[str] = []
    # Checkout revisions may expose standard methods and country-specific
    # custom methods in separate fields. Keep both, including fields added by
    # future API revisions, so the backend can persist and filter unknown ones.
    for key in ("payment_method_types", "custom_payment_methods", "payment_methods", "available_payment_methods", "payment_method_specs"):
        raw = payload.get(key) or []
        if not isinstance(raw, list):
            continue
        for item in raw:
            method = str(
                (item.get("type") or item.get("id") or item.get("name") or "")
                if isinstance(item, dict) else item
            ).strip().lower()
            if method and method not in methods:
                methods.append(method)
    return methods


def _merge_payment_methods(*groups: list[str]) -> list[str]:
    methods: list[str] = []
    for group in groups:
        for method in group:
            normalized = str(method or "").strip().lower()
            if normalized and normalized not in methods:
                methods.append(normalized)
    return methods


def _request_with_retry(request: Any) -> Any:
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            return request()
        except Exception as exc:
            last_error = exc
            if attempt == 0:
                time.sleep(0.4)
    assert last_error is not None
    raise last_error


def _session(proxy_url: str) -> Any:
    session = curl_requests.Session(impersonate="firefox144", verify=ca_bundle_path())
    try:
        session.trust_env = False
    except Exception:
        pass
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    return session


def _checkout_probe_options(
    country: str,
    currency: str,
    *,
    use_promo: bool = False,
    promo_campaign: str = "",
) -> dict[str, Any]:
    indonesia_gopay_probe = country.upper() == "ID" and currency.upper() == "IDR"
    hosted_payment_probe = country.upper() in STRIPE_HOSTED_PAYMENT_COUNTRIES
    return {
        "plan": "plus",
        "country": country,
        "currency": currency,
        "checkout_country": country,
        "checkout_currency": currency,
        "link_type": "gopay" if indonesia_gopay_probe else "paypal",
        "checkout_ui_mode": "redirect" if indonesia_gopay_probe or hosted_payment_probe else "custom",
        "use_promo": use_promo,
        "promo_campaign": promo_campaign if use_promo else "",
        # VN probe uses link_type=paypal which sits in checkout_payload's
        # excluded set, so promo only reaches the OAICS payload when created
        # with it natively.
        "promo_on_create": bool(use_promo),
    }


def _task_style_checkout_probe(
    access_token: str,
    country: str,
    currency: str,
    checkout_proxy_url: str,
    *,
    use_promo: bool = False,
    promo_campaign: str = "",
) -> dict[str, Any]:
    """Run the same Checkout creation path used by PayPal extraction tasks."""
    engine_dir = Path(__file__).resolve().parents[1] / "tools" / "pay153_checkout"
    if str(engine_dir) not in sys.path:
        sys.path.insert(0, str(engine_dir))
    from app import (
        checkout_payload,
        create_checkout,
        custom_checkout_amount_minor,
        custom_checkout_currency,
        fetch_custom_checkout_session_with_retry,
        is_momo_promo_amount,
    )

    options = _checkout_probe_options(country, currency, use_promo=use_promo, promo_campaign=promo_campaign)
    payload = checkout_payload(options, {})
    device_id = str(uuid.uuid4())
    did = str(uuid.uuid4())
    created = create_checkout(
        access_token,
        payload,
        checkout_proxy_url,
        device_id,
        did,
        lambda _message: None,
        use_sen=True,
        use_so=True,
        allow_sentinel_fallback=True,
    )
    data = created.get("data") or {}
    session_id = str(data.get("checkout_session_id") or "")
    try:
        methods = _payment_methods(data)
        amount: int | None = custom_checkout_amount_minor(data)
        amount_currency = str(custom_checkout_currency(data) or "").upper()
        if session_id.startswith("oaics_"):
            processor = str(data.get("processor_entity") or "openai_ie").strip() or "openai_ie"
            custom_data = fetch_custom_checkout_session_with_retry(
                created.get("http"),
                access_token,
                session_id,
                processor,
                device_id,
                attempts=3,
                delay_seconds=0.5,
            )
            methods = _merge_payment_methods(methods, _payment_methods(custom_data))
            custom_amount = custom_checkout_amount_minor(custom_data)
            custom_currency = str(custom_checkout_currency(custom_data) or "").upper()
            if custom_amount is not None:
                amount = custom_amount
            if custom_currency:
                amount_currency = custom_currency
        elif session_id.startswith(("cs_live_", "cs_test_")):
            import stripe_checkout as stripe

            profile = stripe._profile(country)
            publishable_key = str(data.get("publishable_key") or "") or stripe.verify_pk(
                created.get("http"), session_id, lambda _message: None,
            )
            init_data, version, context = stripe.init_checkout(
                created.get("http"), session_id, publishable_key, profile, lambda _message: None,
            )
            elements_data = stripe.fetch_elements_session(
                created.get("http"), publishable_key, session_id, context, version, profile, lambda _message: None,
            )
            methods = _merge_payment_methods(
                methods,
                _payment_methods(init_data),
                _payment_methods(elements_data),
                [str(item) for item in context.get("payment_method_types") or []],
                [str(item) for item in context.get("elements_payment_method_types") or []],
            )
            elements_amount = custom_checkout_amount_minor(elements_data)
            elements_currency = str(custom_checkout_currency(elements_data) or "").upper()
            if elements_amount is not None:
                amount = elements_amount
            if elements_currency:
                amount_currency = elements_currency
        return {
            "kind": session_checkout_kind(session_id),
            "payment_methods": methods,
            "amount": amount,
            "currency": amount_currency,
            "momo_discounted": is_momo_promo_amount(amount, amount_currency),
            "http": 200,
            "error": "",
        }
    finally:
        http = created.get("http")
        close = getattr(http, "close", None)
        if callable(close):
            close()


def probe_trial(access_token: str, proxy_url: str = "") -> dict[str, Any]:
    token = str(access_token or "").strip()
    if not token:
        return {
            "trial": {"state": "", "http": 0, "error": "missing access token"},
            "traffic": {"requests": 0, "total_bytes": 0},
        }
    selected_proxy = str(proxy_url or "").strip()
    session = _session(selected_proxy)
    meter = ProxyTrafficMeter(
        proxy_url=selected_proxy,
        tracked_proxy=bool(selected_proxy),
        operation="commerce_trial",
    )
    result: dict[str, Any] = {
        "trial": {"state": "", "http": 0, "error": ""},
        "traffic": {"requests": 0, "total_bytes": 0},
    }
    try:
        try:
            with use_traffic_meter(meter):
                response = _request_with_retry(lambda: session.get(TRIAL_URL, headers=_headers(token), timeout=30))
            payload, error = _safe_json(response)
            result["trial"] = {
                "state": str(payload.get("state") or "").strip().lower(),
                "http": response.status_code,
                "error": error,
            }
        except Exception as exc:
            result["trial"]["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"
        result["traffic"] = meter.snapshot()
        return result
    finally:
        session.close()


def probe_payment_methods(
    access_token: str,
    proxy_url: str = "",
    country: str = "US",
    currency: str = "USD",
) -> dict[str, Any]:
    token = str(access_token or "").strip()
    if not token:
        return {
            "checkout": {"kind": "", "payment_methods": [], "http": 0, "error": "missing access token"},
            "traffic": {"requests": 0, "total_bytes": 0},
        }
    billing_country = str(country or "US").strip().upper() or "US"
    billing_currency = str(currency or "USD").strip().upper() or "USD"
    selected_proxy = str(proxy_url or "").strip()
    meter = ProxyTrafficMeter(
        proxy_url=selected_proxy,
        tracked_proxy=bool(selected_proxy),
        operation="payment_method_probe",
    )
    result: dict[str, Any] = {
        "checkout": {"kind": "", "payment_methods": [], "http": 0, "error": ""},
        "traffic": {"requests": 0, "total_bytes": 0},
    }
    try:
        with use_traffic_meter(meter):
            result["checkout"] = _task_style_checkout_probe(
                token,
                billing_country,
                billing_currency,
                selected_proxy,
            )
    except Exception as exc:
        message = f"{type(exc).__name__}: {str(exc)[:240]}"
        status = 401 if "HTTP 401" in message else 403 if "HTTP 403" in message else 0
        result["checkout"]["http"] = status
        result["checkout"]["error"] = message
    result["traffic"] = meter.snapshot()
    return result


def probe_momo_promo(
    access_token: str,
    proxy_url: str = "",
    country: str = "VN",
    currency: str = "VND",
) -> dict[str, Any]:
    token = str(access_token or "").strip()
    if not token:
        return {
            "checkout": {
                "kind": "",
                "payment_methods": [],
                "amount": None,
                "currency": "",
                "momo_discounted": False,
                "http": 0,
                "error": "missing access token",
            },
            "traffic": {"requests": 0, "total_bytes": 0},
        }
    billing_country = str(country or "VN").strip().upper() or "VN"
    billing_currency = str(currency or "VND").strip().upper() or "VND"
    selected_proxy = str(proxy_url or "").strip()
    meter = ProxyTrafficMeter(
        proxy_url=selected_proxy,
        tracked_proxy=bool(selected_proxy),
        operation="momo_promo_probe",
    )
    result: dict[str, Any] = {
        "checkout": {
            "kind": "",
            "payment_methods": [],
            "amount": None,
            "currency": "",
            "momo_discounted": False,
            "http": 0,
            "error": "",
        },
        "traffic": {"requests": 0, "total_bytes": 0},
    }
    try:
        with use_traffic_meter(meter):
            result["checkout"] = _task_style_checkout_probe(
                token,
                billing_country,
                billing_currency,
                selected_proxy,
                use_promo=True,
                promo_campaign="plus-1-month-free",
            )
    except Exception as exc:
        message = f"{type(exc).__name__}: {str(exc)[:240]}"
        status = 401 if "HTTP 401" in message else 403 if "HTTP 403" in message else 0
        result["checkout"]["http"] = status
        result["checkout"]["error"] = message
    result["traffic"] = meter.snapshot()
    return result


def probe_commerce(
    access_token: str,
    proxy_url: str = "",
    country: str = "DE",
    currency: str = "",
    *,
    promotion_proxy_url: str = "",
    checkout_proxy_url: str = "",
) -> dict[str, Any]:
    token = str(access_token or "").strip()
    if not token:
        return {"trial": {"state": "", "http": 0, "error": "missing access token"}, "checkout": {"kind": "", "payment_methods": [], "http": 0, "error": "missing access token"}}
    billing_country = str(country or "DE").strip().upper() or "DE"
    billing_currency = str(currency or ("EUR" if billing_country == "DE" else "USD")).strip().upper()
    selected_promotion_proxy = str(promotion_proxy_url or proxy_url).strip()
    selected_checkout_proxy = str(checkout_proxy_url or proxy_url).strip()
    promotion_session = _session(selected_promotion_proxy)
    promotion_meter = ProxyTrafficMeter(
        proxy_url=selected_promotion_proxy,
        tracked_proxy=bool(selected_promotion_proxy),
        operation="commerce_trial",
    )
    checkout_meter = ProxyTrafficMeter(
        proxy_url=selected_checkout_proxy,
        tracked_proxy=bool(selected_checkout_proxy),
        operation="commerce_checkout",
    )
    headers = _headers(token)
    result: dict[str, Any] = {
        "trial": {"state": "", "http": 0, "error": ""},
        "checkout": {"kind": "", "payment_methods": [], "http": 0, "error": ""},
        "traffic": {"requests": 0, "total_bytes": 0},
    }
    try:
        try:
            with use_traffic_meter(promotion_meter):
                trial_response = _request_with_retry(lambda: promotion_session.get(TRIAL_URL, headers=headers, timeout=30))
            trial_payload, trial_error = _safe_json(trial_response)
            result["trial"] = {
                "state": str(trial_payload.get("state") or "").strip().lower(),
                "http": trial_response.status_code,
                "error": trial_error,
            }
        except Exception as exc:
            result["trial"]["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"

        try:
            with use_traffic_meter(checkout_meter):
                result["checkout"] = _task_style_checkout_probe(
                    token,
                    billing_country,
                    billing_currency,
                    selected_checkout_proxy,
                )
        except Exception as exc:
            result["checkout"]["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"
        promotion_traffic = promotion_meter.snapshot()
        checkout_traffic = checkout_meter.snapshot()
        result["traffic"] = {
            "requests": int(promotion_traffic.get("requests") or 0) + int(checkout_traffic.get("requests") or 0),
            "total_bytes": int(promotion_traffic.get("total_bytes") or 0) + int(checkout_traffic.get("total_bytes") or 0),
        }
        return result
    finally:
        promotion_session.close()
