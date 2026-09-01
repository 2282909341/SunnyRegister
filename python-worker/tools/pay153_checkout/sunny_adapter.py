from __future__ import annotations

import re
import sys
import os
from pathlib import Path
from typing import Any

_ENGINE_DIR = Path(__file__).resolve().parent
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))
os.environ.setdefault("PAY153_UPI_GO_BINARY", str(_ENGINE_DIR / "tools" / "upi_go" / "pix_extract_slot"))

from app import STORE
from paypal_routing import checkout_mode


_TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_.-]{40,}")
_PROXY_AUTH_RE = re.compile(r"((?:https?|socks5?)://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_LEGACY_PROMOTION_POOL_RE = re.compile(r"代理池\s*1")
_LEGACY_CHECKOUT_POOL_RE = re.compile(r"代理池\s*2")


def _safe_error(value: Any) -> str:
    text = _TOKEN_RE.sub("[TOKEN]", str(value or ""))
    text = _PROXY_AUTH_RE.sub(r"\1[PROXY]@", text)
    text = _LEGACY_PROMOTION_POOL_RE.sub("Promotion代理池", text)
    text = _LEGACY_CHECKOUT_POOL_RE.sub("Checkout代理池", text)
    return text[:1200]


def start_checkout(payload: dict[str, Any]) -> str:
    link_type = str(payload.get("link_type") or "hosted").strip().lower()
    checkout_kind = str(payload.get("checkout_kind") or "unknown").strip().lower()
    paypal_mode = checkout_mode(checkout_kind)
    raw_retry_count = payload.get("retry_count")
    retry_count = 3 if raw_retry_count is None or str(raw_retry_count).strip() == "" else int(raw_retry_count)
    checkout_proxies = list(payload.get("checkout_proxies") or [])
    promotion_proxies = list(payload.get("promotion_proxies") or [])
    # Keep legacy callers (which omit use_promo) on their explicitly supplied
    # dual pools; only an explicit false toggle means Promotion is not used.
    if link_type == "gcash" or payload.get("use_promo") is False:
        promotion_proxies = list(checkout_proxies)
    default_country, default_currency = {
        "gcash": ("PH", "PHP"),
        "gopay": ("ID", "IDR"),
        "momo": ("VN", "VND"),
        "blik": ("PL", "PLN"),
    }.get(link_type, ("US", "USD"))
    options = {
        "token_raw": str(payload.get("token") or ""),
        "plan": str(payload.get("plan") or "plus"),
        "link_type": link_type,
        "checkout_kind": checkout_kind,
        "paypal_checkout_mode": paypal_mode,
        # OAICS and unknown accounts stay in the Python workflow so the
        # created session can select OAICS or Stripe automatically. Known
        # CS Live accounts retain the reference project's PayPal workflow.
        "oaics_paypal": link_type == "paypal" and paypal_mode != "cs_live",
        "country": str(payload.get("country") or default_country).upper(),
        "currency": str(payload.get("currency") or default_currency).upper(),
        "checkout_country": str(payload.get("country") or default_country).upper(),
        "checkout_currency": str(payload.get("currency") or default_currency).upper(),
        # pay153's entry pool is the Promotion route and its exit pool is the
        # billing/Checkout route. SunnyRegister exposes those pools in the
        # opposite order, so keep the translation at this adapter boundary.
        "entry_proxies": promotion_proxies,
        "exit_proxies": checkout_proxies,
        "named_proxy_pools": True,
        "use_promo": bool(payload.get("use_promo")),
        "promo_campaign": str(payload.get("promo_campaign") or ""),
        "promo_code": str(payload.get("promo_code") or ""),
        "workspace_name": str(payload.get("workspace_name") or "")[:80],
        "workspace_id": str(payload.get("workspace_id") or "")[:120],
        "seat_quantity": int(payload.get("seat_quantity") or 5),
        "price_interval": "year" if payload.get("price_interval") == "year" else "month",
        "credit_quantity": int(payload.get("credit_quantity") or 13),
        "ideal_bank": str(payload.get("ideal_bank") or "")[:40],
        "pix_tax_id": str(payload.get("pix_tax_id") or "")[:14],
        "pix_tax_id_auto": not bool(payload.get("pix_tax_id")),
        "pix_auto_kind": str(payload.get("pix_auto_kind") or "cpf"),
        "retry_count": min(50, max(0, retry_count)),
        "paired_proxy_rotation": True,
        "use_sen": True,
        "use_so": True,
        "entry_proxy_country": str(payload.get("promo_country") or payload.get("country") or default_country).upper(),
        "exit_proxy_country": str(payload.get("country") or default_country).upper(),
    }
    if options["link_type"] == "gcash":
        options["country"] = options["checkout_country"] = "PH"
        options["currency"] = options["checkout_currency"] = "PHP"
        options["entry_proxy_country"] = options["exit_proxy_country"] = "PH"
    if options["link_type"] == "blik":
        # BLIK billing is always Polish. Proxy-country hints remain driven by
        # the two front-end selectors, so an explicit user route still wins.
        options["country"] = options["checkout_country"] = "PL"
        options["currency"] = options["checkout_currency"] = "PLN"
    if options["link_type"] == "ph_short" and options["use_promo"]:
        options["entry_proxy_country"] = str(payload.get("promo_country") or "TR").upper()
    return STORE.create(options, internal=True)


def checkout_status(job_id: str) -> dict[str, Any] | None:
    job = STORE.get(job_id, public=False)
    if not job:
        return None
    raw = job.get("result") if isinstance(job.get("result"), dict) else {}
    link = next(
        (
            str(raw.get(key) or "")
            for key in (
                "paypal_link", "blik_payment_url", "provider_redirect_url", "ideal_redirect_url",
                "redirect_url", "checkout_url", "short_link", "url", "link",
            )
            if raw.get(key)
        ),
        "",
    )
    qr_data = next(
        (str(raw.get(key) or "") for key in ("qr_data", "pixPayload", "upi_payload") if raw.get(key)),
        "",
    )
    qr_image = next(
        (
            str(raw.get(key) or "")
            for key in ("qr_image_png", "qr_image_data_url", "pixQrPngUrl", "pixQrSvgUrl")
            if raw.get(key)
        ),
        "",
    )
    result = {
        "plan": str(raw.get("plan") or ""),
        "account_email": str(raw.get("account_email") or raw.get("email") or ""),
        "account_id": str(raw.get("account_id") or ""),
        "provider": str(raw.get("provider") or raw.get("link_type") or ""),
        "link_type": str(raw.get("link_type") or raw.get("provider") or ""),
        "checkout_session_id": str(raw.get("checkout_session_id") or ""),
        "checkout_kind": str(raw.get("checkout_kind") or ""),
        "payment_link": link,
        "short_link": str(raw.get("short_link") or ""),
        "verification_url": str(raw.get("verification_url") or ""),
        "checkout_url": str(raw.get("checkout_url") or ""),
        "provider_redirect_url": str(raw.get("provider_redirect_url") or ""),
        "paypal_link": str(raw.get("paypal_link") or raw.get("paypal_url") or ""),
        "qr_data": qr_data,
        "qr_status": str(raw.get("qr_status") or ""),
        "qr_expires_at": raw.get("qr_expires_at"),
        "qr_image": qr_image,
        "qr_image_png": str(raw.get("qr_image_png") or ""),
        "qr_image_svg": str(raw.get("qr_image_svg") or ""),
        "country": str(raw.get("checkout_country") or raw.get("country") or ""),
        "currency": str(raw.get("checkout_currency") or raw.get("currency") or ""),
        "checkout_amount": raw.get("checkout_amount"),
        "payment_methods": raw.get("payment_methods") or raw.get("custom_payment_methods") or [],
        "promo_requested": raw.get("promo_requested"),
        "promo_applied": raw.get("promo_applied"),
        "promo_campaign_used": str(raw.get("promo_campaign_used") or raw.get("promo_campaign") or ""),
        "expires_at": raw.get("expires_at"),
        "gcash_order_id": str(raw.get("gcash_order_id") or ""),
        "gcash_authorization_url": str(raw.get("gcash_authorization_url") or ""),
        "gcash_net_auth_id": str(raw.get("gcash_net_auth_id") or ""),
        "gcash_client_id": str(raw.get("gcash_client_id") or ""),
        "gopay_midtrans_url": str(raw.get("gopay_midtrans_url") or ""),
        "blik_payment_url": str(raw.get("blik_payment_url") or ""),
        "payment_status": str(raw.get("payment_status") or ""),
        "payment_callback_path": str(raw.get("payment_callback_path") or ""),
        "payment_expires_at": raw.get("payment_expires_at"),
        "callback_token": str(raw.get("callback_token") or ""),
    }
    return {
        "status": str(job.get("status") or "queued"),
        "progress": int(job.get("percent") or 0),
        "message": str(job.get("text") or ""),
        "error": _safe_error(job.get("error")),
        "logs": [
            {
                "sequence": int(item.get("sequence") or sequence),
                "time": str(item.get("time") or ""),
                "message": _safe_error(item.get("message")),
            }
            for sequence, item in enumerate(job.get("logs") or [], start=1)
            if isinstance(item, dict)
        ][-200:],
        "result": result,
    }


def cancel_checkout(job_id: str) -> bool:
    return STORE.cancel(job_id)
