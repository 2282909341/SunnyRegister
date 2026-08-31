"""Stable browser-style payment fingerprints for GoPay web payment flows."""
from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any


_FINGERPRINT_VERSION = 2
_DEFAULT_LOCALE = "zh-CN"
_DEFAULT_TIMEZONE = "Asia/Shanghai"
_CAPTURED_VIEWPORT = {"width": 787, "height": 586, "device_scale_factor": 1}
_CAPTURED_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36"
)
_CAPTURED_SEC_CH_UA = '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"'


def _seed_from_parts(*parts: str) -> str:
    material = "|".join(str(part or "") for part in parts if str(part or ""))
    return material or "gopay-payment-profile"


def _profile_id(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def _saved_profile_id(value: Any) -> str:
    profile_id = str(value or "").strip().lower()
    if len(profile_id) == 16 and all(char in "0123456789abcdef" for char in profile_id):
        return profile_id
    return ""


def build_payment_fingerprint(*, seed: str = "", phone: str = "", local: str = "", account_id: str = "") -> dict[str, Any]:
    """Build a deterministic profile matching the successful 2026-08-26 HAR."""
    seed_value = _seed_from_parts(seed, account_id, phone, local)

    return {
        "version": _FINGERPRINT_VERSION,
        "profile_id": _profile_id(seed_value),
        "user_agent": _CAPTURED_USER_AGENT,
        "locale": _DEFAULT_LOCALE,
        "timezone": _DEFAULT_TIMEZONE,
        "viewport": deepcopy(_CAPTURED_VIEWPORT),
        "sec_ch_ua": _CAPTURED_SEC_CH_UA,
        "sec_ch_ua_mobile": "?1",
        "sec_ch_ua_platform": '"Android"',
    }


def normalize_payment_fingerprint(profile: dict[str, Any] | None, **seed_parts: str) -> dict[str, Any]:
    """Return a complete profile, preserving valid saved values when present."""
    fallback = build_payment_fingerprint(**seed_parts)
    if not isinstance(profile, dict):
        return fallback
    try:
        saved_version = int(profile.get("version") or 0)
    except (TypeError, ValueError):
        saved_version = 0
    if saved_version != _FINGERPRINT_VERSION:
        if saved_version == 1:
            fallback["profile_id"] = _saved_profile_id(profile.get("profile_id")) or fallback["profile_id"]
        return fallback

    normalized = deepcopy(fallback)
    for key in (
        "version",
        "profile_id",
        "user_agent",
        "locale",
        "timezone",
        "sec_ch_ua",
        "sec_ch_ua_mobile",
        "sec_ch_ua_platform",
    ):
        value = profile.get(key)
        if value not in (None, ""):
            normalized[key] = value

    viewport = profile.get("viewport")
    if isinstance(viewport, dict):
        merged_viewport = deepcopy(fallback["viewport"])
        for key in ("width", "height", "device_scale_factor"):
            value = viewport.get(key)
            if value not in (None, ""):
                try:
                    merged_viewport[key] = int(value)
                except (TypeError, ValueError):
                    pass
        normalized["viewport"] = merged_viewport

    return normalized


def ensure_account_payment_fingerprint(account: dict[str, Any]) -> dict[str, Any]:
    """Ensure an account dict carries exactly one reusable payment fingerprint."""
    profile = normalize_payment_fingerprint(
        account.get("payment_fingerprint"),
        phone=str(account.get("phone", "")),
        local=str(account.get("local", "")),
        account_id=str(account.get("account_id") or account.get("customer_id") or ""),
    )
    account["payment_fingerprint"] = profile
    return profile


def payment_fingerprint_headers(profile: dict[str, Any] | None) -> dict[str, str]:
    """Map a payment fingerprint to reusable browser request headers."""
    fp = normalize_payment_fingerprint(profile)
    locale = str(fp.get("locale") or _DEFAULT_LOCALE)
    accept_language = (
        "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,ru;q=0.6"
        if locale.lower() == "zh-cn"
        else f"{locale},{locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7"
    )

    return {
        "User-Agent": str(fp.get("user_agent") or ""),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Accept-Language": accept_language,
        "Sec-CH-UA": str(fp.get("sec_ch_ua") or ""),
        "Sec-CH-UA-Mobile": str(fp.get("sec_ch_ua_mobile") or "?0"),
        "Sec-CH-UA-Platform": str(fp.get("sec_ch_ua_platform") or '"Windows"'),
    }
