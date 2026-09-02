from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthFailure:
    category: str
    retryable: bool = False
    terminal: bool = False
    rotate_proxy: bool = False
    fresh_context: bool = False
    delay_seconds: float = 0.0


_ACCOUNT_DISABLED = (
    "account_deactivated", "account disabled", "account has been disabled",
    "deleted or deactivated", "account suspended", "account banned",
    "账户已停用", "账户被禁用", "账户已封禁", "账号已封禁", "账号被封禁",
    "アカウントが無効", "アカウントが停止", "계정이 비활성화", "계정이 정지",
)


def classify_auth_failure(error: Any, *, http_status: int = 0) -> AuthFailure:
    text = str(error or "").strip().lower()
    status = int(http_status or 0)
    if any(marker in text for marker in ("task cancelled", "任务已取消", "用户已中断")):
        return AuthFailure("cancelled", terminal=True)
    if any(marker in text for marker in _ACCOUNT_DISABLED):
        return AuthFailure("account_deactivated", terminal=True)
    if any(marker in text for marker in (
        "mailbox_credential_expired", "mailbox_credential_invalid", "mailbox_client_invalid",
        "domain_credential_invalid", "remail_credential_invalid",
    )):
        return AuthFailure("mailbox_credential_invalid", terminal=True)
    if any(marker in text for marker in (
        "incorrect password", "invalid password", "wrong password", "密码错误",
        "invalid totp", "incorrect code", "2fa 密钥", "totp 密钥",
    )):
        return AuthFailure("login_secret_invalid", terminal=True)
    if "refresh token" in text and any(marker in text for marker in ("invalid", "revoked", "expired")):
        return AuthFailure("token_invalid", retryable=True, fresh_context=True)
    if status == 429 or any(marker in text for marker in (
        "rate_limit_exceeded", "rate limit", "too many requests", "请求过多",
    )):
        return AuthFailure("rate_limited", retryable=True, rotate_proxy=True, fresh_context=True, delay_seconds=20)
    if any(marker in text for marker in (
        "cloudflare", "upstream edge", "上游边缘", "proxy connect failed", "https 隧道",
    )):
        return AuthFailure("edge_blocked", retryable=True, rotate_proxy=True, delay_seconds=2)
    if any(marker in text for marker in (
        "invalid_auth_step", "invalid_state", "authorization step", "认证事务状态失效",
        "email-otp/validate", "emailotpvalidate", "proof_required", "sentinel_required",
    )):
        return AuthFailure("stale_auth_context", retryable=True, fresh_context=True, delay_seconds=12)
    if any(marker in text for marker in (
        "challenge_required", "browser challenge", "requires a browser challenge", "turnstile",
    )):
        return AuthFailure("browser_challenge", retryable=True, fresh_context=True)
    if status == 401 or any(marker in text for marker in (
        "token_revoked", "invalidated oauth token", "invalid refresh token", "access token 已失效", "at 已失效",
    )):
        return AuthFailure("token_invalid", retryable=True, fresh_context=True)
    if status == 403:
        return AuthFailure("edge_blocked", retryable=True, rotate_proxy=True, delay_seconds=2)
    if status in {500, 502, 503, 504} or any(marker in text for marker in (
        "connection reset", "connection refused", "timed out", "timeout", "curl: (28)",
        "curl: (35)", "unexpected eof", "tls", "temporary failure", "network is unreachable",
    )):
        return AuthFailure("transient_transport", retryable=True, rotate_proxy=True, delay_seconds=2)
    return AuthFailure("unknown")


def retry_allowed(error: Any, attempt: int, *, operation: str = "auth", http_status: int = 0) -> AuthFailure:
    failure = classify_auth_failure(error, http_status=http_status)
    budgets = {
        "token_refresh": 2,
        "token_probe": 1,
        "protocol_login": 1,
        "mailbox": 1,
    }
    budget = budgets.get(operation, 1)
    if attempt >= budget or failure.terminal:
        return AuthFailure(failure.category, terminal=failure.terminal)
    return failure
