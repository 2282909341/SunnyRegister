# -*- coding: utf-8 -*-
"""代理链（中继）支持：client -> 本机中继 -> 住宅代理 -> 目标。

住宅代理网关经常无法从本机直连，需要先接入本机中继（例如 FlClash 的
mixed 端口 7890），再由中继转发到住宅代理。libcurl 用 CURLOPT_PRE_PROXY
表达该语义，但它**只接受 SOCKS 中继**：传 ``http://`` 中继会直接失败并返回
``curl: (5) Unsupported pre-proxy type``，因此这里只放行 socks 协议，
http(s) 中继会被忽略而不是让整次请求以难懂的错误失败。
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

#: FlClash 等本机中继的 mixed 端口同时支持 HTTP 与 SOCKS5；libcurl 只认 SOCKS，
#: 所以默认值必须写成 socks5h（由中继侧解析代理域名）。
DEFAULT_RELAY_URL = "socks5h://127.0.0.1:7890"
RELAY_ENV_KEYS = ("SUNNY_PROXY_RELAY", "SUNNY_PROBE_RELAY")
RELAY_DISABLED_VALUES = {"0", "off", "none", "no", "false", "direct", "disabled"}
_SOCKS_PREFIXES = ("socks5h://", "socks5://", "socks4a://", "socks4://")

#: 判定“失败发生在代理/中继链路本身”的特征串：这类失败请求并未到达 OpenAI，
#: 可以安全地在关闭中继后重试一次。
RELAY_TRANSPORT_MARKERS = (
    "proxyerror",
    "unsupported pre-proxy type",
    "proxy connect aborted",
    "curl: (5)",
    "curl: (7)",
    "curl: (35)",
    "curl: (52)",
    "curl: (56)",
    "failed to connect",
    "could not connect to server",
    "connection refused",
)

_relay_override: ContextVar[str | None] = ContextVar("sunny_proxy_relay_override", default=None)


def normalize_relay_url(raw: Any) -> str:
    value = str(raw or "").strip()
    if not value or value.lower() in RELAY_DISABLED_VALUES:
        return ""
    return value


def relay_is_chainable(relay: Any) -> bool:
    """libcurl 的 pre-proxy 只支持 SOCKS，HTTP 中继会被拒绝。"""
    return str(relay or "").strip().lower().startswith(_SOCKS_PREFIXES)


def resolve_relay_url(explicit: Any = None) -> str:
    """解析本次请求要用的中继地址；返回空串表示不使用中继。

    优先级：显式参数 > 上下文覆盖 > 环境变量 > 默认本机中继。
    环境变量只要被设置（哪怕是空串）就以其为准，便于一键关闭。
    """
    if explicit is not None:
        return normalize_relay_url(explicit)
    override = _relay_override.get()
    if override is not None:
        return normalize_relay_url(override)
    for key in RELAY_ENV_KEYS:
        if key in os.environ:
            return normalize_relay_url(os.environ.get(key))
    return DEFAULT_RELAY_URL


@contextmanager
def relay_override(relay: Any) -> Iterator[str]:
    """在当前上下文临时覆盖中继地址（传空串即临时关闭中继）。"""
    token = _relay_override.set(str(relay or ""))
    try:
        yield normalize_relay_url(relay)
    finally:
        _relay_override.reset(token)


def relay_curl_options(relay: Any) -> dict[Any, Any]:
    value = normalize_relay_url(relay)
    if not value or not relay_is_chainable(value):
        return {}
    try:
        from curl_cffi import CurlOpt
    except Exception:  # pragma: no cover - curl_cffi 缺失时退化为不使用中继
        return {}
    return {CurlOpt.PRE_PROXY: value}


def apply_relay(session: Any, relay: Any = None) -> str:
    """把中继注入已构造好的 curl_cffi 会话，返回实际生效的中继地址。"""
    value = resolve_relay_url() if relay is None else normalize_relay_url(relay)
    options = relay_curl_options(value)
    if not options:
        return ""
    merged = dict(getattr(session, "curl_options", None) or {})
    merged.update(options)
    try:
        session.curl_options = merged
    except Exception:  # pragma: no cover - 会话不支持时静默保持直连
        return ""
    return value


def looks_like_relay_transport_error(message: Any) -> bool:
    text = str(message or "").lower()
    if not text:
        return False
    return any(marker in text for marker in RELAY_TRANSPORT_MARKERS)
