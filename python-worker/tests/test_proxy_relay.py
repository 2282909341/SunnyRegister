# -*- coding: utf-8 -*-
"""代理链（本机中继 -> 住宅代理 -> 目标）的单元测试。"""
from __future__ import annotations

from curl_cffi import CurlOpt

from sunny_core import proxy_relay
from sunny_core.commerce_probe import _session, probe_payment_methods
from tools.pay153_checkout import stripe_checkout as sc

LOCAL_RELAY = "socks5h://127.0.0.1:7890"


def _clear_relay_env(monkeypatch) -> None:
    for key in proxy_relay.RELAY_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_resolve_relay_url_defaults_to_local_socks_relay(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    assert proxy_relay.resolve_relay_url() == LOCAL_RELAY


def test_resolve_relay_url_prefers_environment(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    monkeypatch.setenv("SUNNY_PROXY_RELAY", "socks5h://relay.example:1080")
    assert proxy_relay.resolve_relay_url() == "socks5h://relay.example:1080"


def test_resolve_relay_url_honours_disabled_environment(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    monkeypatch.setenv("SUNNY_PROXY_RELAY", "off")
    assert proxy_relay.resolve_relay_url() == ""


def test_resolve_relay_url_explicit_value_wins(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    monkeypatch.setenv("SUNNY_PROXY_RELAY", "socks5h://env-relay:1080")
    assert proxy_relay.resolve_relay_url("socks5h://arg-relay:1080") == "socks5h://arg-relay:1080"
    assert proxy_relay.resolve_relay_url("") == ""


def test_relay_override_scopes_and_restores(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    with proxy_relay.relay_override(""):
        assert proxy_relay.resolve_relay_url() == ""
    assert proxy_relay.resolve_relay_url() == LOCAL_RELAY


def test_relay_curl_options_rejects_http_relay(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    assert proxy_relay.relay_curl_options(LOCAL_RELAY) == {CurlOpt.PRE_PROXY: LOCAL_RELAY}
    # libcurl 只接受 SOCKS 中继，http:// 会以 curl: (5) 直接失败，必须被忽略。
    assert proxy_relay.relay_curl_options("http://127.0.0.1:7890") == {}
    assert proxy_relay.relay_curl_options("") == {}


def test_apply_relay_merges_existing_curl_options(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)

    class FakeSession:
        curl_options = {CurlOpt.TIMEOUT: 30}

    session = FakeSession()
    assert proxy_relay.apply_relay(session) == LOCAL_RELAY
    assert session.curl_options[CurlOpt.PRE_PROXY] == LOCAL_RELAY
    assert session.curl_options[CurlOpt.TIMEOUT] == 30


def test_apply_relay_skips_http_relay(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)

    class FakeSession:
        curl_options: dict = {}

    session = FakeSession()
    assert proxy_relay.apply_relay(session, "http://127.0.0.1:7890") == ""
    assert session.curl_options == {}


def test_relay_transport_error_classification() -> None:
    assert proxy_relay.looks_like_relay_transport_error(
        "ProxyError: Failed to perform, curl: (56) Proxy CONNECT aborted."
    )
    assert proxy_relay.looks_like_relay_transport_error(
        "ProxyError: Failed to perform, curl: (5) Unsupported pre-proxy type for 'http://127.0.0.1:7890'."
    )
    assert not proxy_relay.looks_like_relay_transport_error(
        'HTTP 400: {"detail": "Our systems have detected unusual activity"}'
    )
    assert not proxy_relay.looks_like_relay_transport_error("")


def test_private_session_attaches_pre_proxy(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    session = _session("http://vn-proxy.example:10000")
    try:
        assert session.curl_options[CurlOpt.PRE_PROXY] == LOCAL_RELAY
    finally:
        session.close()

    direct = _session("http://vn-proxy.example:10000", relay="off")
    try:
        assert CurlOpt.PRE_PROXY not in (direct.curl_options or {})
    finally:
        direct.close()

    without_proxy = _session("")
    try:
        assert CurlOpt.PRE_PROXY not in (without_proxy.curl_options or {})
    finally:
        without_proxy.close()


def test_build_http_attaches_pre_proxy(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    http = sc.build_http("http://vn-proxy.example:10000")
    try:
        assert http.proxies == {
            "http": "http://vn-proxy.example:10000",
            "https": "http://vn-proxy.example:10000",
        }
        assert http.curl_options[CurlOpt.PRE_PROXY] == LOCAL_RELAY
    finally:
        http.close()


def test_build_http_without_proxy_has_no_pre_proxy(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    http = sc.build_http("")
    try:
        assert CurlOpt.PRE_PROXY not in (http.curl_options or {})
    finally:
        http.close()


def test_probe_payment_methods_retries_without_relay_on_transport_error(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    seen_relays: list[str] = []

    def fake_probe(*_args, **_kwargs):
        seen_relays.append(proxy_relay.resolve_relay_url())
        if len(seen_relays) == 1:
            raise RuntimeError("ProxyError: Failed to perform, curl: (56) Proxy CONNECT aborted.")
        return {"kind": "oaics", "payment_methods": ["momo"], "http": 200, "error": ""}

    monkeypatch.setattr("sunny_core.commerce_probe._task_style_checkout_probe", fake_probe)
    result = probe_payment_methods("token", "http://vn-proxy.example:10000", "VN", "VND")

    assert seen_relays == [LOCAL_RELAY, ""]
    assert result["checkout"]["payment_methods"] == ["momo"]
    assert result["checkout"]["error"] == ""


def test_probe_payment_methods_does_not_retry_on_risk_error(monkeypatch) -> None:
    _clear_relay_env(monkeypatch)
    attempts: list[str] = []

    def fake_probe(*_args, **_kwargs):
        attempts.append(proxy_relay.resolve_relay_url())
        raise RuntimeError('HTTP 400: {"detail": "Our systems have detected unusual activity"}')

    monkeypatch.setattr("sunny_core.commerce_probe._task_style_checkout_probe", fake_probe)
    result = probe_payment_methods("token", "http://vn-proxy.example:10000", "VN", "VND")

    assert attempts == [LOCAL_RELAY]
    assert result["checkout"]["http"] == 400
    assert "unusual activity" in result["checkout"]["error"]
