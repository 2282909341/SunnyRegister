from __future__ import annotations

from sunny_core.proxy import normalize_proxy_url


def test_normalize_kookeey_sticky_as_socks5h() -> None:
    assert (
        normalize_proxy_url("gate.kookeey.info:1000:user:password-DE-session")
        == "socks5h://user:password-DE-session@gate.kookeey.info:1000"
    )


def test_normalize_kookeey_http_scheme_as_socks5h() -> None:
    assert (
        normalize_proxy_url("http://user:password-S@gate.kookeey.info:1086")
        == "socks5h://user:password-S@gate.kookeey.info:1086"
    )


def test_normalize_kookeey_other_port_stays_http() -> None:
    assert (
        normalize_proxy_url("http://user:pass@gate.kookeey.info:8080")
        == "http://user:pass@gate.kookeey.info:8080"
    )


def test_normalize_non_kookeey_unchanged() -> None:
    assert (
        normalize_proxy_url("proxy.example.com:8080:user:pass")
        == "http://user:pass@proxy.example.com:8080"
    )
