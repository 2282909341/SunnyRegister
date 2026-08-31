from __future__ import annotations

import json
import os
from typing import Any

import pytest

from gopay_runtime.app.src.opai.core import captcha_provider


TOKENS = {
    "sceneId": "scene",
    "certifyId": "certify",
    "deviceToken": "device",
    "data": "proof",
}


def _config(**overrides: str) -> dict[str, str]:
    config = {
        "api_key": "",
        "api_base_url": "https://api.2captcha.com",
        "solverify_api_key": "",
        "solverify_api_base_url": "https://solver.solverify.net",
        "solverify_poll_sec": "3",
        "solverify_timeout_sec": "90",
        "scene_id": "scene",
        "prefix": "prefix",
        "region": "sgp",
        "api_get_lib": captcha_provider.DEFAULT_API_GET_LIB,
        "poll_sec": "5",
        "timeout_sec": "180",
        "max_attempts": "1",
    }
    config.update(overrides)
    return config


def test_config_status_distinguishes_each_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(solverify_api_key="solver-key"),
    )
    solverify_only = captcha_provider.captcha_config_status()
    assert solverify_only["configured"] is True
    assert solverify_only["api_key_configured"] is False
    assert solverify_only["twocaptcha_api_key_configured"] is False
    assert solverify_only["solverify_api_key_configured"] is True

    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(solverify_api_key="solver-key", api_key="two-key"),
    )
    both = captcha_provider.captcha_config_status()
    assert both["configured"] is True
    assert both["api_key_configured"] is True
    assert both["twocaptcha_api_key_configured"] is True
    assert both["solverify_api_key_configured"] is True


def test_config_uses_environment_keys_and_fixed_provider_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    env_path = tmp_path / "captcha.env"
    env_path.write_text(
        "OPAI_2CAPTCHA_API_KEY=file-two-key\n"
        "OPAI_2CAPTCHA_API_BASE_URL=https://file-attacker.example\n"
        "OPAI_SOLVERIFY_API_KEY=file-solver-key\n"
        "OPAI_SOLVERIFY_API_BASE_URL=https://file-attacker.example\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPAI_MIDTRANS_CAPTCHA_ENV_FILE", str(env_path))
    monkeypatch.setenv("OPAI_2CAPTCHA_API_KEY", "env-two-key")
    monkeypatch.setenv("OPAI_2CAPTCHA_API_BASE_URL", "http://127.0.0.1:9001")
    monkeypatch.setenv("OPAI_SOLVERIFY_API_KEY", "env-solver-key")
    monkeypatch.setenv("OPAI_SOLVERIFY_API_BASE_URL", "http://127.0.0.1:9002")

    config = captcha_provider.load_captcha_config()

    assert config["api_key"] == "env-two-key"
    assert config["solverify_api_key"] == "env-solver-key"
    assert config["api_base_url"] == captcha_provider.DEFAULT_API_BASE
    assert (
        config["solverify_api_base_url"]
        == captcha_provider.DEFAULT_SOLVERIFY_API_BASE
    )


def test_blank_key_save_does_not_persist_environment_only_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    env_path = tmp_path / "captcha.env"
    monkeypatch.setenv("OPAI_MIDTRANS_CAPTCHA_ENV_FILE", str(env_path))
    monkeypatch.setenv("OPAI_2CAPTCHA_API_KEY", "env-only-two-secret")
    monkeypatch.setenv("OPAI_SOLVERIFY_API_KEY", "env-only-solver-secret")

    status = captcha_provider.write_captcha_config({
        "api_key": "",
        "api_base_url": "https://attacker.example/two",
        "solverify_api_key": "",
        "solverify_api_base_url": "https://attacker.example/solver",
    })

    saved = env_path.read_text(encoding="utf-8")
    assert "env-only-two-secret" not in saved
    assert "env-only-solver-secret" not in saved
    assert f"OPAI_2CAPTCHA_API_BASE_URL={captcha_provider.DEFAULT_API_BASE}" in saved
    assert (
        "OPAI_SOLVERIFY_API_BASE_URL="
        f"{captcha_provider.DEFAULT_SOLVERIFY_API_BASE}"
    ) in saved
    assert status["api_key"] == "env-...cret"
    assert status["solverify_api_key"] == "env-...cret"
    assert os.environ["OPAI_2CAPTCHA_API_KEY"] == "env-only-two-secret"
    assert os.environ["OPAI_SOLVERIFY_API_KEY"] == "env-only-solver-secret"


def test_blank_key_save_preserves_file_key_without_overriding_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    env_path = tmp_path / "captcha.env"
    env_path.write_text(
        "OPAI_2CAPTCHA_API_KEY=file-two-key\n"
        "OPAI_SOLVERIFY_API_KEY=file-solver-key\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPAI_MIDTRANS_CAPTCHA_ENV_FILE", str(env_path))
    monkeypatch.setenv("OPAI_2CAPTCHA_API_KEY", "env-two-key")
    monkeypatch.setenv("OPAI_SOLVERIFY_API_KEY", "env-solver-key")

    captcha_provider.write_captcha_config({
        "api_key": "",
        "solverify_api_key": "",
    })

    saved = env_path.read_text(encoding="utf-8")
    assert "OPAI_2CAPTCHA_API_KEY=file-two-key" in saved
    assert "OPAI_SOLVERIFY_API_KEY=file-solver-key" in saved
    assert "env-two-key" not in saved
    assert "env-solver-key" not in saved
    assert os.environ["OPAI_2CAPTCHA_API_KEY"] == "env-two-key"
    assert os.environ["OPAI_SOLVERIFY_API_KEY"] == "env-solver-key"


def test_browser_context_matches_payment_fingerprint_and_new_default() -> None:
    custom = captcha_provider._captcha_browser_context_options({
        "version": 2,
        "user_agent": "custom-payment-agent",
        "locale": "id-ID",
        "timezone": "Asia/Jakarta",
        "viewport": {
            "width": 412,
            "height": 915,
            "device_scale_factor": 3,
        },
    })
    assert custom == {
        "user_agent": "custom-payment-agent",
        "locale": "id-ID",
        "timezone_id": "Asia/Jakarta",
        "is_mobile": True,
        "has_touch": True,
        "viewport": {"width": 412, "height": 915},
        "device_scale_factor": 3.0,
    }

    default = captcha_provider._captcha_browser_context_options()
    assert default["locale"] == "zh-CN"
    assert default["timezone_id"] == "Asia/Shanghai"
    assert default["viewport"] == {"width": 787, "height": 586}
    assert default["device_scale_factor"] == 1.0
    assert default["is_mobile"] is True
    assert default["has_touch"] is True
    assert "Android 15; Pixel 9" in default["user_agent"]
    assert "Chrome/151.0.0.0" in default["user_agent"]


def test_browser_proxy_routes_preserve_proxy_and_enforce_solverify_http() -> None:
    socks_proxy = "socks5://user:pass@proxy.example:1080"

    regular_routes = captcha_provider._browser_proxy_candidates(socks_proxy)
    assert regular_routes[0][1] == {
        "server": "socks5://proxy.example:1080",
        "username": "user",
        "password": "pass",
    }
    assert all(settings is not None for _, settings in regular_routes)
    assert captcha_provider._browser_proxy_candidates(
        "socks5h://proxy.example:1080"
    )[0][1] == {"server": "socks5://proxy.example:1080"}

    with pytest.raises(
        captcha_provider.CaptchaProviderError,
        match="cannot be rewritten",
    ):
        captcha_provider._browser_proxy_candidates(
            socks_proxy,
            require_http_proxy=True,
        )

    with pytest.raises(captcha_provider.CaptchaProviderError, match="HTTP/HTTPS proxy"):
        captcha_provider._browser_proxy_candidates("", require_http_proxy=True)


def test_solverify_accepts_https_proxy_and_2captcha_accepts_socks() -> None:
    assert captcha_provider._solverify_proxy_fields(
        {
            "server": "https://proxy.example",
            "username": "user",
            "password": "pass",
        }
    ) == {
        "proxyType": "https",
        "proxyAddress": "proxy.example",
        "proxyPort": "443",
        "proxyLogin": "user",
        "proxyPassword": "pass",
    }
    assert captcha_provider._two_captcha_proxy_fields(
        "socks5://user:pass@proxy.example:1080"
    ) == {
        "proxy": "user:pass@proxy.example:1080",
        "proxytype": "SOCKS5",
    }


def test_live_solver_prefers_solverify_then_recaptures_for_2captcha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(solverify_api_key="solver-key", api_key="two-key"),
    )

    def capture(_url: str, **kwargs: Any) -> dict[str, Any]:
        events.append(("capture", kwargs["require_http_proxy"]))
        return {
            "cookies": [{"name": "session", "value": "value"}],
            "solver_proxy": {"server": "http://proxy.example:8080"},
        }

    def solve_solverify(
        _challenge: dict[str, Any],
        progress: Any = None,
    ) -> dict[str, str]:
        events.append(("solverify", progress))
        raise captcha_provider.CaptchaProviderError("Solverify unavailable")

    def solve_two_captcha(
        _challenge: dict[str, Any],
        progress: Any = None,
        *,
        max_attempts: int | None = None,
    ) -> dict[str, str]:
        events.append(("2captcha", max_attempts))
        return TOKENS

    monkeypatch.setattr(captcha_provider, "capture_live_captcha_session", capture)
    monkeypatch.setattr(
        captcha_provider,
        "solve_alibaba_captcha_solverify",
        solve_solverify,
    )
    monkeypatch.setattr(
        captcha_provider,
        "solve_alibaba_captcha",
        solve_two_captcha,
    )

    result = captcha_provider.solve_live_alibaba_captcha(
        "https://app.midtrans.com/snap/v4/redirection/token",
        proxy="socks5://proxy.example:1080",
    )

    assert result["token"] == TOKENS
    assert events == [
        ("capture", True),
        ("solverify", None),
        ("capture", False),
        ("2captcha", 1),
    ]


def test_provider_builds_with_2captcha_only_and_offline_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPAI_MIDTRANS_CAPTCHA_LIVE", "0")
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(api_key="two-key"),
    )
    monkeypatch.setattr(
        captcha_provider,
        "solve_alibaba_captcha",
        lambda challenge, progress=None: TOKENS,
    )
    provider = captcha_provider.build_captcha_token_provider()
    assert provider is not None
    assert provider({"website_url": "https://app.midtrans.com/"}) == {
        "token": TOKENS
    }

    calls: list[str] = []
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(solverify_api_key="solver-key", api_key="two-key"),
    )

    def fail_solverify(
        challenge: dict[str, Any],
        progress: Any = None,
    ) -> dict[str, str]:
        calls.append("solverify")
        raise captcha_provider.CaptchaProviderError("solver failed")

    def solve_two(
        challenge: dict[str, Any],
        progress: Any = None,
    ) -> dict[str, str]:
        calls.append("2captcha")
        return TOKENS

    monkeypatch.setattr(
        captcha_provider,
        "solve_alibaba_captcha_solverify",
        fail_solverify,
    )
    monkeypatch.setattr(captcha_provider, "solve_alibaba_captcha", solve_two)
    provider = captcha_provider.build_captcha_token_provider()
    assert provider is not None
    assert provider({"proxy": "http://proxy.example:8080"}) == {"token": TOKENS}
    assert calls == ["solverify", "2captcha"]


def test_live_provider_forwards_challenge_payment_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPAI_MIDTRANS_CAPTCHA_LIVE", raising=False)
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(api_key="two-key"),
    )
    captured: dict[str, Any] = {}

    def solve_isolated(_website_url: str, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"token": TOKENS}

    monkeypatch.setattr(
        captcha_provider,
        "solve_live_alibaba_captcha_isolated",
        solve_isolated,
    )
    configured_fingerprint = {"version": 2, "locale": "zh-CN"}
    challenge_fingerprint = {
        "version": 2,
        "locale": "id-ID",
        "timezone": "Asia/Jakarta",
    }
    provider = captcha_provider.build_captcha_token_provider(
        payment_fingerprint=configured_fingerprint,
    )
    assert provider is not None

    assert provider({
        "website_url": "https://app.midtrans.com/snap/v4/redirection/token",
        "payment_fingerprint": challenge_fingerprint,
    }) == {"token": TOKENS}
    assert captured["payment_fingerprint"] is challenge_fingerprint


def test_offline_2captcha_uses_initial_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, dict[str, Any], str]] = []
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(
            api_key="two-key",
            api_base_url="https://attacker.example/two",
        ),
    )
    monkeypatch.setattr(captcha_provider.time, "sleep", lambda _seconds: None)

    def legacy_request(
        url: str,
        params: dict[str, Any],
        *,
        method: str = "POST",
    ) -> dict[str, Any]:
        requests.append((url, params, method))
        if url.endswith("/in.php"):
            return {"status": 1, "request": "task-id"}
        return {"status": 1, "request": json.dumps(TOKENS)}

    monkeypatch.setattr(captcha_provider, "_legacy_request", legacy_request)
    initial_loader = captcha_provider.DEFAULT_API_GET_LIB
    result = captcha_provider.solve_alibaba_captcha(
        {
            "website_url": "https://app.midtrans.com/snap/v4/redirection/token#route",
            "scene_id": "scene",
            "prefix": "prefix",
            "api_get_lib": "https://o.alicdn.com/captcha-frontend/dynamicJS/rotating.js",
            "api_get_lib_initial": initial_loader,
        }
    )

    assert result == TOKENS
    assert requests[0][0] == f"{captcha_provider.DEFAULT_API_BASE}/in.php"
    assert requests[1][0] == f"{captcha_provider.DEFAULT_API_BASE}/res.php"
    assert requests[0][1]["api_get_lib"] == initial_loader


def test_solverify_requests_use_fixed_official_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls: list[str] = []
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(
            solverify_api_key="solver-key",
            solverify_api_base_url="https://attacker.example/solver",
        ),
    )
    monkeypatch.setattr(captcha_provider.time, "sleep", lambda _seconds: None)

    def post_json(url: str, _payload: dict[str, Any]) -> dict[str, Any]:
        urls.append(url)
        if url.endswith("/createTask"):
            return {"errorId": 0, "taskId": "task-id"}
        return {
            "errorId": 0,
            "status": "ready",
            "solution": {"value": TOKENS},
        }

    monkeypatch.setattr(captcha_provider, "_post_json", post_json)

    result = captcha_provider.solve_alibaba_captcha_solverify({
        "website_url": "https://app.midtrans.com/snap/v4/redirection/token",
        "scene_id": "scene",
        "prefix": "prefix",
        "region": "sgp",
        "solver_proxy": {"server": "https://proxy.example:443"},
    })

    assert result == TOKENS
    assert urls == [
        f"{captcha_provider.DEFAULT_SOLVERIFY_API_BASE}/createTask",
        f"{captcha_provider.DEFAULT_SOLVERIFY_API_BASE}/getTaskResult",
    ]


@pytest.mark.parametrize(
    ("solver", "responses"),
    [
        (
            "solverify",
            [{
                "errorId": 1,
                "errorCode": "ERROR_BAD_REQUEST",
                "errorDescription": "API key=solver-secret token=solver-token",
                "request": {"clientKey": "solver-secret"},
            }],
        ),
        (
            "2captcha",
            [{
                "errorId": 1,
                "errorCode": "ERROR_BAD_REQUEST",
                "errorDescription": "Bearer provider-secret",
                "request": {"clientKey": "two-secret"},
            }],
        ),
    ],
)
def test_json_provider_create_errors_do_not_expose_response_secrets(
    monkeypatch: pytest.MonkeyPatch,
    solver: str,
    responses: list[dict[str, Any]],
) -> None:
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(
            solverify_api_key="solver-secret",
            api_key="two-secret",
        ),
    )
    monkeypatch.setattr(captcha_provider, "_post_json", lambda *_args, **_kwargs: responses.pop(0))

    challenge = {
        "website_url": "https://app.midtrans.com/snap/v4/redirection/token",
        "scene_id": "scene",
        "prefix": "prefix",
        "region": "sgp",
        "api_get_lib": "https://g.alicdn.com/captcha-frontend/dynamicJS/current.js",
        "solver_proxy": {"server": "https://proxy.example:443"},
    }
    solve = (
        captcha_provider.solve_alibaba_captcha_solverify
        if solver == "solverify"
        else captcha_provider.solve_alibaba_captcha_official
    )

    with pytest.raises(captcha_provider.CaptchaProviderError) as raised:
        solve(challenge)

    message = str(raised.value)
    assert "ERROR_BAD_REQUEST" in message
    assert "solver-secret" not in message
    assert "solver-token" not in message
    assert "provider-secret" not in message
    assert "two-secret" not in message
    assert "[redacted]" in message


@pytest.mark.parametrize("solver", ["solverify", "2captcha"])
def test_json_provider_poll_errors_do_not_expose_response_payload(
    monkeypatch: pytest.MonkeyPatch,
    solver: str,
) -> None:
    responses = iter([
        {"errorId": 0, "taskId": "task-id"},
        {
            "errorId": 1,
            "errorCode": "ERROR_TASK_FAILED",
            "message": "password=provider-password",
            "solution": {"token": "completed-secret"},
        },
    ])
    monkeypatch.setattr(
        captcha_provider,
        "load_captcha_config",
        lambda: _config(
            solverify_api_key="solver-secret",
            api_key="two-secret",
            poll_sec="1",
            solverify_poll_sec="1",
        ),
    )
    monkeypatch.setattr(captcha_provider.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(captcha_provider, "_post_json", lambda *_args, **_kwargs: next(responses))
    challenge = {
        "website_url": "https://app.midtrans.com/snap/v4/redirection/token",
        "scene_id": "scene",
        "prefix": "prefix",
        "region": "sgp",
        "api_get_lib": "https://g.alicdn.com/captcha-frontend/dynamicJS/current.js",
        "solver_proxy": {"server": "https://proxy.example:443"},
    }
    solve = (
        captcha_provider.solve_alibaba_captcha_solverify
        if solver == "solverify"
        else captcha_provider.solve_alibaba_captcha_official
    )

    with pytest.raises(captcha_provider.CaptchaProviderError) as raised:
        solve(challenge)

    message = str(raised.value)
    assert "ERROR_TASK_FAILED" in message
    assert "provider-password" not in message
    assert "completed-secret" not in message
    assert "[redacted]" in message


def test_recursive_tokens_and_provider_specific_timeout_budget() -> None:
    assert captcha_provider._normalize_solution_tokens(
        {"result": {"solution": {"data": {"tokens": TOKENS}}}}
    ) == TOKENS

    only_two = _config(api_key="two-key", timeout_sec="180", max_attempts="2")
    assert captcha_provider._isolated_solver_timeout_seconds(only_two) == 440

    both = _config(
        solverify_api_key="solver-key",
        api_key="two-key",
        solverify_timeout_sec="90",
        timeout_sec="180",
        max_attempts="2",
    )
    assert captcha_provider._isolated_solver_timeout_seconds(both) == 700


def test_default_config_path_is_under_gopay_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPAI_MIDTRANS_CAPTCHA_ENV_FILE", raising=False)

    assert captcha_provider._env_path() == (
        captcha_provider.PROJECT_ROOT / "config" / "captcha.env"
    )
    assert captcha_provider.PROJECT_ROOT.name == "gopay_runtime"
