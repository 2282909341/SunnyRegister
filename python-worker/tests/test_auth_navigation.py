from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from sunny_core.mailbox import MailAccount
from sunny_core.openai_auth import OpenAIEmailRegisterFlow, _goto_auth_page, _goto_chatgpt_page


def test_auth_navigation_accepts_ns_binding_aborted_after_redirect() -> None:
    page = Mock()
    page.url = "https://chatgpt.com/"
    def redirected(*_args, **_kwargs):
        page.url = "https://auth.openai.com/log-in"
        raise RuntimeError("Page.goto: NS_BINDING_ABORTED")
    page.goto.side_effect = redirected
    logs: list[str] = []

    result = _goto_auth_page(page, "https://auth.openai.com/api/accounts/authorize", logs.append)

    assert result is None
    page.goto.assert_called_once()
    assert any("认证导航由上游重定向接管" in message for message in logs)


def test_auth_navigation_retries_when_abort_did_not_land() -> None:
    page = Mock()
    page.url = "about:blank"
    committed = object()
    page.goto.side_effect = [RuntimeError("Page.goto: NS_BINDING_ABORTED"), committed]

    result = _goto_auth_page(page, "https://auth.openai.com/api/accounts/authorize")

    assert result is committed
    assert page.goto.call_count == 2
    assert page.goto.call_args_list[1].kwargs["wait_until"] == "commit"


def test_auth_navigation_accepts_ns_error_abort_after_redirect() -> None:
    page = Mock()
    page.url = "https://chatgpt.com/"

    def redirected(*_args, **_kwargs):
        page.url = "https://auth.openai.com/log-in"
        raise RuntimeError("Page.goto: NS_ERROR_ABORT")

    page.goto.side_effect = redirected

    assert _goto_auth_page(page, "https://auth.openai.com/api/accounts/authorize") is None
    page.goto.assert_called_once()


def test_chatgpt_navigation_retries_transient_ssl_error() -> None:
    page = Mock()
    response = object()
    page.goto.side_effect = [RuntimeError("Page.goto: SSL_ERROR_UNKNOWN"), response]

    assert _goto_chatgpt_page(page) is response
    assert page.goto.call_count == 2
    page.wait_for_timeout.assert_called_once_with(600)


def test_auth_navigation_does_not_accept_unchanged_chatgpt_page() -> None:
    page = Mock()
    page.url = "https://chatgpt.com/"
    committed = object()
    page.goto.side_effect = [RuntimeError("Page.goto: NS_BINDING_ABORTED"), committed]

    result = _goto_auth_page(page, "https://auth.openai.com/api/accounts/authorize")

    assert result is committed
    assert page.goto.call_count == 2


def test_auth_navigation_preserves_unrelated_failures() -> None:
    page = Mock()
    page.goto.side_effect = RuntimeError("Page.goto: net::ERR_CONNECTION_RESET")

    with pytest.raises(RuntimeError, match="ERR_CONNECTION_RESET"):
        _goto_auth_page(page, "https://auth.openai.com/api/accounts/authorize")


def test_auth_navigation_continues_when_dom_timeout_landed_on_auth_page() -> None:
    page = Mock()
    page.url = "about:blank"

    def landed_before_timeout(*_args, **_kwargs):
        page.url = "https://auth.openai.com/about-you"
        raise RuntimeError("Page.goto: Timeout 90000ms exceeded")

    page.goto.side_effect = landed_before_timeout
    logs: list[str] = []

    assert _goto_auth_page(page, "https://auth.openai.com/about-you", logs.append) is None
    page.goto.assert_called_once()
    assert any("DOM 加载等待超时" in message for message in logs)


def test_email_step_waits_when_prefilled_input_is_disabled() -> None:
    logs: list[str] = []
    account = MailAccount("user@icloud.com", "", "", "", "raw")
    flow = OpenAIEmailRegisterFlow(account, "", True, logs.append)
    email_input = Mock()
    email_input.input_value.return_value = account.email
    email_input.is_enabled.return_value = False
    email_input.is_editable.return_value = False
    flow._visible_inputs = Mock(return_value=[email_input])
    flow._click_continue = Mock()

    assert flow._fill_email_if_visible(Mock()) is False
    assert flow._fill_email_if_visible(Mock()) is False

    email_input.fill.assert_not_called()
    flow._click_continue.assert_not_called()
    assert sum("邮箱已提交" in message for message in logs) == 1


def test_email_step_skips_duplicate_fill_for_matching_editable_value() -> None:
    account = MailAccount("user@icloud.com", "", "", "", "raw")
    flow = OpenAIEmailRegisterFlow(account, "", True, None)
    email_input = Mock()
    email_input.input_value.return_value = account.email
    email_input.is_enabled.return_value = True
    email_input.is_editable.return_value = True
    flow._visible_inputs = Mock(return_value=[email_input])
    flow._click_continue = Mock(return_value=True)

    assert flow._fill_email_if_visible(Mock()) is True

    email_input.fill.assert_not_called()
    flow._click_continue.assert_called_once()


def test_native_protocol_handoff_resumes_without_new_signin() -> None:
    account = MailAccount("user@outlook.com", "", "", "", "raw")
    storage_state = {
        "cookies": [{"name": "auth-session", "value": "state", "domain": "auth.openai.com", "path": "/"}],
        "origins": [],
    }
    existing_session = {
        "protocol_browser_handoff": True,
        "protocol_resume_url": "https://auth.openai.com/about-you",
        "protocol_challenge_flow": "oauth_create_account",
        "protocol_email_verified": True,
        "storage_state_json": storage_state,
        "auth_action": "unknown",
    }
    logs: list[str] = []
    flow = OpenAIEmailRegisterFlow(
        account,
        "",
        True,
        logs.append,
        require_refresh_token=False,
        existing_session=existing_session,
        execution_mode="protocol_headless_fallback",
    )
    page = Mock()
    context = Mock()
    context.new_page.return_value = page

    @contextmanager
    def open_browser(**kwargs):
        assert kwargs["storage_state"] is storage_state
        yield SimpleNamespace(context=context, backend="camoufox")

    flow.traffic_optimizer.attach = Mock()
    flow.traffic_optimizer.detach = Mock()
    flow._log_runtime_fingerprint = Mock()
    flow._drive_register_or_login = Mock()
    flow._extract_session_info = Mock(return_value={"access_token": "access", "session_json": {"accessToken": "access"}})
    flow._create_openai_signin_url = Mock(side_effect=AssertionError("handoff must not create a new signin transaction"))

    with (
        patch("sunny_core.openai_auth.open_registration_browser", open_browser),
        patch("sunny_core.openai_auth._goto_auth_page") as goto_auth,
        patch("sunny_core.openai_auth._goto_chatgpt_page") as goto_chatgpt,
    ):
        result = flow.run()

    goto_auth.assert_called_once_with(page, "https://auth.openai.com/about-you", logs.append, timeout=90000)
    goto_chatgpt.assert_not_called()
    flow._create_openai_signin_url.assert_not_called()
    flow._drive_register_or_login.assert_called_once()
    assert result["protocol_browser_handoff"] is True
    assert result["protocol_challenge_flow"] == "oauth_create_account"
    assert any("已恢复协议认证断点" in message for message in logs)
