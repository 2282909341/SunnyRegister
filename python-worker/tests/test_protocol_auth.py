from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from sunny_core.browser_traffic import ProxyTrafficMeter
from sunny_core.mailbox import MailAccount
from sunny_core.protocol_auth import (
    AUTHORIZE_CONTINUE_URL,
    ProtocolChallengeRequired,
    ProtocolLoginSecretRejected,
    ProtocolRegistrationError,
    ProtocolRegistrationFlow,
    login_or_register_protocol,
    _response_error,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="", url=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = text.encode("utf-8") if text else json_bytes(payload)
        self.headers = {"content-type": "application/json" if payload is not None else "text/html"}
        self.url = url

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeCookies:
    def __init__(self):
        self.values = {
            "oai-did": "device-id",
            "__Secure-next-auth.session-token": "session-token",
            "_account": "account-id",
        }
        self.jar = []

    def get(self, name):
        return self.values.get(name)


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.cookies = FakeCookies()
        self.headers = {"user-agent": "test-agent"}
        self.closed = False

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError(f"unexpected request: {method} {url}")
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class FakeReader:
    instances = []

    def __init__(self, account, log, proxy_url):
        self.account = account
        self.proxy_url = proxy_url
        self.connected = False
        self.closed = False
        self.__class__.instances.append(self)

    def connect(self):
        self.connected = True

    def wait_for_code(self, _min_timestamp, timeout=10):
        assert timeout == 10
        return "123456"

    def close(self):
        self.closed = True


def test_protocol_challenge_error_omits_upstream_html() -> None:
    response = FakeResponse(
        status_code=403,
        text="<html><head><style>large challenge page</style></head><body>Cloudflare</body></html>",
    )

    error = _response_error(response, "ChatGPT CSRF initialization")

    assert isinstance(error, ProtocolChallengeRequired)
    assert "HTTP 403" in str(error)
    assert "HTML challenge page was omitted" in str(error)
    assert "<html>" not in str(error)


def test_protocol_account_deactivated_error_is_not_misclassified_as_challenge() -> None:
    response = FakeResponse(
        status_code=403,
        text='{"error":{"code":"account_deactivated","message":"account disabled"}}',
    )

    error = _response_error(response, "Verify ChatGPT password")

    assert isinstance(error, ProtocolRegistrationError)
    assert not isinstance(error, ProtocolChallengeRequired)
    assert "account_deactivated" in str(error)


def test_protocol_request_retries_transient_connection_reset() -> None:
    class FlakySession(FakeSession):
        def request(self, method, url, **kwargs):
            self.requests.append((method, url, kwargs))
            if len(self.requests) == 1:
                raise RuntimeError("Failed to perform, curl: (35) Recv failure: Connection reset by peer")
            return FakeResponse(text="ok", url=url)

    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client", "refresh", "raw"),
        session=FlakySession([]),
    )
    with patch("sunny_core.protocol_auth.time.sleep"):
        response = flow._request("GET", "https://chatgpt.com/", step="ChatGPT session initialization")

    assert response.status_code == 200
    assert len(flow.session.requests) == 2


def test_complete_ls_protocol_login_does_not_connect_mailbox_reader() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
    )
    flow = ProtocolRegistrationFlow(account, existing_account=True)
    assert flow._needs_mailbox_reader() is False


def test_mailbox_protocol_login_skips_reader_when_password_is_available() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password",
    )
    flow = ProtocolRegistrationFlow(account, existing_account=True)
    assert flow._needs_mailbox_reader() is False


def test_remail_registration_disallowed_uses_long_bounded_backoff() -> None:
    account = MailAccount("user@icloud.com", "", "", "", "raw", mailbox_type="remail", mailbox_channel="remail_api")
    flow = ProtocolRegistrationFlow(account, session=FakeSession([]))
    flow.device_id = "device-id"
    responses = [
        FakeResponse(status_code=200, payload={}),
        FakeResponse(status_code=400, text='{"error":{"code":"registration_disallowed"}}'),
        FakeResponse(status_code=400, text='{"error":{"code":"registration_disallowed"}}'),
        FakeResponse(status_code=200, payload={"ok": True}),
    ]
    flow._request = Mock(side_effect=responses)
    flow._sentinel_headers = Mock(return_value={"openai-sentinel-token": "sentinel"})
    with patch("sunny_core.protocol_auth.time.sleep") as sleep:
        result = flow._create_account()
    assert result == {"ok": True}
    assert sleep.call_args_list == [call(8), call(20)]
    assert flow._request.call_count == 4


def test_protocol_email_timeout_resends_once_before_validation() -> None:
    class Flow(ProtocolRegistrationFlow):
        def __init__(self, account, session):
            super().__init__(account, session=session)
            self.waits = []

        def _wait_for_email_code(self, min_timestamp, *, timeout=120):
            self.waits.append((min_timestamp, timeout))
            if len(self.waits) == 1:
                raise TimeoutError("mailbox timeout")
            return "123456"

    account = MailAccount("user@outlook.com", "password", "client", "refresh", "raw")
    session = FakeSession([
        FakeResponse(payload={}),
        FakeResponse(payload={}),
        FakeResponse(payload={"page": {"type": "password"}, "continue_url": "https://auth.openai.com/continue"}),
    ])
    flow = Flow(account, session)

    result = flow._verify_email("https://auth.openai.com/email-verification", load_page=False)

    assert result["page"]["type"] == "password"
    assert [timeout for _timestamp, timeout in flow.waits] == [120, 60]
    send_requests = [request for request in session.requests if request[1].endswith("/api/accounts/email-otp/send")]
    assert len(send_requests) == 2
    assert send_requests[1][2]["headers"]["referer"] == "https://auth.openai.com/email-verification"


def test_protocol_email_otp_timeout_restarts_authentication_once() -> None:
    account = MailAccount("user@outlook.com", "password", "client", "refresh", "raw")
    first = Mock()
    first.run.side_effect = TimeoutError("重新发送协议验证码后等待 60 秒仍未收到验证码")
    second = Mock()
    second.run.return_value = {"access_token": "access-token"}
    logs: list[str] = []

    with patch("sunny_core.protocol_auth.ProtocolRegistrationFlow", side_effect=[first, second]) as flow_class:
        result = login_or_register_protocol(account, log=logs.append)

    assert result["access_token"] == "access-token"
    assert flow_class.call_count == 2
    assert any("重新建立认证事务并重试一次" in item for item in logs)


def test_protocol_homepage_reset_falls_back_to_lightweight_csrf() -> None:
    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client", "refresh", "raw"),
        session=FakeSession([]),
    )
    calls = []

    def request(method, url, *, step, **kwargs):
        calls.append((method, url, step))
        if len(calls) == 1:
            raise ProtocolRegistrationError(
                "ChatGPT session initialization request failed: curl: (35) Recv failure: Connection reset by peer"
            )
        if len(calls) == 2:
            return FakeResponse(payload={"csrfToken": "csrf-token"}, url=url)
        return FakeResponse(payload={"url": "https://auth.openai.com/authorize"}, url=url)

    flow._request = request
    flow._start_next_auth()

    assert calls[0][1] == "https://chatgpt.com/"
    assert calls[1][1] == "https://chatgpt.com/api/auth/csrf"
    assert flow.auth_page_url == "https://auth.openai.com/authorize"


def test_protocol_authorize_email_rebuilds_stale_oauth_session_once() -> None:
    account = MailAccount("user@outlook.com", "password", "client", "refresh", "raw")
    stale_session = FakeSession([
        FakeResponse(
            status_code=409,
            text='{"error":{"message":"Your sign-in session is no longer valid.","code":"invalid_state"}}',
            url="https://auth.openai.com/api/accounts/authorize/continue",
        ),
    ])
    fresh_session = FakeSession([
        FakeResponse(
            payload={"page": {"type": "login_password"}, "continue_url": "https://auth.openai.com/log-in/password"},
            url="https://auth.openai.com/api/accounts/authorize/continue",
        ),
    ])
    flow = ProtocolRegistrationFlow(account, session=stale_session, existing_account=True)
    flow.device_id = "stale-device"
    flow._sentinel_headers = Mock(return_value={"openai-sentinel-token": "sentinel"})
    flow._new_session = Mock(return_value=fresh_session)
    flow._start_next_auth = Mock()
    logs: list[str] = []
    flow.log = logs.append

    result = flow._authorize_email()

    assert result["page"]["type"] == "login_password"
    assert stale_session.closed is True
    assert flow.session is fresh_session
    flow._start_next_auth.assert_called_once_with()
    assert any("重建 OAuth 会话并重试一次" in message for message in logs)
    assert len(fresh_session.requests) == 1


def sentinel_response():
    return FakeResponse(payload={"token": "sentinel-challenge", "proofofwork": {"required": False}})


def json_bytes(payload):
    return json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")


def test_protocol_registration_completes_without_browser() -> None:
    responses = [
        FakeResponse(text="landing"),
        FakeResponse(payload={"csrfToken": "csrf-token"}),
        FakeResponse(payload={"url": "https://auth.openai.com/authorize"}),
        FakeResponse(text="auth page"),
        sentinel_response(),
        FakeResponse(payload={"page": {"type": "password"}, "continue_url": "https://auth.openai.com/create-account/password"}),
        FakeResponse(text="password page"),
        sentinel_response(),
        FakeResponse(payload={"page": {"type": "email_otp_verification"}, "continue_url": "https://auth.openai.com/email-verification"}),
        FakeResponse(text="verification page"),
        FakeResponse(payload={"continue_url": "https://auth.openai.com/email-verification"}),
        FakeResponse(payload={"page": {"type": "about_you"}, "continue_url": "https://auth.openai.com/about-you"}),
        FakeResponse(payload={"page": {"type": "about_you"}}),
        sentinel_response(),
        FakeResponse(payload={"continue_url": "https://chatgpt.com/api/auth/callback/openai?code=test"}),
        FakeResponse(text="callback"),
        FakeResponse(payload={"accessToken": "access-token", "account": {"id": "account-id", "planType": "plus"}}),
    ]
    session = FakeSession(responses)
    account = MailAccount(
        email="user@outlook.com",
        password="MailboxPass123!",
        client_id="client-id",
        refresh_token="mail-refresh-token",
        raw="user@outlook.com----MailboxPass123!----client-id----mail-refresh-token",
    )
    checkpoints = []
    traffic_meter = ProxyTrafficMeter(proxy_url="http://proxy.example:8080", tracked_proxy=True)
    with patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader):
        result = ProtocolRegistrationFlow(
            account,
            "http://proxy.example:8080",
            session=session,
            on_progress=lambda checkpoint, _snapshot: checkpoints.append(checkpoint),
            traffic_meter=traffic_meter,
        ).run()

    assert result["access_token"] == "access-token"
    assert result["plan_type"] == "plus"
    assert result["auth_action"] == "register"
    assert result["execution_mode"] == "protocol"
    assert result["protocol_challenge_strategy"] == "native_headless"
    assert result["sentinel_runtime_used"] is False
    assert result["protocol_traffic"]["requests"] == 17
    assert result["protocol_traffic"]["total_bytes"] > 0
    assert traffic_meter.snapshot()["requests"] == 17
    assert traffic_meter.snapshot()["total_bytes"] > 0
    assert set(traffic_meter.snapshot()["by_kind"]) == {"protocol_http"}
    assert checkpoints == [
        "protocol_started",
        "email_submitted",
        "password_created",
        "email_verified",
        "auth_completed",
        "registered",
    ]
    assert session.closed is True
    assert not session.responses
    urls = [url for _method, url, _kwargs in session.requests]
    assert "https://chatgpt.com/api/auth/session" in urls
    assert all("playwright" not in url and "camoufox" not in url for url in urls)
    assert FakeReader.instances[-1].proxy_url == "http://proxy.example:8080"
    assert FakeReader.instances[-1].closed is True


def test_initial_email_verification_redirect_skips_duplicate_authorize_submit() -> None:
    account = MailAccount("user@outlook.com", "MailboxPass123!", "client-id", "mail-refresh-token", "raw")
    flow = ProtocolRegistrationFlow(account, session=FakeSession([]))
    flow.auth_page_url = "https://auth.openai.com/email-verification"
    flow._start_next_auth = lambda: None
    flow._verify_email = lambda _url, **_kwargs: {"page": {"type": "login_success"}, "continue_url": "https://chatgpt.com/callback"}
    flow._finish_session = lambda _url: {
        "access_token": "access",
        "session_json": {"accessToken": "access"},
        "auth_action": "login",
        "protocol_traffic": flow.traffic.snapshot(),
    }

    with (
        patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader),
        patch.object(flow, "_authorize_email") as duplicate_authorize,
    ):
        result = flow.run()

    assert result["access_token"] == "access"
    duplicate_authorize.assert_not_called()


def test_sentinel_device_challenge_stops_protocol_flow() -> None:
    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client-id", "refresh-token", "raw"),
        session=FakeSession(
            [
                FakeResponse(
                    payload={
                        "token": "sentinel-challenge",
                        "proofofwork": {"required": False},
                        "turnstile": {"required": False, "dx": "device-challenge"},
                    }
                )
            ]
        ),
    )
    flow.device_id = "device-id"

    try:
        flow._sentinel_headers("oauth_create_account")
    except ProtocolChallengeRequired as exc:
        assert "browser challenge" in str(exc)
        assert getattr(exc, "traffic")["requests"] == 1
    else:
        raise AssertionError("device challenge must stop protocol mode")


def test_protocol_challenge_exports_browser_handoff_checkpoint() -> None:
    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client-id", "refresh-token", "raw"),
        session=FakeSession([]),
    )
    flow.session.cookies.jar = [
        SimpleNamespace(name="auth-session", value="state", domain="auth.openai.com", path="/", secure=True)
    ]
    flow.auth_page_url = "https://auth.openai.com/create-account"
    flow.browser_resume_url = "https://auth.openai.com/about-you"
    flow.email_verified = True
    flow._start_next_auth = Mock()
    challenge = ProtocolChallengeRequired("Sentinel oauth_create_account requires a browser challenge")
    challenge.challenge_flow = "oauth_create_account"
    flow._authorize_email = Mock(side_effect=challenge)

    with patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader):
        with pytest.raises(ProtocolChallengeRequired) as raised:
            flow.run()

    handoff = raised.value.browser_handoff
    assert handoff["protocol_browser_handoff"] is True
    assert handoff["protocol_resume_url"] == "https://auth.openai.com/about-you"
    assert handoff["protocol_challenge_flow"] == "oauth_create_account"
    assert handoff["protocol_email_verified"] is True
    assert handoff["storage_state_json"]["cookies"][0]["name"] == "auth-session"


def test_sentinel_protocol_strategy_uses_narrow_runtime_headers() -> None:
    class FakeRuntime:
        def requirements_token(self):
            return "sdk-requirements"

        def build_headers(self, **kwargs):
            assert kwargs["flow"] == "oauth_create_account"
            assert kwargs["device_id"] == "device-id"
            assert kwargs["cached_proof"] == "sdk-requirements"
            return {
                "openai-sentinel-token": "runtime-token",
                "openai-sentinel-so-token": "observer-token",
            }

    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client-id", "refresh-token", "raw"),
        session=FakeSession(
            [
                FakeResponse(
                    payload={
                        "token": "sentinel-challenge",
                        "proofofwork": {"required": False},
                        "turnstile": {"required": True, "dx": "device-challenge"},
                    }
                )
            ]
        ),
        challenge_strategy="sentinel_protocol",
    )
    flow.device_id = "device-id"
    flow._sentinel_runtime = FakeRuntime()

    headers = flow._sentinel_headers("oauth_create_account")

    assert headers["openai-sentinel-token"] == "runtime-token"
    assert headers["openai-sentinel-so-token"] == "observer-token"
    request_body = json.loads(flow.session.requests[0][2]["data"])
    assert request_body["p"] == "sdk-requirements"


def test_sentinel_endpoint_challenge_refreshes_proof_in_same_cookie_session() -> None:
    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client-id", "refresh-token", "raw"),
        session=FakeSession([FakeResponse(status_code=403), FakeResponse(payload={"page": {"type": "login_password"}})]),
        challenge_strategy="sentinel_protocol",
    )
    sentinel = Mock(side_effect=[{"openai-sentinel-token": "stale"}, {"openai-sentinel-token": "fresh"}])
    flow._sentinel_headers = sentinel

    response = flow._request_with_sentinel_retry(
        "authorize_continue",
        AUTHORIZE_CONTINUE_URL,
        step="Submit registration email",
        base_headers={"accept": "application/json"},
        data="{}",
    )

    assert response.status_code == 200
    assert sentinel.call_args_list == [call("authorize_continue"), call("authorize_continue")]
    assert flow.session.requests[0][2]["headers"]["openai-sentinel-token"] == "stale"
    assert flow.session.requests[1][2]["headers"]["openai-sentinel-token"] == "fresh"


def test_verify_email_can_reuse_page_loaded_by_auth_redirect() -> None:
    session = FakeSession(
        [
            FakeResponse(
                payload={"page": {"type": "about_you"}, "continue_url": "https://auth.openai.com/about-you"}
            )
        ]
    )
    flow = ProtocolRegistrationFlow(
        MailAccount("user@outlook.com", "password", "client-id", "refresh-token", "raw"),
        session=session,
    )
    flow.reader = FakeReader(flow.account, lambda _message: None, "")
    flow._wait_for_email_code = lambda _timestamp: "123456"

    result = flow._verify_email(
        "https://auth.openai.com/email-verification",
        request_code=False,
        load_page=False,
    )

    assert result["page"]["type"] == "about_you"
    assert len(session.requests) == 1
    assert session.requests[0][1].endswith("/api/accounts/email-otp/validate")


def test_protocol_password_verification_uses_har_sentinel_flow() -> None:
    flow = ProtocolRegistrationFlow(
        MailAccount(
            "user@outlook.com", "mail-password", "client", "refresh", "raw",
            chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
        ),
        session=FakeSession([FakeResponse(payload={"page": {"type": "mfa_challenge"}})]),
    )
    flow.device_id = "device-id"
    with patch.object(flow, "_sentinel_headers", return_value={"openai-sentinel-token": "proof"}) as sentinel:
        result = flow._verify_login_password("https://auth.openai.com/log-in/password")

    assert result["page"]["type"] == "mfa_challenge"
    sentinel.assert_called_once_with("password_verify")
    request = flow.session.requests[0]
    assert request[2]["headers"]["openai-sentinel-token"] == "proof"
    assert json.loads(request[2]["data"]) == {"password": "ChatGPT-password"}


def test_protocol_password_only_login_uses_saved_password_before_adding_2fa() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password",
    )
    callback = Mock(return_value={
        "complete": True,
        "session": {"access_token": "second-access", "session_json": {"accessToken": "second-access"}},
    })
    flow = ProtocolRegistrationFlow(
        account, existing_account=True, session=FakeSession([]),
        post_registration_callback=callback,
    )
    flow.auth_page_url = "https://auth.openai.com/log-in/password"
    flow._start_next_auth = lambda: None
    flow._authorize_email = lambda: {
        "page": {"type": "login_password"},
        "continue_url": "https://auth.openai.com/log-in/password",
    }
    flow._verify_email = Mock(return_value={"page": {"type": "login_success"}, "continue_url": "https://chatgpt.com/callback"})
    flow._verify_login_password = Mock(return_value={"page": {"type": "login_success"}, "continue_url": "https://chatgpt.com/callback"})
    flow._finish_session = lambda _url: {
        "access_token": "access", "session_json": {"accessToken": "access"},
        "auth_action": "login", "protocol_traffic": flow.traffic.snapshot(),
    }

    with patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader):
        result = flow.run()

    assert result["access_token"] == "second-access"
    flow._verify_login_password.assert_called_once()
    flow._verify_email.assert_not_called()
    callback.assert_called_once()


def test_protocol_rejected_password_falls_back_to_mailbox_otp() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
    )
    flow = ProtocolRegistrationFlow(account, existing_account=True, session=FakeSession([]))
    flow.auth_page_url = "https://auth.openai.com/log-in/password"
    flow._start_next_auth = lambda: None
    flow._authorize_email = lambda: {
        "page": {"type": "login_password"},
        "continue_url": "https://auth.openai.com/log-in/password",
    }
    flow._verify_login_password = Mock(side_effect=ProtocolLoginSecretRejected("HTTP 401 wrong password"))
    flow._verify_email = Mock(return_value={"page": {"type": "login_success"}, "continue_url": "https://chatgpt.com/callback"})
    flow._finish_session = lambda _url: {
        "access_token": "access", "session_json": {"accessToken": "access"},
        "auth_action": "login", "protocol_traffic": flow.traffic.snapshot(),
    }

    with patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader):
        result = flow.run()

    assert result["access_token"] == "access"
    flow._verify_login_password.assert_called_once()
    flow._verify_email.assert_called_once()


def test_protocol_rejected_totp_restarts_with_mailbox_otp() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
    )
    flow = ProtocolRegistrationFlow(account, existing_account=True, session=FakeSession([]))
    flow.auth_page_url = "https://auth.openai.com/log-in/password"
    flow._start_next_auth = lambda: None
    flow._authorize_email = lambda: {
        "page": {"type": "login_password"},
        "continue_url": "https://auth.openai.com/log-in/password",
    }
    flow._verify_login_password = Mock(return_value={
        "page": {"type": "mfa_challenge"},
        "continue_url": "https://auth.openai.com/mfa-challenge/factor",
    })
    flow._complete_mfa = Mock(side_effect=ProtocolLoginSecretRejected("HTTP 401 wrong code"))
    flow._restart_with_email_login = Mock(return_value={
        "page": {"type": "login_success"}, "continue_url": "https://chatgpt.com/callback",
    })
    flow._finish_session = lambda _url: {
        "access_token": "access", "session_json": {"accessToken": "access"},
        "auth_action": "login", "protocol_traffic": flow.traffic.snapshot(),
    }

    with patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader):
        result = flow.run()

    assert result["access_token"] == "access"
    flow._restart_with_email_login.assert_called_once()


def test_protocol_account_deactivated_after_password_does_not_enter_totp() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
    )
    flow = ProtocolRegistrationFlow(account, existing_account=True, session=FakeSession([]))

    with pytest.raises(ProtocolRegistrationError, match="account_deactivated"):
        flow._complete_mfa({
            "page": {"type": "account_deactivated"},
            "continue_url": "https://auth.openai.com/account-disabled",
        })


def test_protocol_security_change_refresh_reuses_cookie_session_and_ls() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
    )
    active_session = FakeSession([])
    flow = ProtocolRegistrationFlow(account, existing_account=False, session=active_session)
    flow.auth_page_url = "https://auth.openai.com/log-in/password"
    flow._start_next_auth = Mock()
    flow._authorize_email = Mock(return_value={
        "page": {"type": "login_password"},
        "continue_url": "https://auth.openai.com/log-in/password",
    })
    after_password = {
        "page": {"type": "mfa_challenge"},
        "continue_url": "https://auth.openai.com/mfa-challenge/factor",
    }
    after_mfa = {"page": {"type": "login_success"}, "continue_url": "https://chatgpt.com/callback"}
    flow._verify_login_password = Mock(return_value=after_password)
    flow._complete_mfa = Mock(return_value=after_mfa)
    flow._select_workspace = Mock(return_value=after_mfa)
    flow._finish_session = Mock(return_value={
        "access_token": "new-access", "session_json": {"accessToken": "new-access"},
    })

    result = flow._refresh_session_with_login_secret()

    assert flow.session is active_session
    assert flow.existing_account is True
    assert result["access_token"] == "new-access"
    flow._verify_login_password.assert_called_once()
    flow._complete_mfa.assert_called_once_with(after_password)
    flow._finish_session.assert_called_once_with("https://chatgpt.com/callback")


def test_protocol_at_refresh_rejects_email_otp_route() -> None:
    account = MailAccount(
        "user@outlook.com", "mail-password", "client", "refresh", "raw",
        chatgpt_password="ChatGPT-password", totp_secret="JBSWY3DPEHPK3PXP",
    )
    flow = ProtocolRegistrationFlow(account, existing_account=True, session=FakeSession([]))
    flow.auth_page_url = "https://auth.openai.com/log-in/password"
    flow._start_next_auth = Mock()
    flow._authorize_email = Mock(return_value={
        "page": {"type": "email_otp_verification"},
        "continue_url": "https://auth.openai.com/email-verification",
    })
    flow._verify_email = Mock(side_effect=AssertionError("AT 刷新不得调用邮箱验证码"))

    with patch("sunny_core.protocol_auth.create_mailbox_reader", FakeReader):
        try:
            flow._refresh_session_with_login_secret()
        except ProtocolChallengeRequired as exc:
            assert "禁止使用邮箱验证码" in str(exc)
        else:
            raise AssertionError("协议 AT 刷新应拒绝邮箱验证码路由")

    flow._verify_email.assert_not_called()
