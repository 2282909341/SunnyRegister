from __future__ import annotations

import base64
from unittest.mock import Mock, patch

import pytest

import sunny_core.mailbox as mailbox_module
from sunny_core.auth_challenges import generate_totp, normalize_totp_secret
from sunny_core.luban_sms import LubanSMSClient, LubanSMSError
from sunny_core.mailbox import (
    URL_API_REQUEST_TIMEOUT,
    MailAccount,
    URLAPIICloudReader,
    _ai1998_latest_mail_html,
    _url_api_strategy,
    account_from_row,
)
from sunny_core.openai_auth import LoginSecretAuthenticationError, OpenAIEmailRegisterFlow, login_or_register
from sunny_core.otp_candidates import extract_otp_candidates
from sunny_core.protocol_auth import ProtocolRegistrationFlow


def test_totp_matches_rfc_vector_and_rejects_invalid_base32() -> None:
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert generate_totp(secret, timestamp=59) == "287082"
    assert normalize_totp_secret("jbsw y3dp ehpk3pxp====") == "JBSWY3DPEHPK3PXP"
    with pytest.raises(ValueError, match="Base32"):
        normalize_totp_secret("not-a-valid-secret")


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"data":{"verification_code":123456}}', "123456"),
        ("<html><body>ChatGPT verification code: <b>234567</b></body></html>", "234567"),
        ("<html><body>OpenAI code <span>2</span><span>4</span><span>6</span><span>8</span><span>0</span><span>2</span></body></html>", "246802"),
        ('<script type="application/json">{"mail":{"body":"OpenAI verification code: 5 6 7 8 9 0"}}</script>', "567890"),
        ('<script>window.__MAIL__={"body":"ChatGPT code: \\u0031\\u0033\\u0035\\u0037\\u0039\\u0031"}</script>', "135791"),
        ("Your OpenAI one-time code is 345678", "345678"),
        (base64.b64encode(b"ChatGPT OTP: 456789").decode(), "456789"),
    ],
)
def test_extract_otp_candidates_supports_common_payloads(payload: str, expected: str) -> None:
    candidates = extract_otp_candidates(payload)
    assert candidates and candidates[0]["code"] == expected
    assert not extract_otp_candidates("ChatGPT reference 1234567 and order 12345")


def test_url_api_html_prefers_mail_body_code_over_sender_suffix_and_date() -> None:
    payload = """
    <section>
      <summary>
        <span class="subject">ChatGPT 用の一時ログインコード</span>
        <span class="date">2026-08-12 20:02:39</span>
      </summary>
      <div class="meta">发件人：noreply_at_tm_openai_com_xd721508@icloud.com</div>
      <div class="body body-rich">この一時検証コードを入力して続行してください:\n536587\n検証コードをリクエストしていない場合、このメールは無視してください。</div>
    </section>
    """

    candidates = extract_otp_candidates(payload)

    assert candidates[0]["code"] == "536587"
    assert candidates[0]["score"] >= 80
    scores = {item["code"]: item["score"] for item in candidates}
    assert scores["721508"] < 0
    assert "202608" not in scores


def test_ai1998_url_api_uses_only_first_latest_mail_card() -> None:
    payload = """
    <html><body>
      <article class="mail-card"><details open>
        <summary><span class="subject">ChatGPT temporary login code</span><span class="date">2026-08-20 10:36:05</span></summary>
        <div class="meta">sender: noreply_at_tm_openai_com_602613@icloud.com</div>
        <div class="body body-rich">Your temporary verification code is: 904540</div>
      </details></article>
      <article class="mail-card"><details>
        <summary><span class="subject">ChatGPT old code</span><span class="date">2026-08-20 09:15:00</span></summary>
        <div class="body body-rich">Verification code: 111111</div>
      </details></article>
    </body></html>
    """

    latest = _ai1998_latest_mail_html(payload)
    candidates = extract_otp_candidates(latest)

    assert _url_api_strategy("https://mail.ai1998.xyz/messages/key/user%40icloud.com") == "ai1998"
    assert candidates[0]["code"] == "904540"
    assert "111111" not in latest
    assert "602613" in latest
    assert next(item for item in candidates if item["code"] == "602613")["score"] < 0


def test_ai1998_reader_dispatches_latest_card_strategy() -> None:
    account = MailAccount(
        "user@icloud.com", "", "", "", "raw",
        mailbox_type="apple", mailbox_channel="url_api",
        access_key="https://mail.ai1998.xyz/messages/key/user%40icloud.com",
    )
    reader = URLAPIICloudReader(account, None)
    reader._latest_generic = Mock(return_value={"otp": "904540"})

    assert reader._latest()["otp"] == "904540"
    reader._latest_generic.assert_called_once_with(URL_API_REQUEST_TIMEOUT, latest_card_only=True)


def test_url_api_html_extracts_standalone_code_and_rejects_rfc_mail_date() -> None:
    payload = """
    <html><body>
      <main>
        <div>邮件 1 封</div>
        <div>ChatGPT 用の一時ログインコード</div>
        <div>Wed, 12 Aug 2026 15:52:26 +0000 (UTC)</div>
        <table><tr><td>
          <p style="font-size: 24px"><span>126399</span></p>
        </td></tr></table>
      </main>
    </body></html>
    """

    candidates = extract_otp_candidates(payload)

    assert candidates[0]["code"] == "126399"
    assert candidates[0]["score"] >= 60
    assert "202615" not in {item["code"] for item in candidates}


def test_url_api_html_ignores_script_and_style_numbers_inside_mail_body() -> None:
    payload = """
    <div class="mail-body">
      <script>window.messageId = 654321;</script>
      <style>.mail-123456 { color: red; }</style>
      <p><span>126399</span></p>
    </div>
    """

    candidates = extract_otp_candidates(payload)

    assert candidates[0]["code"] == "126399"
    scores = {item["code"]: item["score"] for item in candidates}
    assert scores["654321"] < 12
    assert "123456" not in scores


def test_url_api_generic_html_uses_rfc_date_as_message_identity() -> None:
    first = "<html><body><div>Wed, 12 Aug 2026 15:52:26 +0000</div><p><span>126399</span></p></body></html>"
    second = "<html><body><div>Wed, 12 Aug 2026 16:05:10 +0000</div><p><span>126399</span></p></body></html>"

    first_candidate = extract_otp_candidates(first)[0]
    second_candidate = extract_otp_candidates(second)[0]

    assert first_candidate["code"] == second_candidate["code"] == "126399"
    assert first_candidate["key"] != second_candidate["key"]


def test_url_api_candidate_key_changes_for_same_code_in_new_mail() -> None:
    first = '<span class="subject">ChatGPT code</span><span class="date">2026-08-12 20:02:39</span><div class="body">Verification code: 536587</div>'
    second = '<span class="subject">ChatGPT code</span><span class="date">2026-08-12 20:05:10</span><div class="body">Verification code: 536587</div>'

    first_candidate = extract_otp_candidates(first)[0]
    second_candidate = extract_otp_candidates(second)[0]

    assert first_candidate["code"] == second_candidate["code"] == "536587"
    assert first_candidate["key"] != second_candidate["key"]


def test_url_api_reader_ignores_baseline_and_returns_new_code() -> None:
    account = MailAccount(
        email="user@icloud.com",
        password="",
        client_id="",
        refresh_token="",
        raw="user@icloud.com----https://mail.example.test/latest",
        mailbox_type="apple",
        mailbox_channel="url_api",
        access_key="https://mail.example.test/latest",
    )
    reader = URLAPIICloudReader.__new__(URLAPIICloudReader)
    reader.account = account
    reader.log = lambda _message: None
    reader.seen_candidate_keys = set()
    reader.candidate_counts = {}
    old = extract_otp_candidates("ChatGPT verification code 111111")
    new = extract_otp_candidates("ChatGPT verification code 222222")
    responses = [
        {"otp_candidates": old},
        {"otp_candidates": old},
        {"otp_candidates": new + old},
    ]
    reader._latest = Mock(side_effect=responses)

    reader.connect()
    with patch("sunny_core.mailbox.time.sleep", return_value=None):
        assert reader.wait_for_code(0, timeout=5) == "222222"


def test_mczero_url_api_reader_parses_json_codes_and_preview() -> None:
    account = MailAccount(
        email="user@icloud.com",
        password="",
        client_id="",
        refresh_token="",
        raw="user@icloud.com----https://mail.mczero.top/s/token/user@icloud.com",
        mailbox_type="apple",
        mailbox_channel="url_api",
        access_key="https://mail.mczero.top/s/token/user@icloud.com",
    )
    reader = URLAPIICloudReader(account, None)
    response = Mock()
    response.status_code = 200
    response.ok = True
    response.url = "https://mail.mczero.top/s/token/user@icloud.com?format=json&refresh=1"
    response.json.return_value = {
        "state": "ready",
        "message": {
            "id": "message-1",
            "date": "2026-08-15T12:18:30Z",
            "from": "ChatGPT <noreply@icloud.com>",
            "subject": "ChatGPT verification code",
            "codes": ["978744", "978744"],
            "preview": "<p>ChatGPT verification code</p><p>978744</p>",
        },
    }
    with patch.object(mailbox_module.requests, "get", return_value=response) as request:
        message = reader._latest_mczero()
    request.assert_called_once()
    assert "format=json" in request.call_args.args[0]
    assert "refresh=1" in request.call_args.args[0]
    assert message["otp"] == "978744"
    assert message["otp_candidates"][0]["code"] == "978744"
    assert message["body"] == "ChatGPT verification code\n978744"


def test_mczero_url_api_reader_parses_alternate_message_body_field() -> None:
    account = MailAccount(
        "user@icloud.com", "", "", "", "raw",
        mailbox_type="apple", mailbox_channel="url_api",
        access_key="https://mail.mczero.top/s/token/user@icloud.com",
    )
    reader = URLAPIICloudReader(account, None)
    response = Mock()
    response.status_code = 200
    response.ok = True
    response.url = "https://mail.mczero.top/s/token/user@icloud.com?format=json"
    response.json.return_value = {
        "state": "ready",
        "message": {
            "id": "message-2",
            "subject": "ChatGPT verification code",
            "body": "Your one-time code is 482901",
        },
    }
    with patch.object(mailbox_module.requests, "get", return_value=response):
        message = reader._latest_mczero()

    assert message["otp"] == "482901"
    assert message["body"] == "Your one-time code is 482901"


def test_mczero_url_api_reader_falls_back_to_generic_after_specialized_window() -> None:
    account = MailAccount("user@icloud.com", "", "", "", "raw", mailbox_type="apple", mailbox_channel="url_api", access_key="https://mail.mczero.top/s/token/user@icloud.com")
    reader = URLAPIICloudReader.__new__(URLAPIICloudReader)
    reader.account = account
    reader.log = lambda _message: None
    reader.strategy = "mczero"
    reader.seen_candidate_keys = set()
    reader.candidate_counts = {}
    old = extract_otp_candidates("ChatGPT verification code 111111")
    new = extract_otp_candidates("ChatGPT verification code 978744")
    reader._latest = Mock(side_effect=[{"otp_candidates": old}, {"otp_candidates": new}])
    with patch.object(mailbox_module, "URL_API_SPECIALIZED_FALLBACK_SECONDS", 0):
        with patch("sunny_core.mailbox.time.sleep", return_value=None):
            reader.connect()
            assert reader.wait_for_code(0, timeout=5) == "978744"


def test_url_api_reader_never_returns_low_confidence_sender_number() -> None:
    account = MailAccount(
        email="user@icloud.com",
        password="",
        client_id="",
        refresh_token="",
        raw="user@icloud.com----https://mail.example.test/latest",
        mailbox_type="apple",
        mailbox_channel="url_api",
        access_key="https://mail.example.test/latest",
    )
    reader = URLAPIICloudReader.__new__(URLAPIICloudReader)
    reader.account = account
    reader.log = lambda _message: None
    reader.seen_candidate_keys = set()
    reader.candidate_counts = {}
    noise = {"code": "721508", "key": "sender-key", "score": -160}
    reader._latest = Mock(return_value={"otp_candidates": [noise]})

    with patch("sunny_core.mailbox.time.sleep", return_value=None):
        with pytest.raises(TimeoutError):
            reader.wait_for_code(0, timeout=0.01)


def test_url_api_account_row_distinguishes_password_from_mail_url() -> None:
    password_only = account_from_row({
        "email": "user@icloud.com",
        "mailbox_type": "apple",
        "mailbox_channel": "url_api",
        "raw": "user@icloud.com----chatgpt-password",
    })
    assert password_only.chatgpt_password == "chatgpt-password"
    assert password_only.access_key == ""

    with_url = account_from_row({
        "mailbox_type": "apple",
        "mailbox_channel": "url_api",
        "raw": "user@icloud.com----chatgpt-password----https://mail.example.test/latest----JBSWY3DPEHPK3PXP",
    })
    assert with_url.access_key == "https://mail.example.test/latest"
    assert with_url.totp_secret == "JBSWY3DPEHPK3PXP"


def test_luban_sms_lifecycle_and_error_classification() -> None:
    client = LubanSMSClient({"luban_api_key": "key", "luban_service_id": "openai", "luban_base_url": "https://sms.example.test"})
    client._request = Mock(
        side_effect=[
            {"code": 0, "request_id": "req-1", "number": "12025550123"},
            {"code": 0, "msg": "wait"},
            {"code": 0, "sms_msg": "Your ChatGPT code is 654321"},
            {"code": 0},
        ]
    )
    activation = client.get_number()
    assert activation.number == "+12025550123"
    with patch("sunny_core.luban_sms.time.sleep", return_value=None):
        assert client.wait_code(activation.request_id, timeout=10) == "654321"
    client.release(activation.request_id)
    assert client._request.call_args_list[-1].args == ("setStatus",)

    terminal = client._error({"code": 401, "msg": "bad key"}, "failed")
    assert isinstance(terminal, LubanSMSError) and terminal.terminal is True


def test_luban_sms_extracts_nested_code() -> None:
    client = LubanSMSClient({"luban_api_key": "key", "luban_service_id": "openai"})
    client._request = Mock(return_value={"code": 0, "data": {"message": "Your OpenAI code is 654321"}})
    assert client.wait_code("request-1", timeout=1) == "654321"


def test_browser_password_login_uses_exact_imported_password() -> None:
    account = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!", totp_secret="JBSWY3DPEHPK3PXP",
    )
    flow = OpenAIEmailRegisterFlow(account, "", True, None, existing_account=True)
    password_input = Mock()
    flow._visible_inputs = Mock(return_value=[password_input])
    flow._click_continue = Mock(return_value=True)
    page = Mock(url="https://auth.openai.com/log-in/password")

    flow._fill_password_step(page)

    password_input.fill.assert_called_once_with("Short1!", timeout=5000)
    assert account.chatgpt_password == "Short1!"


def test_browser_password_login_uses_saved_password_without_2fa() -> None:
    password_only = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!",
    )
    totp_only = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        totp_secret="JBSWY3DPEHPK3PXP",
    )

    assert OpenAIEmailRegisterFlow(password_only, "", True, None, existing_account=True)._uses_login_secret() is True
    assert OpenAIEmailRegisterFlow(totp_only, "", True, None, existing_account=True)._uses_login_secret() is False


@pytest.mark.parametrize(("headless", "execution_mode"), [(True, "background"), (False, "visible")])
def test_browser_login_secret_failure_retries_same_mode_with_mailbox_otp(headless, execution_mode) -> None:
    account = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!", totp_secret="JBSWY3DPEHPK3PXP",
    )
    first = Mock()
    first.run.side_effect = LoginSecretAuthenticationError("wrong password")
    second = Mock()
    second.run.return_value = {"access_token": "access-token"}

    with patch("sunny_core.openai_auth.OpenAIEmailRegisterFlow", side_effect=[first, second]) as flow_class:
        result = login_or_register(
            account,
            headless=headless,
            existing_account=True,
            require_refresh_token=False,
            execution_mode=execution_mode,
        )

    assert result["access_token"] == "access-token"
    assert flow_class.call_args_list[0].args[2] is headless
    assert flow_class.call_args_list[1].args[2] is headless
    assert flow_class.call_args_list[0].kwargs["prefer_login_secret"] is True
    assert flow_class.call_args_list[1].kwargs["prefer_login_secret"] is False


def test_browser_totp_transition_retries_ls_before_mailbox_fallback() -> None:
    account = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!", totp_secret="JBSWY3DPEHPK3PXP",
    )
    first = Mock()
    first.run.side_effect = LoginSecretAuthenticationError("ChatGPT 2FA 提交后认证页面未继续")
    second = Mock()
    second.run.return_value = {"access_token": "access-token"}

    with patch("sunny_core.openai_auth.OpenAIEmailRegisterFlow", side_effect=[first, second]) as flow_class:
        result = login_or_register(account, existing_account=True, require_refresh_token=False)

    assert result["access_token"] == "access-token"
    assert flow_class.call_count == 2
    assert flow_class.call_args_list[0].kwargs["prefer_login_secret"] is True
    assert flow_class.call_args_list[1].kwargs["prefer_login_secret"] is True


def test_browser_email_otp_timeout_restarts_authentication_once() -> None:
    account = MailAccount("user@example.com", "mailbox-password", "client", "mail-rt", "raw")
    first = Mock()
    first.run.side_effect = TimeoutError("Timed out waiting for OpenAI email OTP after 120 seconds")
    second = Mock()
    second.run.return_value = {"access_token": "access-token"}
    logs: list[str] = []

    with patch("sunny_core.openai_auth.OpenAIEmailRegisterFlow", side_effect=[first, second]) as flow_class:
        result = login_or_register(
            account,
            log=logs.append,
            existing_account=True,
            require_refresh_token=False,
        )

    assert result["access_token"] == "access-token"
    assert flow_class.call_count == 2
    assert flow_class.call_args_list[1].kwargs["existing_session"] is None
    assert any("重新建立隔离登录会话并重试一次" in item for item in logs)


def test_browser_login_secret_account_deactivated_does_not_fallback_to_mailbox_otp() -> None:
    account = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!", totp_secret="JBSWY3DPEHPK3PXP",
    )
    first = Mock()
    first.run.side_effect = LoginSecretAuthenticationError(
        "ChatGPT 密码验证失败: account_deactivated: account disabled"
    )

    with patch("sunny_core.openai_auth.OpenAIEmailRegisterFlow", return_value=first) as flow_class:
        with pytest.raises(LoginSecretAuthenticationError, match="account_deactivated"):
            login_or_register(account, existing_account=True, require_refresh_token=False)

    assert flow_class.call_count == 1


def test_browser_password_step_waits_for_a_transitional_readonly_input() -> None:
    account = MailAccount("user@example.com", "mailbox-password", "client", "mail-rt", "raw")
    messages: list[str] = []
    flow = OpenAIEmailRegisterFlow(account, "", True, messages.append)
    password_input = Mock()
    password_input.is_enabled.return_value = False
    password_input.is_editable.return_value = False
    flow._visible_inputs = Mock(return_value=[password_input])
    page = Mock(url="https://auth.openai.com/create-account/password")

    assert flow._fill_password_step(page) is False
    assert flow._fill_password_step(page) is False
    assert password_input.fill.call_count == 0
    assert messages.count("[认证] 账号需要密码步骤，准备填写 ChatGPT 密码") == 1


def test_browser_login_secret_retries_password_transition_once_before_fallback() -> None:
    account = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!", totp_secret="JBSWY3DPEHPK3PXP",
    )
    messages: list[str] = []

    class Flow(OpenAIEmailRegisterFlow):
        def __init__(self):
            super().__init__(account, "", True, messages.append, existing_account=True)
            self.clock = 0.0
            self.password_fills = 0

        def _has_chatgpt_session(self, _page):
            return False

        def _progress_signature(self, _page):
            return ""

        def _page_reports_existing_account(self, _page):
            return False

        def _detect_route_error(self, _page):
            return ""

        def _has_phone_form(self, _page):
            return False

        def _has_totp_challenge(self, _page):
            return False

        def _has_workspace_selection(self, _page):
            return False

        def _has_visible_password(self, _page):
            return True

        def _fill_password_step(self, _page):
            self.password_fills += 1
            self.login_secret_stage = "password"
            self.login_secret_submitted_at = self.clock
            return True

        def _sleep_checked(self, seconds):
            self.clock += seconds

    flow = Flow()
    page = Mock(url="https://auth.openai.com/log-in/password")
    with patch("sunny_core.openai_auth.time.time", side_effect=lambda: flow.clock):
        with pytest.raises(LoginSecretAuthenticationError, match="密码提交后认证页面未继续"):
            flow._drive_register_or_login(page, 0)

    assert flow.password_fills == 2
    assert any("页面未推进，正在当前登录会话中重试一次" in message for message in messages)


def test_browser_login_secret_stall_requests_mailbox_fallback() -> None:
    account = MailAccount(
        "user@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="Short1!", totp_secret="JBSWY3DPEHPK3PXP",
    )

    class Flow(OpenAIEmailRegisterFlow):
        def __init__(self):
            super().__init__(account, "", True, None, existing_account=True)
            self.clock = 0.0

        def _has_chatgpt_session(self, _page):
            return False

        def _progress_signature(self, _page):
            return "https://auth.openai.com/log-in/password|正在完成账户登录验证"

        def _page_needs_manual_attention(self, _page):
            return False

        def _page_reports_existing_account(self, _page):
            return False

        def _detect_route_error(self, _page):
            return ""

        def _has_phone_form(self, _page):
            return False

        def _has_totp_challenge(self, _page):
            return False

        def _has_workspace_selection(self, _page):
            return False

        def _has_otp_input(self, _page):
            return False

        def _has_visible_password(self, _page):
            return False

        def _fill_email_if_visible(self, _page):
            return False

        def _sleep_checked(self, seconds):
            self.clock += seconds

    flow = Flow()
    page = Mock(url="https://auth.openai.com/log-in/password")
    with patch("sunny_core.openai_auth.time.time", side_effect=lambda: flow.clock):
        with pytest.raises(LoginSecretAuthenticationError, match="密码与 2FA 登录页面超过"):
            flow._drive_register_or_login(page, 0)

    page.reload.assert_called_once()


def test_browser_can_switch_password_page_to_email_otp() -> None:
    account = MailAccount("user@icloud.com", "", "", "", "raw", mailbox_type="apple", mailbox_channel="url_api", access_key="https://mail.example.test")
    flow = OpenAIEmailRegisterFlow(account, "", True, None, existing_account=True)
    target = Mock()
    target.is_visible.return_value = True
    locator = Mock()
    locator.first = target
    page = Mock()
    page.locator.return_value = locator

    assert flow._switch_password_to_email_code(page) is True
    target.click.assert_called_once()


def test_partial_ls_email_login_requires_existing_totp_before_session_completion() -> None:
    account = MailAccount(
        "totp-only@example.com", "mailbox-password", "client", "mail-rt", "raw",
        chatgpt_password="", totp_secret="JBSWY3DPEHPK3PXP",
    )
    events: list[str] = []

    class Flow(OpenAIEmailRegisterFlow):
        def __init__(self):
            super().__init__(account, "", True, events.append, existing_account=True)
            self.phase = "email"

        def _login_secret_rejection(self, _page):
            return ""

        def _has_totp_challenge(self, _page):
            return self.phase == "totp"

        def _has_otp_input(self, _page):
            return self.phase == "totp"

        def _has_chatgpt_session(self, _page):
            return self.phase == "complete"

        def _submit_email_code(self, _page, _timestamp):
            events.append("email")
            self.phase = "totp"

        def _submit_totp_challenge(self, _page):
            events.append("totp")
            self.phase = "complete"

        def _progress_signature(self, _page):
            return ""

        def _sleep_checked(self, _seconds):
            return None

    flow = Flow()
    flow._drive_register_or_login(Mock(url="https://auth.openai.com/email-verification"), 0)
    assert events == ["email", "totp"]


def test_protocol_totp_and_workspace_challenges_use_first_available_workspace() -> None:
    account = MailAccount("user@example.com", "", "", "", "raw", totp_secret="JBSWY3DPEHPK3PXP")
    flow = ProtocolRegistrationFlow(account)
    mfa_result = {"page": {"type": "workspace"}, "oai-client-auth-session": {"workspaces": [{"id": "personal"}, {"id": "team"}]}}
    flow._auth_json_post = Mock(side_effect=[{}, mfa_result, {"continue_url": "https://chatgpt.com/callback"}])
    challenge = {
        "page": {"type": "mfa_challenge"},
        "continue_url": "https://auth.openai.com/mfa-challenge/factor",
        "oai-client-auth-session": {"mfa_challenge_factors": [{"factor_type": "totp", "id": "factor"}]},
    }

    after_mfa = flow._complete_mfa(challenge)
    selected = flow._select_workspace(after_mfa)

    assert selected["continue_url"].endswith("/callback")
    calls = flow._auth_json_post.call_args_list
    assert calls[1].args[0] == "/api/accounts/mfa/verify"
    assert len(calls[1].args[1]["code"]) == 6
    assert calls[2].args[1] == {"workspace_id": "personal"}
