import unittest
import time
import json
from unittest.mock import Mock, patch

from sunny_core.login_secret import RECENT_EMAIL_CODE_MAX_AGE_SECONDS, LoginSecretRateLimitError, LoginSecretSetupFlow, ProtocolLoginSecretSetupFlow, _invalid_auth_state, _invalid_auth_step, _password_already_set, _wrong_email_otp, generate_chatgpt_password
from sunny_core.protocol_auth import ProtocolChallengeRequired
from sunny_core.mailbox import MailAccount, extract_otp


class LoginSecretTests(unittest.TestCase):
    def test_mailbox_otp_requires_six_digits(self):
        self.assertEqual(extract_otp("Your OpenAI code is 123456"), "123456")
        self.assertEqual(extract_otp("Your OpenAI code is 1234"), "")
        self.assertEqual(extract_otp("Reference 12345; code 1234567"), "")

    def test_password_already_set_response_is_detected_without_accepting_unknown_password(self):
        self.assertTrue(_password_already_set({"status": 400, "data": {"code": "password_already_set"}}))
        self.assertTrue(_password_already_set({"status": 400, "data": {"message": "You already have a password."}}))
        self.assertTrue(_password_already_set({"status": 409, "data": {"error": {"type": "password_exists"}}}))
        self.assertFalse(_password_already_set({"status": 400, "data": {"code": "invalid_request_error"}}))

    def test_wrong_email_otp_response_is_recognized_for_retry(self):
        self.assertTrue(_wrong_email_otp({"data": {"code": "wrong_email_otp_code"}}))
        self.assertTrue(_wrong_email_otp({"data": {"message": "Wrong code. Please check it."}}))
        self.assertTrue(_wrong_email_otp({"data": {"error": {"message": "Invalid email OTP"}}}))
        self.assertFalse(_wrong_email_otp({"data": {"code": "account_deactivated"}}))

    def test_invalid_auth_state_is_distinguished_from_generic_conflict(self):
        self.assertTrue(_invalid_auth_state({"data": {"error": {"code": "invalid_state"}}}))
        self.assertTrue(_invalid_auth_state(None, "Your sign-in session is no longer valid"))
        self.assertFalse(_invalid_auth_state({"data": {"error": {"code": "conflict"}}}))

    def test_invalid_auth_step_is_recognized(self):
        self.assertTrue(_invalid_auth_step({"data": {"error": {"code": "invalid_auth_step"}}}))
        self.assertTrue(_invalid_auth_step(None, "Invalid authorization step."))
        self.assertFalse(_invalid_auth_step({"data": {"error": {"code": "invalid_state"}}}))

    def test_browser_reauthentication_timeout_resends_and_waits_again(self):
        class Reader:
            def __init__(self):
                self.calls = []

            def wait_for_code(self, timestamp, timeout):
                self.calls.append((timestamp, timeout))
                if len(self.calls) == 1:
                    raise TimeoutError("mailbox timeout")
                return "654321"

        class Page:
            def __init__(self):
                self.url = ""
                self.codes = []

            def goto(self, url, **_kwargs):
                self.url = url

            def evaluate(self, script, code=None):
                if "email-otp/validate" in script:
                    self.codes.append(code)
                    return {"ok": True, "status": 200, "data": {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}}
                if "api/auth/session" in script:
                    return {"ok": True, "status": 200, "data": {"accessToken": "access-token"}}
                return False

        flow = LoginSecretSetupFlow(self._account(), {}, "")
        flow.reader = Reader()
        page = Page()
        with patch.object(flow, "_click_resend_email_code", return_value=True) as resend:
            result = flow._reauthenticate_with_fresh_email_code(
                page, "https://auth.openai.com/authorize", time.time()
            )
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(page.codes, ["654321"])
        self.assertEqual([timeout for _timestamp, timeout in flow.reader.calls], [120, 60])
        resend.assert_called_once_with(page)

    def test_browser_reauthentication_snapshots_mailbox_before_auth_url_sends_code(self):
        events = []

        class Reader:
            @staticmethod
            def wait_for_code(_timestamp, _timeout):
                return "654321"

        class Page:
            url = ""

            def goto(self, url, **_kwargs):
                events.append(("goto", url))
                self.url = url

            @staticmethod
            def evaluate(script, _code=None):
                if "email-otp/validate" in script:
                    return {"ok": True, "status": 200, "data": {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}}
                if "api/auth/session" in script:
                    return {"ok": True, "status": 200, "data": {"accessToken": "access-token"}}
                return False

        flow = LoginSecretSetupFlow(self._account(), {}, "")
        flow._reader_instance = Mock(side_effect=lambda: events.append(("mailbox", "connect")) or Reader())

        result = flow._reauthenticate_with_fresh_email_code(
            Page(), "https://auth.openai.com/authorize", time.time()
        )

        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(events[:2], [("mailbox", "connect"), ("goto", "https://auth.openai.com/authorize")])

    def test_password_reauthentication_completes_existing_totp_after_email(self):
        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.phase = "totp"
                self.used_totp = ""

            def _page_state(self, _page):
                if self.phase == "totp":
                    return {
                        "url": "https://auth.openai.com/authorize",
                        "passwordInputs": 0,
                        "codeInputs": 1,
                        "text": "Enter verification code",
                    }
                return {
                    "url": "https://chatgpt.com/?action=add_password",
                    "passwordInputs": 0,
                    "codeInputs": 0,
                    "text": "",
                }

            def _fill_code(self, page, code):
                self.used_totp = code
                self.phase = "complete"
                page.url = "https://chatgpt.com/?action=add_password"
                return True

            def _session_json(self, _page):
                if not self.used_totp:
                    raise RuntimeError("not authenticated")
                return {"accessToken": "access-token"}

            def _sleep(self, _seconds):
                return None

        self_account = self._account()
        self_account.totp_secret = "JBSWY3DPEHPK3PXP"
        page = type("Page", (), {"url": "https://chatgpt.com/?action=add_password"})()
        flow = Flow()
        with patch("sunny_core.login_secret.generate_totp", return_value="654321"):
            flow._complete_existing_totp_after_email_reauth(page)
        self.assertEqual(flow.used_totp, "654321")

    def test_password_reauthentication_tries_recent_registration_code_before_mailbox(self):
        class Reader:
            def wait_for_code(self, *_args):
                raise AssertionError("the recent registration code should be tried first")

        class Page:
            def __init__(self):
                self.url = ""
                self.codes = []

            def goto(self, url, **_kwargs):
                self.url = url

            def evaluate(self, script, code=None):
                if "email-otp/validate" in script:
                    self.codes.append(code)
                    return {"ok": True, "status": 200, "data": {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}}
                if "api/auth/session" in script:
                    return {"ok": True, "status": 200, "data": {"accessToken": "access-token"}}
                return False

        flow = LoginSecretSetupFlow(self._account(), {}, "")
        flow.reader = Reader()
        page = Page()
        logs = []
        flow.log = logs.append
        result = flow._reauthenticate_with_fresh_email_code(
            page,
            "https://auth.openai.com/authorize",
            time.time(),
            recent_email_code="123456",
            recent_email_code_at=time.time(),
            prefer_recent_email_code=True,
        )
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(page.codes, ["123456"])
        self.assertTrue(any("已成功复用注册/登录阶段邮箱验证码完成重认证" in item for item in logs))

    def test_browser_login_secret_refreshes_access_token_after_security_change(self):
        class Context:
            def storage_state(self):
                return {"cookies": [{"name": "session", "value": "new"}]}

        class Flow(LoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(account, {"access_token": "old-token", "expires_at": 1}, "")
                self.session_reads = 0

            def _session_json(self, _page):
                self.session_reads += 1
                return {"accessToken": "old-token" if self.session_reads == 1 else "new-token"}

            def _add_password(self, _page):
                return "new-password"

            def _refresh_session_with_login_secret(self, _page):
                self.session_reads += 1
                return {"accessToken": "new-token"}

            @staticmethod
            def _access_token_is_valid(_page, token):
                return token == "new-token"

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        flow = Flow(account)
        result = flow._run_on_page(Mock(), Context())
        self.assertEqual(result["session"]["access_token"], "new-token")
        self.assertEqual(result["session"]["session_json"]["accessToken"], "new-token")
        self.assertTrue(result["access_token_refreshed"])
        self.assertNotIn("expires_at", result["session"])
        self.assertEqual(flow.session_reads, 2)

    def test_protocol_login_secret_refreshes_access_token_after_security_change(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                protocol_session = Mock()
                protocol_session.refresh_session_with_login_secret.return_value = {
                    "session_json": {"accessToken": "new-token"}
                }
                super().__init__(account, {"access_token": "old-token", "expires_at": 1}, protocol_session)
                self.session_reads = 0

            def _session_json(self):
                self.session_reads += 1
                return {"accessToken": "old-token" if self.session_reads == 1 else "new-token"}

            def _add_password(self, _password):
                return {"accessToken": "after-password"}

            @staticmethod
            def _access_token_is_valid(token):
                return token == "new-token"

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        result = Flow(account).run()
        self.assertEqual(result["session"]["access_token"], "new-token")
        self.assertEqual(result["session"]["session_json"]["accessToken"], "new-token")
        self.assertTrue(result["access_token_refreshed"])
        self.assertNotIn("expires_at", result["session"])

    def test_browser_valid_access_token_skips_login_secret_refresh(self):
        class Context:
            @staticmethod
            def storage_state():
                return {"cookies": []}

        class Flow(LoginSecretSetupFlow):
            def _session_json(self, _page):
                return {"accessToken": "current-token"}

            def _access_token_is_valid(self, _page, token):
                return token == "current-token"

            def _refresh_session_with_login_secret(self, _page):
                raise AssertionError("有效 AT 不应重新登录")

        account = self._account()
        account.chatgpt_password = "ChatGPT-password"
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        result = Flow(
            account,
            {"access_token": "old-token"},
            "",
            force_access_token_refresh=True,
        )._run_on_page(Mock(), Context())

        self.assertTrue(result["complete"])
        self.assertTrue(result["access_token_refreshed"])
        self.assertEqual(result["session"]["access_token"], "current-token")

    def test_browser_at_probe_uses_shared_probe_and_keeps_diagnostic(self):
        flow = LoginSecretSetupFlow(self._account(), {}, "http://proxy.example:8080")
        page = Mock()
        with patch(
            "sunny_core.access_token_probe.probe_access_token",
            return_value={"status": "blocked", "error": "边缘拦截，未判定令牌失效"},
        ) as probe:
            self.assertFalse(flow._access_token_is_valid(page, "access-token"))

        probe.assert_called_once_with("access-token", "http://proxy.example:8080")
        page.evaluate.assert_not_called()
        self.assertIn("边缘拦截", flow.last_access_token_probe_error)

    def test_browser_at_refresh_rejects_email_fallback(self):
        class Flow(LoginSecretSetupFlow):
            def _page_state(self, _page):
                return {
                    "url": "https://auth.openai.com/email-verification",
                    "passwordInputs": 0,
                    "codeInputs": 1,
                    "text": "email verification",
                }

            def _reader_instance(self):
                raise AssertionError("AT 刷新禁止读取邮箱验证码")

            def _sleep(self, _seconds):
                return None

        page = type("Page", (), {"url": "https://auth.openai.com/email-verification"})()
        with self.assertRaisesRegex(RuntimeError, "禁止回退邮箱验证码"):
            Flow(self._account(), {}, "")._complete_reauthentication(
                page,
                time.time(),
                "ChatGPT-password",
                allow_email_fallback=False,
            )

    def test_protocol_valid_access_token_skips_login_secret_refresh(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def _session_json(self):
                return {"accessToken": "current-token"}

            def _access_token_is_valid(self, token):
                return token == "current-token"

            def _refresh_session_with_login_secret(self):
                raise AssertionError("有效 AT 不应重新登录")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        flow = Flow(account, {"access_token": "old-token"}, object())
        flow._add_password = lambda _password: {"accessToken": "current-token"}
        result = flow.run()

        self.assertTrue(result["complete"])
        self.assertTrue(result["access_token_refreshed"])
        self.assertEqual(result["session"]["access_token"], "current-token")

    def test_browser_partial_security_change_skips_access_token_refresh(self):
        class Flow(LoginSecretSetupFlow):
            def _session_json(self, _page):
                return {"accessToken": "current-token"}

            def _add_password(self, _page):
                return "new-password"

            def _setup_2fa(self, _page, _password):
                raise TimeoutError("邮箱验证码等待超时")

            def _refresh_session_with_login_secret(self, _page):
                raise AssertionError("partial LS must not trigger AT refresh")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, "")._run_on_page(
            Mock(), Mock(storage_state=lambda: {"cookies": []})
        )
        self.assertFalse(result["complete"])
        self.assertFalse(result["access_token_refreshed"])
        self.assertTrue(any("添加2FA失败" in error for error in result["errors"]))

    def test_browser_persists_password_before_two_factor_step(self):
        class Flow(LoginSecretSetupFlow):
            def _session_json(self, _page):
                return {"accessToken": "current-token"}

            def _add_password(self, _page):
                return "new-password"

            def _setup_2fa(self, _page, _password):
                raise TimeoutError("邮箱验证码等待超时")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        saved = []
        result = Flow(
            account,
            {"access_token": "current-token"},
            "",
            on_credential_saved=lambda kind, value: saved.append((kind, value)),
        )._run_on_page(Mock(), Mock(storage_state=lambda: {"cookies": []}))

        self.assertFalse(result["complete"])
        self.assertIn(("password", "new-password"), saved)

    def test_browser_password_is_persisted_inside_confirmed_remote_step(self):
        class Flow(LoginSecretSetupFlow):
            def _dismiss_continue_gate(self, _page):
                return False

            def _reauth_for_password(self, _page, _password, **_kwargs):
                return None

            def _add_password_via_protocol(self, _page, _password):
                return {"ok": True, "status": 200, "data": {"success": True}}

        saved = []
        account = self._account()
        account.chatgpt_password = ""
        flow = Flow(
            account,
            {},
            "",
            on_credential_saved=lambda kind, value: saved.append((kind, value)),
        )

        password = flow._add_password(Mock())

        self.assertEqual(account.chatgpt_password, password)
        self.assertEqual(saved, [("password", password)])

    def test_browser_totp_is_persisted_before_session_refresh_failure(self):
        class Flow(LoginSecretSetupFlow):
            def __init__(self, account, saved):
                super().__init__(
                    account,
                    {},
                    "",
                    on_credential_saved=lambda kind, value: saved.append((kind, value)),
                )
                self.info_calls = 0

            def _mfa_info(self, _page, _access_token):
                self.info_calls += 1
                enabled = self.info_calls > 1
                factors = [{"id": "factor-id", "factor_type": "totp"}] if enabled else []
                return {"ok": True, "status": 200, "data": {"mfa_enabled": enabled, "factors": {"totp": factors}}}

            def _enroll_totp(self, _page, _access_token):
                return {"ok": True, "status": 200, "data": {"secret": "NEW-TOTP", "session_id": "session-id", "factor": {"id": "factor-id"}}}

            def _activate_totp(self, _page, _access_token, _code, _session_id):
                return {"ok": True, "status": 200, "data": {"success": True}}

            def _fresh_totp_code(self, _secret, **_kwargs):
                return "123456"

            def _session_json(self, _page):
                raise RuntimeError("session unavailable after MFA activation")

        saved = []
        account = self._account()
        account.totp_secret = ""

        with self.assertRaisesRegex(RuntimeError, "session unavailable"):
            Flow(account, saved)._setup_2fa_protocol(Mock(), "access-token")

        self.assertEqual(account.totp_secret, "NEW-TOTP")
        self.assertEqual(saved, [("totp_secret", "NEW-TOTP")])

    def test_protocol_partial_security_change_skips_access_token_refresh(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def _session_json(self):
                return {"accessToken": "current-token"}

            def _add_password(self, _password):
                return {"accessToken": "current-token"}

            def _setup_2fa(self, _access_token):
                raise TimeoutError("邮箱验证码等待超时")

            def _refresh_session_with_login_secret(self):
                raise AssertionError("partial LS must not trigger AT refresh")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, object()).run()
        self.assertFalse(result["complete"])
        self.assertFalse(result["access_token_refreshed"])
        self.assertTrue(any("添加2FA失败" in error for error in result["errors"]))

    def test_protocol_password_is_persisted_before_session_refresh_failure(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def _reauthenticate(self, *_args, **_kwargs):
                return {"accessToken": "access-token"}

            def _request(self, *_args, **_kwargs):
                return 200, {"success": True}, ""

            def _session_json(self):
                raise RuntimeError("session unavailable after password creation")

        saved = []
        account = self._account()
        account.chatgpt_password = ""
        flow = Flow(
            account,
            {},
            object(),
            on_credential_saved=lambda kind, value: saved.append((kind, value)),
        )

        with self.assertRaisesRegex(RuntimeError, "session unavailable"):
            flow._add_password("new-password")

        self.assertEqual(account.chatgpt_password, "new-password")
        self.assertEqual(saved, [("password", "new-password")])

    def test_protocol_totp_success_updates_shared_account_for_browser_takeover(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def _session_json(self):
                return {"accessToken": "current-token"}

            def _add_password(self, _password):
                return {"accessToken": "current-token"}

            def _setup_2fa(self, _access_token):
                return "NEW-TOTP-SECRET", {"accessToken": "current-token"}

            def _access_token_is_valid(self, _token):
                return True

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, object()).run()

        self.assertTrue(result["complete"])
        self.assertEqual(result["totp_secret"], "NEW-TOTP-SECRET")
        self.assertEqual(account.totp_secret, "NEW-TOTP-SECRET")

    def test_browser_password_failure_skips_two_factor_step(self):
        class Flow(LoginSecretSetupFlow):
            def _session_json(self, _page):
                return {"accessToken": "current-token"}

            def _add_password(self, _page):
                raise RuntimeError("password failed")

            def _setup_2fa(self, _page, _password):
                raise AssertionError("2FA must not run before password succeeds")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, "")._run_on_page(
            Mock(), Mock(storage_state=lambda: {"cookies": []})
        )
        self.assertFalse(result["complete"])
        self.assertTrue(any("添加密码失败" in error for error in result["errors"]))
        self.assertTrue(any("添加2FA未执行" in error for error in result["errors"]))

    def test_protocol_password_failure_skips_two_factor_step(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def _session_json(self):
                return {"accessToken": "current-token"}

            def _add_password(self, _password):
                raise RuntimeError("password failed")

            def _setup_2fa(self, _access_token):
                raise AssertionError("2FA must not run before password succeeds")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, object()).run()
        self.assertFalse(result["complete"])
        self.assertTrue(any("添加密码失败" in error for error in result["errors"]))
        self.assertTrue(any("添加2FA未执行" in error for error in result["errors"]))

    def test_browser_new_login_secret_sets_password_before_two_factor(self):
        operations = []

        class Flow(LoginSecretSetupFlow):
            def _session_json(self, _page):
                return {"accessToken": "current-token"}

            def _setup_2fa(self, _page, _password):
                operations.append("2fa")
                self.account.totp_secret = "NEW-TOTP-SECRET"
                return "NEW-TOTP-SECRET", {"accessToken": "current-token"}

            def _add_password(self, _page):
                operations.append("password")
                return "new-password"

            def _access_token_is_valid(self, _page, _token):
                return True

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, "")._run_on_page(
            Mock(), Mock(storage_state=lambda: {"cookies": []})
        )

        self.assertEqual(operations, ["password", "2fa"])
        self.assertTrue(result["complete"])

    def test_protocol_new_login_secret_sets_password_before_two_factor(self):
        operations = []

        class Flow(ProtocolLoginSecretSetupFlow):
            def _session_json(self):
                return {"accessToken": "current-token"}

            def _setup_2fa(self, _access_token):
                operations.append("2fa")
                return "NEW-TOTP-SECRET", {"accessToken": "current-token"}

            def _add_password(self, _password):
                operations.append("password")
                return {"accessToken": "revoked-token"}

            def _access_token_is_valid(self, token):
                return token == "fresh-token"

            def _refresh_session_with_login_secret(self):
                return {"accessToken": "fresh-token"}

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, object()).run()

        self.assertEqual(operations, ["password", "2fa"])
        self.assertTrue(result["complete"])
        self.assertEqual(result["session"]["access_token"], "fresh-token")

    def test_browser_existing_password_skips_password_and_adds_two_factor(self):
        operations = []

        class Flow(LoginSecretSetupFlow):
            def _session_json(self, _page):
                return {"accessToken": "current-token"}

            def _add_password(self, _page):
                raise AssertionError("existing password must skip password setup")

            def _setup_2fa(self, _page, password):
                operations.append(("2fa", password))
                return "NEW-TOTP-SECRET", {"accessToken": "current-token"}

            def _access_token_is_valid(self, _page, _token):
                return True

        account = self._account()
        account.chatgpt_password = "existing-password"
        account.totp_secret = ""
        result = Flow(account, {"access_token": "current-token"}, "")._run_on_page(
            Mock(), Mock(storage_state=lambda: {"cookies": []})
        )

        self.assertEqual(operations, [("2fa", "existing-password")])
        self.assertTrue(result["complete"])
        self.assertFalse(result["password_added"])
        self.assertTrue(result["totp_added"])

    def test_protocol_existing_two_factor_skips_two_factor_and_refreshes(self):
        operations = []

        class Flow(ProtocolLoginSecretSetupFlow):
            def _session_json(self):
                return {"accessToken": "current-token"}

            def _add_password(self, password):
                operations.append(("password", password))
                return {"accessToken": "current-token"}

            def _setup_2fa(self, _access_token):
                raise AssertionError("existing 2FA must skip 2FA setup")

            def _access_token_is_valid(self, token):
                return token == "fresh-token"

            def _refresh_session_with_login_secret(self):
                return {"accessToken": "fresh-token"}

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = "existing-totp-secret"
        result = Flow(account, {"access_token": "current-token"}, object()).run()

        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0][0], "password")
        self.assertTrue(result["complete"])
        self.assertTrue(result["password_added"])
        self.assertFalse(result["totp_added"])
        self.assertTrue(result["access_token_refreshed"])

    def test_login_secret_is_incomplete_when_reauthentication_returns_old_access_token(self):
        class Flow(LoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(account, {"access_token": "old-token"}, "")

            def _session_json(self, _page):
                return {"accessToken": "old-token"}

            def _add_password(self, _page):
                return "new-password"

            def _refresh_session_with_login_secret(self, _page):
                raise RuntimeError("登录密钥重认证后仍返回注册阶段的旧 Access Token")

        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        result = Flow(account)._run_on_page(Mock(), Mock(storage_state=lambda: {"cookies": []}))
        self.assertFalse(result["complete"])
        self.assertFalse(result["access_token_refreshed"])
        self.assertTrue(any("旧 Access Token" in error for error in result["errors"]))

    def test_password_reauthentication_reads_distinct_new_code_after_recent_code_rejected(self):
        class Reader:
            def __init__(self):
                self.calls = []

            def wait_for_code(self, _timestamp, timeout):
                self.calls.append(timeout)
                return "654321"

        class Page:
            def __init__(self):
                self.url = ""
                self.codes = []

            def goto(self, url, **_kwargs):
                self.url = url

            def evaluate(self, script, code=None):
                if "email-otp/validate" in script:
                    self.codes.append(code)
                    if len(self.codes) == 1:
                        return {"ok": False, "status": 401, "data": {"code": "wrong_email_otp_code", "message": "Wrong code"}}
                    return {"ok": True, "status": 200, "data": {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}}
                if "api/auth/session" in script:
                    return {"ok": True, "status": 200, "data": {"accessToken": "access-token"}}
                return False

        flow = LoginSecretSetupFlow(self._account(), {}, "")
        flow.reader = Reader()
        page = Page()
        result = flow._reauthenticate_with_fresh_email_code(
            page,
            "https://auth.openai.com/authorize",
            time.time(),
            recent_email_code="123456",
            recent_email_code_at=time.time(),
            prefer_recent_email_code=True,
        )
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(page.codes, ["123456", "654321"])
        self.assertEqual(flow.reader.calls, [10])

    def test_protocol_reauthentication_timeout_resends_once(self):
        class Reader:
            def __init__(self):
                self.calls = []

            def wait_for_code(self, timestamp, timeout):
                self.calls.append((timestamp, timeout))
                if len(self.calls) == 1:
                    raise TimeoutError("mailbox timeout")
                return "654321"

        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(account, {}, object())
                self.reader = Reader()
                self.requests = []

            def _request(self, method, url, **kwargs):
                self.requests.append((method, url, kwargs))
                if url.endswith("/api/auth/csrf"):
                    return 200, {"csrfToken": "csrf-token"}, ""
                if "/api/auth/signin/openai?" in url:
                    return 200, {"url": "https://auth.openai.com/authorize"}, ""
                if url.endswith("/api/accounts/email-otp/validate"):
                    return 200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}, ""
                if url.endswith("/api/auth/session"):
                    return 200, {"accessToken": "access-token"}, ""
                return 200, {}, ""

        flow = Flow(self._account())
        result = flow._reauthenticate("https://chatgpt.com/?action=add_password")
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual([timeout for _timestamp, timeout in flow.reader.calls], [120, 60])
        resend_requests = [item for item in flow.requests if item[1].endswith("/api/accounts/email-otp/send")]
        self.assertEqual(len(resend_requests), 1)
        self.assertEqual(resend_requests[0][2]["headers"]["referer"], "https://auth.openai.com/authorize")

    def test_protocol_password_reauthentication_tries_recent_code_then_distinct_code(self):
        class Reader:
            def __init__(self):
                self.calls = []

            def wait_for_code(self, _timestamp, timeout):
                self.calls.append(timeout)
                return "654321"

        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(
                    account,
                    {},
                    object(),
                    recent_email_code="123456",
                    recent_email_code_at=time.time(),
                )
                self.reader = Reader()
                self.codes = []

            def _request(self, method, url, **kwargs):
                if url.endswith("/api/auth/csrf"):
                    return 200, {"csrfToken": "csrf-token"}, ""
                if "/api/auth/signin/openai?" in url:
                    return 200, {"url": "https://auth.openai.com/authorize"}, ""
                if url.endswith("/api/accounts/email-otp/validate"):
                    code = kwargs.get("json", {}).get("code")
                    self.codes.append(code)
                    if len(self.codes) == 1:
                        return 401, {"code": "wrong_email_otp_code", "message": "Wrong code"}, "Wrong code"
                    return 200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}, ""
                if url.endswith("/api/auth/session"):
                    return 200, {"accessToken": "access-token"}, ""
                return 200, {}, ""

        flow = Flow(self._account())
        result = flow._reauthenticate(
            "https://chatgpt.com/?action=add_password",
            prefer_recent_email_code=True,
        )
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(flow.codes, ["123456", "654321"])
        self.assertEqual(flow.reader.calls, [10])

    def test_protocol_reauthentication_snapshots_mailbox_before_auth_url_sends_code(self):
        events = []

        class Reader:
            @staticmethod
            def wait_for_code(_timestamp, _timeout):
                return "654321"

        class Flow(ProtocolLoginSecretSetupFlow):
            def _reader_instance(self):
                events.append(("mailbox", "connect"))
                return Reader()

            def _request(self, method, url, **kwargs):
                if url.endswith("/api/auth/csrf"):
                    return 200, {"csrfToken": "csrf-token"}, ""
                if "/api/auth/signin/openai?" in url:
                    return 200, {"url": "https://auth.openai.com/authorize"}, ""
                if method == "GET" and url == "https://auth.openai.com/authorize":
                    events.append(("auth", "send"))
                    return 200, {}, ""
                if url.endswith("/api/accounts/email-otp/validate"):
                    return 200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}, ""
                if url.endswith("/api/auth/session"):
                    return 200, {"accessToken": "access-token"}, ""
                return 200, {}, ""

        flow = Flow(self._account(), {}, object())
        result = flow._reauthenticate("https://chatgpt.com/?action=add_password")

        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(events[:2], [("mailbox", "connect"), ("auth", "send")])

    def test_protocol_reauthentication_reads_mailbox_when_recent_code_expired(self):
        class Reader:
            def __init__(self):
                self.calls = []

            def wait_for_code(self, _timestamp, timeout):
                self.calls.append(timeout)
                return "654321"

        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(
                    account,
                    {},
                    object(),
                    recent_email_code="123456",
                    recent_email_code_at=time.time() - RECENT_EMAIL_CODE_MAX_AGE_SECONDS - 1,
                )
                self.reader = Reader()
                self.codes = []
                self.logs = []
                self.log = self.logs.append

            def _request(self, method, url, **kwargs):
                if url.endswith("/api/auth/csrf"):
                    return 200, {"csrfToken": "csrf-token"}, ""
                if "/api/auth/signin/openai?" in url:
                    return 200, {"url": "https://auth.openai.com/authorize"}, ""
                if url.endswith("/api/accounts/email-otp/validate"):
                    self.codes.append(kwargs.get("json", {}).get("code"))
                    return 200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}, ""
                if url.endswith("/api/auth/session"):
                    return 200, {"accessToken": "access-token"}, ""
                return 200, {}, ""

        flow = Flow(self._account())
        result = flow._reauthenticate(
            "https://chatgpt.com/?action=add_password",
            prefer_recent_email_code=True,
        )
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(flow.codes, ["654321"])
        self.assertEqual(flow.reader.calls, [120])
        self.assertTrue(any("已超过复用窗口" in item for item in flow.logs))
        self.assertTrue(any("已使用邮箱渠道最新验证码完成重认证" in item for item in flow.logs))

    def test_protocol_password_invalid_state_switches_to_browser_takeover(self):
        flow = ProtocolLoginSecretSetupFlow(self._account(), {}, object())
        flow._reauthenticate = Mock(return_value={"accessToken": "access-token"})
        flow._request = Mock(return_value=(409, {"error": {"code": "invalid_state", "message": "Your sign-in session is no longer valid."}}, "invalid_state"))

        with self.assertRaises(ProtocolChallengeRequired):
            flow._add_password("Strong-password-1!")

        flow._reauthenticate.assert_called_once_with(
            "https://chatgpt.com/?action=add_password",
            prefer_recent_email_code=True,
            post_login_add_password=True,
        )

    def test_protocol_password_reauthentication_uses_dedicated_add_password_transaction(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(account, {}, object())
                self.signin_url = ""

            def _request(self, method, url, **kwargs):
                if url.endswith("/api/auth/csrf"):
                    return 200, {"csrfToken": "csrf-token"}, ""
                if "/api/auth/signin/openai?" in url:
                    self.signin_url = url
                    return 200, {"url": "https://auth.openai.com/authorize"}, ""
                if url.endswith("/api/accounts/email-otp/validate"):
                    return 200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}, ""
                if url.endswith("/api/auth/session"):
                    return 200, {"accessToken": "access-token"}, ""
                return 200, {}, ""

            def _wait_for_code(self, _reader, _min_timestamp, _timeout):
                return "654321"

        flow = Flow(self._account())
        flow.reader = object()
        flow._reauthenticate(
            "https://chatgpt.com/?action=add_password",
            post_login_add_password=True,
        )

        self.assertIn("post_login_add_password=true", flow.signin_url)
        self.assertIn("reauth=password", flow.signin_url)

    def test_protocol_password_persistent_invalid_auth_step_requires_browser_takeover(self):
        flow = ProtocolLoginSecretSetupFlow(self._account(), {}, object())
        flow._reauthenticate = Mock(return_value={"accessToken": "access-token"})
        invalid_step = (
            400,
            {"error": {"code": "invalid_auth_step", "message": "Invalid authorization step."}},
            "invalid_auth_step",
        )
        flow._request = Mock(side_effect=[invalid_step, invalid_step])

        with self.assertRaises(ProtocolChallengeRequired):
            flow._add_password("Strong-password-1!")

        flow._reauthenticate.assert_called_once_with(
            "https://chatgpt.com/?action=add_password",
            prefer_recent_email_code=True,
            post_login_add_password=True,
        )

    def test_protocol_recent_registration_code_is_attempted_only_once_across_reauthentication(self):
        class Reader:
            def __init__(self):
                self.calls = []

            def wait_for_code(self, _timestamp, timeout):
                self.calls.append(timeout)
                return "654321"

        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(
                    account,
                    {},
                    object(),
                    recent_email_code="123456",
                    recent_email_code_at=time.time(),
                )
                self.reader = Reader()
                self.codes = []

            def _request(self, method, url, **kwargs):
                if url.endswith("/api/auth/csrf"):
                    return 200, {"csrfToken": "csrf-token"}, ""
                if "/api/auth/signin/openai?" in url:
                    return 200, {"url": "https://auth.openai.com/authorize"}, ""
                if url.endswith("/api/accounts/email-otp/validate"):
                    self.codes.append(kwargs.get("json", {}).get("code"))
                    return 200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}, ""
                if url.endswith("/api/auth/session"):
                    return 200, {"accessToken": "access-token"}, ""
                return 200, {}, ""

        flow = Flow(self._account())
        flow._reauthenticate("https://chatgpt.com/?action=add_password", prefer_recent_email_code=True)
        flow._reauthenticate("https://chatgpt.com/?action=add_password", prefer_recent_email_code=True)

        self.assertEqual(flow.codes, ["123456", "654321"])
        self.assertEqual(flow.reader.calls, [120])

    def test_protocol_challenge_is_exposed_for_native_browser_takeover(self):
        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        flow = ProtocolLoginSecretSetupFlow(account, {"access_token": "old-token"}, object())
        flow._session_json = Mock(return_value={"accessToken": "old-token"})
        flow._add_password = Mock(side_effect=ProtocolChallengeRequired("Sentinel challenge"))

        result = flow.run()

        self.assertTrue(result["browser_challenge_required"])
        self.assertFalse(result["complete"])

    def test_browser_takeover_can_force_at_refresh_with_complete_login_secret(self):
        class Context:
            @staticmethod
            def storage_state():
                return {"cookies": [{"name": "session", "value": "new"}]}

        class Flow(LoginSecretSetupFlow):
            def _ensure_chatgpt_page(self, _page):
                return None

            def _dismiss_continue_gate(self, _page):
                return False

            def _session_json(self, _page):
                return {"accessToken": "old-token"}

            def _refresh_session_with_login_secret(self, _page):
                return {"accessToken": "new-token"}

            @staticmethod
            def _access_token_is_valid(_page, token):
                return token == "new-token"

        account = self._account()
        account.chatgpt_password = "ChatGPT-password"
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        saved_sessions = []
        result = Flow(
            account,
            {"access_token": "old-token", "expires_at": 1},
            "",
            force_access_token_refresh=True,
            on_session_saved=lambda session: saved_sessions.append(session),
        )._run_on_page(Mock(), Context())

        self.assertTrue(result["complete"])
        self.assertTrue(result["access_token_refreshed"])
        self.assertEqual(result["session"]["access_token"], "new-token")
        self.assertNotIn("expires_at", result["session"])
        self.assertEqual(saved_sessions, [{"accessToken": "new-token"}])

    @staticmethod
    def _account():
        return MailAccount(
            email="user@example.com",
            password="mail-password",
            client_id="client-id",
            refresh_token="refresh-token",
            raw="user@example.com----mail-password----client-id----refresh-token",
            chatgpt_password="ChatGPT-password",
        )

    def test_generated_password_has_required_length_and_character_classes(self):
        password = generate_chatgpt_password(20)
        self.assertEqual(len(password), 20)
        self.assertRegex(password, r"[A-Z]")
        self.assertRegex(password, r"[a-z]")
        self.assertRegex(password, r"[0-9]")
        self.assertRegex(password, r"[!@#$%^&*?_\-+=]")

    def test_complete_credentials_are_skipped_without_browser(self):
        account = MailAccount(
            email="user@example.com",
            password="mail-password",
            client_id="client-id",
            refresh_token="refresh-token",
            raw="user@example.com----mail-password----client-id----refresh-token",
            chatgpt_password="ChatGPT-password",
            totp_secret="JBSWY3DPEHPK3PXP",
        )
        result = LoginSecretSetupFlow(account, {}, "").run()
        self.assertTrue(result["skipped"])
        self.assertEqual(result["password"], "ChatGPT-password")
        self.assertEqual(result["totp_secret"], "JBSWY3DPEHPK3PXP")

    def test_registration_browser_context_is_reused_for_login_secret(self):
        account = self._account()
        account.chatgpt_password = ""
        account.totp_secret = ""
        flow = LoginSecretSetupFlow(account, {"storage_state_json": {"cookies": []}}, "")
        page = object()
        context = object()
        expected = {"complete": False, "errors": ["stub"]}
        with patch.object(flow, "_run_on_page", return_value=expected) as run_on_page:
            with patch("sunny_core.login_secret.open_registration_browser", side_effect=AssertionError("unexpected second browser")):
                result = flow.run(browser_page=page, browser_context=context)
        self.assertIs(result, expected)
        run_on_page.assert_called_once_with(page, context)

    def test_protocol_login_secret_skips_complete_credentials_without_network(self):
        account = self._account()
        account.totp_secret = "JBSWY3DPEHPK3PXP"
        flow = ProtocolLoginSecretSetupFlow(account, {}, object())
        result = flow.run()
        self.assertTrue(result["skipped"])
        self.assertTrue(result["complete"])

    def test_password_protocol_endpoint_uses_existing_auth_state(self):
        class FakePage:
            def __init__(self):
                self.url = ""
                self.visited = []

            def goto(self, url, **_kwargs):
                self.visited.append(url)
                self.url = url

            def evaluate(self, _script, password):
                self.password = password
                return {"ok": True, "status": 200, "data": {"success": True}}

        page = FakePage()
        result = LoginSecretSetupFlow._add_password_via_protocol(page, "Strong-password-1!")
        self.assertTrue(result["ok"])
        self.assertEqual(page.visited, ["https://auth.openai.com/reset-password/new-password"])
        self.assertEqual(page.password, "Strong-password-1!")

    def test_settings_surface_opens_profile_menu_before_searching_settings(self):
        class FakePage:
            def __init__(self):
                self.script = ""

            def evaluate(self, script):
                self.script = script
                return True

        page = FakePage()
        self.assertTrue(LoginSecretSetupFlow._open_settings_surface(page))
        self.assertIn("accounts-profile-button", page.script)
        self.assertIn("settings|設定|设置", page.script)

    def test_continue_gate_accepts_single_continue_button(self):
        class FakePage:
            def evaluate(self, script):
                self.script = script
                return True

        page = FakePage()
        self.assertTrue(LoginSecretSetupFlow._dismiss_continue_gate(page))
        self.assertIn("buttons.length === 1", page.script)
        self.assertIn("continue|next|finish", page.script)

    def test_chatgpt_page_is_reused_during_login_secret_steps(self):
        class Page:
            url = "https://chatgpt.com/"

            def __init__(self):
                self.visited = []

            def goto(self, url, **_kwargs):
                self.visited.append(url)
                self.url = url

        page = Page()
        LoginSecretSetupFlow._ensure_chatgpt_page(page)
        self.assertEqual(page.visited, [])
        page.url = "https://auth.openai.com/authorize"
        LoginSecretSetupFlow._ensure_chatgpt_page(page)
        self.assertEqual(page.visited, ["https://chatgpt.com"])

    def test_recent_email_code_is_only_usable_for_a_short_window(self):
        now = 1_700_000_000.0
        self.assertTrue(LoginSecretSetupFlow._recent_email_code_usable("123456", now - 30, now))
        self.assertTrue(LoginSecretSetupFlow._recent_email_code_usable("123456", now - RECENT_EMAIL_CODE_MAX_AGE_SECONDS, now))
        self.assertFalse(LoginSecretSetupFlow._recent_email_code_usable("123456", now - RECENT_EMAIL_CODE_MAX_AGE_SECONDS - 1, now))
        self.assertFalse(LoginSecretSetupFlow._recent_email_code_usable("not-code", now - 1, now))

    def test_reauthentication_prefers_recent_registration_code_before_mailbox_reader(self):
        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "", recent_email_code="123456", recent_email_code_at=time.time())
                self.submitted = False
                self.used_code = ""

            @staticmethod
            def _page_state(_page):
                if Flow.instance.submitted:
                    return {"url": "https://chatgpt.com/", "passwordInputs": 0, "codeInputs": 0, "text": ""}
                return {"url": "https://auth.openai.com/email-verification", "passwordInputs": 0, "codeInputs": 1, "text": ""}

            @staticmethod
            def _session_json(_page):
                if not Flow.instance.submitted:
                    raise RuntimeError("not submitted")
                return {"accessToken": "access-token"}

            def _fill_code(self, page, code):
                self.used_code = code
                self.submitted = True
                page.url = "https://chatgpt.com/"
                return True

            def _reader_instance(self):
                raise AssertionError("recent code should be used before reading the mailbox")

            def _sleep(self, _seconds):
                return None

        self_account = self._account()
        Flow.instance = Flow()
        class Page:
            url = "https://auth.openai.com/email-verification"

        page = Page()
        Flow.instance._complete_reauthentication(
            page,
            time.time(),
            "ChatGPT-password",
            recent_email_code="123456",
            recent_email_code_at=time.time(),
        )
        self.assertEqual(Flow.instance.used_code, "123456")

    def test_reauthentication_rejects_recent_code_once_then_waits_for_distinct_code(self):
        class Reader:
            def __init__(self):
                self.codes = iter(("123456", "654321"))
                self.timestamps = []

            def wait_for_code(self, timestamp, *_args):
                self.timestamps.append(timestamp)
                return next(self.codes)

        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.reader_stub = Reader()
                self.submitted_codes = []
                self.logs = []

            def _page_state(self, _page):
                if self.submitted_codes == ["123456"]:
                    return {
                        "url": "https://auth.openai.com/email-verification",
                        "passwordInputs": 0,
                        "codeInputs": 1,
                        "text": "Wrong code. Please check it and try again.",
                    }
                return {
                    "url": "https://auth.openai.com/email-verification",
                    "passwordInputs": 0,
                    "codeInputs": 1,
                    "text": "",
                }

            def _session_json(self, _page):
                if self.submitted_codes != ["123456", "654321"]:
                    raise RuntimeError("not authenticated")
                return {"accessToken": "access-token"}

            def _reader_instance(self):
                return self.reader_stub

            def _fill_code(self, page, code):
                self.submitted_codes.append(code)
                if code == "654321":
                    page.url = "https://chatgpt.com/"
                return True

            def _sleep(self, _seconds):
                return None

        self_account = self._account()
        flow = Flow()
        flow.log = flow.logs.append
        page = type("Page", (), {"url": "https://auth.openai.com/email-verification"})()

        flow._complete_reauthentication(
            page,
            time.time(),
            "ChatGPT-password",
            recent_email_code="123456",
            recent_email_code_at=time.time(),
        )

        self.assertEqual(flow.submitted_codes, ["123456", "654321"])
        self.assertGreaterEqual(len(flow.reader_stub.timestamps), 2)
        self.assertEqual(flow.reader_stub.timestamps[0], flow.reader_stub.timestamps[-1])
        self.assertEqual(flow.logs.count("[登录密钥] 优先复用本次注册刚使用的邮箱验证码"), 1)
        self.assertEqual(flow.logs.count("[登录密钥] 注册阶段验证码无法用于重认证，将等待新的邮箱验证码"), 1)

    def test_at_refresh_reauthentication_recognizes_japanese_totp_after_password(self):
        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.phase = "password"
                self.used_totp = ""
                self.logs = []
                self.log = self.logs.append

            def _page_state(self, _page):
                if self.phase == "password":
                    return {
                        "url": "https://auth.openai.com/authorize",
                        "passwordInputs": 1,
                        "codeInputs": 0,
                        "text": "パスワードを入力してください",
                    }
                return {
                    "url": "https://auth.openai.com/authorize",
                    "passwordInputs": 0,
                    "codeInputs": 1,
                    "text": "認証アプリの認証コードを入力してください",
                }

            def _submit_password(self, _page, _password):
                self.phase = "totp"
                return True

            def _fill_code(self, page, code):
                self.used_totp = code
                page.url = "https://chatgpt.com/"
                return True

            def _session_json(self, _page):
                if not self.used_totp:
                    raise RuntimeError("not authenticated")
                return {"accessToken": "new-token"}

            def _reader_instance(self):
                raise AssertionError("TOTP page must not read an email code")

            def _sleep(self, _seconds):
                return None

        self_account = self._account()
        self_account.totp_secret = "JBSWY3DPEHPK3PXP"
        page = type("Page", (), {"url": "https://auth.openai.com/authorize"})()
        flow = Flow()
        with patch("sunny_core.login_secret.generate_totp", return_value="654321"):
            flow._complete_reauthentication(page, time.time(), "ChatGPT-password")
        self.assertEqual(flow.used_totp, "654321")
        self.assertTrue(any("已提交 ChatGPT 密码" in item for item in flow.logs))
        self.assertTrue(any("已提交 2FA 动态验证码" in item for item in flow.logs))

    def test_at_refresh_stops_before_totp_when_account_is_deactivated(self):
        class Page:
            url = "https://auth.openai.com/authorize"

        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.phase = "password"

            def _page_state(self, _page):
                if self.phase == "password":
                    return {
                        "url": "https://auth.openai.com/authorize",
                        "passwordInputs": 1,
                        "codeInputs": 0,
                        "text": "パスワードを入力してください",
                    }
                return {
                    "url": "https://auth.openai.com/account-disabled",
                    "passwordInputs": 0,
                    "codeInputs": 0,
                    "text": "このアカウントは無効になっています",
                }

            def _submit_password(self, _page, _password):
                self.phase = "disabled"
                return True

            def _sleep(self, _seconds):
                return None

            def _reader_instance(self):
                raise AssertionError("disabled account must not wait for mailbox OTP")

        self_account = self._account()
        self_account.totp_secret = "JBSWY3DPEHPK3PXP"
        with self.assertRaisesRegex(RuntimeError, "account_deactivated"):
            Flow()._complete_reauthentication(Page(), time.time(), "ChatGPT-password", allow_email_fallback=False)

    def test_at_refresh_stops_immediately_on_rate_limit_error_page(self):
        class Page:
            url = "https://auth.openai.com/error?payload=rate_limit_exceeded"

        class Flow(LoginSecretSetupFlow):
            def _page_state(self, _page):
                return {
                    "url": Page.url,
                    "passwordInputs": 0,
                    "codeInputs": 0,
                    "text": "認証エラー リクエストが多すぎます error_code: rate_limit_exceeded",
                }

            def _sleep(self, _seconds):
                raise AssertionError("rate-limit error must not wait for the full timeout")

        with self.assertRaises(LoginSecretRateLimitError):
            Flow(self._account(), {}, "")._complete_reauthentication(
                Page(), time.time(), "ChatGPT-password", allow_email_fallback=False
            )

    def test_at_refresh_waits_when_totp_input_remains_visible_during_navigation(self):
        class Page:
            url = "https://auth.openai.com/authorize"

        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.totp_submitted = False
                self.waited_after_totp = False

            def _page_state(self, _page):
                return {
                    "url": "https://auth.openai.com/authorize",
                    "passwordInputs": 0,
                    "codeInputs": 1,
                    "text": "認証アプリの認証コードを入力してください",
                }

            def _fill_code(self, _page, _code):
                self.totp_submitted = True
                return True

            def _sleep(self, seconds):
                if self.totp_submitted and seconds < 1:
                    self.waited_after_totp = True
                    page.url = "https://chatgpt.com/"

            def _session_json(self, _page):
                return {"accessToken": "new-token"}

            def _reader_instance(self):
                raise AssertionError("TOTP 跳转等待期间不得读取邮箱验证码")

        self_account = self._account()
        self_account.totp_secret = "JBSWY3DPEHPK3PXP"
        page = Page()
        flow = Flow()
        with patch("sunny_core.login_secret.generate_totp", return_value="654321"):
            flow._complete_reauthentication(
                page,
                time.time(),
                "ChatGPT-password",
                allow_email_fallback=False,
            )

        self.assertTrue(flow.totp_submitted)
        self.assertTrue(flow.waited_after_totp)

    def test_password_reauthentication_always_reads_a_fresh_mailbox_code(self):
        class Reader:
            def wait_for_code(self, min_timestamp):
                self.min_timestamp = min_timestamp
                return "654321"

        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(
                    self_account,
                    {},
                    "",
                    recent_email_code="123456",
                    recent_email_code_at=time.time(),
                )
                self.reader_stub = Reader()
                self.used_code = ""
                self.submitted = False

            @staticmethod
            def _page_state(_page):
                if Flow.instance.submitted:
                    return {"url": "https://chatgpt.com/", "passwordInputs": 0, "codeInputs": 0, "text": ""}
                return {"url": "https://auth.openai.com/email-verification", "passwordInputs": 0, "codeInputs": 1, "text": ""}

            @staticmethod
            def _session_json(_page):
                if not Flow.instance.submitted:
                    raise RuntimeError("not submitted")
                return {"accessToken": "access-token"}

            def _reader_instance(self):
                return self.reader_stub

            def _fill_code(self, page, code):
                self.used_code = code
                self.submitted = True
                page.url = "https://chatgpt.com/"
                return True

            def _sleep(self, _seconds):
                return None

        self_account = self._account()
        Flow.instance = Flow()
        page = type("Page", (), {"url": "https://auth.openai.com/email-verification"})()
        Flow.instance._complete_reauthentication(
            page,
            time.time(),
            "ChatGPT-password",
            recent_email_code="123456",
            recent_email_code_at=time.time(),
            force_fresh_email_code=True,
        )
        self.assertEqual(Flow.instance.used_code, "654321")
        self.assertGreaterEqual(Flow.instance.reader_stub.min_timestamp, time.time() - 2)

    def test_password_reauthentication_requests_post_login_add_password_flow(self):
        class FakePage:
            def __init__(self):
                self.visited = []
                self.scripts = []

            def goto(self, url, **_kwargs):
                self.visited.append(url)
                self.url = url

            def evaluate(self, script, _payload=None):
                self.scripts.append(script)
                if "/api/auth/signin/openai" in script:
                    return {"ok": True, "status": 200, "data": {"url": "https://auth.openai.com/authorize"}}
                if "email-otp/validate" in script:
                    return {"ok": True, "status": 200, "data": {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}}
                raise AssertionError("unexpected browser request")

        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.used_code = ""

            def _reader_instance(self):
                class Reader:
                    def wait_for_code(inner, _min_timestamp):
                        self.used_code = "654321"
                        return self.used_code

                return Reader()

            @staticmethod
            def _session_json(_page):
                return {"accessToken": "access-token"}

        self_account = self._account()
        page = FakePage()
        flow = Flow()
        result = flow._reauth_for_password(page, "ChatGPT-password")
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(flow.used_code, "654321")
        self.assertTrue(any("post_login_add_password:'true'" in script for script in page.scripts))
        self.assertTrue(any("action=add_password" in script for script in page.scripts))
        self.assertTrue(any("email-otp/validate" in script for script in page.scripts))

    def test_browser_two_factor_reauthentication_always_reads_a_fresh_code(self):
        class Page:
            url = "https://chatgpt.com/"

            def evaluate(self, script, _payload=None):
                if "/api/auth/signin/openai" in script:
                    return {"ok": True, "status": 200, "data": {"url": "https://auth.openai.com/authorize"}}
                if "/api/auth/csrf" in script:
                    return {"ok": True, "status": 200, "data": {"csrfToken": "csrf-token"}}
                raise AssertionError("unexpected browser request")

        flow = LoginSecretSetupFlow(
            self._account(),
            {},
            "",
            recent_email_code="123456",
            recent_email_code_at=time.time(),
        )
        reauthenticate = Mock(return_value={"accessToken": "access-token"})
        flow._reauthenticate_with_fresh_email_code = reauthenticate

        flow._reauth_for_2fa(
            Page(),
            "ChatGPT-password",
            recent_email_code="123456",
            recent_email_code_at=flow.recent_email_code_at,
        )

        self.assertFalse(reauthenticate.call_args.kwargs["prefer_recent_email_code"])
        self.assertNotIn("recent_email_code", reauthenticate.call_args.kwargs)

    def test_browser_reauthentication_reads_new_code_after_old_code_is_rejected(self):
        class Reader:
            def __init__(self):
                self.codes = iter(("111111", "222222"))

            def wait_for_code(self, _timestamp):
                return next(self.codes)

        class Page:
            def __init__(self):
                self.url = ""
                self.codes = []

            def goto(self, url, **_kwargs):
                self.url = url

            def evaluate(self, _script, code):
                self.codes.append(code)
                if len(self.codes) == 1:
                    return {"ok": False, "status": 401, "data": {"code": "wrong_email_otp_code", "message": "Wrong code"}}
                return {"ok": True, "status": 200, "data": {"continue_url": "https://chatgpt.com/api/auth/callback/openai"}}

        class Flow(LoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, "")
                self.reader = Reader()

            @staticmethod
            def _session_json(_page):
                return {"accessToken": "access-token"}

        self_account = self._account()
        page = Page()
        result = Flow()._reauthenticate_with_fresh_email_code(page, "https://auth.openai.com/authorize", time.time())
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(page.codes, ["111111", "222222"])

    def test_protocol_reauthentication_reads_new_code_after_old_code_is_rejected(self):
        class Response:
            def __init__(self, status, data=None):
                self.status_code = status
                self._data = data
                self.text = json.dumps(data or {})

            def json(self):
                return self._data

        class Reader:
            def __init__(self):
                self.codes = iter(("111111", "222222"))

            def wait_for_code(self, _timestamp, _timeout):
                return next(self.codes)

        class Http:
            def __init__(self):
                self.validation_codes = []

            def request(self, method, url, **kwargs):
                if method == "GET" and url.endswith("/api/auth/csrf"):
                    return Response(200, {"csrfToken": "csrf-token"})
                if method == "POST" and "/api/auth/signin/openai?" in url:
                    return Response(200, {"url": "https://auth.openai.com/authorize"})
                if method == "GET" and "auth.openai.com/authorize" in url:
                    return Response(200, {})
                if method == "POST" and url.endswith("/api/accounts/email-otp/validate"):
                    code = kwargs["json"]["code"]
                    self.validation_codes.append(code)
                    if len(self.validation_codes) == 1:
                        return Response(401, {"code": "wrong_email_otp_code", "message": "Wrong code"})
                    return Response(200, {"continue_url": "https://chatgpt.com/api/auth/callback/openai"})
                if method == "GET" and "chatgpt.com/api/auth/callback" in url:
                    return Response(200, {})
                if method == "GET" and url.endswith("/api/auth/session"):
                    return Response(200, {"accessToken": "access-token"})
                raise AssertionError(f"unexpected request: {method} {url}")

        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self):
                super().__init__(self_account, {}, http)
                self.reader = Reader()

        self_account = self._account()
        http = Http()
        result = Flow()._reauthenticate("https://chatgpt.com/?action=add_password")
        self.assertEqual(result["accessToken"], "access-token")
        self.assertEqual(http.validation_codes, ["111111", "222222"])

    def test_totp_protocol_setup_uses_existing_session_without_reauthentication(self):
        class FakePage:
            def __init__(self):
                self.info_calls = 0
                self.calls = []

            def goto(self, url, **_kwargs):
                self.url = url

            def evaluate(self, script, payload=None):
                if "/api/auth/session" in script:
                    return {"ok": True, "status": 200, "data": {"accessToken": "access-token"}}
                if "mfa_info" in script:
                    self.info_calls += 1
                    enabled = self.info_calls > 1
                    factors = [{"id": "factor-id", "factor_type": "totp"}] if enabled else []
                    return {"ok": True, "status": 200, "data": {"mfa_enabled": enabled, "factors": {"totp": factors}}}
                if "accounts/mfa/enroll" in script:
                    self.calls.append("enroll")
                    return {"ok": True, "status": 200, "data": {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session-id", "factor": {"id": "factor-id"}}}
                if "activate_enrollment" in script:
                    self.calls.append(("activate", payload["code"], payload["sessionId"]))
                    return {"ok": True, "status": 200, "data": {"success": True}}
                raise AssertionError("unexpected browser request")

        class Flow(LoginSecretSetupFlow):
            def _fresh_totp_code(self, _secret, **_kwargs):
                return "123456"

            def _reauth_for_2fa(self, _page, _password, **_kwargs):
                raise AssertionError("valid session must not be reauthenticated")

        page = FakePage()
        flow = Flow(self._account(), {}, "")
        secret, session = flow._setup_2fa(page, "ChatGPT-password")
        self.assertEqual(secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(session["accessToken"], "access-token")
        self.assertEqual(page.calls, ["enroll", ("activate", "123456", "session-id")])
        self.assertEqual(flow.account.totp_secret, secret)

    def test_totp_protocol_activation_retries_next_code_after_401(self):
        class Flow(ProtocolLoginSecretSetupFlow):
            def __init__(self, account):
                super().__init__(account, {}, object())
                self.activation_codes = []
                self.info_calls = 0

            def _mfa_request(self, method, url, _access_token, **kwargs):
                if url.endswith("/accounts/mfa_info"):
                    self.info_calls += 1
                    enabled = self.info_calls > 1
                    factors = [{"id": "factor-id", "factor_type": "totp"}] if enabled else []
                    return 200, {"mfa_enabled": enabled, "factors": {"totp": factors}}, ""
                if url.endswith("/accounts/mfa/enroll"):
                    return 200, {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session-id", "factor": {"id": "factor-id"}}, ""
                if url.endswith("/accounts/mfa/user/activate_enrollment"):
                    self.activation_codes.append(kwargs["json"]["code"])
                    if len(self.activation_codes) == 1:
                        return 401, {"error": {"code": "invalid_totp_code"}}, "invalid_totp_code"
                    return 200, {"success": True}, ""
                raise AssertionError(f"unexpected MFA request: {method} {url}")

            def _session_json(self):
                return {"accessToken": "new-access-token"}

        account = self._account()
        account.totp_secret = ""
        logs = []
        flow = Flow(account)
        flow.log = logs.append
        with patch("sunny_core.login_secret.generate_totp", side_effect=["111111", "222222"]), patch(
            "sunny_core.login_secret.time.sleep"
        ):
            secret, _session = flow._setup_2fa("access-token")

        self.assertEqual(secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(flow.activation_codes, ["111111", "222222"])
        self.assertTrue(any("动态验证码可能已过期" in message for message in logs))

    def test_totp_protocol_reauthenticates_once_only_after_unauthorized_response(self):
        class FakePage:
            def __init__(self):
                self.authorized = False
                self.info_calls = 0

            def goto(self, url, **_kwargs):
                self.url = url

            def evaluate(self, script, _payload=None):
                if "/api/auth/session" in script:
                    return {"ok": True, "status": 200, "data": {"accessToken": "access-token"}}
                if "mfa_info" in script:
                    if not self.authorized:
                        return {"ok": False, "status": 401, "data": {}}
                    self.info_calls += 1
                    enabled = self.info_calls > 1
                    factors = [{"id": "factor-id", "factor_type": "totp"}] if enabled else []
                    return {"ok": True, "status": 200, "data": {"mfa_enabled": enabled, "factors": {"totp": factors}}}
                if "accounts/mfa/enroll" in script:
                    return {"ok": True, "status": 200, "data": {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session-id", "factor": {"id": "factor-id"}}}
                if "activate_enrollment" in script:
                    return {"ok": True, "status": 200, "data": {"success": True}}
                raise AssertionError("unexpected browser request")

        class Flow(LoginSecretSetupFlow):
            reauth_count = 0

            def _fresh_totp_code(self, _secret, **_kwargs):
                return "123456"

            def _reauth_for_2fa(self, page, _password, **_kwargs):
                self.reauth_count += 1
                page.authorized = True
                return {"accessToken": "new-access-token"}

        page = FakePage()
        flow = Flow(self._account(), {}, "")
        secret, _session = flow._setup_2fa(page, "ChatGPT-password")
        self.assertEqual(secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(flow.reauth_count, 1)

    def test_totp_secret_is_not_saved_until_mfa_info_confirms_activation(self):
        class FakePage:
            def evaluate(self, script, _payload=None):
                if "mfa_info" in script:
                    return {"ok": True, "status": 200, "data": {"mfa_enabled": False, "factors": {"totp": []}}}
                if "accounts/mfa/enroll" in script:
                    return {"ok": True, "status": 200, "data": {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session-id", "factor": {"id": "factor-id"}}}
                if "activate_enrollment" in script:
                    return {"ok": True, "status": 200, "data": {"success": True}}
                raise AssertionError("unexpected browser request")

        class Flow(LoginSecretSetupFlow):
            def _fresh_totp_code(self, _secret, **_kwargs):
                return "123456"

        flow = Flow(self._account(), {}, "")
        with self.assertRaisesRegex(RuntimeError, "mfa_info 未确认"):
            flow._setup_2fa_protocol(FakePage(), "access-token")
        self.assertEqual(flow.account.totp_secret, "")


if __name__ == "__main__":
    unittest.main()
