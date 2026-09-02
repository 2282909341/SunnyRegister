from __future__ import annotations

import unittest
from unittest.mock import ANY, MagicMock, Mock, patch
from urllib.parse import parse_qs, urlparse

import requests

from sunny_core import worker
from sunny_core.agent_identity import AgentIdentityUnavailableError
from sunny_core.browser_backend import open_registration_browser
from sunny_core.mailbox import MailAccount
from sunny_core.openai_auth import BrowserDriverDisconnectedError, DEFAULT_REDIRECT_URI, OpenAIEmailRegisterFlow
from sunny_core.protocol_auth import ProtocolChallengeRequired, ProtocolRegistrationError


class FakeDB:
    def __init__(self, configs=None) -> None:
        self.task_id = "test-task"
        self.configs = configs or {}
        self.mailbox_updates: list[dict] = []
        self.account_updates: list[dict] = []
        self.sessions: list[dict] = []
        self.password_updates: list[dict] = []
        self.events: list[tuple] = []
        self.sub2api_updates: list[dict] = []

    def ensure_not_cancelled(self) -> None:
        return None

    def cancel_requested(self) -> bool:
        return False

    def mailbox_status(self, mailbox_id) -> str:
        return self.mailbox_updates[-1]["status"] if self.mailbox_updates else "未注册"

    def event(self, *args, **kwargs) -> None:
        self.events.append((args, kwargs))

    def mark_mailbox(self, mailbox_id, status, error="", openai_rt="") -> None:
        self.mailbox_updates.append({"id": mailbox_id, "status": status, "error": error, "openai_rt": openai_rt})

    def usable_phone_count(self) -> int:
        return 0

    def smsbower_available(self) -> bool:
        return False

    def smspool_available(self) -> bool:
        return False

    def get_config(self, key) -> dict:
        return self.configs.get(key, {})

    def upsert_account(self, email, **fields) -> int:
        self.account_updates.append({"email": email, **fields})
        return 7

    def upsert_session(self, email, account_id, session, raw="") -> None:
        self.sessions.append({"email": email, "account_id": account_id, "session": session, "raw": raw})

    def save_chatgpt_password(self, mailbox_id, password) -> None:
        self.password_updates.append({"mailbox_id": mailbox_id, "password": password})

    def record_proxy_traffic(self, *args, **kwargs) -> None:
        return None

    def set_account_sub2api_status(self, email, status, sub2api_id="", error="") -> None:
        self.sub2api_updates.append({"email": email, "status": status, "sub2api_id": sub2api_id, "error": error})

    def fetch_mailbox_by_email(self, email) -> dict | None:
        return mailbox() if email == "user@example.com" else None


def mailbox(status="未注册", openai_rt="") -> dict:
    return {
        "id": 1,
        "email": "user@example.com",
        "password": "password",
        "client_id": "client-id",
        "refresh_token": "outlook-refresh-token",
        "openai_rt": openai_rt,
        "raw": "user@example.com----password----client-id----outlook-refresh-token",
        "account_type": "free",
        "status": status,
    }


class StageStatusTests(unittest.TestCase):
    def test_login_secret_result_message_distinguishes_credentials_from_at_refresh(self):
        message = worker._login_secret_result_message({
            "password": "password",
            "totp_secret": "totp-secret",
            "access_token_refreshed": False,
            "complete": False,
            "errors": ["刷新 ChatGPT Access Token 失败"],
        })
        self.assertIn("密码与 2FA 已成功并保存", message)
        self.assertIn("Access Token 更新未完成", message)
        self.assertNotIn("登录密钥未全部完成", message)

    class AboutYouControl:
        def __init__(self, value="", **attributes):
            self.value = value
            self.attributes = attributes

        def get_attribute(self, name):
            return self.attributes.get(name, "")

        def input_value(self, timeout=800):
            return self.value

    def test_about_you_prefers_japanese_age_field_over_birth_date_switch(self):
        flow = object.__new__(OpenAIEmailRegisterFlow)
        context = (
            "name=age id=age placeholder= aria-label=年齢 autocomplete= inputmode=numeric type=text "
            "__FIELD_CONTEXT_END__ 何才ですか？ 生年月日を使用する"
        )

        self.assertEqual(flow._about_you_second_field_kind_from_context(context), "age")

    def test_about_you_recognizes_explicit_date_input(self):
        flow = object.__new__(OpenAIEmailRegisterFlow)
        context = "name=birthdate id=dob aria-label=生年月日 type=date __FIELD_CONTEXT_END__ 年齢"

        self.assertEqual(flow._about_you_second_field_kind_from_context(context), "birth_date")

    def test_about_you_fills_segmented_birth_date_controls(self):
        flow = object.__new__(OpenAIEmailRegisterFlow)
        controls = [
            self.AboutYouControl(name="name"),
            self.AboutYouControl(name="month", aria_label="month"),
            self.AboutYouControl(name="day", aria_label="day"),
            self.AboutYouControl(name="year", aria_label="year"),
        ]
        with patch.object(flow, "_force_fill", side_effect=lambda control, value: setattr(control, "value", value)):
            date_controls = flow._about_you_date_controls(controls)
            flow._fill_about_you_date_controls(date_controls, "1995-10-11", "name=birthdate")
        self.assertEqual([control.value for control in date_controls], ["10", "11", "1995"])

    def test_about_you_current_values_accepts_valid_segmented_birth_date(self):
        flow = object.__new__(OpenAIEmailRegisterFlow)
        controls = [
            self.AboutYouControl(name="name", value="Grace Clark"),
            self.AboutYouControl(name="month", aria_label="month", value="10"),
            self.AboutYouControl(name="day", aria_label="day", value="11"),
            self.AboutYouControl(name="year", aria_label="year", value="1995"),
        ]
        page = MagicMock()
        with patch.object(flow, "_visible_inputs", return_value=controls), patch.object(
            flow, "_about_you_second_field_context", return_value="name=month aria-label=month __FIELD_CONTEXT_END__ 生年月日"
        ):
            self.assertTrue(flow._about_you_current_values_ok(page))

    def test_existing_account_error_recognizes_japanese_response(self):
        flow = object.__new__(OpenAIEmailRegisterFlow)
        page = MagicMock()
        page.locator.return_value.inner_text.return_value = (
            "このメールアドレスには、すでにアカウントがあります。ログインしてください。 "
            "error_code: user_already_exists"
        )

        self.assertTrue(flow._page_reports_existing_account(page))

    def test_existing_account_footer_does_not_interrupt_new_registration(self):
        flow = object.__new__(OpenAIEmailRegisterFlow)
        page = MagicMock()
        page.locator.return_value.inner_text.return_value = "Create your account Already have an account? Log in"

        self.assertFalse(flow._page_reports_existing_account(page))

    def test_protocol_batch_policy_enables_fast_path_after_repeated_challenges(self):
        policy = worker._ProtocolBatchPolicy()

        self.assertFalse(policy.should_start_in_browser())
        policy.record_challenge()
        self.assertFalse(policy.should_start_in_browser())
        policy.record_challenge()

        self.assertTrue(policy.should_start_in_browser())

    def test_protocol_batch_policy_stays_on_protocol_when_success_rate_is_sufficient(self):
        policy = worker._ProtocolBatchPolicy()
        policy.record_challenge()
        policy.record_challenge()
        policy.record_success()

        self.assertFalse(policy.should_start_in_browser())

    def run_one(self, stage: str, session: dict, status="未注册", import_result=None):
        db = FakeDB()
        payload = {"registration_stage": stage, "execution_mode": "background"}
        import_side_effect = import_result if isinstance(import_result, Exception) else None
        import_value = {} if import_result is None or isinstance(import_result, Exception) else import_result
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register", return_value=session),
            patch.object(worker, "_import_sub2api", return_value=import_value, side_effect=import_side_effect),
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(status), 1, 1)
        return db, ok, result

    def test_proxy_pool_exhaustion_fails_only_current_mailbox(self):
        db = FakeDB()
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "background"}
        with (
            patch.object(worker, "_prepare_register_proxy", side_effect=RuntimeError("代理池中没有可用代理")),
            patch.object(worker, "login_or_register") as executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 2)

        self.assertFalse(ok)
        self.assertIn("代理池中没有可用代理", str(result))
        self.assertEqual(db.mailbox_updates[-1]["status"], "失败")
        self.assertEqual(db.account_updates[-1]["status"], "failed")
        executor.assert_not_called()

    def test_proxy_pool_exhaustion_preserves_registered_mailbox_status(self):
        db = FakeDB()
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "background"}
        with patch.object(worker, "_prepare_register_proxy", side_effect=RuntimeError("代理池中没有可用代理")):
            ok, result = worker._run_one(db, "sunny_login", payload, mailbox(status="已注册"), 1, 1)

        self.assertFalse(ok)
        self.assertIn("代理池中没有可用代理", str(result))
        self.assertEqual(db.mailbox_updates[-1]["status"], "已注册")
        self.assertEqual(db.account_updates[-1]["status"], "registered")

    def test_rebound_login_keeps_original_database_identity(self):
        db = FakeDB()
        rebound = mailbox(status="已注册")
        rebound["_original_email_for_auth"] = rebound["email"]
        rebound["email"] = "rebound@example.com"
        pickup_url = "https://mail-api.example/pickup?email=rebound%40example.com&token=test-token"
        rebound["raw"] = f"rebound@example.com----{pickup_url}"
        rebound["mailbox_type"] = "domain"
        rebound["mailbox_channel"] = "domain_api"
        rebound["access_key"] = pickup_url
        session = {
            "access_token": "fresh-access-token",
            "session_json": {"accessToken": "fresh-access-token"},
            "auth_action": "login",
            "plan_type": "plus",
        }
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "background"}
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register", return_value=session),
        ):
            ok, result = worker._run_one(db, "sunny_login", payload, rebound, 1, 1)

        self.assertTrue(ok)
        self.assertEqual(result["email"], "rebound@example.com")
        self.assertTrue(db.account_updates)
        self.assertTrue(all(item["email"] == "user@example.com" for item in db.account_updates))
        self.assertTrue(db.sessions)
        self.assertTrue(all(item["email"] == "user@example.com" for item in db.sessions))

    def test_protocol_mode_dispatches_without_browser_executor(self):
        db = FakeDB()
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "protocol"}
        session = {
            "access_token": "protocol-access",
            "auth_action": "register",
            "plan_type": "plus",
            "session_json": {"accessToken": "protocol-access", "account": {"planType": "plus"}},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy.example:8080", "mode": "proxy_pool"}),
            patch.object(worker, "login_or_register_protocol", return_value=session) as protocol_executor,
            patch.object(worker, "login_or_register") as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        browser_executor.assert_not_called()
        protocol_executor.assert_called_once()
        self.assertEqual(protocol_executor.call_args.kwargs["challenge_strategy"], "sentinel_protocol")
        traffic_meter = protocol_executor.call_args.kwargs["traffic_meter"]
        self.assertTrue(traffic_meter.tracked_proxy)
        self.assertEqual(traffic_meter.proxy_url, "http://proxy.example:8080")
        self.assertEqual(db.account_updates[-1]["account_type"], "plus")

    def test_background_registration_directly_uses_protocol_headless_fallback(self):
        db = FakeDB()
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "background"}
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register_protocol") as protocol_executor,
            patch.object(worker, "login_or_register", return_value=browser_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        protocol_executor.assert_not_called()
        browser_executor.assert_called_once()
        self.assertIs(browser_executor.call_args.args[2], True)
        self.assertEqual(browser_executor.call_args.kwargs["execution_mode"], "protocol_headless_fallback")
        self.assertIsNone(browser_executor.call_args.kwargs["existing_session"])
        saved_session = db.sessions[-1]["session"]
        self.assertEqual(saved_session["requested_execution_mode"], "background")
        self.assertEqual(saved_session["execution_mode"], "protocol_headless_fallback")
        self.assertEqual(saved_session["protocol_fallback"], "direct_headless")
        self.assertTrue(any("不预执行协议注册请求" in str(args[0]) for args, _kwargs in db.events))

    def test_protocol_challenge_falls_back_to_headless_browser_only(self):
        db = FakeDB()
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "native_headless",
        }
        challenge = ProtocolChallengeRequired("Sentinel requires a browser challenge")
        challenge.traffic = {"requests": 4, "total_bytes": 2048}
        challenge.browser_handoff = {
            "protocol_browser_handoff": True,
            "protocol_resume_url": "https://auth.openai.com/about-you",
            "protocol_challenge_flow": "oauth_create_account",
            "protocol_email_verified": True,
            "storage_state_json": {"cookies": [{"name": "auth-session", "value": "state", "domain": "auth.openai.com", "path": "/"}], "origins": []},
        }
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy.example:8080", "mode": "pool"}),
            patch.object(worker, "login_or_register_protocol", side_effect=challenge) as protocol_executor,
            patch.object(worker, "login_or_register", return_value=browser_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        protocol_executor.assert_called_once()
        browser_executor.assert_called_once()
        args, kwargs = browser_executor.call_args
        self.assertEqual(args[1], "http://proxy.example:8080")
        self.assertIs(args[2], True)
        self.assertIsNone(kwargs["phone_provider"])
        self.assertFalse(kwargs["require_refresh_token"])
        self.assertEqual(kwargs["execution_mode"], "protocol_headless_fallback")
        self.assertIs(kwargs["existing_session"], challenge.browser_handoff)
        self.assertEqual(db.sessions[-1]["session"]["execution_mode"], "protocol_headless_fallback")
        self.assertEqual(db.sessions[-1]["session"]["protocol_fallback"], "native_challenge_handoff")
        self.assertEqual(db.sessions[-1]["session"]["protocol_traffic"]["total_bytes"], 2048)
        self.assertTrue(any("后台无头浏览器" in str(args[0]) for args, _kwargs in db.events))

    def test_initial_authorize_challenge_uses_native_browser_handoff(self):
        db = FakeDB()
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "native_headless",
        }
        challenge = ProtocolChallengeRequired("Sentinel authorize_continue requires a browser challenge")
        challenge.traffic = {"requests": 4, "total_bytes": 2048}
        challenge.browser_handoff = {
            "protocol_browser_handoff": True,
            "protocol_resume_url": "https://auth.openai.com/create-account",
            "protocol_challenge_flow": "authorize_continue",
            "protocol_email_verified": False,
            "storage_state_json": {"cookies": [{"name": "auth-session", "value": "state", "domain": "auth.openai.com", "path": "/"}], "origins": []},
        }
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy.example:8080", "mode": "pool"}),
            patch.object(worker, "login_or_register_protocol", side_effect=challenge) as protocol_executor,
            patch.object(worker, "login_or_register", return_value=browser_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        protocol_executor.assert_called_once()
        browser_executor.assert_called_once()
        self.assertEqual(protocol_executor.call_args.kwargs["challenge_strategy"], "native_headless")
        self.assertIs(browser_executor.call_args.kwargs["existing_session"], challenge.browser_handoff)
        self.assertEqual(db.sessions[-1]["session"]["protocol_fallback"], "native_challenge_handoff")

    def test_native_browser_handoff_failure_retries_one_fresh_headless_session(self):
        db = FakeDB()
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "native_headless",
        }
        challenge = ProtocolChallengeRequired("Sentinel oauth_create_account requires a browser challenge")
        challenge.browser_handoff = {
            "protocol_browser_handoff": True,
            "protocol_resume_url": "https://auth.openai.com/about-you",
            "protocol_challenge_flow": "oauth_create_account",
            "protocol_email_verified": True,
            "storage_state_json": {"cookies": [{"name": "auth-session", "value": "state", "domain": "auth.openai.com", "path": "/"}], "origins": []},
        }
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register_protocol", side_effect=challenge),
            patch.object(worker, "login_or_register", side_effect=[RuntimeError("handoff cookie expired"), browser_session]) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        self.assertEqual(browser_executor.call_count, 2)
        self.assertIs(browser_executor.call_args_list[0].kwargs["existing_session"], challenge.browser_handoff)
        self.assertIsNone(browser_executor.call_args_list[1].kwargs["existing_session"])
        self.assertEqual(db.sessions[-1]["session"]["protocol_fallback"], "headless_after_handoff_failure")
        self.assertTrue(any("清除失效断点" in str(args[0]) for args, _kwargs in db.events))

    def test_protocol_batch_challenges_do_not_skip_protocol_checkpoint(self):
        db = FakeDB()
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "native_headless",
        }
        policy = worker._ProtocolBatchPolicy()
        policy.record_challenge()
        policy.record_challenge()
        protocol_session = {
            "access_token": "protocol-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "protocol-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy.example:8080", "mode": "pool"}),
            patch.object(worker, "login_or_register_protocol", return_value=protocol_session) as protocol_executor,
            patch.object(worker, "login_or_register") as browser_executor,
        ):
            ok, result = worker._run_one(
                db,
                "sunny_register",
                payload,
                mailbox(),
                3,
                10,
                protocol_batch_policy=policy,
            )

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        protocol_executor.assert_called_once()
        browser_executor.assert_not_called()
        self.assertNotIn("protocol_fallback", db.sessions[-1]["session"])
        self.assertFalse(any("跳过重复协议验证" in str(args[0]) for args, _kwargs in db.events))

    def test_protocol_non_challenge_error_does_not_start_browser(self):
        db = FakeDB()
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "protocol"}
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register_protocol", side_effect=ProtocolRegistrationError("invalid protocol response")),
            patch.object(worker, "login_or_register") as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertFalse(ok)
        self.assertIn("invalid protocol response", str(result))
        browser_executor.assert_not_called()

    def test_protocol_transport_error_falls_back_to_headless_browser(self):
        db = FakeDB()
        payload = {"registration_stage": worker.REGISTER_ONLY, "execution_mode": "protocol"}
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        error = ProtocolRegistrationError(
            "Validate email verification code request failed: curl: (28) Operation timed out"
        )
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy.example:8080", "mode": "pool"}),
            patch.object(worker, "login_or_register_protocol", side_effect=error),
            patch.object(worker, "login_or_register", return_value=browser_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        browser_executor.assert_called_once()
        self.assertEqual(browser_executor.call_args.kwargs["execution_mode"], "protocol_headless_fallback")
        self.assertTrue(any("可恢复的网络传输错误" in str(args[0]) for args, _kwargs in db.events))

    def test_sentinel_protocol_strategy_falls_back_to_full_browser_on_challenge(self):
        db = FakeDB()
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "sentinel_protocol",
        }
        challenge = ProtocolChallengeRequired("Sentinel runtime failed")
        challenge.traffic = {"requests": 2, "total_bytes": 512}
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register_protocol", side_effect=challenge) as protocol_executor,
            patch.object(worker, "login_or_register", return_value=browser_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        self.assertEqual(protocol_executor.call_args.kwargs["challenge_strategy"], "sentinel_protocol")
        browser_executor.assert_called_once()
        self.assertEqual(browser_executor.call_args.kwargs["execution_mode"], "protocol_headless_fallback")

    def test_sentinel_protocol_transport_error_falls_back_to_full_browser(self):
        db = FakeDB()
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "sentinel_protocol",
        }
        error = ProtocolRegistrationError(
            "Sentinel oauth_create_account request failed: curl: (35) Recv failure: Connection reset by peer"
        )
        browser_session = {
            "access_token": "browser-access",
            "auth_action": "register",
            "plan_type": "free",
            "session_json": {"accessToken": "browser-access"},
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register_protocol", side_effect=error),
            patch.object(worker, "login_or_register", return_value=browser_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        browser_executor.assert_called_once()

    def test_protocol_mode_continues_phone_stage_with_headless_oauth(self):
        db = FakeDB()
        payload = {"registration_stage": worker.CODEX_PHONE_BIND, "execution_mode": "protocol"}
        protocol_session = {"access_token": "protocol-access", "auth_action": "register"}
        completed_session = {
            "access_token": "browser-access",
            "refresh_token": "refresh-token",
            "phone_bound": True,
            "auth_action": "login",
        }
        phone_provider = Mock()
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "_combined_phone_provider", return_value=phone_provider) as phone_allocator,
            patch.object(worker, "login_or_register_protocol", return_value=protocol_session),
            patch.object(worker, "login_or_register", return_value=completed_session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        self.assertEqual(result["completed_status"], "已接码")
        phone_allocator.assert_called_once()
        browser_executor.assert_called_once()
        self.assertIs(browser_executor.call_args.kwargs["phone_provider"], phone_provider)
        self.assertTrue(browser_executor.call_args.kwargs["require_refresh_token"])
        self.assertEqual(browser_executor.call_args.kwargs["execution_mode"], "protocol_post_stage")
        self.assertIs(browser_executor.call_args.kwargs["existing_session"], protocol_session)

    def test_manual_rt_acquire_persists_token_to_account_mailbox_and_session(self):
        db = FakeDB()
        payload = {"registration_stage": worker.CODEX_PHONE_BIND, "execution_mode": "background"}
        session = {
            "access_token": "access-token",
            "refresh_token": "rt_manual",
            "phone_bound": True,
            "auth_action": "login",
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "_combined_phone_provider", return_value=None),
            patch.object(worker, "login_or_register", return_value=session) as browser_executor,
        ):
            ok, result = worker._run_one(db, "sunny_acquire_rt", payload, mailbox(status="已接码"), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["has_refresh_token"])
        self.assertEqual(db.sessions[-1]["session"]["refresh_token"], "rt_manual")
        self.assertTrue(any(update.get("openai_rt") == "rt_manual" for update in db.account_updates))
        self.assertTrue(any(update.get("openai_rt") == "rt_manual" for update in db.mailbox_updates))
        self.assertTrue(browser_executor.call_args.kwargs["require_refresh_token"])

    def test_agent_identity_stage_skips_phone_and_imports_with_access_token(self):
        db = FakeDB()
        payload = {"registration_stage": worker.AGENT_IDENTITY_REVERSE_PROXY, "execution_mode": "protocol", "proxy_all_traffic": True}
        session = {"access_token": "protocol-access", "auth_action": "login", "plan_type": "plus"}
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy.example:8080", "mode": "pool"}),
            patch.object(worker, "_combined_phone_provider") as phone_allocator,
            patch.object(worker, "login_or_register_protocol", return_value=session),
            patch.object(worker, "login_or_register") as browser_executor,
            patch.object(worker, "_import_sub2api_agent_identity", return_value={"created": 1}) as importer,
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(status="已注册"), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        self.assertTrue(result["agent_identity"])
        self.assertEqual(result["completed_status"], "已反代")
        phone_allocator.assert_not_called()
        browser_executor.assert_not_called()
        importer.assert_called_once_with(db, "user@example.com", 7, session, "http://proxy.example:8080")

    def test_agent_identity_import_uses_codex_session_contract(self):
        db = FakeDB({
            "sub2api": {
                "enabled": True,
                "base_url": "https://sub2api.example",
                "admin_token": "admin-secret",
                "name_prefix": "Sunny-",
                "group_ids": [2, "3"],
                "concurrency": 5,
                "priority": 1,
                "notes_include_sk": True,
            }
        })
        auth_json = {
            "auth_mode": "agentIdentity",
            "agent_identity": {
                "agent_runtime_id": "runtime-id",
                "agent_private_key": "private-key",
                "account_id": "account-id",
                "chatgpt_user_id": "user-id",
            },
        }
        response = Mock(status_code=200)
        response.json.return_value = {"data": {"created": 1, "updated": 0, "failed": 0, "items": [{"account_id": 91}]}}
        with (
            patch.object(worker, "create_agent_identity_auth", return_value=auth_json) as creator,
            patch.object(worker.requests, "post", return_value=response) as post,
        ):
            result = worker._import_sub2api_agent_identity(
                db,
                "user@example.com",
                7,
                {"access_token": "access-token", "plan_type": "plus"},
                "http://proxy.example:8080",
            )

        self.assertEqual(result["created"], 1)
        creator.assert_called_once_with(
            "access-token",
            email="user@example.com",
            plan_type="plus",
            proxy_url="http://proxy.example:8080",
            should_cancel=db.cancel_requested,
            log=ANY,
        )
        request = post.call_args
        self.assertEqual(request.args[0], "https://sub2api.example/api/v1/admin/accounts/import/codex-session")
        self.assertEqual(request.kwargs["headers"]["X-API-Key"], "admin-secret")
        self.assertEqual(request.kwargs["headers"]["Accept"], "application/json")
        self.assertFalse(request.kwargs["allow_redirects"])
        payload = request.kwargs["json"]
        self.assertEqual(set(payload), {"contents", "update_existing"})
        self.assertTrue(payload["update_existing"])
        self.assertEqual(len(payload["contents"]), 1)
        imported_auth = __import__("json").loads(payload["contents"][0])
        self.assertEqual(imported_auth["notes"], "邮箱凭证：user@example.com----password----client-id----outlook-refresh-token")
        self.assertEqual(imported_auth["auth_mode"], "agentIdentity")
        self.assertEqual(imported_auth["agent_identity"]["agent_runtime_id"], "runtime-id")

    def test_agent_identity_import_falls_back_to_refresh_token_oauth(self):
        db = FakeDB({
            "sub2api": {
                "enabled": True,
                "base_url": "https://sub2api.example",
                "admin_token": "admin-secret",
            }
        })
        fallback_result = {"id": 91}
        with (
            patch.object(
                worker,
                "create_agent_identity_auth",
                side_effect=AgentIdentityUnavailableError("agent_registry_not_enabled"),
            ),
            patch.object(worker, "_import_sub2api", return_value=fallback_result) as fallback,
        ):
            result = worker._import_sub2api_agent_identity(
                db,
                "user@example.com",
                7,
                {"access_token": "access-token", "refresh_token": "refresh-token"},
                "",
            )

        self.assertEqual(result["id"], 91)
        self.assertEqual(result["_sunny_import_mode"], "oauth_refresh_token")
        fallback.assert_called_once()
        self.assertTrue(any("回退到标准 sub2api OAuth 导入" in args[0] for args, _ in db.events))

    def test_agent_identity_import_without_refresh_token_is_actionable(self):
        db = FakeDB({
            "sub2api": {
                "enabled": True,
                "base_url": "https://sub2api.example",
                "admin_token": "admin-secret",
            }
        })
        with patch.object(
            worker,
            "create_agent_identity_auth",
            side_effect=AgentIdentityUnavailableError("agent_registry_not_enabled"),
        ):
            with self.assertRaisesRegex(
                AgentIdentityUnavailableError,
                "没有 Refresh Token.*Codex 接码绑定",
            ):
                worker._import_sub2api_agent_identity(
                    db,
                    "user@example.com",
                    7,
                    {"access_token": "access-token"},
                    "",
                )

    def test_agent_identity_import_reports_html_gateway_response(self):
        db = FakeDB({
            "sub2api": {
                "enabled": True,
                "base_url": "https://sub2api.example",
                "admin_token": "admin-secret",
            }
        })
        auth_json = {
            "auth_mode": "agentIdentity",
            "agent_identity": {
                "agent_runtime_id": "runtime-id",
                "agent_private_key": "private-key",
                "account_id": "account-id",
                "chatgpt_user_id": "user-id",
            },
        }
        response = Mock(
            status_code=200,
            text="<!doctype html><html><head><title>502 Bad gateway</title></head></html>",
            headers={"Content-Type": "text/html; charset=UTF-8"},
            url="https://sub2api.example/api/v1/admin/accounts/import/codex-session",
        )
        response.json.side_effect = ValueError("unexpected character")
        with (
            patch.object(worker, "create_agent_identity_auth", return_value=auth_json),
            patch.object(worker.requests, "post", return_value=response),
        ):
            with self.assertRaisesRegex(RuntimeError, "返回非 JSON 内容.*502 Bad gateway"):
                worker._import_sub2api_agent_identity(
                    db,
                    "user@example.com",
                    7,
                    {"access_token": "access-token", "plan_type": "plus"},
                    "",
                )

    def test_agent_identity_import_does_not_follow_login_redirect(self):
        db = FakeDB({
            "sub2api": {
                "enabled": True,
                "base_url": "https://sub2api.example",
                "admin_token": "admin-secret",
            }
        })
        auth_json = {
            "auth_mode": "agentIdentity",
            "agent_identity": {
                "agent_runtime_id": "runtime-id",
                "agent_private_key": "private-key",
                "account_id": "account-id",
                "chatgpt_user_id": "user-id",
            },
        }
        response = Mock(
            status_code=302,
            text="",
            headers={"Location": "/login"},
            url="https://sub2api.example/api/v1/admin/accounts/import/codex-session",
        )
        with (
            patch.object(worker, "create_agent_identity_auth", return_value=auth_json),
            patch.object(worker.requests, "post", return_value=response) as post,
        ):
            with self.assertRaisesRegex(RuntimeError, "发生重定向到 /login"):
                worker._import_sub2api_agent_identity(
                    db,
                    "user@example.com",
                    7,
                    {"access_token": "access-token", "plan_type": "plus"},
                    "",
                )
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_agent_identity_import_normalizes_api_v1_base_url(self):
        self.assertEqual(
            worker._sub2api_codex_import_url("https://sub2api.example/api/v1"),
            "https://sub2api.example/api/v1/admin/accounts/import/codex-session",
        )
        self.assertEqual(
            worker._sub2api_codex_import_url("https://sub2api.example/api/v1/admin"),
            "https://sub2api.example/api/v1/admin/accounts/import/codex-session",
        )

    def test_missing_phone_resources_keeps_registered_status(self):
        db, ok, result = self.run_one(worker.CODEX_PHONE_BIND, {"access_token": "access", "auth_action": "register"})
        self.assertTrue(ok)
        self.assertEqual(db.mailbox_updates[-1]["status"], "已注册")
        self.assertEqual(db.account_updates[-1]["status"], "registered")
        self.assertFalse(result["stage_complete"])

    def test_phone_completed_without_rt_keeps_phone_bound_status(self):
        db, ok, result = self.run_one(worker.CODEX_PHONE_BIND, {"access_token": "access", "phone_bound": True, "post_registration_error": "RT failed"})
        self.assertTrue(ok)
        self.assertEqual(db.mailbox_updates[-1]["status"], "已接码")
        self.assertEqual(db.account_updates[-1]["status"], "phone_bound")
        self.assertFalse(result["stage_complete"])

    def test_reverse_proxy_failure_keeps_phone_bound_status(self):
        db, ok, result = self.run_one(
            worker.IMPORT_REVERSE_PROXY,
            {"access_token": "access", "refresh_token": "rt", "auth_action": "register"},
            import_result=RuntimeError("sub2api unavailable"),
        )
        self.assertTrue(ok)
        self.assertEqual(db.mailbox_updates[-1]["status"], "已接码")
        self.assertEqual(db.account_updates[-1]["status"], "phone_bound")
        self.assertEqual(db.sub2api_updates[-1]["status"], "failed")
        self.assertFalse(result["stage_complete"])

    def test_reverse_proxy_success_sets_reverse_proxied_status(self):
        db, ok, result = self.run_one(
            worker.IMPORT_REVERSE_PROXY,
            {"access_token": "access", "refresh_token": "rt", "auth_action": "register"},
            import_result={"id": "remote-account"},
        )
        self.assertTrue(ok)
        self.assertEqual(db.mailbox_updates[-1]["status"], "已反代")
        self.assertEqual(db.account_updates[-1]["status"], "reverse_proxied")
        self.assertTrue(result["stage_complete"])

    def test_completed_status_does_not_regress(self):
        db, ok, result = self.run_one(worker.REGISTER_ONLY, {"access_token": "access", "auth_action": "login"}, status="已反代")
        self.assertTrue(ok)
        self.assertEqual(db.mailbox_updates[-1]["status"], "已反代")
        self.assertEqual(db.account_updates[-1]["status"], "reverse_proxied")
        self.assertEqual(result["completed_status"], "已反代")

    def test_registration_checkpoint_can_be_saved_before_phone_stage(self):
        db = FakeDB()
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
            chatgpt_password="generated-password",
        )
        worker._persist_registration_checkpoint(
            db,
            mailbox(),
            account,
            "registered",
            {"access_token": "access-token", "session_json": {"accessToken": "access-token"}},
            "未注册",
        )
        self.assertEqual(db.mailbox_updates[-1]["status"], "已注册")
        self.assertEqual(db.account_updates[-1]["status"], "registered")
        self.assertEqual(len(db.sessions), 1)
        self.assertEqual(db.password_updates, [{"mailbox_id": 1, "password": "generated-password"}])

    def test_registration_password_checkpoint_survives_later_flow_failure(self):
        db = FakeDB()

        def execute(*_args, **kwargs):
            kwargs["on_progress"](
                "password_created",
                {"generated_chatgpt_password": "generated-password"},
            )
            raise RuntimeError("browser disconnected after password creation")

        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "background",
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register", side_effect=execute),
        ):
            ok, _result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertFalse(ok)
        self.assertEqual(db.password_updates, [{"mailbox_id": 1, "password": "generated-password"}])
        self.assertTrue(any("立即保存" in str(args[0]) for args, _kwargs in db.events if args))

    def test_login_secret_flow_persists_first_at_then_replaces_it_with_second_at(self):
        db = FakeDB()
        first_session = {
            "access_token": "first-access",
            "session_json": {"accessToken": "first-access"},
            "auth_action": "register",
        }
        second_session = {
            "access_token": "second-access",
            "session_json": {"accessToken": "second-access"},
            "auth_action": "register",
        }

        def execute(*_args, **kwargs):
            kwargs["on_progress"]("registered", first_session)
            return {
                **second_session,
                "login_secret_result": {
                    "complete": True,
                    "errors": [],
                    "session": second_session,
                },
            }

        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "background",
            "setup_login_secret": True,
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register", side_effect=execute),
        ):
            ok, result = worker._run_one(db, "sunny_register", payload, mailbox(), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        self.assertEqual([item["session"]["access_token"] for item in db.sessions], ["first-access", "second-access"])
        self.assertEqual(db.account_updates[-1]["access_token"], "second-access")

    def test_protocol_login_secret_challenge_uses_cookie_browser_takeover(self):
        db = FakeDB()
        protocol_storage = {
            "cookies": [{
                "name": "__Secure-next-auth.session-token",
                "value": "protocol-session",
                "domain": ".chatgpt.com",
                "path": "/",
            }],
            "origins": [],
        }
        protocol_session = {
            "access_token": "first-access",
            "session_json": {"accessToken": "first-access"},
            "storage_state_json": protocol_storage,
            "auth_action": "login",
            "login_secret_result": {
                "complete": False,
                "browser_challenge_required": True,
                "errors": ["刷新 ChatGPT Access Token 失败: Sentinel challenge"],
                "session": {
                    "access_token": "first-access",
                    "session_json": {"accessToken": "first-access"},
                    "storage_state_json": protocol_storage,
                },
            },
        }
        browser_session = {
            "access_token": "second-access",
            "session_json": {"accessToken": "second-access"},
            "storage_state_json": {"cookies": [{"name": "session", "value": "browser"}]},
            "auth_action": "login",
        }
        browser_result = {
            "complete": True,
            "password": "ChatGPT-password",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "password_added": False,
            "totp_added": False,
            "access_token_refreshed": True,
            "errors": [],
            "session": browser_session,
        }
        payload = {
            "registration_stage": worker.REGISTER_ONLY,
            "execution_mode": "protocol",
            "protocol_challenge_strategy": "sentinel_protocol",
            "setup_login_secret": True,
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "", "mode": "direct"}),
            patch.object(worker, "login_or_register_protocol", return_value=protocol_session),
            patch.object(worker, "setup_login_secret", return_value=browser_result) as takeover,
        ):
            ok, result = worker._run_one(db, "sunny_login", payload, mailbox(status="已注册"), 1, 1)

        self.assertTrue(ok)
        self.assertTrue(result["stage_complete"])
        self.assertEqual(db.sessions[-1]["session"]["access_token"], "second-access")
        self.assertEqual(takeover.call_args.args[1]["storage_state_json"], protocol_storage)
        self.assertTrue(takeover.call_args.kwargs["force_access_token_refresh"])

class SessionFallbackTests(unittest.TestCase):
    def test_existing_account_applies_login_secret_callback_in_current_browser(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        callback = Mock(return_value={
            "complete": True,
            "session": {
                "access_token": "second-access",
                "session_json": {"accessToken": "second-access"},
                "storage_state_json": {"cookies": [{"name": "session", "value": "second"}]},
            },
        })
        flow = OpenAIEmailRegisterFlow(
            account, "", True, lambda _message: None,
            existing_account=True, require_refresh_token=False,
            post_registration_callback=callback,
        )
        context, page = Mock(), Mock()

        result = flow._apply_post_registration_callback(
            context, page,
            {"access_token": "first-access", "session_json": {"accessToken": "first-access"}},
        )

        callback.assert_called_once()
        self.assertEqual(result["access_token"], "second-access")
        self.assertEqual(result["login_secret_result"]["session"]["access_token"], "second-access")

    def test_protocol_session_continues_oauth_without_repeating_email_login(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        existing_session = {
            "access_token": "protocol-access",
            "auth_action": "login",
            "storage_state_json": {
                "cookies": [{
                    "name": "__Secure-next-auth.session-token",
                    "value": "session-token",
                    "domain": ".chatgpt.com",
                    "path": "/",
                }],
                "origins": [],
            },
        }
        flow = OpenAIEmailRegisterFlow(
            account,
            "",
            True,
            lambda _message: None,
            existing_account=True,
            require_refresh_token=True,
            existing_session=existing_session,
        )
        page = Mock()
        page.goto.return_value = Mock(status=200)
        context = Mock()
        context.new_page.return_value = page
        browser_session = Mock(context=context, backend="camoufox")
        manager = MagicMock()
        manager.__enter__.return_value = browser_session
        expected = {"access_token": "oauth-access", "refresh_token": "rt_test"}

        with (
            patch("sunny_core.openai_auth.open_registration_browser", return_value=manager) as open_browser,
            patch.object(flow, "_log_runtime_fingerprint"),
            patch.object(flow, "_preconnect_otp_reader") as preconnect,
            patch.object(flow, "_extract_session_info", return_value=expected) as extract,
        ):
            result = flow.run()

        self.assertEqual(result["refresh_token"], "rt_test")
        preconnect.assert_not_called()
        context.clear_cookies.assert_not_called()
        extract.assert_called_once_with(context, page, emit_registered=False)
        self.assertEqual(open_browser.call_args.kwargs["storage_state"], existing_session["storage_state_json"])

    def test_refresh_token_failure_keeps_chatgpt_session(self):
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
        )
        logs: list[str] = []
        flow = OpenAIEmailRegisterFlow(account, "", True, logs.append, require_refresh_token=True)
        flow.phone_verification_completed = True

        class Context:
            @staticmethod
            def storage_state():
                return {"cookies": []}

        with (
            patch.object(flow, "_read_chatgpt_session_json", return_value={"accessToken": "access-token"}),
            patch.object(flow, "_authorize_rt_from_browser", side_effect=RuntimeError("SMS provider unavailable")),
        ):
            result = flow._extract_session_info(Context(), object())

        self.assertEqual(result["access_token"], "access-token")
        self.assertTrue(result["phone_bound"])
        self.assertIn("Refresh Token", result["post_registration_error"])
        self.assertTrue(any("ChatGPT" in item and "Session" in item for item in logs))

    def test_session_reader_prefers_context_request_without_navigating_page(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        response = Mock(status=200)
        response.text.return_value = '{"accessToken":"access-token"}'
        context = Mock()
        context.request.get.return_value = response
        page = Mock()
        page.context.browser.is_connected.return_value = True

        result = flow._read_chatgpt_session_json(context, page)

        self.assertEqual(result["accessToken"], "access-token")
        page.goto.assert_not_called()
        page.evaluate.assert_not_called()

    def test_session_reader_does_not_retry_dead_playwright_driver(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        context = Mock()
        context.request.get.side_effect = RuntimeError("Page.evaluate: Connection closed while reading from the driver")
        page = Mock()
        page.context.browser.is_connected.return_value = True

        with patch.object(flow, "_sleep_checked") as sleep:
            with self.assertRaises(BrowserDriverDisconnectedError):
                flow._read_chatgpt_session_json(context, page)

        self.assertEqual(context.request.get.call_count, 1)
        page.evaluate.assert_not_called()
        sleep.assert_not_called()


class BrowserCsrfTests(unittest.TestCase):
    def test_signin_uses_browser_session_for_csrf_and_post(self):
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
        )
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        context = Mock()
        context.cookies.return_value = [{"name": "oai-did", "value": "device-id"}]

        class Page:
            def evaluate(self, script, payload=None):
                if "/api/auth/csrf" in script:
                    return {"ok": True, "status": 200, "text": '{"csrfToken":"browser-csrf"}'}
                self_payload = payload or {}
                assert self_payload["csrfToken"] == "browser-csrf"
                return {"ok": True, "status": 200, "text": '{"url":"https://auth.openai.com/authorize"}'}

        signin_url = flow._create_openai_signin_url(context, Page())

        self.assertEqual(signin_url, "https://auth.openai.com/authorize")
        context.request.get.assert_not_called()
        context.request.post.assert_not_called()

    def test_signin_fallback_retries_tls_disconnect(self):
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
        )
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        context = Mock()
        context.cookies.return_value = [{"name": "oai-did", "value": "device-id"}]
        page = Mock()
        page.evaluate.side_effect = [
            {"ok": True, "status": 200, "text": '{"csrfToken":"browser-csrf"}'},
            RuntimeError("browser fetch failed"),
        ]
        response = Mock(ok=True)
        response.json.return_value = {"url": "https://auth.openai.com/authorize"}
        context.request.post.side_effect = [
            RuntimeError("Client network socket disconnected before secure TLS connection was established"),
            response,
        ]

        signin_url = flow._create_openai_signin_url(context, page)

        self.assertEqual(signin_url, "https://auth.openai.com/authorize")
        self.assertEqual(context.request.post.call_count, 2)
        page.wait_for_timeout.assert_called_once_with(600)


class BrowserBackendTests(unittest.TestCase):
    def test_background_mode_uses_one_camoufox_incognito_context(self):
        fingerprint = Mock(
            locale="ja-JP",
            languages=["ja-JP", "ja"],
            timezone="Asia/Tokyo",
        )
        manager = MagicMock()
        browser = Mock()
        context = Mock()
        browser.new_context.return_value = context
        manager.__enter__.return_value = browser

        with patch("camoufox.sync_api.Camoufox", return_value=manager) as camoufox:
            with open_registration_browser(
                headless=True,
                proxy_url="http://user:pass@proxy.example:8080",
                fingerprint=fingerprint,
                log=lambda _message: None,
            ) as session:
                self.assertEqual(session.backend, "camoufox")
                self.assertIs(session.context, context)

        options = camoufox.call_args.kwargs
        self.assertTrue(options["headless"])
        self.assertTrue(options["humanize"])
        self.assertEqual(options["locale"], ["ja-JP", "ja"])
        self.assertEqual(options["proxy"]["server"], "http://proxy.example:8080")
        self.assertTrue(options["geoip"])
        browser.new_context.assert_called_once_with(
            no_viewport=True,
            locale="ja-JP",
            timezone_id="Asia/Tokyo",
        )
        context.close.assert_called_once()
        manager.__exit__.assert_called_once()

    def test_background_mode_loads_existing_protocol_storage_state(self):
        fingerprint = Mock(locale="ja-JP", languages=["ja-JP", "ja"], timezone="Asia/Tokyo")
        manager = MagicMock()
        browser = Mock()
        context = Mock()
        browser.new_context.return_value = context
        manager.__enter__.return_value = browser
        storage_state = {
            "cookies": [{
                "name": "__Secure-next-auth.session-token",
                "value": "session-token",
                "domain": ".chatgpt.com",
                "path": "/",
            }],
            "origins": [],
        }

        with patch("camoufox.sync_api.Camoufox", return_value=manager):
            with open_registration_browser(
                headless=True,
                proxy_url="",
                fingerprint=fingerprint,
                log=lambda _message: None,
                storage_state=storage_state,
            ):
                pass

        browser.new_context.assert_called_once_with(
            no_viewport=True,
            locale="ja-JP",
            timezone_id="Asia/Tokyo",
            storage_state=storage_state,
        )

    def test_disconnected_camoufox_skips_duplicate_browser_close(self):
        fingerprint = Mock(locale="ja-JP", languages=["ja-JP", "ja"], timezone="Asia/Tokyo")
        manager = MagicMock()
        browser = Mock()
        browser.is_connected.return_value = False
        context = Mock()
        browser.new_context.return_value = context
        manager.__enter__.return_value = browser

        with patch("camoufox.sync_api.Camoufox", return_value=manager):
            with open_registration_browser(
                headless=True,
                proxy_url="",
                fingerprint=fingerprint,
                log=lambda _message: None,
            ):
                pass

        context.close.assert_not_called()
        self.assertIsNone(manager.browser)
        manager.__exit__.assert_called_once()


class BrowserOAuthCallbackTests(unittest.TestCase):
    @staticmethod
    def make_flow(logs: list[str] | None = None) -> OpenAIEmailRegisterFlow:
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
        )
        return OpenAIEmailRegisterFlow(account, "", True, (logs if logs is not None else []).append)

    def test_callback_requires_matching_oauth_state(self):
        flow = self.make_flow()
        callback_url = f"{DEFAULT_REDIRECT_URI}?code=auth-code&state=expected-state"

        result = flow._extract_oauth_callback_from_url(callback_url, "expected-state")

        self.assertEqual(result["code"], "auth-code")
        with self.assertRaisesRegex(RuntimeError, "state mismatch"):
            flow._extract_oauth_callback_from_url(callback_url, "other-state")

    def test_oauth_url_matches_current_codex_cli_authorize_shape(self):
        flow = self.make_flow()

        oauth_url, verifier, state = flow._prepare_browser_oauth_url()

        query = parse_qs(urlparse(oauth_url).query)
        self.assertTrue(verifier)
        self.assertEqual(query["state"], [state])
        self.assertEqual(query["redirect_uri"], [DEFAULT_REDIRECT_URI])
        self.assertEqual(query["scope"], ["openid profile email offline_access"])
        self.assertEqual(query["codex_cli_simplified_flow"], ["true"])
        self.assertEqual(query["id_token_add_organizations"], ["true"])
        self.assertNotIn("prompt", query)
        self.assertNotIn("login_hint", query)

    def test_codex_account_chooser_selects_current_session(self):
        flow = self.make_flow()

        class Page:
            url = "https://auth.openai.com/choose-an-account"

            def evaluate(self, script, payload):
                self.script = script
                self.payload = payload
                return True

        page = Page()

        self.assertTrue(flow._select_codex_account_if_visible(page))
        self.assertEqual(page.payload, {"email": "user@example.com"})
        self.assertIn('button[name="session_id"]', page.script)
        self.assertIn("form.requestSubmit(target)", page.script)

    def test_token_exchange_uses_independent_proxied_form_request(self):
        flow = self.make_flow()
        flow.proxy_url = "http://user:pass@proxy.example:8080"
        response = Mock(ok=True, status_code=200)
        response.json.return_value = {
            "access_token": "access-token",
            "refresh_token": "rt_test",
            "id_token": "id-token",
        }
        session = Mock()
        session.post.return_value = response

        with patch.object(requests, "Session", return_value=session):
            result = flow._exchange_browser_code_for_token(Mock(), "auth-code", "code-verifier")

        self.assertEqual(result["refresh_token"], "rt_test")
        session.proxies.update.assert_called_once_with({
            "http": "http://user:pass@proxy.example:8080",
            "https": "http://user:pass@proxy.example:8080",
        })
        request = session.post.call_args
        self.assertEqual(
            request.kwargs["data"],
            {
                "grant_type": "authorization_code",
                "client_id": ANY,
                "code": "auth-code",
                "redirect_uri": DEFAULT_REDIRECT_URI,
                "code_verifier": "code-verifier",
            },
        )

    def test_token_exchange_retries_network_error_and_falls_back_endpoint(self):
        flow = self.make_flow()
        response = Mock(ok=True, status_code=200)
        response.json.return_value = {"access_token": "access-token", "refresh_token": "rt_test"}
        session = Mock()
        session.post.side_effect = [
            requests.exceptions.SSLError("wrong version number"),
            requests.exceptions.SSLError("wrong version number"),
            requests.exceptions.SSLError("wrong version number"),
            response,
        ]

        with (
            patch.object(requests, "Session", return_value=session),
            patch.object(flow, "_sleep_checked", return_value=None),
        ):
            result = flow._exchange_browser_code_for_token(Mock(), "auth-code", "code-verifier")

        self.assertEqual(result["refresh_token"], "rt_test")
        self.assertEqual(session.post.call_count, 4)
        self.assertNotEqual(session.post.call_args_list[0].args[0], session.post.call_args_list[-1].args[0])

    def test_attribute_based_consent_submit_captures_callback_before_chrome_error(self):
        logs: list[str] = []
        flow = self.make_flow(logs)

        class Request:
            def __init__(self, url: str):
                self.url = url

        class Route:
            def __init__(self, url: str):
                self.request = Request(url)
                self.fulfilled = False

            def fulfill(self, **_kwargs):
                self.fulfilled = True

        class Page:
            def __init__(self):
                self.url = "about:blank"
                self.listeners = {}
                self.route_handler = None
                self.callback_fulfilled = False

            def on(self, event, handler):
                self.listeners[event] = handler

            def route(self, _pattern, handler):
                self.route_handler = handler

            def goto(self, oauth_url, **_kwargs):
                self.url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
                self.oauth_state = parse_qs(urlparse(oauth_url).query)["state"][0]

            def evaluate(self, script):
                self.uses_stable_submit_identity = (
                    'data-dd-action-name="Continue"' in script
                    and "form.requestSubmit(target)" in script
                    and "缍氳" in script
                )
                callback_url = f"{DEFAULT_REDIRECT_URI}?code=auth-code&state={self.oauth_state}"
                route = Route(callback_url)
                self.route_handler(route)
                self.callback_fulfilled = route.fulfilled
                self.url = "chrome-error://chromewebdata/"
                return self.uses_stable_submit_identity

            def unroute(self, *_args):
                return None

            def remove_listener(self, *_args):
                return None

        page = Page()
        with (
            patch.object(flow, "_has_phone_form", return_value=False),
            patch.object(flow, "_sleep_checked", return_value=None),
            patch.object(flow, "_exchange_browser_code_for_token", return_value={"refresh_token": "rt_test"}) as exchange,
        ):
            result = flow._authorize_rt_from_browser(Mock(), page)

        self.assertEqual(result["refresh_token"], "rt_test")
        self.assertTrue(page.callback_fulfilled)
        exchange.assert_called_once_with(ANY, "auth-code", ANY)
        self.assertTrue(page.callback_fulfilled)

    def test_codex_consent_workspace_selection_resumes_oauth_callback(self):
        logs: list[str] = []
        flow = self.make_flow(logs)

        class Request:
            def __init__(self, url: str):
                self.url = url

        class Route:
            def __init__(self, url: str):
                self.request = Request(url)

            def fulfill(self, **_kwargs):
                return None

        class Page:
            def __init__(self):
                self.url = "about:blank"
                self.route_handler = None

            def on(self, _event, _handler):
                return None

            def route(self, _pattern, handler):
                self.route_handler = handler

            def goto(self, oauth_url, **_kwargs):
                self.url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
                self.oauth_state = parse_qs(urlparse(oauth_url).query)["state"][0]

            def evaluate(self, script):
                if "sunnyRegisterWorkspaceSelected" in script and not getattr(self, "workspace_selected", False):
                    self.workspace_selected = True
                    return True
                if "sunnyRegisterSubmitted" not in script or not getattr(self, "workspace_selected", False):
                    return False
                callback_url = f"{DEFAULT_REDIRECT_URI}?code=workspace-auth-code&state={self.oauth_state}"
                self.route_handler(Route(callback_url))
                self.url = callback_url
                return True

            def unroute(self, *_args):
                return None

            def remove_listener(self, *_args):
                return None

        with (
            patch.object(flow, "_has_phone_form", return_value=False),
            patch.object(flow, "_has_totp_challenge", return_value=False),
            patch.object(flow, "_sleep_checked", return_value=None),
            patch.object(flow, "_exchange_browser_code_for_token", return_value={"refresh_token": "rt_test"}) as exchange,
        ):
            result = flow._authorize_rt_from_browser(Mock(), Page())

        self.assertEqual(result["refresh_token"], "rt_test")
        exchange.assert_called_once_with(ANY, "workspace-auth-code", ANY)
        self.assertTrue(any("已选择 Codex 授权 workspace" in item for item in logs))

    def test_workspace_select_response_captures_callback_before_navigation(self):
        logs: list[str] = []
        flow = self.make_flow(logs)

        class Response:
            url = "https://auth.openai.com/api/accounts/workspace/select"

            def __init__(self, callback_url: str):
                self.callback_url = callback_url

            def json(self):
                return {"continue_url": self.callback_url}

        class Page:
            def __init__(self):
                self.url = "about:blank"
                self.listeners = {}

            def on(self, event, handler):
                self.listeners[event] = handler

            def route(self, *_args):
                return None

            def goto(self, oauth_url, **_kwargs):
                self.url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
                self.oauth_state = parse_qs(urlparse(oauth_url).query)["state"][0]

            def evaluate(self, script, *_args):
                if "sunnyRegisterWorkspaceSelected" in script and not getattr(self, "selected", False):
                    self.selected = True
                    return True
                if "sunnyRegisterSubmitted" in script and self.selected:
                    callback = f"{DEFAULT_REDIRECT_URI}?code=response-auth-code&state={self.oauth_state}"
                    self.listeners["response"](Response(callback))
                    return True
                return False

            def unroute(self, *_args):
                return None

            def remove_listener(self, *_args):
                return None

        with (
            patch.object(flow, "_has_phone_form", return_value=False),
            patch.object(flow, "_has_totp_challenge", return_value=False),
            patch.object(flow, "_sleep_checked", return_value=None),
            patch.object(flow, "_exchange_browser_code_for_token", return_value={"refresh_token": "rt_test"}) as exchange,
        ):
            result = flow._authorize_rt_from_browser(Mock(), Page())

        self.assertEqual(result["refresh_token"], "rt_test")
        exchange.assert_called_once_with(ANY, "response-auth-code", ANY)

    def test_codex_consent_submit_allows_one_delayed_retry(self):
        flow = self.make_flow()
        page = Mock()
        # First evaluate submits the form. The delayed retry first clears the
        # stale marker, then submits the still-mounted React Router form again.
        page.evaluate.side_effect = [True, None, True]
        with patch("sunny_core.openai_auth.time.time", side_effect=[100.0, 109.0]):
            self.assertTrue(flow._click_codex_consent_if_visible(page))
            self.assertTrue(flow._click_codex_consent_if_visible(page))
            self.assertFalse(flow._click_codex_consent_if_visible(page))
        self.assertEqual(flow._codex_consent_submit_count, 2)
        self.assertEqual(page.evaluate.call_count, 3)


class BrowserEmailOTPSubmitTests(unittest.TestCase):
    def test_camoufox_email_otp_prefers_native_form_submit(self):
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
        )
        logs: list[str] = []
        flow = OpenAIEmailRegisterFlow(account, "", True, logs.append)
        flow.otp_reader = Mock()
        flow.otp_reader.wait_for_code.return_value = "123456"
        otp_input = Mock()

        with (
            patch.object(flow, "_visible_inputs", return_value=[otp_input]),
            patch.object(flow, "_submit_email_code_form", return_value=True) as native_submit,
            patch.object(flow, "_validate_email_code_api", return_value="") as api_submit,
            patch.object(flow, "_wait_after_otp_submit") as wait_transition,
        ):
            flow._submit_email_code(Mock(), 0)

        self.assertEqual(otp_input.fill.call_args_list[-1].args[0], "123456")
        native_submit.assert_called_once()
        api_submit.assert_not_called()
        wait_transition.assert_called_once()
        self.assertTrue(any("Camoufox" in item for item in logs))

    def test_existing_account_camoufox_otp_uses_single_sentinel_request(self):
        account = MailAccount(
            email="registered@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="registered@example.com----password----client-id----outlook-refresh-token",
        )
        logs: list[str] = []
        flow = OpenAIEmailRegisterFlow(account, "", True, logs.append, existing_account=True)
        flow.otp_reader = Mock()
        flow.otp_reader.wait_for_code.return_value = "123456"
        page = Mock()

        with (
            patch.object(flow, "_fill_email_code_inputs") as fill_inputs,
            patch.object(flow, "_submit_email_code_form") as native_submit,
            patch.object(flow, "_validate_email_code_api", return_value="https://chatgpt.com/") as api_submit,
            patch.object(flow, "_wait_after_otp_submit") as wait_transition,
        ):
            flow._submit_email_code(page, 0)

        fill_inputs.assert_not_called()
        native_submit.assert_not_called()
        api_submit.assert_called_once_with(page, "123456")
        page.goto.assert_called_once_with("https://chatgpt.com/", wait_until="domcontentloaded", timeout=90000)
        wait_transition.assert_called_once_with(page)
        self.assertTrue(any("续期登录浏览器会话" in item for item in logs))

    def test_sentinel_required_json_is_classified_as_challenge(self):
        account = MailAccount("registered@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None, existing_account=True)

        self.assertTrue(flow._is_cloudflare_challenge('{"error":{"code":"sentinel_required"}}'))

    def test_email_otp_falls_back_to_native_then_json_api_on_html_route_error(self):
        account = MailAccount(
            email="user@example.com",
            password="password",
            client_id="client-id",
            refresh_token="outlook-refresh-token",
            raw="user@example.com----password----client-id----outlook-refresh-token",
        )
        flow = OpenAIEmailRegisterFlow(account, "", False, lambda _message: None)
        flow.otp_reader = Mock()
        flow.otp_reader.wait_for_code.return_value = "123456"
        page = Mock()
        otp_input = Mock()

        with (
            patch.object(flow, "_visible_inputs", return_value=[otp_input]),
            patch.object(flow, "_submit_email_code_form", return_value=True),
            patch.object(flow, "_wait_after_otp_submit", side_effect=[RuntimeError("Route Error (400 Invalid content type: text/html; charset=UTF-8)"), None]) as wait_transition,
            patch.object(flow, "_retry_email_code_page_submit_after_route_error", return_value=False) as retry_page_submit,
            patch.object(flow, "_validate_email_code_api", side_effect=[RuntimeError("temporary api error"), "https://chatgpt.com/"]) as api_submit,
        ):
            flow._submit_email_code(page, 0)

        retry_page_submit.assert_called_once_with(page, "123456")
        self.assertEqual(api_submit.call_count, 2)
        page.goto.assert_called_once_with("https://chatgpt.com/", wait_until="domcontentloaded", timeout=90000)
        self.assertEqual(wait_transition.call_count, 2)

    def test_camoufox_email_otp_uses_sentinel_api_after_native_submit_stalls(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        flow.otp_reader = Mock()
        flow.otp_reader.wait_for_code.return_value = "123456"
        page = Mock()

        with (
            patch.object(flow, "_visible_inputs", return_value=[Mock()]),
            patch.object(flow, "_submit_email_code_form", return_value=True) as native_submit,
            patch.object(flow, "_wait_after_otp_submit", side_effect=RuntimeError("still on OTP page")),
            patch.object(flow, "_validate_email_code_api", side_effect=RuntimeError("EmailOtpValidate was blocked by Cloudflare")) as api_submit,
        ):
            with self.assertRaisesRegex(RuntimeError, "EmailOtpValidate"):
                flow._submit_email_code(page, 0)

        api_submit.assert_called_once()
        native_submit.assert_called_once()

    def test_camoufox_invalid_native_otp_requests_fresh_code_without_api_reuse(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        flow.otp_reader = Mock()
        flow.otp_reader.wait_for_code.return_value = "123456"
        page = Mock()

        with (
            patch.object(flow, "_visible_inputs", return_value=[Mock()]),
            patch.object(flow, "_submit_email_code_form", return_value=True),
            patch.object(
                flow,
                "_wait_after_otp_submit",
                side_effect=RuntimeError("Still on email verification page: 不正確なコード"),
            ),
            patch.object(flow, "_retry_with_fresh_email_code") as retry_fresh,
            patch.object(flow, "_validate_email_code_api") as api_submit,
        ):
            flow._submit_email_code(page, 0)

        retry_fresh.assert_called_once_with(page, "123456")
        api_submit.assert_not_called()

    def test_email_otp_api_stops_immediately_on_max_attempts(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        page = Mock()
        page.url = "https://auth.openai.com/email-verification"
        page.evaluate.return_value = "Mozilla/5.0 Firefox/135.0"
        response = {
            "ok": False,
            "status": 400,
            "text": '{"error":{"message":"Too many tries.","code":"max_check_attempts"}}',
        }

        with (
            patch("sunny_core.openai_auth.build_sentinel_token", return_value="sentinel-token"),
            patch("sunny_core.openai_auth.browser_fetch", return_value=response) as fetch,
        ):
            with self.assertRaisesRegex(RuntimeError, "尝试次数已达上限"):
                flow._validate_email_code_api(page, "123456")

        fetch.assert_called_once()

    def test_email_otp_api_attaches_sentinel_and_device_headers(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        flow.device_id = "device-id"
        page = Mock()
        page.url = "https://auth.openai.com/email-verification"
        page.evaluate.return_value = "Mozilla/5.0 Firefox/135.0"
        response = {"ok": True, "status": 200, "text": "{}", "data": {"continue_url": "https://auth.openai.com/about-you"}}

        with (
            patch("sunny_core.openai_auth.build_sentinel_token", return_value="sentinel-token") as build_token,
            patch("sunny_core.openai_auth.browser_fetch", return_value=response) as fetch,
        ):
            next_url = flow._validate_email_code_api(page, "123456")

        self.assertEqual(next_url, "https://auth.openai.com/about-you")
        build_token.assert_called_once_with(
            page,
            "device-id",
            "email_otp_validate",
            "Mozilla/5.0 Firefox/135.0",
            timeout_ms=15000,
        )
        headers = fetch.call_args.kwargs["headers"]
        self.assertEqual(headers["openai-sentinel-token"], "sentinel-token")
        self.assertEqual(headers["oai-device-id"], "device-id")

    def test_email_otp_api_retries_aborted_browser_fetch(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)
        page = Mock()
        page.url = "https://auth.openai.com/email-verification"
        page.evaluate.return_value = "Mozilla/5.0 Firefox/135.0"
        aborted = {"ok": False, "status": 0, "text": "The operation was aborted."}
        success = {"ok": True, "status": 200, "text": "{}", "data": {"continue_url": "https://auth.openai.com/about-you"}}

        with (
            patch("sunny_core.openai_auth.build_sentinel_token", return_value="sentinel-token"),
            patch("sunny_core.openai_auth.browser_fetch", side_effect=[aborted, success]) as fetch,
            patch.object(flow, "_sleep_checked") as sleep_checked,
        ):
            next_url = flow._validate_email_code_api(page, "608426")

        self.assertEqual(next_url, "https://auth.openai.com/about-you")
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual([call.kwargs["timeout_ms"] for call in fetch.call_args_list], [15000, 15000])
        sleep_checked.assert_called_once_with(1.5)

    def test_native_otp_submit_uses_stable_identifiers_and_clicks_submitter(self):
        account = MailAccount("user@example.com", "password", "client-id", "mail-rt", "raw")
        flow = OpenAIEmailRegisterFlow(account, "", True, lambda _message: None)

        class Page:
            def evaluate(self, script):
                return (
                    'data-dd-action-name="Continue"' in script
                    and 'name="intent"][value="validate"' in script
                    and "submitter.click()" in script
                    and "form.requestSubmit(submitter)" in script
                )

        with patch.object(flow, "_submit_email_code_by_locator", return_value=False):
            self.assertTrue(flow._submit_email_code_form(Page()))

class Sub2APIImportPayloadTests(unittest.TestCase):
    def test_sub2api_notes_include_login_secret_when_available(self):
        db = Mock()
        db.fetch_mailbox_by_email.return_value = {
            "raw": "user@example.com----password----client-id----refresh-token",
            "chat_gpt_password": "ChatGPT-password",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }
        cfg = {
            "notes_include_sk": True,
            "notes_include_ls": True,
            "notes_include_custom": True,
            "notes_custom_text": "自定义备注",
        }
        notes = worker._sub2api_notes(db, "user@example.com", {}, cfg)
        self.assertEqual(
            notes,
            "邮箱凭证：user@example.com----password----client-id----refresh-token\n"
            "密码2FA：user@example.com----ChatGPT-password----JBSWY3DPEHPK3PXP\n"
            "自定义备注",
        )
        self.assertEqual(worker._sub2api_notes(db, "user@example.com", {}, {}), "")
        self.assertEqual(
            worker._sub2api_notes(db, "user@example.com", {}, {"notes_include_ls": True}),
            "密码2FA：user@example.com----ChatGPT-password----JBSWY3DPEHPK3PXP",
        )

    def test_oauth_protocol_fields_are_forwarded_to_sub2api(self):
        db = Mock()
        db.task_id = "test-task"
        db.fetch_mailbox_by_email.return_value = mailbox()
        db.get_config.return_value = {
            "enabled": True,
            "base_url": "https://sub2api.example",
            "admin_token": "admin-key",
            "name_prefix": "Sunny-",
            "group_ids": [2, 3],
            "concurrency": 5,
            "priority": 1,
            "notes_include_sk": True,
        }
        response = Mock(status_code=200, text='{"success":1,"failed":0}')
        response.json.return_value = {"success": 1, "failed": 0, "results": []}
        session = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "id_token": "id-token",
            "client_id": "client-id",
            "chatgpt_account_id": "account-id",
            "chatgpt_user_id": "user-id",
            "organization_id": "org-id",
            "plan_type": "plus",
            "expires_at": 123456789,
        }

        with patch.object(worker.requests, "post", return_value=response) as post:
            result = worker._import_sub2api(db, "user@example.com", 7, session)

        self.assertEqual(result["success"], 1)
        request_body = post.call_args.kwargs["json"]
        self.assertEqual(len(request_body["accounts"]), 1)
        payload = request_body["accounts"][0]
        self.assertEqual(payload["credentials"]["client_id"], "client-id")
        self.assertEqual(payload["credentials"]["chatgpt_account_id"], "account-id")
        self.assertEqual(payload["credentials"]["chatgpt_user_id"], "user-id")
        self.assertEqual(payload["credentials"]["organization_id"], "org-id")
        self.assertEqual(payload["credentials"]["plan_type"], "plus")
        self.assertEqual(payload["credentials"]["expires_at"], 123456789)
        self.assertEqual(payload["notes"], "邮箱凭证：user@example.com----password----client-id----outlook-refresh-token")
        self.assertIn("gpt-5.6-sol", payload["credentials"]["model_mapping"])
        self.assertEqual(payload["extra"]["import_source"], "sunnyregister_oauth_code")
        self.assertTrue(post.call_args.kwargs["headers"]["Idempotency-Key"].startswith("sunny-test-task-7-"))

    def test_batch_import_retries_transient_failure_and_requires_confirmation(self):
        db = Mock()
        db.task_id = "test-task"
        db.get_config.return_value = {
            "enabled": True,
            "base_url": "https://sub2api.example",
            "admin_token": "admin-key",
            "proxy_id": 9,
            "load_factor": 80,
            "model_whitelist": ["gpt-5.6-sol"],
        }
        retry = Mock(status_code=503, text="temporary")
        success = Mock(status_code=200, text='{"success":1,"failed":0}')
        success.json.return_value = {"success": 1, "failed": 0, "results": []}
        session = {"access_token": "at", "refresh_token": "rt"}

        with patch.object(worker.requests, "post", side_effect=[retry, success]) as post:
            worker._import_sub2api(db, "user@example.com", 7, session)

        self.assertEqual(post.call_count, 2)
        first = post.call_args_list[0].kwargs
        second = post.call_args_list[1].kwargs
        self.assertEqual(first["headers"]["Idempotency-Key"], second["headers"]["Idempotency-Key"])
        account = second["json"]["accounts"][0]
        self.assertEqual(account["proxy_id"], 9)
        self.assertEqual(account["load_factor"], 80)
        self.assertEqual(account["credentials"]["model_mapping"], {"gpt-5.6-sol": "gpt-5.6-sol"})

        ambiguous = Mock(status_code=200, text='{"message":"accepted"}')
        ambiguous.json.return_value = {"message": "accepted"}
        with patch.object(worker.requests, "post", return_value=ambiguous):
            with self.assertRaisesRegex(RuntimeError, "未确认成功"):
                worker._import_sub2api(db, "user@example.com", 7, session)

        nested = Mock(status_code=200, text='{"results":[]}')
        nested.json.return_value = {
            "results": [{"status": "created", "account": {"id": "remote-9", "email": "user@example.com"}}]
        }
        with patch.object(worker.requests, "post", return_value=nested):
            worker._import_sub2api(db, "user@example.com", 7, session)
        self.assertEqual(db.set_account_sub2api_status.call_args.args, ("user@example.com", "imported", "remote-9"))

        with self.assertRaisesRegex(RuntimeError, "Access Token"):
            worker._import_sub2api(db, "user@example.com", 7, {"refresh_token": "rt"})


class AddLoginSecretTaskTests(unittest.TestCase):
    def test_account_uses_workbench_sentinel_protocol_runtime(self):
        db = MagicMock()
        db.fetch_mailbox_by_email.return_value = {
            "id": 11,
            "email": "user@example.com",
            "status": "已注册",
            "chat_gpt_password": "",
            "totp_secret": "",
        }
        with patch.object(worker, "_run_one", return_value=(True, {"login_secret_complete": True})) as run_one:
            success, errors, item = worker._add_login_secret_account(
                db,
                {},
                {"id": 7, "email": "user@example.com"},
                1,
                1,
            )

        self.assertEqual((success, errors, item["status"]), (1, [], "success"))
        task_payload = run_one.call_args.args[2]
        self.assertEqual(task_payload["execution_mode"], "protocol")
        self.assertEqual(task_payload["protocol_challenge_strategy"], "sentinel_protocol")
        self.assertIs(task_payload["setup_login_secret"], True)
        self.assertEqual(task_payload["registration_stage"], worker.REGISTER_ONLY)

    def test_complete_login_secret_is_skipped_before_runtime(self):
        db = MagicMock()
        db.fetch_mailbox_by_email.return_value = {
            "id": 11,
            "email": "user@example.com",
            "status": "已注册",
            "chat_gpt_password": "chatgpt-password",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }
        with patch.object(worker, "_run_one") as run_one:
            success, errors, item = worker._add_login_secret_account(
                db,
                {},
                {"id": 7, "email": "user@example.com"},
                1,
                1,
            )

        self.assertEqual((success, errors, item["status"]), (0, [], "skipped"))
        run_one.assert_not_called()

    def test_password_only_account_is_sent_to_runtime_for_2fa_setup(self):
        db = MagicMock()
        db.fetch_mailbox_by_email.return_value = {
            "id": 11,
            "email": "user@example.com",
            "status": "已注册",
            "chat_gpt_password": "chatgpt-password",
            "totp_secret": "",
        }
        with patch.object(worker, "_run_one", return_value=(True, {"login_secret_complete": True})) as run_one:
            success, errors, item = worker._add_login_secret_account(
                db,
                {},
                {"id": 7, "email": "user@example.com"},
                1,
                1,
            )

        self.assertEqual((success, errors, item["status"]), (1, [], "success"))
        run_one.assert_called_once()
        runtime_mailbox = run_one.call_args.args[3]
        self.assertEqual(runtime_mailbox["chat_gpt_password"], "chatgpt-password")

    def test_default_concurrency_is_one_and_a_half_times_cpu_count(self):
        db = MagicMock()
        db.task_id = "task-add-ls"
        db.cancel_requested.return_value = False
        db.fetch_accounts.return_value = [
            {"id": index, "email": f"user-{index}@example.com"}
            for index in range(1, 5)
        ]

        def isolated(_task_id, _payload, account_id, index, _total):
            return index, 1, [], {"email": f"user-{account_id}@example.com", "status": "success", "login_secret_complete": True}

        with (
            patch.object(worker.os, "cpu_count", return_value=2),
            patch.object(worker, "_add_login_secret_isolated", side_effect=isolated),
        ):
            success, errors, items = worker._add_login_secrets(db, {"account_ids": [1, 2, 3, 4], "account_ids_explicit": True})

        self.assertEqual((success, errors, len(items)), (4, [], 4))
        concurrency_events = [call.kwargs.get("detail", {}) for call in db.event.call_args_list if "添加 LS 并发数" in str(call.args[0])]
        self.assertEqual(concurrency_events[0]["cpu_count"], 2)
        self.assertEqual(concurrency_events[0]["default_concurrency"], 3)
        self.assertEqual(concurrency_events[0]["concurrency"], 3)


class RebindProxyRotationTests(unittest.TestCase):
    def test_rebind_rotates_proxy_after_login_transport_timeout(self):
        db = MagicMock()
        first_error = ProtocolRegistrationError(
            "OpenAI authorization initialization request failed: curl: (28) Operation timed out"
        )
        first_error.rebind_phase = "login"
        payload = {
            "proxy_pool": [
                "http://proxy-one.example:8080",
                "http://proxy-two.example:8080",
            ],
            "proxy_ids": [1, 2],
        }
        selected = []

        def prepare(_db, current_payload, _email, slot):
            excluded = set(current_payload.get("_excluded_register_proxies") or [])
            address = "http://proxy-one.example:8080" if not excluded else "http://proxy-two.example:8080"
            return {"register": address, "mode": "proxy_pool", "slot": slot}

        def execute(_db, account, proxy, _log):
            selected.append(proxy)
            if len(selected) == 1:
                raise first_error
            return {"email": account["email"], "status": "success"}

        with (
            patch.object(worker, "_prepare_register_proxy", side_effect=prepare),
            patch.object(worker, "rebind_one", side_effect=execute),
        ):
            result = worker._rebind_with_proxy_rotation(
                db,
                payload,
                {"id": 1, "email": "rotate@example.com"},
                0,
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(selected, ["http://proxy-one.example:8080", "http://proxy-two.example:8080"])
        self.assertTrue(any("切换下一条" in str(call.args[0]) for call in db.event.call_args_list))

    def test_rebind_does_not_rotate_proxy_after_business_failure(self):
        db = MagicMock()
        payload = {
            "proxy_pool": [
                "http://proxy-one.example:8080",
                "http://proxy-two.example:8080",
            ],
            "proxy_ids": [1, 2],
        }
        with (
            patch.object(worker, "_prepare_register_proxy", return_value={"register": "http://proxy-one.example:8080"}),
            patch.object(worker, "rebind_one", side_effect=RuntimeError("当前账户不允许邮箱换绑")) as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "不允许邮箱换绑"):
                worker._rebind_with_proxy_rotation(db, payload, {"id": 1, "email": "business@example.com"}, 0)

        execute.assert_called_once()


class RebindTaskTests(unittest.TestCase):
    def test_serial_rebind_selects_proxy_by_account_slot(self):
        db = MagicMock()
        db.task_id = "task-rebind-proxy"
        db.cancel_requested.return_value = False
        db.fetch_accounts.return_value = [
            {"id": 1, "email": "first@example.com"},
            {"id": 2, "email": "second@example.com"},
        ]
        slots = []

        def select_proxy(_db, _payload, _email, slot):
            slots.append(slot)
            return {"register": f"http://proxy-{slot}.example:8080"}

        with (
            patch.object(worker, "_prepare_register_proxy", side_effect=select_proxy),
            patch.object(worker, "rebind_one", side_effect=lambda _db, account, _proxy, _log: {"email": account["email"], "status": "success"}),
        ):
            success, errors, items = worker._rebind_sessions(db, {"concurrency": 1})

        self.assertEqual((success, errors, len(items)), (2, [], 2))
        self.assertEqual(slots, [0, 1])

    def test_default_concurrency_is_one_and_a_half_times_cpu_count(self):
        db = MagicMock()
        db.task_id = "task-rebind"
        db.cancel_requested.return_value = False
        db.fetch_accounts.return_value = [
            {"id": index, "email": f"user-{index}@example.com"}
            for index in range(1, 5)
        ]

        def isolated(_task_id, _payload, account_id, index, _total):
            return index, {"email": f"user-{account_id}@example.com", "status": "success", "new_email": f"rebound-{account_id}@example.com"}

        with (
            patch.object(worker.os, "cpu_count", return_value=2),
            patch.object(worker, "_rebind_one_isolated", side_effect=isolated),
        ):
            success, errors, items = worker._rebind_sessions(db, {})

        self.assertEqual((success, errors, len(items)), (4, [], 4))
        concurrency_events = [call.kwargs.get("detail", {}) for call in db.event.call_args_list if "邮箱换绑并发数" in str(call.args[0])]
        self.assertEqual(concurrency_events[0]["cpu_count"], 2)
        self.assertEqual(concurrency_events[0]["default_concurrency"], 3)
        self.assertEqual(concurrency_events[0]["concurrency"], 3)

    def test_all_prefiltered_accounts_do_not_expand_to_all_database_accounts(self):
        db = MagicMock()
        skipped = {"email": "complete@example.com", "status": "skipped", "login_secret_complete": True}

        success, errors, items = worker._add_login_secrets(
            db,
            {
                "account_ids": [],
                "account_ids_explicit": True,
                "prefiltered_login_secret_items": [skipped],
            },
        )

        self.assertEqual((success, errors, items), (0, [], [skipped]))
        db.fetch_accounts.assert_not_called()
        db.update_task.assert_called_once_with(progress_total=1, progress_current=1, success_count=0, error_count=0)


if __name__ == "__main__":
    unittest.main()
