from __future__ import annotations

import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

from sunny_core import worker
from sunny_core.db import SunnyDB, SunnyTaskCancelled


class FakeRefreshDB:
    def __init__(self, *, refresh_token: str = "", mailbox_status: str = "已注册") -> None:
        self.refresh_token = refresh_token
        self.access_token = ""
        self.mailbox_status = mailbox_status
        self.events: list[str] = []
        self.event_details: list[dict] = []
        self.sessions: list[dict] = []
        self.marked_status = ""
        self.renewal_failure = ""
        self.deactivated_error = ""
        self.discarded_token = ""

    def fetch_accounts(self, _ids=None):
        return [{"id": 7, "email": "registered@example.com", "openai_rt": self.refresh_token, "access_token": self.access_token}]

    def fetch_session_by_email(self, _email):
        return {"refresh_token": self.refresh_token, "access_token": self.access_token, "access_token_status": "invalid" if not self.access_token else "valid"}

    def fetch_mailbox_by_email(self, _email):
        return {"id": 11, "email": "registered@example.com", "status": self.mailbox_status}

    def ensure_not_cancelled(self):
        return None

    def event(self, message, *_args, **_kwargs):
        self.events.append(message)
        detail = _kwargs.get("detail")
        if isinstance(detail, dict):
            self.event_details.append(detail)

    def update_task(self, **_kwargs):
        return None

    def upsert_session(self, _email, _account_id, session, _raw_line=""):
        self.sessions.append(session)
        self.access_token = str(session.get("access_token") or self.access_token)
        self.refresh_token = str(session.get("refresh_token") or self.refresh_token)

    def upsert_account(self, *_args, **_kwargs):
        return 7

    def mark_mailbox_by_email(self, *_args, **_kwargs):
        self.marked_status = str(_args[1])
        return None

    def mark_access_token_renewal_failed(self, _email, error=""):
        self.renewal_failure = str(error)

    def mark_account_deactivated(self, _email, error=""):
        self.deactivated_error = str(error)

    def discard_unverified_access_token(self, _email, access_token, _error=""):
        self.discarded_token = str(access_token)
        if self.access_token == access_token:
            self.access_token = ""


def test_login_secret_callback_account_deactivated_is_promoted_to_terminal_error():
    with unittest.TestCase().assertRaisesRegex(RuntimeError, "account_deactivated"):
        worker._raise_if_login_secret_account_deactivated(
            {"complete": False, "errors": ["account_deactivated: account disabled"]}
        )


class RefreshSessionTests(unittest.TestCase):
    def test_cancelled_renewal_stops_without_recording_failure(self):
        db = FakeRefreshDB()
        with patch.object(worker, "_run_one", side_effect=SunnyTaskCancelled("Task cancelled by user")):
            with self.assertRaises(SunnyTaskCancelled):
                worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(db.renewal_failure, "")

    def test_missing_refresh_token_reuses_protocol_native_headless_login(self):
        db = FakeRefreshDB()
        def login(*_args):
            db.upsert_session("registered@example.com", 7, {"access_token": "at_login"})
            return True, {"has_access_token": True, "has_refresh_token": False}
        with (
            patch.object(worker, "_run_one", side_effect=login) as run_one,
            patch.object(worker, "probe_access_token", side_effect=[{"status": "invalid"}, {"status": "valid"}]),
        ):
            ok, errors, items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["refresh_method"], "login")
        self.assertTrue(items[0]["verified"])
        payload = run_one.call_args.args[2]
        self.assertEqual(payload["execution_mode"], "protocol")
        self.assertEqual(payload["protocol_challenge_strategy"], "sentinel_protocol")
        self.assertEqual(payload["registration_stage"], "register_only")
        self.assertTrue(payload["access_token_renewal"])
        renewal = [item for item in db.event_details if item.get("progress_type") == "access_token_renewal"]
        self.assertEqual((renewal[0]["current"], renewal[0]["total"]), (1, 10))
        self.assertEqual((renewal[-1]["current"], renewal[-1]["total"], renewal[-1]["state"]), (10, 10, "succeeded"))

    def test_refresh_token_is_used_before_browser_fallback(self):
        db = FakeRefreshDB(refresh_token="rt_test")
        token = {"access_token": "at_new", "refresh_token": "rt_new", "expires_at": 1893456000}
        with (
            patch.object(worker, "refresh_openai_access_token", return_value=token),
            patch.object(worker, "probe_access_token", side_effect=[{"status": "invalid"}, {"status": "valid"}]),
            patch.object(worker, "_run_one") as run_one,
        ):
            ok, errors, items = worker._refresh_sessions(db, {"account_ids": [7], "proxy_enabled": False})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["refresh_method"], "refresh_token")
        self.assertEqual(db.sessions[0]["expires_at"], 1893456000)
        run_one.assert_not_called()
        renewal = [item for item in db.event_details if item.get("progress_type") == "access_token_renewal"]
        self.assertEqual(renewal[0]["checkpoint"], "precheck_started")
        self.assertTrue(any(item["checkpoint"] == "secondary_probe" for item in renewal))
        self.assertEqual(renewal[-1]["state"], "succeeded")

    def test_refresh_token_does_not_downgrade_reverse_proxy_status(self):
        db = FakeRefreshDB(refresh_token="rt_test", mailbox_status="已反代")
        token = {"access_token": "at_new", "refresh_token": "rt_new"}
        with (
            patch.object(worker, "refresh_openai_access_token", return_value=token),
            patch.object(worker, "probe_access_token", side_effect=[{"status": "invalid"}, {"status": "valid"}]),
        ):
            ok, errors, _items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(db.marked_status, "已反代")

    def test_failed_renewal_is_persisted_for_account_status_display(self):
        db = FakeRefreshDB()
        with (
            patch.object(worker, "_run_one", return_value=(False, "login failed")),
            patch.object(worker, "probe_access_token", return_value={"status": "invalid"}),
        ):
            ok, errors, _items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 0)
        self.assertIn("login failed", errors[0])
        self.assertIn("login failed", db.renewal_failure)

    def test_login_result_that_fails_secondary_probe_is_discarded(self):
        db = FakeRefreshDB()

        def login(*_args):
            db.upsert_session("registered@example.com", 7, {"access_token": "at_unverified"})
            return True, {"has_access_token": True, "has_refresh_token": False}

        with (
            patch.object(worker, "_run_one", side_effect=login),
            patch.object(worker, "probe_access_token", side_effect=[{"status": "invalid"}, {"status": "invalid", "error": "AT 已失效"}]),
        ):
            ok, errors, items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 0)
        self.assertIn("二次验活失败", errors[0])
        self.assertEqual(db.discarded_token, "at_unverified")
        self.assertEqual(items[0]["status"], "failed")

    def test_account_deactivated_is_banned_without_retry(self):
        db = FakeRefreshDB()
        deactivated = (
            'EmailOtpValidate failed: HTTP 403 sentinel=yes {"error": {'
            '"message": "You do not have an account because it has been deleted or deactivated.", '
            '"code": "account_deactivated"}}'
        )
        with (
            patch.object(worker, "_run_one", return_value=(False, deactivated)) as run_one,
            patch.object(worker, "probe_access_token", return_value={"status": "invalid"}),
        ):
            ok, errors, _items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 0)
        self.assertIn("account_deactivated", errors[0])
        self.assertIn("account_deactivated", db.deactivated_error)
        self.assertEqual(db.renewal_failure, "")
        self.assertEqual(run_one.call_count, 1)
        self.assertFalse(worker._is_otp_security_context_failure(deactivated))

    def test_otp_403_retries_once_with_fresh_headless_context(self):
        db = FakeRefreshDB()
        otp_error = (
            "邮箱验证码已由页面提交，但注册状态未推进。关键请求："
            "REQ POST https://auth.openai.com/api/accounts/email-otp/validate | "
            "RESP 403 application/json"
        )
        def successful_login(*_args):
            db.upsert_session("registered@example.com", 7, {"access_token": "at_login"})
            return True, {"has_access_token": True, "has_refresh_token": False}
        responses = iter([(False, otp_error), successful_login])
        def run_login(*args):
            response = next(responses)
            return response(*args) if callable(response) else response
        with (
            patch.object(
                worker,
                "_run_one",
                side_effect=run_login,
            ) as run_one,
            patch.object(worker, "probe_access_token", side_effect=[{"status": "invalid"}, {"status": "valid"}]),
            patch.object(worker.time, "sleep", return_value=None) as sleep_mock,
        ):
            ok, errors, items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["refresh_method"], "login")
        self.assertEqual(run_one.call_count, 2)
        retry_payload = run_one.call_args_list[1].args[2]
        self.assertEqual(retry_payload["execution_mode"], "background")
        self.assertTrue(retry_payload["renewal_retry_fresh_context"])
        self.assertTrue(any("新的隔离无痕后台浏览器上下文" in message for message in db.events))
        self.assertEqual(sleep_mock.call_count, 12)

    def test_protocol_failure_falls_back_to_fresh_background_login(self):
        db = FakeRefreshDB()
        def successful_login(*_args):
            db.upsert_session("registered@example.com", 7, {"access_token": "at_login"})
            return True, {"has_access_token": True, "has_refresh_token": False}
        responses = iter([(False, "protocol request failed"), successful_login])
        def run_login(*args):
            response = next(responses)
            return response(*args) if callable(response) else response
        with (
            patch.object(
                worker,
                "_run_one",
                side_effect=run_login,
            ) as run_one,
            patch.object(worker, "probe_access_token", side_effect=[{"status": "invalid"}, {"status": "valid"}]),
            patch.object(worker.time, "sleep", return_value=None) as sleep_mock,
        ):
            ok, errors, items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["refresh_method"], "login")
        self.assertEqual(run_one.call_args_list[0].args[2]["execution_mode"], "protocol")
        self.assertEqual(run_one.call_args_list[1].args[2]["execution_mode"], "background")
        self.assertTrue(run_one.call_args_list[1].args[2]["renewal_retry_fresh_context"])
        self.assertEqual(sleep_mock.call_count, 2)

    def test_renewal_worker_pool_runs_accounts_with_bounded_concurrency(self):
        class ParallelDB:
            task_id = "renewal-task"

            def __init__(self) -> None:
                self.updates: list[dict] = []

            def fetch_accounts(self, _ids=None):
                return [{"id": index, "email": f"user{index}@example.com"} for index in range(1, 5)]

            def event(self, *_args, **_kwargs):
                return None

            def cancel_requested(self):
                return False

            def update_task(self, **fields):
                self.updates.append(fields)

        db = ParallelDB()
        lock = threading.Lock()
        active = 0
        peak = 0

        def refresh_one(_task_id, _payload, account_id, index, total):
            nonlocal active, peak
            self.assertEqual(total, 4)
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return index, 1, [], [{"email": f"user{account_id}@example.com"}]

        with (
            patch.object(worker, "_refresh_sessions_isolated", side_effect=refresh_one) as isolated,
            patch.object(worker, "probe_access_token", return_value={"status": "invalid"}),
        ):
            ok, errors, items = worker._refresh_sessions(db, {"account_ids": [1, 2, 3, 4], "concurrency": 3})

        self.assertEqual(ok, 4)
        self.assertEqual(errors, [])
        self.assertEqual(len(items), 4)
        self.assertEqual(isolated.call_count, 4)
        self.assertEqual(peak, 3)
        self.assertEqual(db.updates[-1]["progress_current"], 4)

    def test_renewal_worker_pool_refills_a_freed_slot_immediately(self):
        class ParallelDB:
            task_id = "renewal-refill-task"

            def fetch_accounts(self, _ids=None):
                return [{"id": index, "email": f"user{index}@example.com"} for index in range(1, 5)]

            def event(self, *_args, **_kwargs):
                return None

            def cancel_requested(self):
                return False

            def update_task(self, **_fields):
                return None

        initial_started = threading.Event()
        fourth_started = threading.Event()
        release_slow = threading.Event()
        fallback_released = threading.Event()
        start_lock = threading.Lock()
        started_count = 0

        def release_on_timeout():
            fallback_released.set()
            release_slow.set()

        fallback = threading.Timer(1.0, release_on_timeout)

        def refresh_one(_task_id, _payload, account_id, index, _total):
            nonlocal started_count
            with start_lock:
                started_count += 1
                if started_count == 3:
                    initial_started.set()
            if account_id == 1:
                self.assertTrue(initial_started.wait(0.5))
            elif account_id in {2, 3}:
                self.assertTrue(release_slow.wait(2.0))
            else:
                fourth_started.set()
                release_slow.set()
            return index, 1, [], [{"email": f"user{account_id}@example.com"}]

        fallback.start()
        try:
            with (
                patch.object(worker, "_refresh_sessions_isolated", side_effect=refresh_one),
                patch.object(worker, "probe_access_token", return_value={"status": "invalid"}),
            ):
                ok, errors, items = worker._refresh_sessions(
                    ParallelDB(),
                    {"account_ids": [1, 2, 3, 4], "concurrency": 3},
                )
        finally:
            fallback.cancel()
            release_slow.set()

        self.assertEqual((ok, errors, len(items)), (4, [], 4))
        self.assertTrue(fourth_started.is_set())
        self.assertFalse(fallback_released.is_set(), "next account waited for the entire concurrency group")

    def test_icloud_renewal_reuses_auth_proxy_when_auxiliary_route_is_direct(self):
        proxies = {"register": "http://proxy.example:8080"}

        self.assertEqual(
            worker._mailbox_proxy_for_task({"access_token_renewal": True}, proxies, "", "apple"),
            "http://proxy.example:8080",
        )
        self.assertEqual(worker._mailbox_proxy_for_task({}, proxies, "", "apple"), "")
        self.assertEqual(
            worker._mailbox_proxy_for_task({"access_token_renewal": True}, proxies, "", "microsoft"),
            "",
        )

    def test_failed_renewal_does_not_duplicate_email_prefix(self):
        db = FakeRefreshDB()
        with (
            patch.object(worker, "_run_one", return_value=(False, "[registered@example.com] login failed")),
            patch.object(worker, "probe_access_token", return_value={"status": "invalid"}),
        ):
            _ok, errors, _items = worker._refresh_sessions(db, {"account_ids": [7]})

        self.assertEqual(errors, ["[registered@example.com] login failed"])

    def test_wrong_otp_does_not_retry_security_context(self):
        self.assertFalse(worker._is_otp_security_context_failure("邮箱验证码被 OpenAI 拒绝；验证码错误"))


class AccountDeactivatedPersistenceTests(unittest.TestCase):
    def test_marks_mailbox_account_and_session_atomically(self):
        db = SunnyDB.__new__(SunnyDB)
        db.task_id = "test"
        db.conn = sqlite3.connect(":memory:")
        db.conn.row_factory = sqlite3.Row
        db.conn.execute("create table sunny_mailboxes(email text, status text, last_error text, last_health_checked_at text, status_changed_at text, updated_at text)")
        db.conn.execute("create table sunny_accounts(email text, status text, last_error text, last_health_checked_at text, status_changed_at text, updated_at text)")
        db.conn.execute("create table sunny_sessions(email text, access_token_status text, access_token_checked_at text, access_token_error text, updated_at text)")
        db.conn.execute("insert into sunny_mailboxes(email,status) values('user@example.com','已注册')")
        db.conn.execute("insert into sunny_accounts(email,status) values('user@example.com','registered')")
        db.conn.execute("insert into sunny_sessions(email,access_token_status) values('user@example.com','renewal_failed')")

        db.mark_account_deactivated("user@example.com", "account_deactivated")

        mailbox = db.conn.execute("select * from sunny_mailboxes").fetchone()
        account = db.conn.execute("select * from sunny_accounts").fetchone()
        session = db.conn.execute("select * from sunny_sessions").fetchone()
        self.assertEqual(mailbox["status"], "已封禁")
        self.assertEqual(account["status"], "banned")
        self.assertEqual(session["access_token_status"], "invalid")
        self.assertTrue(mailbox["last_health_checked_at"])
        self.assertEqual(mailbox["last_health_checked_at"], account["last_health_checked_at"])
        self.assertIn("account_deactivated", session["access_token_error"])
        db.close()


class AuthenticatedSessionPersistenceTests(unittest.TestCase):
    def test_rebound_login_updates_stable_rows_with_api_session_token(self):
        db = SunnyDB.__new__(SunnyDB)
        db.task_id = "test"
        db.postgres = False
        db.conn = sqlite3.connect(":memory:")
        db.conn.row_factory = sqlite3.Row
        db.conn.execute(
            """create table sunny_mailboxes(
                id integer primary key,email text,rebind_email text
            )"""
        )
        db.conn.execute(
            """create table sunny_accounts(
                id integer primary key,mailbox_id integer,email text,status text,access_token text,
                openai_rt text,last_error text,status_changed_at text,created_at text,updated_at text
            )"""
        )
        db.conn.execute(
            """create table sunny_sessions(
                id integer primary key,account_id integer,email text,access_token text,refresh_token text,
                id_token text,session_json text,storage_state_json text,raw_mailbox_line text,
                access_token_status text,access_token_error text,access_token_checked_at text,
                expires_at text,last_refresh_at text,created_at text,updated_at text
            )"""
        )
        db.conn.execute("insert into sunny_mailboxes values(11,'original@example.com','rebound@example.com')")
        db.conn.execute(
            "insert into sunny_accounts values(7,11,'original@example.com','registered','old-free-at','','',null,null,null)"
        )
        db.conn.execute(
            "insert into sunny_sessions values(17,7,'original@example.com','old-free-at','','','','','',"
            "'invalid','',null,null,null,null,null)"
        )
        db.conn.execute(
            "insert into sunny_accounts values(8,11,'rebound@example.com','registered','duplicate-at','','',null,null,null)"
        )
        db.conn.execute(
            "insert into sunny_sessions values(18,8,'rebound@example.com','duplicate-at','','','','','',"
            "'valid','',null,null,null,null,null)"
        )
        db.conn.commit()

        session = {
            "access_token": "stale-carried-at",
            "session_json": {"accessToken": "fresh-plus-at"},
            "storage_state_json": {},
        }
        account_id = db.persist_authenticated_session("original@example.com", 11, session)

        self.assertEqual(account_id, 7)
        self.assertEqual(session["access_token"], "fresh-plus-at")
        account = db.conn.execute("select * from sunny_accounts where id=7").fetchone()
        saved_session = db.conn.execute("select * from sunny_sessions where id=17").fetchone()
        self.assertEqual(account["access_token"], "fresh-plus-at")
        self.assertEqual(saved_session["access_token"], "fresh-plus-at")
        self.assertEqual(db.conn.execute("select count(*) from sunny_accounts").fetchone()[0], 1)
        self.assertEqual(db.conn.execute("select count(*) from sunny_sessions").fetchone()[0], 1)
        db.close()


class AcquireRefreshTokenTests(unittest.TestCase):
    def test_existing_refresh_token_returns_without_login(self):
        db = FakeRefreshDB(refresh_token="rt_existing")
        with (
            patch.object(worker, "_run_one") as run_one,
            patch.object(worker, "refresh_openai_access_token", return_value={"access_token": "at_new", "refresh_token": "rt_rotated"}),
            patch.object(worker, "probe_access_token", return_value={"status": "valid"}),
        ):
            ok, errors, items = worker._acquire_refresh_tokens(db, {"account_ids": [7]})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["acquire_method"], "refresh_token_validated")
        self.assertTrue(items[0]["verified"])
        run_one.assert_not_called()

    def test_missing_refresh_token_runs_protocol_codex_oauth(self):
        db = FakeRefreshDB()
        def acquire(*_args):
            db.upsert_session("registered@example.com", 7, {"access_token": "at_new", "refresh_token": "rt_new"})
            return True, {"has_refresh_token": True}
        with (
            patch.object(worker, "_run_one", side_effect=acquire) as run_one,
            patch.object(worker, "probe_access_token", return_value={"status": "valid"}),
        ):
            ok, errors, items = worker._acquire_refresh_tokens(db, {"account_ids": [7]})

        self.assertEqual(ok, 1)
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["acquire_method"], "codex_oauth")
        self.assertEqual(run_one.call_args.args[1], "sunny_acquire_rt")
        payload = run_one.call_args.args[2]
        self.assertEqual(payload["execution_mode"], "protocol")
        self.assertEqual(payload["protocol_challenge_strategy"], "sentinel_protocol")
        self.assertEqual(payload["registration_stage"], worker.CODEX_PHONE_BIND)

    def test_missing_refresh_token_reports_clear_failure(self):
        db = FakeRefreshDB()
        result = {"has_refresh_token": False, "stage_error": "OAuth phone verification required"}
        with patch.object(worker, "_run_one", return_value=(True, result)):
            ok, errors, items = worker._acquire_refresh_tokens(db, {"account_ids": [7]})

        self.assertEqual(ok, 0)
        self.assertEqual(items[0]["status"], "failed")
        self.assertIn("无法获取该账户RT", errors[0])
        self.assertIn("OAuth phone verification required", errors[0])


if __name__ == "__main__":
    unittest.main()
