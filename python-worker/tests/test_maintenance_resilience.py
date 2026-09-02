from __future__ import annotations

import sqlite3
import unittest

from sunny_core.auth_resilience import classify_auth_failure, retry_allowed
from sunny_core.db import SunnyDB
from sunny_core.mailbox import _recipient_matches
from sunny_core.proxy_scheduler import TaskProxyScheduler


class AuthResilienceTests(unittest.TestCase):
    def test_terminal_and_retryable_failures_are_separated(self):
        self.assertTrue(classify_auth_failure("account_deactivated").terminal)
        self.assertTrue(classify_auth_failure("mailbox_credential_expired").terminal)
        rate_limit = classify_auth_failure("rate_limit_exceeded")
        self.assertTrue(rate_limit.retryable)
        self.assertTrue(rate_limit.rotate_proxy)
        stale = classify_auth_failure("invalid_auth_step")
        self.assertTrue(stale.fresh_context)
        self.assertFalse(retry_allowed("invalid_auth_step", 1, operation="protocol_login").retryable)
        self.assertEqual(classify_auth_failure("edge rejected", http_status=403).category, "edge_blocked")

    def test_invalid_openai_refresh_token_does_not_disable_mailbox_credentials(self):
        failure = classify_auth_failure("Invalid OpenAI refresh token")
        self.assertEqual(failure.category, "token_invalid")
        self.assertFalse(failure.terminal)


class ProxySchedulerTests(unittest.TestCase):
    def test_sticky_lease_rotates_after_rate_limit_cooldown(self):
        checked: list[str] = []

        def preflight(address: str):
            checked.append(address)
            return {"ok": True, "latency_ms": 25 if address.endswith("1") else 40}

        scheduler = TaskProxyScheduler(
            [
                {"id": 1, "register": "http://proxy-1"},
                {"id": 2, "register": "http://proxy-2"},
            ],
            preflight,
        )
        first = scheduler.acquire("user@example.com")
        self.assertEqual(first.proxy_id, 1)
        self.assertEqual(scheduler.acquire("user@example.com").proxy_id, 1)
        scheduler.record(first, success=False, error="rate_limit_exceeded")
        second = scheduler.acquire("user@example.com")
        self.assertEqual(second.proxy_id, 2)
        self.assertEqual(len(checked), 2)
        self.assertEqual(scheduler.snapshot()["cooling"], 1)

    def test_bad_account_credentials_do_not_penalize_proxy(self):
        scheduler = TaskProxyScheduler(
            [{"id": 1, "register": "http://proxy-1"}],
            lambda _address: {"ok": True, "latency_ms": 10},
        )
        lease = scheduler.acquire("user@example.com")
        scheduler.record(lease, success=False, error="incorrect password")
        self.assertEqual(scheduler.acquire("user@example.com").proxy_id, 1)
        self.assertEqual(scheduler.snapshot()["cooling"], 0)


class MailboxLeaseTests(unittest.TestCase):
    def setUp(self):
        self.db = SunnyDB.__new__(SunnyDB)
        self.db.task_id = "test"
        self.db.postgres = False
        self.db.conn = sqlite3.connect(":memory:")
        self.db.conn.row_factory = sqlite3.Row
        self.db.conn.execute(
            "create table sunny_mailbox_leases(id integer primary key autoincrement,mailbox_id integer unique,owner text,expires_at datetime,created_at datetime,updated_at datetime)"
        )

    def tearDown(self):
        self.db.close()

    def test_mailbox_lease_is_exclusive_and_releasable(self):
        self.assertTrue(self.db.acquire_mailbox_lease(9, "task-a", 60))
        self.assertFalse(self.db.acquire_mailbox_lease(9, "task-b", 60))
        self.db.release_mailbox_lease(9, "task-a")
        self.assertTrue(self.db.acquire_mailbox_lease(9, "task-b", 60))

    def test_recipient_filter_avoids_cross_account_otp(self):
        self.assertTrue(_recipient_matches("target@example.com", "Target <target@example.com>"))
        self.assertFalse(_recipient_matches("target@example.com", "other@example.com"))


if __name__ == "__main__":
    unittest.main()
