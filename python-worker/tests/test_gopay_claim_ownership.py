from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


RUNTIME_SRC = Path(__file__).resolve().parents[1] / "gopay_runtime" / "app" / "src"
if str(RUNTIME_SRC) not in sys.path:
    sys.path.insert(0, str(RUNTIME_SRC))


@pytest.fixture(autouse=True)
def _stub_optional_tls_client(monkeypatch: pytest.MonkeyPatch):
    """Keep ownership tests runnable without the optional TLS client package."""
    if "tls_client" not in sys.modules:
        fake_tls_client = ModuleType("tls_client")
        fake_tls_client.Session = type("Session", (), {})
        monkeypatch.setitem(sys.modules, "tls_client", fake_tls_client)


def test_cli_initial_claim_renewal_uses_compare_and_swap_token() -> None:
    from opai.core import gopay_protocol_worker

    calls: list[tuple[str, str, dict[str, str] | None]] = []

    class FakeInbox:
        def _req(self, method: str, path: str, data=None):
            calls.append((method, path, data))
            return {"id": "job", "claimed_at": "renewed-token"}

    renewed = gopay_protocol_worker._renew_claim_before_payment(
        FakeInbox(), "job", "original-token"
    )

    assert renewed == "renewed-token"
    assert calls == [
        ("PUT", "/api/jobs/job/claim", {"claimed_at": "original-token"})
    ]


def test_cli_initial_claim_renewal_stops_on_conflict() -> None:
    from opai.core import gopay_protocol_worker

    class FakeInbox:
        def _req(self, *_args, **_kwargs):
            raise RuntimeError("PUT /api/jobs/job/claim -> HTTP 409")

    with pytest.raises(gopay_protocol_worker.PaymentClaimLostError):
        gopay_protocol_worker._renew_claim_before_payment(
            FakeInbox(), "job", "original-token"
        )


def test_cli_initial_claim_renewal_preserves_legacy_empty_token_behavior() -> None:
    from opai.core import gopay_protocol_worker

    class FailingInbox:
        def _req(self, *_args, **_kwargs):
            raise AssertionError("legacy jobs must not issue an unguarded renewal")

    assert gopay_protocol_worker._renew_claim_before_payment(
        FailingInbox(), "job", ""
    ) == ""


def test_reactivated_sms_order_is_persisted_without_replacing_account_tokens(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from opai.core import gopay_protocol_worker

    accounts_path = tmp_path / "accounts.json"
    accounts_path.write_text(
        json.dumps([{
            "phone": "+628123456789",
            "local": "8123456789",
            "access_token": "keep-access-token",
            "refresh_token": "keep-refresh-token",
            "activation_id": "old-order",
            "sms_provider": "smspool",
            "sms_consumed_code_activation_id": "old-order",
            "sms_consumed_code_hashes": ["old-code-hash"],
        }]),
        encoding="utf-8",
    )
    monkeypatch.setattr(gopay_protocol_worker, "ACCOUNTS_FILE", str(accounts_path))

    assert gopay_protocol_worker._persist_account_sms_activation(
        "+628123456789",
        "smspool",
        "new-order",
    ) is True

    account = json.loads(accounts_path.read_text(encoding="utf-8"))[0]
    assert account["activation_id"] == "new-order"
    assert account["sms_provider"] == "smspool"
    assert account["sms_activation_status"] == "active"
    assert account["sms_consumed_code_activation_id"] == "new-order"
    assert account["sms_consumed_code_hashes"] == []
    assert account["access_token"] == "keep-access-token"
    assert account["refresh_token"] == "keep-refresh-token"


def test_smspool_release_retries_transient_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opai.core import gopay_protocol_worker, smspool_helpers

    attempts: list[str] = []

    def cancel(order_id: str) -> bool:
        attempts.append(order_id)
        return len(attempts) == 3

    monkeypatch.setattr(smspool_helpers, "smspool_cancel", cancel)
    monkeypatch.setattr(gopay_protocol_worker.time, "sleep", lambda _seconds: None)

    assert gopay_protocol_worker._release_sms(
        "smspool",
        "",
        "order-id",
        attempts=3,
    ) is True
    assert attempts == ["order-id", "order-id", "order-id"]


def test_web_payment_preflight_renews_current_claim_token() -> None:
    from opai.core import payment_inbox

    calls: list[tuple[str, str]] = []

    class FakeStore:
        def renew_claim(self, job_id: str, *, claimed_at: str):
            calls.append((job_id, claimed_at))
            return "renewed-token"

    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._store = FakeStore()

    assert manager._renew_inbox_claim_before_payment(
        "inbox-job",
        "original-token",
    ) == "renewed-token"
    assert calls == [("inbox-job", "original-token")]


def test_web_payment_preflight_stops_when_claim_was_replaced() -> None:
    from opai.core import payment_inbox

    class FakeStore:
        def renew_claim(self, _job_id: str, *, claimed_at: str):
            assert claimed_at == "stale-token"
            return None

    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._store = FakeStore()

    with pytest.raises(payment_inbox.PaymentClaimLostError):
        manager._renew_inbox_claim_before_payment(
            "inbox-job",
            "stale-token",
        )


def test_smspool_background_cancel_retry_runs_success_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opai.core import smspool_helpers

    attempts: list[str] = []
    completed: list[bool] = []

    def cancel(order_id: str) -> bool:
        attempts.append(order_id)
        return len(attempts) == 2

    monkeypatch.setattr(smspool_helpers, "smspool_cancel", cancel)
    thread = smspool_helpers.schedule_smspool_cancel_retry(
        "order-id",
        retry_attempts=2,
        delay_seconds=0,
        on_success=lambda: completed.append(True),
    )

    assert thread is not None
    thread.join(timeout=2)
    assert thread.is_alive() is False
    assert attempts == ["order-id", "order-id"]
    assert completed == [True]
