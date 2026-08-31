from __future__ import annotations

import json
import sys
import threading
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


RUNTIME_SRC = Path(__file__).resolve().parents[1] / "gopay_runtime" / "app" / "src"
if str(RUNTIME_SRC) not in sys.path:
    sys.path.insert(0, str(RUNTIME_SRC))


def _payment_inbox_module():
    from opai.core import payment_inbox

    return payment_inbox


def _stub_tls_client(monkeypatch):
    fake_tls_client = ModuleType("tls_client")
    fake_tls_client.Session = type("Session", (), {})
    monkeypatch.setitem(sys.modules, "tls_client", fake_tls_client)


def test_claim_next_provider_filter_treats_provider_as_a_value(tmp_path):
    payment_inbox = _payment_inbox_module()
    store = payment_inbox.InboxStore(tmp_path / "payment_inbox.db")
    job = store.create(
        account_name="test",
        account_email="test@example.com",
        plan_kind="plus",
        checkout_url="https://example.test/checkout",
        provider="paypal",
        provider_url="https://paypal.example.test/ba",
    )

    # An input containing SQL syntax must not broaden the provider predicate.
    assert store.claim_next_pending(
        provider="gopay' OR 1=1 --",
        ttl_sec=3600,
    ) is None
    current = store.get(job["id"])
    assert current and current["claimed_at"] == ""


def test_browser_claim_is_atomic_and_respects_claim_ttl(tmp_path):
    payment_inbox = _payment_inbox_module()
    store = payment_inbox.InboxStore(tmp_path / "payment_inbox.db")
    job = store.create(
        account_name="test",
        account_email="test@example.com",
        plan_kind="plus",
        checkout_url="https://example.test/checkout",
        provider="gopay",
        provider_url="https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000",
    )

    first = store.claim_pending(job["id"], ttl_sec=3600)
    assert first and first["claimed_at"]
    first_claim = first["claimed_at"]

    # A live claim belongs to the first browser/worker and cannot be replaced.
    assert store.claim_pending(job["id"], ttl_sec=3600) is None
    assert store.get(job["id"])["claimed_at"] == first_claim

    # Once the lease is expired, a new claimant may take it atomically.
    store.patch(job["id"], {"claimed_at": "2000-01-01T00:00:00+00:00"})
    replacement = store.claim_pending(job["id"], ttl_sec=3600)
    assert replacement and replacement["claimed_at"] != "2000-01-01T00:00:00+00:00"


def test_browser_claim_endpoint_returns_conflict_for_live_claim(tmp_path):
    payment_inbox = _payment_inbox_module()
    store = payment_inbox.InboxStore(tmp_path / "payment_inbox.db")
    job = store.create(
        account_name="test",
        account_email="test@example.com",
        plan_kind="plus",
        checkout_url="https://example.test/checkout",
        provider="gopay",
        provider_url="https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000",
    )
    responses = []

    def invoke_claim() -> None:
        handler = object.__new__(payment_inbox._InboxHandler)
        handler.path = f"/api/jobs/{job['id']}/claim"
        handler.server = SimpleNamespace(store=store, claim_ttl_sec=3600.0)
        handler._check_auth = lambda: True
        handler._read_json_body = lambda: {}
        handler._send_json = lambda code, data: responses.append((int(code), data))
        handler.do_PUT()

    invoke_claim()
    invoke_claim()

    assert responses[0][0] == 200
    assert responses[0][1]["id"] == job["id"]
    assert responses[0][1]["provider_url"] == job["provider_url"]
    assert responses[0][1]["ttl_sec"] == 3600.0
    assert responses[1] == (409, {"error": "claim_unavailable"})


def test_web_claim_loss_does_not_cancel_shared_inbox_job(monkeypatch):
    payment_inbox = _payment_inbox_module()
    job_id = "claim-loss-payment"
    phone = "+628123456789"
    snap = "123e4567-e89b-12d3-a456-426614174000"
    url = f"https://app.midtrans.com/snap/v4/redirection/{snap}"

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, requested_id, status):
            self.statuses.append((requested_id, status))
            return {"id": requested_id, "status": status}

    class FakePayment:
        def __init__(self, **_kwargs):
            raise AssertionError("payment must stop after claim loss")

    fake_protocol = ModuleType("opai.core.gopay_payment_protocol")
    fake_protocol.GoPayFraudDenyError = type("GoPayFraudDenyError", (Exception,), {})
    fake_protocol.GoPayPayment = FakePayment
    monkeypatch.setitem(sys.modules, "opai.core.gopay_payment_protocol", fake_protocol)
    monkeypatch.setattr(
        payment_inbox,
        "_find_gopay_account",
        lambda _phone: ({"phone": phone, "sms_provider": "smsbower"}, 0),
    )
    monkeypatch.setattr(
        payment_inbox,
        "_preflight_gopay_proxy",
        lambda _proxy: {"ok": True, "ip": "127.0.0.1"},
    )
    release_calls = []
    monkeypatch.setattr(
        payment_inbox,
        "_update_gopay_midtrans_binding_status",
        lambda *_args, **_kwargs: pytest.fail(
            "claim loss before charge must not leave a failed account binding"
        ),
    )
    monkeypatch.setattr(
        payment_inbox,
        "_release_gopay_midtrans_binding",
        lambda *args, **kwargs: release_calls.append((args, kwargs)) or True,
    )

    claim_lost = threading.Event()
    claim_lost.set()
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._store = FakeStore()
    manager._lock = threading.RLock()
    manager._jobs = {
        job_id: {
            "id": job_id,
            "phone": phone,
            "status": "running",
            "prompt": None,
            "logs": [],
            "snap_token": snap,
        }
    }
    manager._snap_states = {}
    manager._save_state_locked = lambda: None
    snap_updates = []
    manager._update_snap_state = lambda _snap, status, **_kwargs: snap_updates.append(status)
    manager._start_inbox_claim_heartbeat = lambda *_args: (
        threading.Event(), claim_lost, None
    )

    manager._run(
        job_id=job_id,
        phone=phone,
        local="8123456789",
        pin="123456",
        midtrans_url=url,
        inbox_job_id="inbox-job",
        inbox_claimed_at="2026-08-31T00:00:00+00:00",
        proxy="",
        payment_fingerprint={"profile_id": "test-profile"},
        midtrans_client_key="client-key",
    )

    assert manager._jobs[job_id]["status"] == "failed"
    assert "租约" in manager._jobs[job_id]["message"]
    assert manager._store.statuses == []
    assert snap_updates == ["failed"]
    assert release_calls == [
        (
            (phone, job_id),
            {
                "message": "支付租约已丢失且尚未扣款，预占已释放，可由其他 worker 接管",
            },
        )
    ]


def test_payment_task_state_path_uses_persistent_override(monkeypatch, tmp_path):
    payment_inbox = _payment_inbox_module()
    state_path = tmp_path / "gopay" / "payment_tasks.json"

    monkeypatch.setenv("OPAI_PAYMENT_TASK_STATE_FILE", str(state_path))

    assert payment_inbox._payment_task_state_path() == state_path.resolve()


def test_gopay_inbox_claim_ttl_defaults_to_one_hour(monkeypatch):
    payment_inbox = _payment_inbox_module()
    monkeypatch.delenv("OPAI_GOPAY_INBOX_CLAIM_TTL_SEC", raising=False)

    assert payment_inbox._gopay_inbox_claim_ttl_sec() == 3600.0


def test_cli_worker_claim_passes_gopay_lease_ttl(monkeypatch):
    payment_inbox = _payment_inbox_module()
    _stub_tls_client(monkeypatch)
    from opai.core import gopay_protocol_worker

    calls = []

    class FakeInbox:
        def _req(self, method, path, data=None):
            calls.append((method, path, data))
            return {
                "id": "inbox-job",
                "provider_url": (
                    "https://app.midtrans.com/snap/v4/redirection/"
                    "123e4567-e89b-12d3-a456-426614174000"
                ),
            }

    monkeypatch.setattr(payment_inbox, "_gopay_inbox_claim_ttl_sec", lambda: 5400.0)
    monkeypatch.setattr(gopay_protocol_worker, "_job_remaining_sec", lambda _job: 600.0)

    job = gopay_protocol_worker._claim_job(FakeInbox(), min_remaining=300)

    assert job and job["id"] == "inbox-job"
    assert calls == [
        (
            "POST",
            "/api/jobs/claim_next",
            {
                "prefer_paypal_url": False,
                "prefer_oldest": True,
                "provider": "gopay",
                "ttl_sec": 5400.0,
            },
        )
    ]


def test_inbox_release_claim_is_compare_and_swap(tmp_path):
    payment_inbox = _payment_inbox_module()
    store = payment_inbox.InboxStore(tmp_path / "payment_inbox.db")
    job = store.create(
        account_name="test",
        account_email="test@example.com",
        plan_kind="plus",
        checkout_url="https://example.test/checkout",
        provider="gopay",
        provider_url="https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000",
    )
    claimed = store.claim_next_pending(provider="gopay", ttl_sec=3600)
    assert claimed and claimed["id"] == job["id"]
    original_claim = str(claimed["claimed_at"])

    newer_claim = "2099-01-01T00:00:00+00:00"
    store.patch(job["id"], {"claimed_at": newer_claim})
    stale_release = store.release_claim(job["id"], claimed_at=original_claim)
    assert stale_release and stale_release["claimed_at"] == newer_claim

    released = store.release_claim(job["id"], claimed_at=newer_claim)
    assert released and released["claimed_at"] == ""


def test_inbox_renew_claim_is_compare_and_swap(tmp_path):
    payment_inbox = _payment_inbox_module()
    store = payment_inbox.InboxStore(tmp_path / "payment_inbox.db")
    job = store.create(
        account_name="test",
        account_email="test@example.com",
        plan_kind="plus",
        checkout_url="https://example.test/checkout",
        provider="gopay",
        provider_url="https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000",
    )
    claimed = store.claim_next_pending(provider="gopay", ttl_sec=3600)
    assert claimed and claimed["id"] == job["id"]
    original_claim = str(claimed["claimed_at"])

    renewed = store.renew_claim(job["id"], claimed_at=original_claim)
    assert renewed and renewed != original_claim
    assert store.renew_claim(job["id"], claimed_at=original_claim) is None

    store.patch(job["id"], {"claimed_at": "2099-01-01T00:00:00+00:00"})
    assert store.renew_claim(job["id"], claimed_at=renewed) is None


def test_claim_start_failure_releases_inbox_claim(monkeypatch):
    payment_inbox = _payment_inbox_module()

    class FakeStore:
        def __init__(self):
            self.release_calls: list[tuple[str, str]] = []

        def claim_next_pending(self, **kwargs):
            assert kwargs["ttl_sec"] == 3600.0
            return {
                "id": "inbox-job",
                "provider_url": "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000",
                "claimed_at": "2026-08-31T00:00:00+00:00",
            }

        def release_claim(self, job_id, *, claimed_at=""):
            self.release_calls.append((job_id, claimed_at))
            return {"id": job_id, "status": "pending", "claimed_at": ""}

    monkeypatch.delenv("OPAI_GOPAY_INBOX_CLAIM_TTL_SEC", raising=False)
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._store = FakeStore()
    manager._lock = threading.RLock()
    monkeypatch.setattr(
        manager,
        "start",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("preflight failed")),
    )

    with pytest.raises(ValueError, match="preflight failed"):
        manager.claim_and_start(phone="+628123456789", pin="123456")

    assert manager._store.release_calls == [
        ("inbox-job", "2026-08-31T00:00:00+00:00")
    ]


def test_payment_task_public_dto_redacts_internal_payment_secrets():
    payment_inbox = _payment_inbox_module()
    snap = "123e4567-e89b-12d3-a456-426614174000"
    url = f"https://app.midtrans.com/snap/v4/redirection/{snap}"
    proxy = "http://proxy-user:proxy-password@proxy.example:8080"
    client_key = "Mid-client-secret-key"
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._lock = threading.RLock()
    manager._jobs = {
        "payment-job": {
            "id": "payment-job",
            "phone": "+628123456789",
            "local": "8123456789",
            "pin": "739184",
            "_otp": ["260517"],
            "proxy": proxy,
            "midtrans_url": url,
            "snap_token": snap,
            "payment_fingerprint": {"profile_id": "private-profile"},
            "challenge_ref": "private-challenge",
            "status": "waiting_otp",
            "payment_phase": "charge_started",
            "message": f"等待 OTP，内部链接 {url}",
            "created_at": "2026-08-31T00:00:00Z",
            "updated_at": "2026-08-31T00:01:00Z",
            "charge_started_at": "2026-08-31T00:00:30Z",
            "prompt": {
                "label": "支付 OTP",
                "phone": "+628123456789",
                "timeout": 60,
                "started_at": "2026-08-31T00:00:30Z",
                "code": "260517",
            },
            "midtrans_meta": {
                "snap_token": snap,
                "midtrans_client_key": client_key,
                "order_id": "ufpi_order-1",
                "gross_amount": "1",
                "currency": "IDR",
                "expiry_time": "2026-08-31T01:00:00Z",
                "account_status": "PENDING",
                "transaction_status": "pending",
                "is_setup_authorization": True,
                "is_paid_invoice": False,
            },
            "logs": [
                {"at": "2026-08-31T00:00:10Z", "message": f"开始支付 -> {url}"},
                {"at": "2026-08-31T00:00:20Z", "message": f"代理 {proxy}"},
                {"at": "2026-08-31T00:00:25Z", "message": "charge challenge_ref=private-challenge"},
                {
                    "at": "2026-08-31T00:00:30Z",
                    "message": f"pin=739184 otp=260517 client_key={client_key}",
                },
            ],
            "result": {
                "success": False,
                "detail": f"transaction pending for {snap}",
                "transaction_status": "pending",
                "internal_response": {"access_token": "private-token"},
            },
        }
    }

    public = manager.get("payment-job")

    assert public is not None
    assert public["status"] == "waiting_otp"
    assert public["payment_phase"] == "charge_started"
    assert public["order_id"] == "ufpi_order-1"
    assert public["gross_amount"] == "1"
    assert public["currency"] == "IDR"
    assert public["midtrans_meta"] == {
        "order_id": "ufpi_order-1",
        "gross_amount": "1",
        "currency": "IDR",
        "expiry_time": "2026-08-31T01:00:00Z",
        "account_status": "PENDING",
        "transaction_status": "pending",
        "is_setup_authorization": True,
        "is_paid_invoice": False,
    }
    assert public["prompt"] == {
        "label": "支付 OTP",
        "phone": "+628123456789",
        "timeout": 60,
        "started_at": "2026-08-31T00:00:30Z",
    }
    serialized = json.dumps(public, ensure_ascii=False)
    for secret in (
        url,
        snap,
        proxy,
        "proxy-user",
        "proxy-password",
        "739184",
        "260517",
        client_key,
        "private-profile",
        "private-challenge",
        "private-token",
    ):
        assert secret not in serialized
    for private_field in (
        "pin",
        "_otp",
        "proxy",
        "midtrans_url",
        "snap_token",
        "payment_fingerprint",
        "challenge_ref",
    ):
        assert private_field not in public


def test_clear_finished_keeps_remote_success_awaiting_reconciliation():
    payment_inbox = _payment_inbox_module()
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._lock = threading.RLock()
    manager._conds = {}
    manager._jobs = {
        "success": {"id": "success", "status": "success", "created_at": "1"},
        "pending-cleanup": {
            "id": "pending-cleanup",
            "status": "success_unreconciled",
            "created_at": "2",
            "reconciliation_errors": [{"component": "inbox", "error": "temporary"}],
        },
        "failed": {"id": "failed", "status": "failed", "created_at": "3"},
    }
    manager._save_state_locked = lambda: None

    removed = manager.clear_finished()

    assert removed == 2
    assert set(manager._jobs) == {"pending-cleanup"}


def test_internal_midtrans_lookup_does_not_expose_url_in_public_list():
    payment_inbox = _payment_inbox_module()
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._lock = threading.RLock()
    manager._jobs = {
        "older": {
            "id": "older",
            "midtrans_url": url,
            "created_at": "2026-08-31T00:00:00Z",
        },
        "newer": {
            "id": "newer",
            "midtrans_url": url,
            "created_at": "2026-08-31T00:01:00Z",
        },
    }

    assert manager._find_latest_job_id_by_midtrans_url(url) == "newer"
    assert all("midtrans_url" not in job for job in manager.list())


def test_account_reservation_requires_explicit_previous_owner(monkeypatch):
    payment_inbox = _payment_inbox_module()
    accounts = [{
        "phone": "+628123456789",
        "midtrans_binding_status": "reserved",
        "midtrans_binding_job_id": "auto-flow-a",
        "midtrans_binding_order_id": "order-1",
    }]

    monkeypatch.setattr(payment_inbox, "_gopay_accounts_write_guard", nullcontext)
    monkeypatch.setattr(payment_inbox, "_load_gopay_accounts_raw", lambda: accounts)
    monkeypatch.setattr(payment_inbox, "_write_gopay_accounts_raw", lambda value: None)

    assert payment_inbox._reserve_gopay_midtrans_binding(
        "+628123456789",
        job_id="web-payment-b",
        order_id="order-1",
    ) is False
    assert accounts[0]["midtrans_binding_job_id"] == "auto-flow-a"

    assert payment_inbox._reserve_gopay_midtrans_binding(
        "+628123456789",
        job_id="web-payment-b",
        order_id="order-1",
        expected_previous_job_id="auto-flow-a",
    ) is True
    assert accounts[0]["midtrans_binding_job_id"] == "web-payment-b"

    assert payment_inbox._update_gopay_midtrans_binding_status(
        "+628123456789",
        "failed",
        job_id="auto-flow-a",
    ) is False
    assert accounts[0]["midtrans_binding_status"] == "reserved"

    assert payment_inbox._update_gopay_midtrans_binding_status(
        "+628123456789",
        "success",
        job_id="web-payment-b",
    ) is True
    assert accounts[0]["midtrans_binding_status"] == "success"


def test_auto_flow_reuses_its_own_account_reservation(monkeypatch):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-owner"
    order_id = "order-1"
    phone = "+628123456789"
    account = {
        "phone": phone,
        "balance": 1,
        "midtrans_binding_status": "reserved",
        "midtrans_binding_job_id": outer_id,
        "midtrans_binding_order_id": order_id,
    }

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._lock = threading.RLock()
    manager._register_lock = threading.RLock()
    manager._jobs = {outer_id: {"id": outer_id, "logs": []}}
    manager._append_log = lambda *_args, **_kwargs: None

    monkeypatch.setattr(payment_inbox, "_normalize_gopay_binding_history", lambda: None)
    monkeypatch.setattr(payment_inbox, "_load_gopay_accounts_raw", lambda: [account])
    monkeypatch.setattr(payment_inbox, "_find_gopay_account", lambda _phone: (account, 0))
    monkeypatch.setattr(payment_inbox, "_refresh_gopay_balance", lambda _phone: {"balance": 1})
    monkeypatch.setattr(payment_inbox, "_gopay_payment_sms_active", lambda _account: True)
    monkeypatch.setattr(
        payment_inbox,
        "_reserve_gopay_midtrans_binding",
        lambda _phone, **kwargs: kwargs["job_id"] == outer_id,
    )

    selected = manager._ensure_gopay_account(
        outer_id,
        pin="123456",
        order_id=order_id,
        midtrans_url="https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000",
    )

    assert selected is account


@pytest.mark.parametrize("active_status", ["awaiting_captcha", "validating_otp"])
def test_loaded_active_payment_becomes_non_retryable_recovery_candidate(active_status):
    payment_inbox = _payment_inbox_module()
    job_id = "interrupted-job"
    snap = "123e4567-e89b-12d3-a456-426614174000"
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._jobs = {
        job_id: {
            "id": job_id,
            "status": active_status,
            "snap_token": snap,
            "logs": [],
        }
    }
    manager._snap_states = {}
    manager._recovery_job_ids = []

    assert manager._normalize_loaded_jobs() is True
    assert manager._jobs[job_id]["status"] == "interrupted_unknown"
    assert manager._jobs[job_id]["interrupted_from_status"] == active_status
    assert manager._snap_states[snap]["status"] == "interrupted_unknown"
    assert manager._recovery_job_ids == [job_id]


def test_interrupted_settled_transaction_reconciles_without_new_charge(monkeypatch):
    payment_inbox = _payment_inbox_module()
    job_id = "recover-settled"
    snap = "123e4567-e89b-12d3-a456-426614174000"
    url = f"https://app.midtrans.com/snap/v4/redirection/{snap}"

    class RecoveryPayment:
        def __init__(self, **_kwargs):
            pass

        def transaction_status(self, midtrans_url):
            assert midtrans_url == url
            return {
                "ok": True,
                "http_status": 200,
                "transaction_status": "settlement",
            }

        def pay(self, **_kwargs):
            raise AssertionError("recovery must not issue a new payment")

    fake_protocol = ModuleType("opai.core.gopay_payment_protocol")
    fake_protocol.GoPayPayment = RecoveryPayment
    monkeypatch.setitem(sys.modules, "opai.core.gopay_payment_protocol", fake_protocol)
    monkeypatch.setattr(
        payment_inbox,
        "_find_gopay_account",
        lambda _phone: ({"phone": "+628123456789", "pin": "123456"}, 0),
    )

    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._lock = threading.RLock()
    manager._jobs = {
        job_id: {
            "id": job_id,
            "status": "interrupted_unknown",
            "phone": "+628123456789",
            "midtrans_url": url,
            "snap_token": snap,
            "inbox_job_id": "inbox-job",
            "payment_fingerprint": {"version": 2, "profile_id": "profile"},
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    finalized = []
    manager._finalize_remote_success = lambda **kwargs: finalized.append(kwargs)

    manager._resume_interrupted_job(job_id)

    assert len(finalized) == 1
    assert finalized[0]["result"]["transaction_status"] == "settlement"


def test_failed_result_after_charge_is_not_made_retryable(monkeypatch):
    payment_inbox = _payment_inbox_module()
    from opai.core import captcha_provider

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, job_id, status):
            self.statuses.append((job_id, status))
            return {"id": job_id, "status": status}

    class ChargeThenUncertainPayment:
        def __init__(self, **_kwargs):
            pass

        def pay(self, **kwargs):
            kwargs["progress"]("Step 9: charge")
            return {
                "success": False,
                "detail": "transaction_status=pending",
                "transaction_status": "pending",
            }

    fake_protocol = ModuleType("opai.core.gopay_payment_protocol")
    fake_protocol.GoPayFraudDenyError = type("GoPayFraudDenyError", (Exception,), {})
    fake_protocol.GoPayPayment = ChargeThenUncertainPayment
    monkeypatch.setitem(sys.modules, "opai.core.gopay_payment_protocol", fake_protocol)

    job_id = "charge-uncertain"
    phone = "+628123456789"
    snap = "123e4567-e89b-12d3-a456-426614174000"
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._store = FakeStore()
    manager._lock = threading.RLock()
    manager._conds = {}
    manager._snap_states = {}
    manager._jobs = {
        job_id: {
            "id": job_id,
            "phone": phone,
            "snap_token": snap,
            "status": "running",
            "message": "running",
            "prompt": None,
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    snap_updates = []
    manager._update_snap_state = lambda _snap, status, **_kwargs: snap_updates.append(status)
    monkeypatch.setattr(payment_inbox, "_preflight_gopay_proxy", lambda _proxy: {"ok": True, "ip": "127.0.0.1"})
    monkeypatch.setattr(
        payment_inbox,
        "_find_gopay_account",
        lambda _phone: ({"phone": phone, "sms_provider": "smsbower"}, 0),
    )
    monkeypatch.setattr(payment_inbox, "_update_gopay_midtrans_binding_status", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(captcha_provider, "build_captcha_token_provider", lambda **_kwargs: None)

    manager._run(
        job_id=job_id,
        phone=phone,
        local="8123456789",
        pin="123456",
        midtrans_url=f"https://app.midtrans.com/snap/v4/redirection/{snap}",
        inbox_job_id="inbox-job",
        proxy="",
        payment_fingerprint={"profile_id": "test-profile"},
        midtrans_client_key="client-key",
    )

    assert manager._jobs[job_id]["status"] == "interrupted_unknown"
    assert "failed" not in snap_updates
    assert manager._store.statuses == []


def test_auto_flow_start_failure_releases_outer_account_reservation(monkeypatch):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-owner"
    phone = "+628123456789"
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"
    accounts = [{
        "phone": phone,
        "midtrans_binding_status": "reserved",
        "midtrans_binding_job_id": outer_id,
        "midtrans_binding_order_id": "order-1",
        "midtrans_binding_url": url,
    }]

    class FakeStore:
        def set_status_if_pending(self, job_id, status):
            return {"id": job_id, "status": status}

    class FakeServer:
        store = FakeStore()

    class FailingWebPayment:
        def start(self, **_kwargs):
            raise ValueError("payment preflight failed")

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._server = FakeServer()
    manager._web_payment = FailingWebPayment()
    manager._lock = threading.RLock()
    manager._processed = {"test@example.com"}
    manager._jobs = {
        outer_id: {
            "id": outer_id,
            "email": "test@example.com",
            "status": "running",
            "stage": "gopay_account",
            "midtrans_url": url,
            "inbox_job_id": "inbox-job",
            "order_id": "order-1",
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    manager._ensure_gopay_account = lambda *_args, **_kwargs: accounts[0]
    monkeypatch.setattr(payment_inbox, "_gopay_accounts_write_guard", nullcontext)
    monkeypatch.setattr(payment_inbox, "_load_gopay_accounts_raw", lambda: accounts)
    monkeypatch.setattr(payment_inbox, "_write_gopay_accounts_raw", lambda _value: None)

    manager._run(
        job_id=outer_id,
        record={"email": "test@example.com", "access_token": "token"},
        pin="123456",
        proxy="",
    )

    assert manager._jobs[outer_id]["status"] == "failed"
    assert "midtrans_binding_job_id" not in accounts[0]
    assert "midtrans_binding_status" not in accounts[0]
    assert accounts[0]["midtrans_binding_message"] == "自动支付未启动，账号预占已释放，可重新使用"


def test_auto_flow_claim_loss_does_not_cancel_shared_inbox_job(monkeypatch):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-claim-lost"
    phone = "+628123456789"
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, job_id, status):
            self.statuses.append((job_id, status))
            return {"id": job_id, "status": status}

    class FakeServer:
        store = FakeStore()

    class ClaimLostWebPayment:
        def start(self, **_kwargs):
            raise payment_inbox.PaymentClaimLostError("支付租约已丢失")

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._server = FakeServer()
    manager._web_payment = ClaimLostWebPayment()
    manager._lock = threading.RLock()
    manager._processed = {"test@example.com"}
    manager._jobs = {
        outer_id: {
            "id": outer_id,
            "email": "test@example.com",
            "status": "running",
            "stage": "gopay_account",
            "midtrans_url": url,
            "inbox_job_id": "inbox-job",
            "order_id": "order-1",
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    manager._ensure_gopay_account = lambda *_args, **_kwargs: {"phone": phone}
    monkeypatch.setattr(
        payment_inbox,
        "_release_gopay_midtrans_binding",
        lambda *_args, **_kwargs: True,
    )

    manager._run(
        job_id=outer_id,
        record={"email": "test@example.com", "access_token": "token"},
        pin="123456",
        proxy="",
    )

    assert manager._jobs[outer_id]["status"] == "failed"
    assert "租约已丢失" in manager._jobs[outer_id]["message"]
    assert manager._server.store.statuses == []
    assert "test@example.com" in manager._processed


@pytest.mark.parametrize(
    ("outer_status", "outer_stage"),
    [
        ("running", "payment"),
        ("interrupted_unknown", "payment"),
        ("running", "gopay_account"),
    ],
)
def test_auto_flow_restart_waits_for_existing_payment_without_restarting(
    monkeypatch,
    outer_status,
    outer_stage,
):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-job"
    payment_id = "web-payment-job"
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"

    class FakeWebPayment:
        def _find_latest_job_id_by_midtrans_url(self, requested_url):
            assert requested_url == url
            return payment_id

        def get(self, requested_id):
            assert requested_id == payment_id
            return {"id": payment_id, "status": "success", "message": "payment completed"}

    class ImmediateThread:
        def __init__(self, *, target, args=(), kwargs=None, **_options):
            self.target = target
            self.args = args
            self.kwargs = kwargs or {}

        def start(self):
            self.target(*self.args, **self.kwargs)

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._lock = threading.RLock()
    manager._web_payment = FakeWebPayment()
    manager._pin = "123456"
    manager._proxy = ""
    manager._jobs = {
        outer_id: {
            "id": outer_id,
            "status": outer_status,
            "stage": outer_stage,
            "midtrans_url": url,
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    manager._run = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("outer flow must not start another payment")
    )
    monkeypatch.setattr(payment_inbox.threading, "Thread", ImmediateThread)

    manager._resume_interrupted_jobs()

    job = manager._jobs[outer_id]
    assert job["payment_task_id"] == payment_id
    assert job["status"] == "success"
    assert "未重复发起 charge" in job["message"]


def test_auto_flow_propagates_unknown_payment_without_retry(monkeypatch):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-unknown"
    payment_id = "web-payment-unknown"
    phone = "+628123456789"
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, job_id, status):
            self.statuses.append((job_id, status))
            return {"id": job_id, "status": status}

    class FakeServer:
        store = FakeStore()

    class UnknownWebPayment:
        def __init__(self):
            self.start_calls = 0

        def start(self, **_kwargs):
            self.start_calls += 1
            return {"id": payment_id, "status": "running"}

        def get(self, requested_id):
            assert requested_id == payment_id
            return {
                "id": payment_id,
                "status": "interrupted_unknown",
                "message": "charge 后状态未确认；已禁止重新扣款",
            }

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._server = FakeServer()
    manager._web_payment = UnknownWebPayment()
    manager._lock = threading.RLock()
    manager._processed = {"test@example.com"}
    manager._jobs = {
        outer_id: {
            "id": outer_id,
            "email": "test@example.com",
            "status": "running",
            "stage": "gopay_account",
            "midtrans_url": url,
            "inbox_job_id": "inbox-job",
            "order_id": "order-1",
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    manager._ensure_gopay_account = lambda *_args, **_kwargs: {"phone": phone}

    manager._run(
        job_id=outer_id,
        record={"email": "test@example.com", "access_token": "token"},
        pin="123456",
        proxy="",
    )

    job = manager._jobs[outer_id]
    assert job["status"] == "interrupted_unknown"
    assert job["stage"] == "payment"
    assert manager._server.store.statuses == []
    assert "test@example.com" in manager._processed
    manager._record_for_email = lambda _email: {
        "email": "test@example.com",
        "access_token": "token",
    }
    reused = manager.start(email="test@example.com", force=True)
    assert reused["id"] == outer_id
    assert manager._web_payment.start_calls == 1


@pytest.mark.parametrize("failure_mode", ["get_error", "timeout"])
def test_auto_flow_existing_payment_error_never_starts_new_chain(monkeypatch, failure_mode):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-payment-error"
    payment_id = "web-payment-error"
    phone = "+628123456789"
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, job_id, status):
            self.statuses.append((job_id, status))
            return {"id": job_id, "status": status}

    class FakeServer:
        store = FakeStore()

    class ExistingPayment:
        def __init__(self):
            self.start_calls = 0

        def start(self, **_kwargs):
            self.start_calls += 1
            return {"id": payment_id, "status": "running"}

        def get(self, _requested_id):
            if failure_mode == "get_error":
                raise OSError("payment state unavailable")
            return {"id": payment_id, "status": "running", "message": "still processing"}

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._server = FakeServer()
    manager._web_payment = ExistingPayment()
    manager._lock = threading.RLock()
    manager._processed = {"test@example.com"}
    manager._jobs = {
        outer_id: {
            "id": outer_id,
            "email": "test@example.com",
            "status": "running",
            "stage": "gopay_account",
            "midtrans_url": url,
            "inbox_job_id": "inbox-job",
            "order_id": "order-1",
            "logs": [],
        }
    }
    manager._save_state_locked = lambda: None
    manager._ensure_gopay_account = lambda *_args, **_kwargs: {"phone": phone}
    monkeypatch.setenv("OPAI_AUTO_FLOW_PAYMENT_TIMEOUT_SEC", "60")

    if failure_mode == "timeout":
        clock = iter([100.0, 100.0, 200.0])
        real_time = payment_inbox.time
        monkeypatch.setattr(
            payment_inbox,
            "time",
            SimpleNamespace(
                time=lambda: next(clock),
                sleep=lambda _seconds: None,
                monotonic=real_time.monotonic,
            ),
        )

    manager._run(
        job_id=outer_id,
        record={"email": "test@example.com", "access_token": "token"},
        pin="123456",
        proxy="",
    )

    assert manager._jobs[outer_id]["status"] == "interrupted_unknown"
    assert manager._server.store.statuses == []
    assert "test@example.com" in manager._processed
    assert manager._web_payment.start_calls == 1


@pytest.mark.parametrize(
    ("inner_status", "failure_stage"),
    [
        ("success", "payment_state"),
        ("success", "payment_task_link"),
        ("success", "account_binding"),
        ("success_unreconciled", "payment_state"),
    ],
)
def test_auto_flow_remote_success_is_not_downgraded_by_outer_cleanup(
    monkeypatch,
    inner_status,
    failure_stage,
):
    payment_inbox = _payment_inbox_module()
    outer_id = "auto-flow-success"
    payment_id = "web-payment-success"
    phone = "+628123456789"
    url = "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, job_id, status):
            self.statuses.append((job_id, status))
            return {"id": job_id, "status": status}

    class FakeServer:
        store = FakeStore()

    class SuccessfulWebPayment:
        def start(self, **_kwargs):
            return {"id": payment_id, "status": "running"}

        def get(self, requested_id):
            assert requested_id == payment_id
            return {
                "id": payment_id,
                "status": inner_status,
                "message": "payment completed",
            }

    manager = object.__new__(payment_inbox._AutoFlowManager)
    manager._server = FakeServer()
    manager._web_payment = SuccessfulWebPayment()
    manager._lock = threading.RLock()
    manager._processed = {"test@example.com"}
    manager._jobs = {
        outer_id: {
            "id": outer_id,
            "email": "test@example.com",
            "status": "running",
            "stage": "gopay_account",
            "midtrans_url": url,
            "inbox_job_id": "inbox-job",
            "order_id": "order-1",
            "logs": [],
        }
    }

    def save_state():
        if failure_stage == "payment_task_link" and manager._jobs[outer_id].get("payment_task_id"):
            raise OSError("outer payment task link write failed")
        if (
            failure_stage == "payment_state"
            and manager._jobs[outer_id].get("payment_status") in {"success", "success_unreconciled"}
        ):
            raise OSError("outer payment state write failed")

    def update_binding(*_args, **_kwargs):
        if failure_stage == "account_binding":
            raise OSError("outer account binding write failed")
        return True

    manager._save_state_locked = save_state
    manager._ensure_gopay_account = lambda *_args, **_kwargs: {"phone": phone}
    monkeypatch.setattr(payment_inbox, "_update_gopay_midtrans_binding_status", update_binding)
    monkeypatch.setattr(payment_inbox, "_find_gopay_account", lambda _phone: ({"phone": phone}, 0))
    monkeypatch.setattr(payment_inbox, "_mark_gopay_sms_done", lambda _account: True)

    manager._run(
        job_id=outer_id,
        record={"email": "test@example.com", "access_token": "token"},
        pin="123456",
        proxy="",
    )

    assert manager._jobs[outer_id]["status"] == inner_status
    assert manager._server.store.statuses == []
    assert "test@example.com" in manager._processed


def test_manual_payment_otp_accepts_only_one_code_per_prompt():
    payment_inbox = _payment_inbox_module()
    job_id = "otp-job"
    manager = object.__new__(payment_inbox._WebPaymentManager)
    manager._lock = threading.RLock()
    manager._conds = {job_id: threading.Condition(manager._lock)}
    manager._jobs = {
        job_id: {
            "id": job_id,
            "status": "waiting_otp",
            "prompt": {"label": "支付 OTP"},
            "logs": [],
            "_otp": [],
        }
    }
    manager._save_state_locked = lambda: None

    accepted = manager.submit_otp(job_id, "123456")
    duplicate = manager.submit_otp(job_id, "123456")

    assert accepted and accepted["status"] == "validating_otp"
    assert duplicate is None
    assert manager._jobs[job_id]["_otp"] == ["123456"]


def test_cli_payment_reuses_persisted_fingerprint_and_preflight(monkeypatch):
    payment_inbox = _payment_inbox_module()
    _stub_tls_client(monkeypatch)
    from opai.core import gopay_protocol_worker

    saved_fingerprint = {
        "version": 2,
        "profile_id": "persisted-profile",
        "user_agent": "ua",
        "locale": "zh-CN",
        "timezone": "Asia/Shanghai",
        "viewport": {"width": 787, "height": 586, "device_scale_factor": 1},
        "sec_ch_ua": "brands",
        "sec_ch_ua_mobile": "?1",
        "sec_ch_ua_platform": '"Android"',
    }
    saved_account = {
        "phone": "+628123456789",
        "local": "8123456789",
        "balance": 10,
        "payment_fingerprint": saved_fingerprint,
    }
    events = []
    snap = "123e4567-e89b-12d3-a456-426614174000"

    class FakePayment:
        def __init__(self, *, proxy, payment_fingerprint):
            events.append(("payment", proxy, payment_fingerprint["profile_id"]))

        def pay(self, **kwargs):
            events.append(("pay", kwargs["midtrans_client_key"]))
            return {"success": True, "detail": "payment completed"}

    class FakeInbox:
        def _req(self, method, path):
            events.append(("inbox", method, path))
            return {"ok": True}

    monkeypatch.setattr(payment_inbox, "_load_gopay_accounts", lambda: [saved_account])
    monkeypatch.setattr(payment_inbox, "_find_gopay_account", lambda _phone: (saved_account, 0))
    monkeypatch.setattr(payment_inbox, "_preflight_gopay_proxy", lambda _proxy: {"ok": True, "ip": "1.2.3.4"})
    monkeypatch.setattr(
        payment_inbox,
        "_midtrans_transaction_meta",
        lambda *_args, **_kwargs: {"midtrans_client_key": "client-key"},
    )
    monkeypatch.setattr(
        payment_inbox,
        "_validate_payment_midtrans_meta",
        lambda _meta, *, balance=None: events.append(("validate", balance)),
    )
    monkeypatch.setattr(gopay_protocol_worker, "GoPayPayment", FakePayment)
    monkeypatch.setattr(gopay_protocol_worker, "_cli_payment_state", lambda _url: (snap, {}))
    monkeypatch.setattr(
        gopay_protocol_worker,
        "_persist_cli_payment_state",
        lambda _snap, status, **kwargs: events.append(("journal", status)) or {"status": status},
    )
    monkeypatch.setattr(
        sys.modules["opai.core.captcha_provider"],
        "build_captcha_token_provider",
        lambda **_kwargs: None,
    )

    success, detail = gopay_protocol_worker._pay_job(
        {
            "id": "inbox-job",
            "provider_url": f"https://app.midtrans.com/snap/v4/redirection/{snap}",
        },
        {
            "phone": "+628123456789",
            "local": "8123456789",
            "aid": "activation",
        },
        FakeInbox(),
        "sms-key",
        "123456",
        proxy="http://proxy.example:8080",
    )

    assert success is True
    assert detail == "payment completed"
    assert ("payment", "http://proxy.example:8080", "persisted-profile") in events
    assert ("validate", 10) in events
    assert ("pay", "client-key") in events
    assert ("journal", "linking") in events
    assert ("journal", "success") in events


def test_cli_payment_failure_after_charge_is_persisted_as_non_retryable(monkeypatch):
    payment_inbox = _payment_inbox_module()
    _stub_tls_client(monkeypatch)
    from opai.core import gopay_protocol_worker

    snap = "123e4567-e89b-12d3-a456-426614174000"
    saved_account = {
        "phone": "+628123456789",
        "local": "8123456789",
        "balance": 10,
        "payment_fingerprint": {"version": 2, "profile_id": "persisted-profile"},
    }
    events = []

    class FakePayment:
        def __init__(self, **_kwargs):
            pass

        def pay(self, **kwargs):
            kwargs["progress"]("Step 9: charge")
            raise OSError("connection dropped after charge")

    class FakeInbox:
        def _req(self, method, path):
            events.append(("inbox", method, path))
            return {"ok": True}

    monkeypatch.setattr(payment_inbox, "_load_gopay_accounts", lambda: [saved_account])
    monkeypatch.setattr(payment_inbox, "_find_gopay_account", lambda _phone: (saved_account, 0))
    monkeypatch.setattr(payment_inbox, "_preflight_gopay_proxy", lambda _proxy: {"ok": True, "ip": "1.2.3.4"})
    monkeypatch.setattr(
        payment_inbox,
        "_midtrans_transaction_meta",
        lambda *_args, **_kwargs: {"midtrans_client_key": "client-key"},
    )
    monkeypatch.setattr(payment_inbox, "_validate_payment_midtrans_meta", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gopay_protocol_worker, "GoPayPayment", FakePayment)
    monkeypatch.setattr(gopay_protocol_worker, "_cli_payment_state", lambda _url: (snap, {}))
    monkeypatch.setattr(
        gopay_protocol_worker,
        "_persist_cli_payment_state",
        lambda _snap, status, **kwargs: events.append(("journal", status)) or {"status": status},
    )
    monkeypatch.setattr(
        sys.modules["opai.core.captcha_provider"],
        "build_captcha_token_provider",
        lambda **_kwargs: None,
    )

    success, detail = gopay_protocol_worker._pay_job(
        {
            "id": "inbox-job",
            "provider_url": f"https://app.midtrans.com/snap/v4/redirection/{snap}",
        },
        {
            "phone": "+628123456789",
            "local": "8123456789",
            "aid": "activation",
        },
        FakeInbox(),
        "sms-key",
        "123456",
        proxy="http://proxy.example:8080",
    )

    assert success is False
    assert "connection dropped after charge" in detail
    assert [event for event in events if event[0] == "journal"] == [
        ("journal", "linking"),
        ("journal", "charge_started"),
        ("journal", "interrupted_unknown"),
    ]
    assert ("inbox", "PUT", "/api/jobs/inbox-job/cancel") in events


def test_invalid_otp_requests_replacement_before_waiting_again(monkeypatch):
    _stub_tls_client(monkeypatch)
    from opai.core.gopay_payment_protocol import GoPayPayment

    payment = object.__new__(GoPayPayment)
    calls = []
    responses = iter([
        {"status": 400, "body": {"error": "invalid OTP code"}},
        {"status": 200, "body": {"message": "replacement sent"}},
        {"status": 200, "body": {"challenge_id": "challenge"}},
    ])

    def post(path, body):
        calls.append((path, body))
        return next(responses)

    payment._gwa_post = post
    waits = []
    notes = []
    response, error = payment._validate_linking_otp_with_retry(
        reference="reference-id",
        full_phone="+628123456789",
        otp_code="111111",
        wait_otp=lambda phone, timeout: waits.append((phone, timeout)) or "222222",
        note=notes.append,
    )

    assert error == ""
    assert response["status"] == 200
    assert [path for path, _body in calls] == [
        "/v1/linking/validate-otp",
        "/v1/linking/resend-otp",
        "/v1/linking/validate-otp",
    ]
    assert calls[-1][1]["otp"] == "222222"
    assert waits == [("+628123456789", 120)]
    assert any("replacement OTP requested" in note for note in notes)


@pytest.mark.parametrize("status", [429, 500, 503])
def test_rate_limit_or_server_error_does_not_request_replacement_otp(monkeypatch, status):
    _stub_tls_client(monkeypatch)
    from opai.core.gopay_payment_protocol import GoPayPayment

    payment = object.__new__(GoPayPayment)
    calls = []
    payment._gwa_post = lambda path, body: (
        calls.append((path, body))
        or {"status": status, "body": {"error": "temporary OTP service error"}}
    )

    _response, error = payment._validate_linking_otp_with_retry(
        reference="reference-id",
        full_phone="+628123456789",
        otp_code="111111",
        wait_otp=lambda *_args: pytest.fail("must not wait for a replacement OTP"),
        note=lambda _message: None,
    )

    assert error == f"validate-otp failed: {status}"
    assert [path for path, _body in calls] == ["/v1/linking/validate-otp"]


def test_midtrans_metadata_referer_matches_redirect_version(monkeypatch):
    payment_inbox = _payment_inbox_module()
    snap = "123e4567-e89b-12d3-a456-426614174000"
    captured = []

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "transaction_details": {
                    "order_id": "ufpi_order-1",
                    "gross_amount": "1",
                    "currency": "IDR",
                },
                "merchant": {"client_key": "client-key"},
            }

    class FakeSession:
        def __init__(self, **_kwargs):
            self.proxies = {}

        def get(self, url, *, headers, timeout_seconds):
            captured.append((url, headers, timeout_seconds))
            return FakeResponse()

    fake_tls_client = ModuleType("tls_client")
    fake_tls_client.Session = FakeSession
    monkeypatch.setitem(sys.modules, "tls_client", fake_tls_client)

    meta = payment_inbox._midtrans_transaction_meta(
        f"https://app.midtrans.com/snap/v3/redirection/{snap}"
    )

    assert meta["order_id"] == "ufpi_order-1"
    assert captured[0][1]["Referer"] == f"https://app.midtrans.com/snap/v3/redirection/{snap}"


def test_transaction_status_uses_validated_midtrans_url(monkeypatch):
    _stub_tls_client(monkeypatch)
    from opai.core.gopay_payment_protocol import GoPayPayment

    snap = "123e4567-e89b-12d3-a456-426614174000"
    payment = object.__new__(GoPayPayment)
    payment._midtrans_referer = ""
    calls = []
    payment._midtrans_get = lambda path: (
        calls.append(path)
        or {"status": 200, "body": {"transaction_status": "settlement"}}
    )

    result = payment.transaction_status(
        f"https://app.midtrans.com/snap/v3/redirection/{snap}"
    )

    assert result["ok"] is True
    assert result["transaction_status"] == "settlement"
    assert calls == [f"/snap/v1/transactions/{snap}/status"]
    assert payment._midtrans_referer.endswith(f"/snap/v3/redirection/{snap}")

    invalid = payment.transaction_status(
        f"https://app.midtrans.com.evil.test/snap/v4/redirection/{snap}"
    )
    assert invalid["ok"] is False
    assert invalid["transaction_status"] == "invalid_url"
    assert len(calls) == 1
