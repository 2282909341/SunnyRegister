from __future__ import annotations

import json
import sys
import threading
import urllib.request
from types import ModuleType

import pytest


def test_gopay_embedded_service_uses_configured_phone_pool(monkeypatch, tmp_path):
    pool_path = tmp_path / "phone_pool.json"
    monkeypatch.setenv("OPAI_GOPAY_PHONE_POOL_FILE", str(pool_path))
    monkeypatch.setenv("OPAI_GOPAY_ACCOUNTS_FILE", str(tmp_path / "accounts.json"))
    monkeypatch.setenv("OPAI_GOPAY_SMS_ENV_FILE", str(tmp_path / "sms.env"))

    from gopay_runtime.gopay import server as gopay_server

    assert gopay_server.POOL == pool_path
    httpd = gopay_server.start_embedded()
    try:
        base_url = f"http://127.0.0.1:{httpd.server_port}"
        accounts = json.loads(urllib.request.urlopen(base_url + "/api/accounts", timeout=5).read())
        phones = json.loads(urllib.request.urlopen(base_url + "/api/phone-pool", timeout=5).read())
        assert accounts == {"accounts": []}
        assert phones == {"phones": []}
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_gopay_embedded_service_exposes_captcha_status_and_config(monkeypatch, tmp_path):
    env_path = tmp_path / "captcha.env"
    monkeypatch.setenv("OPAI_MIDTRANS_CAPTCHA_ENV_FILE", str(env_path))
    for key in (
        "OPAI_2CAPTCHA_API_KEY",
        "OPAI_2CAPTCHA_API_BASE_URL",
        "OPAI_2CAPTCHA_POLL_SEC",
        "OPAI_2CAPTCHA_TIMEOUT_SEC",
        "OPAI_2CAPTCHA_MAX_ATTEMPTS",
        "OPAI_SOLVERIFY_API_KEY",
        "OPAI_SOLVERIFY_API_BASE_URL",
        "OPAI_SOLVERIFY_POLL_SEC",
        "OPAI_SOLVERIFY_TIMEOUT_SEC",
        "OPAI_MIDTRANS_CAPTCHA_SCENE_ID",
        "OPAI_MIDTRANS_CAPTCHA_PREFIX",
        "OPAI_MIDTRANS_CAPTCHA_REGION",
        "OPAI_MIDTRANS_CAPTCHA_API_GET_LIB",
    ):
        monkeypatch.delenv(key, raising=False)

    from gopay_runtime.gopay import server as gopay_server

    httpd = gopay_server.start_embedded()
    try:
        base_url = f"http://127.0.0.1:{httpd.server_port}"

        initial = json.loads(urllib.request.urlopen(base_url + "/api/captcha-status", timeout=5).read())
        assert initial["api_key_configured"] is False
        assert initial["provider"] == "未配置"
        assert initial["env_file"] == str(env_path)

        payload = {
            "api_key": "captcha-test-key-1234",
            "api_base_url": "https://captcha.example.test/api",
            "solverify_api_key": "solver-test-key-5678",
            "solverify_api_base_url": "https://solver.example.test",
            "solverify_poll_sec": "2",
            "solverify_timeout_sec": "90",
            "scene_id": "scene-test",
            "prefix": "prefix-test",
            "region": "cn",
            "api_get_lib": "https://captcha.example.test/loader.js",
            "poll_sec": "4",
            "timeout_sec": "120",
            "max_attempts": "2",
        }
        request = urllib.request.Request(
            base_url + "/api/captcha-config",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        saved = json.loads(urllib.request.urlopen(request, timeout=5).read())
        assert saved["provider"] == "Solverify 优先 / 2Captcha 备用"
        assert saved["api_key"] == "capt...1234"
        assert saved["solverify_api_key"] == "solv...5678"
        assert saved["max_attempts"] == "2"

        current = json.loads(urllib.request.urlopen(base_url + "/api/captcha-status", timeout=5).read())
        assert current == saved
        env_text = env_path.read_text(encoding="utf-8")
        assert "OPAI_2CAPTCHA_API_KEY=captcha-test-key-1234" in env_text
        assert "OPAI_SOLVERIFY_API_KEY=solver-test-key-5678" in env_text
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize(
    "failure_stage",
    ["payment_state", "snap_state", "account_binding", "inbox", "sms_release"],
)
def test_web_payment_remote_success_is_never_downgraded_by_local_cleanup(
    monkeypatch,
    failure_stage,
):
    from gopay_runtime.gopay import server as gopay_server

    payment_inbox = sys.modules["opai.core.payment_inbox"]
    captcha_provider = sys.modules["opai.core.captcha_provider"]

    class FakeStore:
        def __init__(self):
            self.statuses = []

        def set_status_if_pending(self, job_id, status):
            self.statuses.append((job_id, status))
            if failure_stage == "inbox":
                raise OSError("inbox write failed")
            return {"id": job_id, "status": status}

    class SuccessfulPayment:
        def __init__(self, **_kwargs):
            pass

        def pay(self, **_kwargs):
            return {
                "success": True,
                "detail": "payment completed",
                "transaction_status": "settlement",
            }

    fake_protocol = ModuleType("opai.core.gopay_payment_protocol")
    fake_protocol.GoPayFraudDenyError = type("GoPayFraudDenyError", (Exception,), {})
    fake_protocol.GoPayPayment = SuccessfulPayment
    monkeypatch.setitem(sys.modules, "opai.core.gopay_payment_protocol", fake_protocol)

    job_id = "remote-success-job"
    phone = "+628123456789"
    snap = "123e4567-e89b-12d3-a456-426614174000"
    midtrans_url = f"https://app.midtrans.com/snap/v4/redirection/{snap}"
    store = FakeStore()
    manager = object.__new__(gopay_server._WebPaymentManager)
    manager._store = store
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

    persisted_statuses = []

    def save_state():
        status = manager._jobs[job_id]["status"]
        persisted_statuses.append(status)
        if failure_stage == "payment_state" and status in {"success", "success_unreconciled"}:
            raise OSError("payment state write failed")

    snap_updates = []

    def update_snap(_snap, status, **_kwargs):
        snap_updates.append(status)
        if failure_stage == "snap_state" and status == "success":
            raise OSError("snap state write failed")

    binding_updates = []

    def update_binding(_phone, status, **_kwargs):
        binding_updates.append(status)
        if failure_stage == "account_binding" and status == "success":
            raise OSError("account binding write failed")
        return True

    def release_sms(_phone):
        if failure_stage == "sms_release":
            raise OSError("SMS release failed")
        return ""

    monkeypatch.setattr(manager, "_save_state_locked", save_state)
    monkeypatch.setattr(manager, "_update_snap_state", update_snap)
    monkeypatch.setattr(manager, "_release_payment_sms_after_success", release_sms)
    monkeypatch.setattr(payment_inbox, "_preflight_gopay_proxy", lambda _proxy: {"ok": True, "ip": "127.0.0.1"})
    monkeypatch.setattr(
        payment_inbox,
        "_find_gopay_account",
        lambda _phone: ({"phone": phone, "sms_provider": "smsbower"}, 0),
    )
    monkeypatch.setattr(payment_inbox, "_update_gopay_midtrans_binding_status", update_binding)
    monkeypatch.setattr(captcha_provider, "build_captcha_token_provider", lambda **_kwargs: None)

    manager._run(
        job_id=job_id,
        phone=phone,
        local="8123456789",
        pin="123456",
        midtrans_url=midtrans_url,
        inbox_job_id="inbox-job",
        proxy="",
        payment_fingerprint={"profile_id": "test-profile"},
        midtrans_client_key="client-key",
    )

    job = manager._jobs[job_id]
    assert job["status"] == "success_unreconciled"
    assert job["result"]["success"] is True
    assert job["reconciliation_errors"]
    assert "failed" not in snap_updates
    assert "failed" not in binding_updates
    assert all(status != "failed" for status in persisted_statuses)
