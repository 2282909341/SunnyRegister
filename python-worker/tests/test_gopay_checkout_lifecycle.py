from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest


PAY153_DIR = Path(__file__).parents[1] / "tools" / "pay153_checkout"
if str(PAY153_DIR) not in sys.path:
    sys.path.insert(0, str(PAY153_DIR))

import app as checkout_app  # noqa: E402


class FakeHttp:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeCookies:
    def __init__(self) -> None:
        self.values = {"oai-did": "device"}

    def set(self, name: str, value: str, **_kwargs) -> None:
        self.values[name] = value

    def get_dict(self) -> dict[str, str]:
        return dict(self.values)


class FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self) -> dict:
        return self._payload


class ScriptedHttp(FakeHttp):
    def __init__(self, response: FakeResponse) -> None:
        super().__init__()
        self.response = response
        self.cookies = FakeCookies()
        self.post_calls = 0

    def post(self, *_args, **_kwargs) -> FakeResponse:
        self.post_calls += 1
        return self.response


def bound_gopay_context(
    http: object,
    proxy: str = "http://fake-proxy",
) -> checkout_app.CheckoutClientContext:
    return checkout_app.CheckoutClientContext(
        payment_provider="gopay",
        device_id="device",
        did="device",
        user_agent="Mozilla/5.0 test-agent",
        proxy_route=proxy,
        session_owner=f"checkout-http:{id(http)}",
        cookies={"oai-did": "device"},
    )


@pytest.mark.parametrize(
    "outcome",
    ["success", "ordinary_failure", "approval_blocked"],
)
def test_http_session_cleanup_helper_closes_every_registered_session(
    outcome: str,
) -> None:
    provider_http = FakeHttp()
    promotion_http = FakeHttp()
    stripe_http = FakeHttp()
    sessions = [provider_http, promotion_http, stripe_http, provider_http]

    try:
        if outcome == "ordinary_failure":
            raise RuntimeError("upstream HTTP 400")
        if outcome == "approval_blocked":
            raise RuntimeError("GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED")
    except RuntimeError:
        pass
    finally:
        checkout_app.close_http_sessions(sessions)

    assert provider_http.close_calls == 1
    assert promotion_http.close_calls == 1
    assert stripe_http.close_calls == 1


@pytest.mark.parametrize(
    "outcome",
    ["success", "ordinary_failure", "approval_blocked"],
)
def test_gopay_session_registry_closes_all_roles_for_every_terminal_outcome(
    outcome: str,
) -> None:
    registry = checkout_app.HttpSessionRegistry()
    provider_http = registry.track(FakeHttp())
    promotion_http = registry.track(FakeHttp())
    stripe_http = registry.track(FakeHttp())

    try:
        if outcome == "ordinary_failure":
            raise RuntimeError("upstream HTTP 400")
        if outcome == "approval_blocked":
            raise checkout_app.CheckoutApprovalBlockedError("result=blocked")
    except RuntimeError:
        pass
    finally:
        registry.close()

    assert provider_http.close_calls == 1
    assert promotion_http.close_calls == 1
    assert stripe_http.close_calls == 1


def test_gopay_http_session_cleanup_continues_after_one_close_fails() -> None:
    broken_http = FakeHttp(close_error=RuntimeError("close failed"))
    healthy_http = FakeHttp()

    checkout_app.close_http_sessions([broken_http, healthy_http])

    assert broken_http.close_calls == 1
    assert healthy_http.close_calls == 1


def test_http_session_registry_deduplicates_releases_and_closes_idempotently() -> None:
    registry = checkout_app.HttpSessionRegistry()
    retained_http = FakeHttp()
    released_http = FakeHttp()
    registry.track(retained_http)
    registry.track(retained_http)
    registry.track(released_http)

    assert registry.release(released_http) is released_http
    registry.close()
    registry.close()

    assert retained_http.close_calls == 1
    assert released_http.close_calls == 0


def test_gopay_creation_identity_failure_closes_http_session_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = FakeHttp()
    context = bound_gopay_context(object())
    monkeypatch.setattr(checkout_app.sc, "build_http", lambda _proxy: http)

    with pytest.raises(
        checkout_app.PaymentFlowError,
        match="CLIENT_CONTEXT_MISMATCH",
    ):
        checkout_app.create_checkout(
            "fake-token",
            {"checkout_ui_mode": "redirect"},
            "http://fake-proxy",
            "device",
            "device",
            lambda _message: None,
            diagnostic_label="GoPay",
            client_context=context,
            proof_policy=checkout_app.ProofPolicy.strict_gopay(),
        )

    assert http.close_calls == 1


def test_gopay_creation_fails_closed_when_cookie_binding_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = FakeHttp()
    monkeypatch.setattr(checkout_app.sc, "build_http", lambda _proxy: http)

    with pytest.raises(checkout_app.PaymentFlowError) as caught:
        checkout_app.create_checkout(
            "fake-token",
            {"checkout_ui_mode": "redirect"},
            "http://fake-proxy",
            "device",
            "device",
            lambda _message: None,
            diagnostic_label="GoPay",
        )

    assert caught.value.code == "CLIENT_COOKIE_BINDING_FAILED"
    assert http.close_calls == 1


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"result": "approved"}, "approved"),
        ({"result": "APPROVED"}, "approved"),
        ({"result": "blocked"}, "blocked"),
        ({"result": "BLOCKED"}, "blocked"),
        ({"result": "invalid_promotion"}, "invalid_promotion"),
        ({"result": "failed"}, "failed"),
        ({"result": "denied"}, "failed"),
        ({"result": "requires_action"}, "failed"),
        ({}, "missing"),
        ({"result": None}, "missing"),
        ({"result": ""}, "missing"),
        ({"result": "future_upstream_state"}, "unknown"),
    ],
)
def test_gopay_approval_result_has_explicit_state_classification(
    payload: dict,
    expected: str,
) -> None:
    assert checkout_app.approval_result_status(payload) == expected


def test_curl_56_wrong_version_number_is_a_proxy_ssl_failure() -> None:
    message = (
        "Failed to perform, curl: (56) BoringSSL SSL_read: BoringSSL: "
        "error:100000f7:SSL routines:OPENSSL_internal:WRONG_VERSION_NUMBER, errno 0"
    )

    assert checkout_app._proxy_transport_error_kind(message) == "SSL/连接重置"
    assert checkout_app._is_proxy_ssl_error(message) is True


def test_shared_checkout_creation_budget_stops_nested_rebuild_multiplication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_sessions: list[FakeHttp] = []

    def fake_create_checkout(*_args, **_kwargs) -> dict:
        http = FakeHttp()
        created_sessions.append(http)
        return {
            "data": {"checkout_session_id": f"oaics_{len(created_sessions)}"},
            "http": http,
        }

    monkeypatch.setattr(checkout_app, "create_checkout", fake_create_checkout)
    budget = checkout_app.CheckoutCreationBudget(limit=3)
    common = {
        "token": "fake-token",
        "payload": {"checkout_ui_mode": "redirect"},
        "proxy": "http://fake-proxy",
        "device_id": "device",
        "did": "device",
        "log": lambda _message: None,
        "attempts": 2,
        "method_name": "GoPay",
        "error_prefix": "GOPAY",
        "creation_budget": budget,
    }

    with pytest.raises(RuntimeError, match="GOPAY_CS_LIVE_REBUILD_EXHAUSTED"):
        checkout_app.create_local_method_cs_live_checkout(**common)
    with pytest.raises(RuntimeError, match="GOPAY_CHECKOUT_CREATION_BUDGET_EXHAUSTED"):
        checkout_app.create_local_method_cs_live_checkout(**common)

    assert len(created_sessions) == 3
    assert budget.used == 3
    assert budget.remaining == 0
    assert all(http.close_calls == 1 for http in created_sessions)


def test_checkout_creation_cancel_check_runs_before_each_real_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_sessions: list[FakeHttp] = []
    cancel_checks = 0

    def fake_create_checkout(*_args, **_kwargs) -> dict:
        http = FakeHttp()
        created_sessions.append(http)
        return {
            "data": {"checkout_session_id": f"oaics_{len(created_sessions)}"},
            "http": http,
        }

    def cancel_check() -> None:
        nonlocal cancel_checks
        cancel_checks += 1
        if cancel_checks == 2:
            raise InterruptedError("cancelled before next Checkout create")

    monkeypatch.setattr(checkout_app, "create_checkout", fake_create_checkout)
    budget = checkout_app.CheckoutCreationBudget(limit=5)

    with pytest.raises(InterruptedError, match="cancelled before next Checkout create"):
        checkout_app.create_local_method_cs_live_checkout(
            "fake-token",
            {"checkout_ui_mode": "redirect"},
            "http://fake-proxy",
            "device",
            "device",
            lambda _message: None,
            attempts=5,
            method_name="GoPay",
            error_prefix="GOPAY",
            creation_budget=budget,
            cancel_check=cancel_check,
        )

    assert cancel_checks == 2
    assert len(created_sessions) == 1
    assert budget.used == 1
    assert created_sessions[0].close_calls == 1


def test_retryable_checkout_creation_consumes_budget_and_closes_failed_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_sessions: list[FakeHttp] = []

    def fake_create_unmanaged(*_args, _session_holder=None, **_kwargs) -> dict:
        http = FakeHttp()
        failed_sessions.append(http)
        if _session_holder is not None:
            _session_holder.append(http)
        raise RuntimeError("OpenAI Checkout HTTP 503: upstream temporarily unavailable")

    monkeypatch.setattr(checkout_app, "_create_checkout_unmanaged", fake_create_unmanaged)
    budget = checkout_app.CheckoutCreationBudget(limit=2)

    with pytest.raises(RuntimeError, match="GOPAY_CHECKOUT_CREATION_BUDGET_EXHAUSTED"):
        checkout_app.create_local_method_cs_live_checkout(
            "fake-token",
            {"checkout_ui_mode": "redirect"},
            "http://fake-proxy",
            "device",
            "device",
            lambda _message: None,
            attempts=5,
            method_name="GoPay",
            error_prefix="GOPAY",
            creation_budget=budget,
        )

    assert len(failed_sessions) == 2
    assert budget.used == 2
    assert budget.remaining == 0
    assert all(http.close_calls == 1 for http in failed_sessions)

    with pytest.raises(RuntimeError, match="GOPAY_CHECKOUT_CREATION_BUDGET_EXHAUSTED"):
        checkout_app.create_local_method_cs_live_checkout(
            "fake-token",
            {"checkout_ui_mode": "redirect"},
            "http://fake-proxy",
            "device",
            "device",
            lambda _message: None,
            attempts=1,
            method_name="GoPay",
            error_prefix="GOPAY",
            creation_budget=budget,
        )

    assert len(failed_sessions) == 2


def test_checkout_creation_budget_deadline_stops_before_consuming_a_slot() -> None:
    now = [100.0]
    budget = checkout_app.CheckoutCreationBudget(
        limit=5,
        deadline_seconds=2,
        clock=lambda: now[0],
    )
    now[0] = 102.1

    with pytest.raises(RuntimeError, match="GOPAY_CHECKOUT_CREATION_DEADLINE_EXCEEDED"):
        budget.consume()

    assert budget.used == 0
    assert budget.remaining == 5


def test_account_shared_budget_exhaustion_stops_before_next_outer_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    logs: list[str] = []
    run_single_calls = 0
    successful_consumes = 0
    budget_ids: set[int] = set()

    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, message: logs.append(message)
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        nonlocal run_single_calls, successful_consumes
        run_single_calls += 1
        budget = attempt_options["_gopay_creation_budget"]
        budget_ids.add(id(budget))
        try:
            budget.consume()
        except RuntimeError as exc:
            state.update(status="error", error=str(exc))
            return
        successful_consumes += 1
        state.update(
            status="error",
            error="GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED: result=blocked",
            payment_error={
                "code": "GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED",
                "retryable": True,
                "rebuild_checkout": True,
            },
        )

    store._run_single = run_single
    monkeypatch.setattr(checkout_app, "GOPAY_CHECKOUT_CREATION_LIMIT", 3)

    with patch.object(checkout_app.time, "sleep"):
        store._run_locked("job-gopay-budget", {
            "retry_count": 50,
            "link_type": "gopay",
            "use_promo": True,
            "country": "ID",
            "checkout_country": "ID",
            "entry_proxies": ["http://promotion-1:8001"],
            "exit_proxies": ["http://checkout-1:9001"],
            "paired_proxy_rotation": True,
        })

    assert successful_consumes == 3
    assert run_single_calls == 4
    assert len(budget_ids) == 1
    assert state["status"] == "error"
    assert str(state["error"]).startswith("GOPAY_CHECKOUT_CREATION_BUDGET_EXHAUSTED")
    assert sum("提链尝试" in message for message in logs) == 1


def test_default_account_budget_covers_oaics_rebuilds_for_ten_cs_live_candidates() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    captured_limits: list[int] = []

    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, _message: None
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        captured_limits.append(attempt_options["_gopay_creation_budget"].limit)
        state.update(status="done", result={})

    store._run_single = run_single
    store._run_locked("job-gopay-default-budget", {
        "retry_count": 0,
        "link_type": "gopay",
        "use_promo": True,
        "country": "ID",
        "checkout_country": "ID",
        "entry_proxies": ["http://promotion-1:8001"],
        "exit_proxies": ["http://checkout-1:9001"],
        "paired_proxy_rotation": True,
    })

    assert captured_limits == [100]


@pytest.mark.parametrize(
    ("status_code", "payload", "expected_error"),
    [
        (200, {"result": "blocked"}, "GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED"),
        (200, {"result": "invalid_promotion"}, "GOPAY_APPROVAL_INVALID_PROMOTION"),
        (200, {"result": "failed"}, "GOPAY_APPROVAL_FAILED"),
        (200, {}, "GOPAY_APPROVAL_MISSING_RESULT"),
        (200, {"result": "future_upstream_state"}, "GOPAY_APPROVAL_UNKNOWN_RESULT"),
        (403, {"result": "blocked"}, "GOPAY_APPROVAL_HTTP_ERROR"),
    ],
)
def test_gopay_approval_rebuilds_only_typed_blocked_result_and_keeps_caller_http(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    payload: dict,
    expected_error: str,
) -> None:
    http = ScriptedHttp(FakeResponse(status_code, payload))
    context = bound_gopay_context(http)
    monkeypatch.setattr(checkout_app.sc, "build_http", lambda _proxy: http)
    monkeypatch.setattr(
        checkout_app,
        "resolve_payment_sentinel_headers",
        lambda *_args, **_kwargs: {},
    )

    with pytest.raises(RuntimeError, match=expected_error) as caught:
        checkout_app.approve_gopay_checkout_or_rebuild(
            "fake-token",
            "cs_live_test",
            "openai_llc",
            "http://fake-proxy",
            "device",
            "device",
            http=http,
            client_context=context,
        )

    assert http.post_calls == 1
    assert http.close_calls == 0
    if payload.get("result") != "blocked" or status_code != 200:
        assert "GOPAY_APPROVAL_BLOCKED_REBUILD_REQUIRED" not in str(caught.value)


def test_gopay_approved_result_returns_and_keeps_caller_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = ScriptedHttp(FakeResponse(200, {"result": "approved"}))
    context = bound_gopay_context(http)
    monkeypatch.setattr(checkout_app.sc, "build_http", lambda _proxy: http)
    monkeypatch.setattr(
        checkout_app,
        "resolve_payment_sentinel_headers",
        lambda *_args, **_kwargs: {},
    )

    result = checkout_app.approve_gopay_checkout_or_rebuild(
        "fake-token",
        "cs_live_test",
        "openai_llc",
        "http://fake-proxy",
        "device",
        "device",
        http=http,
        client_context=context,
    )

    assert result == {"result": "approved"}
    assert http.post_calls == 1
    assert http.close_calls == 0


def test_gopay_approval_fails_closed_when_session_cookie_is_missing() -> None:
    http = ScriptedHttp(FakeResponse(200, {"result": "approved"}))
    context = bound_gopay_context(http)
    http.cookies.values.clear()

    with pytest.raises(checkout_app.PaymentFlowError) as caught:
        checkout_app.approve_gopay_checkout_or_rebuild(
            "fake-token",
            "cs_live_test",
            "openai_llc",
            "http://fake-proxy",
            "device",
            "device",
            http=http,
            client_context=context,
        )

    assert caught.value.code == "CLIENT_CONTEXT_MISMATCH"
    assert http.post_calls == 0
    assert http.close_calls == 0


def test_shared_approval_keeps_legacy_missing_result_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = ScriptedHttp(FakeResponse(200, {}))
    monkeypatch.setattr(checkout_app.sc, "build_http", lambda _proxy: http)
    monkeypatch.setattr(
        checkout_app,
        "resolve_payment_sentinel_headers",
        lambda *_args, **_kwargs: {},
    )

    result = checkout_app.approve_checkout(
        "fake-token",
        "cs_live_test",
        "openai_llc",
        "http://fake-proxy",
        "device",
        "device",
    )

    assert result == {}
    assert http.post_calls == 1
    assert http.close_calls == 1
