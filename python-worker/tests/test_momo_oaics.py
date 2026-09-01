from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest


PAY153_DIR = Path(__file__).parents[1] / "tools" / "pay153_checkout"
if str(PAY153_DIR) not in sys.path:
    sys.path.insert(0, str(PAY153_DIR))

import app as checkout_app  # noqa: E402
import provider_checkout as provider_checkout_module  # noqa: E402


def test_momo_stage1_requests_custom_oaics_and_defers_trial_campaign() -> None:
    payload = checkout_app.checkout_payload(
        {
            "plan": "plus",
            "link_type": "momo",
            "country": "VN",
            "currency": "VND",
            "checkout_country": "VN",
            "checkout_currency": "VND",
            "use_promo": True,
            "promo_campaign": "plus-1-month-free",
            "promo_on_create": False,
            "checkout_ui_mode": "custom",
        },
        {},
    )

    assert payload["checkout_ui_mode"] == "custom"
    assert payload["billing_details"] == {"country": "VN", "currency": "VND"}
    assert "promo_campaign" not in payload


def test_momo_stage1_can_attach_verified_campaign_at_checkout_creation() -> None:
    payload = checkout_app.checkout_payload(
        {
            "plan": "plus",
            "link_type": "momo",
            "country": "VN",
            "currency": "VND",
            "checkout_country": "VN",
            "checkout_currency": "VND",
            "use_promo": True,
            "promo_campaign": "account-specific-campaign",
            "promo_on_create": True,
            "checkout_ui_mode": "custom",
        },
        {},
    )

    assert payload["promo_campaign"] == {
        "promo_campaign_id": "account-specific-campaign",
        "is_coupon_from_query_param": False,
    }


def test_momo_authorization_url_accepts_expected_stripe_handoff() -> None:
    url = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_V9sheJQ8YBaT9uRLR4gw2ilYZiC8pWl"
    )

    assert checkout_app.is_valid_momo_authorization_url(url)
    assert checkout_app.momo_authorization_url({"next_action": {"url": url}}) == url


def test_momo_authorization_url_accepts_har_observed_payment_action_nonce() -> None:
    url = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/pa_nonce_VB99UramZf155SBdCjUYH0N18NB1KSw"
    )
    confirm_payload = {
        "status": "success",
        "setup_intent": {
            "next_action": {"redirect_to_url": {"url": url}},
        },
    }

    assert checkout_app.is_valid_momo_authorization_url(url)
    assert checkout_app.momo_authorization_url(confirm_payload) == url


def test_momo_authorization_url_rejects_checkout_and_other_provider_urls() -> None:
    assert not checkout_app.is_valid_momo_authorization_url(
        "https://chatgpt.com/checkout/openai_ie/oaics_example"
    )
    assert not checkout_app.is_valid_momo_authorization_url(
        "https://pm-redirects.stripe.com/authorize/acct_test/not_a_nonce"
    )
    assert not checkout_app.is_valid_momo_authorization_url(
        "https://pm-redirects.stripe.com/authorize/acct_test/xa_nonce_unexpected"
    )


def test_momo_attempts_request_custom_oaics_and_keep_cs_live_fallback() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    strategies: list[tuple[str, str, bool]] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, _message: None
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        strategies.append((
            str(attempt_options["checkout_ui_mode"]),
            str(attempt_options["local_method_strategy"]),
            bool(attempt_options["promo_on_create"]),
        ))
        if len(strategies) >= 4:
            state.update(status="done", result={})
        else:
            state.update(status="error", error="MOMO_METHOD_UNAVAILABLE: oaics_test")

    store._run_single = run_single
    store._run_locked("job-momo", {
        "retry_count": 3,
        "link_type": "momo",
        "use_promo": True,
        "country": "VN",
        "checkout_country": "VN",
        "entry_proxies": ["http://promotion:8001"],
        "exit_proxies": ["http://checkout:9001"],
        "paired_proxy_rotation": True,
    })

    assert strategies == [
        ("custom", "standalone", True),
        ("custom", "late_promo", False),
        ("custom", "standalone", True),
        ("custom", "late_promo", False),
    ]


def test_momo_rebuilds_ten_new_oaics_inside_one_account_attempt() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    attempts: list[dict] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, _message: None
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        attempts.append(attempt_options)
        if len(attempts) == checkout_app.MOMO_CHECKOUT_REBUILD_ATTEMPTS:
            state.update(status="done", error="", result={})
        else:
            state.update(
                status="error",
                error="MOMO_PROMOTION_INCOMPATIBLE_REBUILD_REQUIRED: fixture",
            )

    store._run_single = run_single
    store._run_locked("job-momo-inner", {
        "retry_count": 0,
        "link_type": "momo",
        "use_promo": True,
        "country": "VN",
        "checkout_country": "VN",
        "entry_proxies": ["http://promotion:8001"],
        "exit_proxies": ["http://checkout:9001"],
        "paired_proxy_rotation": True,
    })

    assert len(attempts) == checkout_app.MOMO_CHECKOUT_REBUILD_ATTEMPTS
    assert len({id(options) for options in attempts}) == len(attempts)
    assert [options["promo_on_create"] for options in attempts] == [True, False] * 5
    assert [options["local_method_strategy"] for options in attempts] == [
        "standalone", "late_promo",
    ] * 5
    assert state["status"] == "done"
    assert state["result"]["attempt"] == 1


def test_momo_exhausts_inner_budget_before_rotating_outer_proxy() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    attempts: list[tuple[str, str, bool, str]] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, _message: None
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        attempts.append((
            str(attempt_options["fixed_entry_proxy"]),
            str(attempt_options["fixed_exit_proxy"]),
            bool(attempt_options["promo_on_create"]),
            str(attempt_options["local_method_strategy"]),
        ))
        if len(attempts) == checkout_app.MOMO_CHECKOUT_REBUILD_ATTEMPTS + 1:
            state.update(status="done", error="", result={})
        else:
            state.update(
                status="error",
                error="MOMO_PROMOTION_INCOMPATIBLE_REBUILD_REQUIRED: fixture",
            )

    store._run_single = run_single
    with patch.object(checkout_app.time, "sleep"):
        store._run_locked("job-momo-proxy-rotation", {
            "retry_count": 1,
            "link_type": "momo",
            "use_promo": True,
            "country": "VN",
            "checkout_country": "VN",
            "entry_proxies": ["http://promotion-1", "http://promotion-2"],
            "exit_proxies": ["http://checkout-1", "http://checkout-2"],
            "paired_proxy_rotation": True,
        })

    assert len(attempts) == checkout_app.MOMO_CHECKOUT_REBUILD_ATTEMPTS + 1
    assert len({attempt[:2] for attempt in attempts[:10]}) == 1
    assert attempts[10][:2] != attempts[0][:2]
    assert attempts[0][2:] == (True, "standalone")
    assert attempts[10][2:] == (False, "late_promo")
    assert state["status"] == "done"
    assert state["result"]["attempt"] == 2


def test_momo_blocked_confirmation_rebuilds_a_new_session() -> None:
    store = object.__new__(checkout_app.JobStore)
    state = {"status": "running", "error": "", "result": None}
    attempts: list[dict] = []
    store.cancelled = lambda _job_id: False
    store.get = lambda _job_id: dict(state)
    store.update = lambda _job_id, **fields: state.update(fields)
    store.log = lambda _job_id, _message: None
    store._record_success = lambda _job_id, _result: None

    def run_single(_job_id: str, attempt_options: dict) -> None:
        attempts.append(attempt_options)
        if len(attempts) == 2:
            state.update(status="done", error="", result={})
        else:
            state.update(
                status="error",
                error="MOMO_OAICS_CONFIRM_BLOCKED: current session is blocked",
            )

    store._run_single = run_single
    store._run_locked("job-momo-blocked", {
        "retry_count": 0,
        "link_type": "momo",
        "use_promo": False,
        "country": "VN",
        "checkout_country": "VN",
        "entry_proxies": ["http://vn:8001"],
        "exit_proxies": ["http://vn:9001"],
        "paired_proxy_rotation": True,
    })

    assert len(attempts) == 2
    assert id(attempts[0]) != id(attempts[1])
    assert state["status"] == "done"


def test_momo_promotion_action_requires_momo_before_update() -> None:
    assert checkout_app.momo_promotion_action([], "", 0, "VND", True) == "rebuild"
    assert checkout_app.momo_promotion_action(["card"], "pm_wrong", 0, "VND", True) == "rebuild"
    assert checkout_app.momo_promotion_action([], "cpmt_momo", 522500, "VND", True) == "refresh"


def test_momo_promotion_action_skips_duplicate_update_for_discounted_checkout() -> None:
    assert checkout_app.momo_promotion_action(["card", "momo"], "", 0, "VND", True) == "already_discounted"
    assert checkout_app.momo_promotion_action(["momo"], "", 50, "vnd", True) == "already_discounted"
    assert checkout_app.momo_promotion_action(["momo"], "", 51, "VND", True) == "refresh"
    assert checkout_app.momo_promotion_action(["momo"], "", None, "VND", True) == "refresh"
    assert checkout_app.momo_promotion_action(
        ["momo"], "", 522500, "VND", True, True,
    ) == "rebuild_late"
    assert checkout_app.momo_promotion_action(["momo"], "", 522500, "VND", False) == "continue"


def test_momo_promotion_incompatible_error_is_classified_for_rebuild() -> None:
    incompatible = (
        'HTTP 400 {"detail":"This promotion is not compatible with the checkout\'s payment methods."}'
    )
    assert checkout_app.momo_promotion_is_payment_method_incompatible(incompatible)
    assert checkout_app.momo_create_checkout_rebuild_error(incompatible, True).startswith(
        "MOMO_PROMOTION_INCOMPATIBLE_REBUILD_REQUIRED:"
    )
    assert checkout_app.momo_create_checkout_rebuild_error(incompatible, True).endswith(
        "strategy=create_with_promo；将丢弃创建请求并切换优惠时序"
    )
    assert checkout_app.momo_create_checkout_rebuild_error("HTTP 400 invalid promotion", True) == ""
    assert not checkout_app.momo_promotion_is_payment_method_incompatible(
        "HTTP 400 invalid promotion"
    )
    assert checkout_app.momo_checkout_requires_rebuild(
        "MOMO_PROMOTION_INCOMPATIBLE_REBUILD_REQUIRED: fixture"
    )
    assert checkout_app.momo_checkout_requires_rebuild(
        "MOMO_METHOD_REMOVED_REBUILD_REQUIRED: fixture"
    )
    assert checkout_app.momo_checkout_requires_rebuild(
        "MOMO_OAICS_CONFIRM_BLOCKED: fixture"
    )
    assert checkout_app.momo_checkout_requires_rebuild(
        "CUSTOM_CONFIRM_BLOCKED: MoMo payment method was blocked"
    )
    assert checkout_app.momo_checkout_requires_rebuild(
        "MOMO_REDIRECT_MISSING: fixture"
    )
    assert not checkout_app.momo_checkout_requires_rebuild(
        "Sentinel token generation failed"
    )


def test_momo_reuses_checkout_session_only_for_identical_routes() -> None:
    route = "socks5h://gate.example:1000#route=vn-sticky"

    assert checkout_app.momo_reuses_checkout_http_session("momo", route, route)
    assert not checkout_app.momo_reuses_checkout_http_session(
        "momo", route, "socks5h://gate.example:1000#route=vn-other",
    )
    assert not checkout_app.momo_reuses_checkout_http_session("gopay", route, route)


def test_momo_native_method_detection_reads_har_observed_oaics_shapes() -> None:
    payload = {
        "checkout_session": {
            "payment_method_types": ["link", "card", "momo"],
            "available_payment_methods": [{"type": "momo"}],
            "custom_payment_methods": [{"id": "cpmt_unrelated", "type": "wallet"}],
        },
    }

    assert checkout_app.oaics_native_payment_method_types(payload) == ["link", "card", "momo"]


def test_native_snapshot_can_exclude_custom_payment_method_containers() -> None:
    payload = {
        "checkout_session": {
            "payment_method_types": ["link", "card", "momo"],
            "custom_payment_methods": [{"id": "cpmt_unrelated", "type": "wallet"}],
        },
    }

    assert provider_checkout_module.published_payment_method_snapshot(payload) == (
        ["link", "card", "momo", "wallet"],
        True,
    )
    assert provider_checkout_module.published_payment_method_snapshot(
        payload,
        include_custom_methods=False,
    ) == (["link", "card", "momo"], True)


def test_custom_only_snapshot_is_absent_when_native_parser_excludes_custom_methods() -> None:
    payload = {
        "checkout_session": {
            "customPaymentMethods": [{"id": "cpmt_momo", "type": "momo"}],
        },
    }

    assert provider_checkout_module.published_payment_method_snapshot(payload) == (
        ["momo"],
        True,
    )
    assert provider_checkout_module.published_payment_method_snapshot(
        payload,
        include_custom_methods=False,
    ) == ([], False)


def test_momo_stage_uses_latest_explicit_methods_instead_of_stale_history() -> None:
    prior = {
        "payment_method_types": ["card", "momo"],
        "custom_payment_methods": [{"id": "cpmt_momo", "type": "momo"}],
    }
    latest = {"payment_method_types": ["card"], "custom_payment_methods": []}

    assert checkout_app.oaics_stage_native_payment_method_types(latest, prior) == ["card"]
    assert checkout_app.oaics_stage_custom_payment_method_id(latest, prior, "momo") == ""
    assert checkout_app.oaics_stage_native_payment_method_types({}, prior) == ["card", "momo"]
    assert checkout_app.oaics_stage_custom_payment_method_id({}, prior, "momo") == "cpmt_momo"

    nested_latest = {
        "checkout_session": {
            "payment_method_types": ["card"],
            "custom_payment_methods": [],
        },
    }
    nested_empty = {
        "checkout_session": {
            "payment_method_types": [],
            "custom_payment_methods": [],
        },
    }
    assert checkout_app.oaics_stage_native_payment_method_types(
        nested_empty, prior,
    ) == []
    assert checkout_app.oaics_stage_custom_payment_method_id(
        nested_latest, prior, "momo",
    ) == ""

    nested_momo = {
        "checkout_session": {
            "custom_payment_methods": [{"id": "cpmt_nested", "type": "momo"}],
        },
    }
    assert checkout_app.oaics_stage_custom_payment_method_id(
        nested_momo, {}, "momo",
    ) == "cpmt_nested"

    camel_empty = {
        "checkoutSession": {
            "paymentMethodTypes": [],
            "customPaymentMethods": [],
        },
    }
    assert checkout_app.oaics_stage_native_payment_method_types(
        camel_empty, prior,
    ) == []
    assert checkout_app.oaics_stage_custom_payment_method_id(
        camel_empty, prior, "momo",
    ) == ""


def test_momo_does_not_treat_unlabelled_sole_custom_method_as_momo() -> None:
    unlabeled = {
        "checkout_session": {
            "customPaymentMethods": [{"id": "cpmt_unlabelled"}],
        },
    }

    assert checkout_app.oaics_stage_custom_payment_method_id(
        unlabeled, {}, "momo",
    ) == ""
    assert checkout_app.custom_payment_method_id_for(
        {"customPaymentMethods": [{"id": "cpmt_unlabelled"}]},
        "gcash",
    ) == "cpmt_unlabelled"

    mixed_fields = {
        "custom_payment_methods": [],
        "customPaymentMethods": [
            {"id": "cpmt_momo", "type": "momo"},
            {"id": "cpmt_momo", "type": "momo"},
        ],
    }
    assert checkout_app.oaics_custom_payment_method_items(mixed_fields) == [
        {"id": "cpmt_momo", "type": "momo"},
    ]
    assert checkout_app.oaics_stage_custom_payment_method_id(
        mixed_fields, {}, "momo",
    ) == "cpmt_momo"


def test_momo_oaics_poll_does_not_restore_explicitly_empty_methods() -> None:
    fallback = {
        "payment_method_types": ["card", "momo"],
        "custom_payment_methods": [{"id": "cpmt_momo", "type": "momo"}],
    }
    http = _RecordingHttp([
        _FakeResponse({
            "payment_method_types": [],
            "custom_payment_methods": [],
        }),
        _FakeResponse({
            "payment_method_types": ["momo"],
            "custom_payment_methods": [],
        }),
    ])

    with patch.object(checkout_app.time, "sleep"):
        state = checkout_app.fetch_oaics_native_checkout_with_retry(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "device-fixture",
            "momo",
            preserve_from=fallback,
            attempts=2,
            delay_seconds=0,
        )

    assert state["payment_method_types"] == ["momo"]
    assert len(http.calls) == 2


def test_momo_discounted_amount_accepts_har_threshold() -> None:
    assert checkout_app.is_momo_promo_amount(0, "VND")
    assert checkout_app.is_momo_promo_amount(50, "vnd")
    assert not checkout_app.is_momo_promo_amount(51, "VND")
    assert not checkout_app.is_momo_promo_amount(0, "IDR")


def test_momo_oaics_error_redacts_confirmation_and_intent_secrets() -> None:
    rendered = checkout_app._redact_oaics_payment_error(
        "ctoken_private seti_fixture_secret_private pi_fixture_secret_private"
    )

    assert "private" not in rendered
    assert rendered.count("[PAYMENT_SECRET]") == 3


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = "{}"

    def json(self) -> dict:
        return self._payload


class _RecordingHttp:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1

    def post(self, url: str, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    def get(self, url: str, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


def test_momo_create_promo_waits_for_amount_to_settle_before_rebuilding() -> None:
    initial = {
        "payment_method_types": ["momo"],
        "amount_total": 522500,
        "currency": "VND",
    }
    settled = {
        "payment_method_types": ["momo"],
        "amount_total": 1,
        "currency": "VND",
    }
    http = _RecordingHttp([_FakeResponse(settled)])
    logs: list[str] = []

    with patch.object(checkout_app.time, "sleep"):
        state = checkout_app.fetch_momo_discounted_checkout_with_retry(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "device-fixture",
            initial,
            attempts=3,
            delay_seconds=0,
            log=logs.append,
        )

    assert state == settled
    assert len(http.calls) == 1
    assert logs and "amount=522500 VND" in logs[0]


def test_momo_late_promo_waits_for_stable_method_snapshot() -> None:
    initial = {
        "payment_method_types": ["momo"],
        "amount_total": 522500,
        "currency": "VND",
    }
    withdrawn = {
        "paymentMethodTypes": [],
        "customPaymentMethods": [],
        "amount_total": 522500,
        "currency": "VND",
    }
    http = _RecordingHttp([
        _FakeResponse(withdrawn),
        _FakeResponse(withdrawn),
    ])

    with patch.object(checkout_app.time, "sleep"):
        state = checkout_app.fetch_momo_checkout_stable_with_retry(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "device-fixture",
            initial,
            attempts=3,
            delay_seconds=0,
        )

    assert state == withdrawn
    assert checkout_app.oaics_stage_native_payment_method_types(
        state, initial,
    ) == []
    assert len(http.calls) == 2


def test_momo_late_promo_rebuilds_when_snapshot_never_stabilizes() -> None:
    initial = {
        "payment_method_types": ["momo"],
        "amount_total": 522500,
        "currency": "VND",
    }
    http = _RecordingHttp([
        _FakeResponse({
            "paymentMethodTypes": [],
            "amount_total": 522500,
            "currency": "VND",
        }),
        _FakeResponse({
            "paymentMethodTypes": ["momo"],
            "amount_total": 1,
            "currency": "VND",
        }),
    ])

    with (
        patch.object(checkout_app.time, "sleep"),
        pytest.raises(RuntimeError, match="MOMO_CHECKOUT_REBUILD_REQUIRED"),
    ):
        checkout_app.fetch_momo_checkout_stable_with_retry(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "device-fixture",
            initial,
            attempts=3,
            delay_seconds=0,
        )

    assert len(http.calls) == 2


@pytest.mark.parametrize("marker", ["not_blocked", "not blocked", "unblocked"])
def test_momo_confirm_does_not_misclassify_negated_blocked_marker(marker: str) -> None:
    assert not checkout_app.checkout_confirmation_is_blocked(
        {"result": marker},
        '{"result":"' + marker + '"}',
    )


def test_momo_session_cleanup_closes_each_http_client_once() -> None:
    class _Closable:
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1

    checkout_http = _Closable()
    stripe_http = _Closable()

    checkout_app.close_http_sessions([
        checkout_http, checkout_http, stripe_http,
    ])

    assert checkout_http.close_count == 1
    assert stripe_http.close_count == 1


def test_momo_checkout_uses_checkout_flow_and_strict_sentinel_identity() -> None:
    class _Cookies:
        def __init__(self) -> None:
            self.values: list[tuple[str, str, str]] = []

        def set(self, name: str, value: str, *, domain: str) -> None:
            self.values.append((name, value, domain))

    http = _RecordingHttp([
        _FakeResponse({}),
        _FakeResponse({
            "checkout_session_id": "oaics_fixture",
            "processor_entity": "openai_llc",
        }),
    ])
    http.cookies = _Cookies()

    with (
        patch.object(checkout_app.sc, "build_http", return_value=http),
        patch.object(
            checkout_app,
            "resolve_payment_sentinel_headers",
            return_value={"OpenAI-Sentinel-Token": "sentinel-fixture"},
        ) as sentinel,
    ):
        created = checkout_app.create_checkout(
            "access-token",
            {"checkout_ui_mode": "custom"},
            "socks5h://vn-proxy",
            "device-fixture",
            "device-fixture",
            lambda _message: None,
            allow_sentinel_fallback=False,
            diagnostic_label="MoMo",
        )

    assert created["data"]["checkout_session_id"] == "oaics_fixture"
    sentinel.assert_called_once()
    args, kwargs = sentinel.call_args
    assert args[1:5] == (
        "socks5h://vn-proxy",
        "chatgpt_checkout",
        "device-fixture",
        "device-fixture",
    )
    assert kwargs["allow_fallback"] is False
    assert http.cookies.values == [
        ("oai-did", "device-fixture", "chatgpt.com"),
    ]
    assert http.close_count == 0
    _, checkout_url, checkout_request = http.calls[1]
    assert checkout_url == checkout_app.sc.OPENAI_CHECKOUT_URL
    assert checkout_request["headers"]["OAI-Device-Id"] == "device-fixture"
    assert checkout_request["headers"]["OpenAI-Sentinel-Token"] == "sentinel-fixture"


def test_momo_create_promotion_400_is_rebuildable_and_closes_unregistered_session() -> None:
    warmup = _FakeResponse({})
    rejected = _FakeResponse({}, status_code=400)
    rejected.text = (
        '{"detail":"This promotion is not compatible with the checkout\'s payment methods."}'
    )
    http = _RecordingHttp([warmup, rejected])

    with (
        patch.object(checkout_app.sc, "build_http", return_value=http),
        patch.object(
            checkout_app,
            "resolve_payment_sentinel_headers",
            return_value={},
        ),
        pytest.raises(RuntimeError, match="MOMO_PROMOTION_INCOMPATIBLE_REBUILD_REQUIRED"),
    ):
        checkout_app.create_checkout(
            "access-token",
            {
                "checkout_ui_mode": "custom",
                "promo_campaign": {"promo_campaign_id": "plus-1-month-free"},
            },
            "socks5h://vn-proxy",
            "device-fixture",
            "device-fixture",
            lambda _message: None,
            allow_sentinel_fallback=False,
            diagnostic_label="MoMo",
        )

    assert http.close_count == 1


def test_momo_checkout_closes_session_when_sentinel_generation_fails() -> None:
    http = _RecordingHttp([_FakeResponse({})])

    with (
        patch.object(checkout_app.sc, "build_http", return_value=http),
        patch.object(
            checkout_app,
            "resolve_payment_sentinel_headers",
            side_effect=RuntimeError("sentinel fixture failure"),
        ),
        pytest.raises(RuntimeError, match="sentinel fixture failure"),
    ):
        checkout_app.create_checkout(
            "access-token",
            {"checkout_ui_mode": "custom"},
            "socks5h://vn-proxy",
            "device-fixture",
            "device-fixture",
            lambda _message: None,
            allow_sentinel_fallback=False,
            diagnostic_label="MoMo",
        )

    assert http.close_count == 1


def test_momo_checkout_closes_session_on_non_promotion_http_error() -> None:
    rejected = _FakeResponse({}, status_code=500)
    rejected.text = '{"detail":"upstream failure"}'
    http = _RecordingHttp([_FakeResponse({}), rejected])

    with (
        patch.object(checkout_app.sc, "build_http", return_value=http),
        patch.object(
            checkout_app,
            "resolve_payment_sentinel_headers",
            return_value={},
        ),
        pytest.raises(RuntimeError, match="OpenAI Checkout HTTP 500"),
    ):
        checkout_app.create_checkout(
            "access-token",
            {"checkout_ui_mode": "custom"},
            "socks5h://vn-proxy",
            "device-fixture",
            "device-fixture",
            lambda _message: None,
            allow_sentinel_fallback=False,
            diagnostic_label="MoMo",
        )

    assert http.close_count == 1


def test_momo_confirmation_token_uses_payment_method_without_leaking_it_to_logs() -> None:
    http = _RecordingHttp([_FakeResponse({"id": "ctoken_fixture"})])

    token_id = checkout_app.create_oaics_confirmation_token(
        http, "pk_live_fixture", "pm_fixture",
    )

    assert token_id == "ctoken_fixture"
    method, url, request = http.calls[0]
    assert method == "POST"
    assert url.endswith("/v1/confirmation_tokens")
    assert request["data"]["payment_method"] == "pm_fixture"
    assert request["data"]["key"] == "pk_live_fixture"


def test_momo_native_checkout_confirm_uses_confirm_token_contract() -> None:
    redirect = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_VA3BRLWr6svCcb3IbJQljuUq2OZpfPW"
    )
    http = _RecordingHttp([
        _FakeResponse({"ok": True}),
        _FakeResponse({
            "status": "success",
            "setup_intent": {"next_action": {"redirect_to_url": {"url": redirect}}},
        }),
    ])

    with patch.object(
        checkout_app,
        "resolve_payment_sentinel_headers",
        return_value={"OpenAI-Sentinel-Token": "sentinel-fixture"},
    ):
        result = checkout_app.confirm_oaics_native_payment_method(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "momo",
            "ctoken_fixture",
            "http://vn-proxy",
            "device-fixture",
            "did-fixture",
        )

    assert checkout_app.momo_authorization_url(result) == redirect
    assert http.calls[0][1].endswith("/backend-api/sentinel/ping")
    _, url, request = http.calls[1]
    assert url.endswith("/backend-api/payments/checkout/confirm")
    assert request["json"] == {
        "checkout_session_id": "oaics_fixture",
        "selected_payment_method_type": "momo",
        "confirm_token": "ctoken_fixture",
    }


@pytest.mark.parametrize("status_code", [200, 400])
def test_momo_native_confirm_classifies_result_blocked_before_http_error(
    status_code: int,
) -> None:
    blocked = _FakeResponse({"result": "blocked", "code": "risk_blocked"}, status_code)
    blocked.text = '{"result":"blocked","code":"risk_blocked"}'
    http = _RecordingHttp([blocked])

    with (
        patch.object(checkout_app, "resolve_payment_sentinel_headers", return_value={}),
        pytest.raises(RuntimeError, match="MOMO_OAICS_CONFIRM_BLOCKED"),
    ):
        checkout_app.confirm_oaics_native_payment_method(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "momo",
            "ctoken_fixture",
            "http://vn-proxy",
            "device-fixture",
            "did-fixture",
        )

    assert len(http.calls) == 1


@pytest.mark.parametrize("status_code", [200, 400])
def test_momo_custom_confirm_blocked_rebuilds_without_reusing_session(
    status_code: int,
) -> None:
    blocked = _FakeResponse({"result": "blocked", "code": "risk_blocked"}, status_code)
    blocked.text = '{"result":"blocked","code":"risk_blocked"}'
    http = _RecordingHttp([blocked])

    with (
        patch.object(checkout_app, "resolve_payment_sentinel_headers", return_value={}),
        pytest.raises(RuntimeError, match="CUSTOM_CONFIRM_BLOCKED"),
    ):
        checkout_app.confirm_custom_checkout_method_with_retry(
            http,
            "access-token",
            "oaics_fixture",
            "openai_llc",
            "cpmt_momo",
            "http://vn-proxy",
            "device-fixture",
            "did-fixture",
            method_name="MoMo",
            max_retries=2,
            rebuild_on_blocked=True,
        )

    assert len(http.calls) == 1


def test_momo_intent_fallback_confirms_setup_intent_with_created_payment_method() -> None:
    redirect = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_VA3BRLWr6svCcb3IbJQljuUq2OZpfPW"
    )
    http = _RecordingHttp([_FakeResponse({
        "id": "seti_fixture",
        "status": "requires_action",
        "next_action": {"redirect_to_url": {"url": redirect}},
    })])

    result = checkout_app.confirm_oaics_momo_intent(
        http,
        "pk_live_fixture",
        "pm_fixture",
        {"setup_intent": {"client_secret": "seti_fixture_secret_value"}},
        "oaics_fixture",
        "openai_llc",
    )

    assert checkout_app.momo_authorization_url(result) == redirect
    _, url, request = http.calls[0]
    assert url.endswith("/v1/setup_intents/seti_fixture/confirm")
    assert request["data"]["payment_method"] == "pm_fixture"
    assert "confirmation_token" not in request["data"]


def test_momo_intent_poll_reads_redirect_after_approval() -> None:
    redirect = (
        "https://pm-redirects.stripe.com/authorize/"
        "acct_1HOrSwC6h1nxGoI3/sa_nonce_VA3BRLWr6svCcb3IbJQljuUq2OZpfPW"
    )
    http = _RecordingHttp([
        _FakeResponse({"id": "seti_fixture", "status": "processing"}),
        _FakeResponse({
            "id": "seti_fixture",
            "status": "requires_action",
            "next_action": {"redirect_to_url": {"url": redirect}},
        }),
    ])

    with patch.object(checkout_app.time, "sleep"):
        result = checkout_app.poll_oaics_momo_intent(
            http,
            "pk_live_fixture",
            {"setup_intent": {"client_secret": "seti_fixture_secret_value"}},
            attempts=2,
        )

    assert checkout_app.momo_authorization_url(result) == redirect
    assert [call[0] for call in http.calls] == ["GET", "GET"]
