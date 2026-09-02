from __future__ import annotations

import pytest

from sunny_core.fingerprint_pool import impersonate_pool, pick_impersonate
from sunny_core import worker as worker_module


class _FakeDB:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def ensure_not_cancelled(self) -> None:
        return None

    def event(self, message: str, level: str = "info", detail: dict | None = None) -> None:
        self.events.append((message, level, detail or {}))


def test_pick_impersonate_is_deterministic() -> None:
    seed = "junior-annulus-4k@icloud.com"
    assert pick_impersonate(seed) == pick_impersonate(seed)
    assert pick_impersonate("") == pick_impersonate("")
    assert pick_impersonate("a@b.c") in impersonate_pool()


def test_pick_impersonate_spreads_across_pool() -> None:
    picked = {pick_impersonate(f"user-{index}@example.com") for index in range(300)}
    assert len(picked) >= 3
    assert picked <= set(impersonate_pool())


def test_pool_targets_are_supported_by_curl_cffi() -> None:
    from curl_cffi import requests as curl_requests

    supported = {entry.name for entry in curl_requests.BrowserType}
    assert set(impersonate_pool()) <= supported


def test_pacing_range_payload_override() -> None:
    low, high = worker_module._register_pacing_range({"register_pacing_min_sec": 1, "register_pacing_max_sec": 3})
    assert (low, high) == (1.0, 3.0)
    # inverted bounds are clamped to a deterministic single value (the low bound)
    low, high = worker_module._register_pacing_range({"register_pacing_min_sec": 5, "register_pacing_max_sec": 4})
    assert (low, high) == (5.0, 5.0)


def test_pacing_range_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUNNY_REGISTER_PACING_MIN_SEC", "2")
    monkeypatch.setenv("SUNNY_REGISTER_PACING_MAX_SEC", "6")
    low, high = worker_module._register_pacing_range({})
    assert (low, high) == (2.0, 6.0)


def test_pacing_disabled_when_max_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUNNY_REGISTER_PACING_MIN_SEC", "0")
    monkeypatch.setenv("SUNNY_REGISTER_PACING_MAX_SEC", "0")
    db = _FakeDB()
    worker_module._pacing_delay(db, {})
    assert db.events == []


def test_pacing_delay_emits_event_and_sleeps_in_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUNNY_REGISTER_PACING_MIN_SEC", "4")
    monkeypatch.setenv("SUNNY_REGISTER_PACING_MAX_SEC", "4")
    delays: list[float] = []

    def fake_delay(_db, seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(worker_module, "_interruptible_delay", fake_delay)
    db = _FakeDB()
    worker_module._pacing_delay(db, {})
    assert delays == [4.0]
    assert db.events and db.events[0][2].get("pacing_seconds") == 4.0