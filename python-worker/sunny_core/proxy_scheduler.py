from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .auth_resilience import classify_auth_failure


@dataclass(frozen=True)
class ProxyLease:
    subject: str
    proxy_id: int
    address: str
    slot: int
    latency_ms: int = 0

    def payload(self) -> dict[str, Any]:
        return {
            "proxy_id": self.proxy_id,
            "register": self.address,
            "address": self.address,
            "slot": self.slot,
            "latency_ms": self.latency_ms,
        }


class TaskProxyScheduler:
    """Task-scoped sticky proxy leases with lazy pulse checks and cooldowns."""

    def __init__(
        self,
        candidates: list[dict[str, Any]],
        preflight: Callable[[str], dict[str, Any]],
        *,
        cooldown_seconds: float = 20,
    ) -> None:
        self._candidates = [dict(item) for item in candidates if str(item.get("register") or "").strip()]
        self._preflight = preflight
        self._cooldown_seconds = max(1.0, float(cooldown_seconds))
        self._lock = threading.Lock()
        self._sticky: dict[str, int] = {}
        self._health: dict[int, dict[str, Any]] = {}

    def _candidate_order(self, subject: str, preferred_index: int) -> list[int]:
        count = len(self._candidates)
        if count == 0:
            return []
        sticky = self._sticky.get(subject)
        start = sticky if sticky is not None else max(0, int(preferred_index)) % count
        return [(start + offset) % count for offset in range(count)]

    def acquire(self, subject: str, preferred_index: int = 0) -> ProxyLease:
        key = str(subject or "").strip().lower()
        if not self._candidates:
            return ProxyLease(key, 0, "", 0)
        now = time.monotonic()
        for slot in self._candidate_order(key, preferred_index):
            with self._lock:
                state = dict(self._health.get(slot) or {})
            if float(state.get("cooldown_until") or 0) > now:
                continue
            if not state.get("checked"):
                check = self._preflight(str(self._candidates[slot].get("register") or ""))
                state = {
                    "checked": True,
                    "ok": bool(check.get("ok")),
                    "latency_ms": int(check.get("latency_ms") or 0),
                    "error": str(check.get("error") or ""),
                }
                if not state["ok"]:
                    state["cooldown_until"] = now + self._cooldown_seconds
                with self._lock:
                    self._health[slot] = state
            if not state.get("ok"):
                continue
            with self._lock:
                self._sticky[key] = slot
            candidate = self._candidates[slot]
            return ProxyLease(
                key,
                int(candidate.get("id") or 0),
                str(candidate.get("register") or ""),
                slot,
                int(state.get("latency_ms") or 0),
            )
        return ProxyLease(key, 0, "", -1)

    def record(self, lease: ProxyLease, *, success: bool, error: Any = "") -> None:
        if lease.slot < 0 or lease.slot >= len(self._candidates):
            return
        with self._lock:
            state = dict(self._health.get(lease.slot) or {"checked": True, "ok": True})
            if success:
                state.update({"ok": True, "failures": 0, "last_success_at": time.monotonic()})
            else:
                failure = classify_auth_failure(error)
                if failure.rotate_proxy:
                    failures = int(state.get("failures") or 0) + 1
                    state.update({
                        "ok": False,
                        "failures": failures,
                        "error": str(error or "")[:500],
                        "cooldown_until": time.monotonic() + min(300, self._cooldown_seconds * (2 ** (failures - 1))),
                    })
                    self._sticky.pop(lease.subject, None)
            self._health[lease.slot] = state

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            healthy = sum(1 for state in self._health.values() if state.get("ok"))
            cooling = sum(1 for state in self._health.values() if float(state.get("cooldown_until") or 0) > time.monotonic())
            return {"total": len(self._candidates), "checked": len(self._health), "healthy": healthy, "cooling": cooling, "sticky": len(self._sticky)}
