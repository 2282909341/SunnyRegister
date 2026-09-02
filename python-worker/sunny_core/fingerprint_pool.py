"""Per-account TLS/browser fingerprint pool.

SunnyRegister previously used the same curl_cffi impersonate target
("chrome136") for every registration, so every account shared an identical
JA3/JA4/HTTP2 fingerprint that OpenAI could trivially cluster into one
automated batch and wave-ban. This module deterministically maps each account
(seed = account email) to one of several modern desktop fingerprints: every
account gets a distinct TLS/client signature, while a single account keeps one
consistent fingerprint across its entire lifetime (registration -> password/2FA
-> access-token probes), which is what a real browser user looks like.
"""
from __future__ import annotations

import hashlib

# Modern desktop impersonation targets supported by curl_cffi 0.16.x and
# accepted by chatgpt.com. Deliberately excludes Android/iOS and very old
# targets so the pool stays believable at the edge.
_DESKTOP_IMPERSONATE_TARGETS = (
    "chrome124",
    "chrome131",
    "chrome136",
    "chrome142",
    "chrome145",
    "firefox133",
    "firefox135",
    "firefox144",
    "firefox147",
    "safari17_0",
    "safari18_0",
    "edge101",
)


def pick_impersonate(seed: str = "") -> str:
    """Return the deterministic impersonate target for ``seed``.

    The same seed always maps to the same target; distinct seeds spread across
    the whole pool so accounts registered in the same batch do not share a
    fingerprint. The empty seed maps to one fixed target (a stable default for
    callers that have no per-account identity available).
    """
    digest = hashlib.sha256((seed or "default").encode("utf-8")).hexdigest()
    return _DESKTOP_IMPERSONATE_TARGETS[int(digest, 16) % len(_DESKTOP_IMPERSONATE_TARGETS)]


def impersonate_pool() -> tuple[str, ...]:
    """Expose the supported targets (used by tests and tooling)."""
    return _DESKTOP_IMPERSONATE_TARGETS