"""Structured classification of Checkout session identities.

Checkout creation responses have historically contained a mix of structured
fields, hosted URLs, and diagnostic text.  This module keeps the evidence
ordering explicit so a stale ID in a message cannot override an authoritative
current session ID.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit


_SESSION_ID_FULL_PATTERN = re.compile(r"^(?:oaics|cs_(?:live|test))_[A-Za-z0-9]+$")

# Only ID-shaped values under explicit session fields are authoritative.  A
# generic ``id`` field can appear in diagnostics or unrelated nested objects,
# so its value must never be promoted to the active Checkout identity.
_EXPLICIT_ID_KEYS = frozenset({"checkout_session_id", "session_id"})
_TRUSTED_URL_KEYS = frozenset({
    "checkout_url",
    "checkout_link",
    "hosted_checkout_url",
    "hosted_url",
    "payment_link",
    "payment_url",
    "redirect_url",
    "source_checkout_url",
    "stripe_hosted_url",
    "url",
})


class CheckoutSessionIdentityError(ValueError):
    """Base error for a malformed or ambiguous Checkout identity response."""


class CheckoutSessionIdentityConflictError(CheckoutSessionIdentityError):
    """Raised when one evidence level contains multiple distinct session IDs."""

    def __init__(self, source: str, candidates: Iterable[str]) -> None:
        self.code = "CHECKOUT_SESSION_ID_CONFLICT"
        self.error_code = self.code
        self.source = str(source)
        self.candidates = tuple(sorted(set(str(item) for item in candidates)))
        rendered = ",".join(self.candidates)
        super().__init__(
            f"CHECKOUT_SESSION_ID_CONFLICT: source={self.source} candidates={rendered}"
        )


@dataclass(frozen=True, slots=True)
class CheckoutSessionIdentity:
    """A normalized Checkout session ID and the evidence level that supplied it."""

    session_id: str
    kind: str
    source: str

    @property
    def checkout_session_id(self) -> str:
        """Compatibility spelling for callers that use the wire-field name."""
        return self.session_id

    @property
    def id(self) -> str:
        return self.session_id

    def __getitem__(self, key: str) -> str:
        if key in {"session_id", "checkout_session_id", "id"}:
            return self.session_id
        if key in {"kind", "source"}:
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


def _canonical_key(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()


def _session_kind(session_id: str) -> str:
    if session_id.startswith("oaics_"):
        return "oaics"
    if session_id.startswith("cs_live_"):
        return "cs_live"
    if session_id.startswith("cs_test_"):
        return "cs_test"
    return "unknown"


def _exact_session_id(value: Any) -> str:
    candidate = str(value or "").strip()
    return candidate if _SESSION_ID_FULL_PATTERN.fullmatch(candidate) else ""


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_strings(item)


def _session_id_from_trusted_url(value: Any) -> str:
    """Extract an ID only from a known Checkout host and path shape."""
    text = str(value or "").strip()
    for _attempt in range(4):
        try:
            parsed = urlsplit(text)
        except ValueError:
            parsed = None
        if parsed is None:
            decoded = unquote(text)
            if decoded == text:
                break
            text = decoded
            continue
        host = (parsed.hostname or "").lower().rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            port = -1
        if (
            parsed.scheme.lower() == "https"
            and port in {None, 443}
            and parsed.username is None
            and parsed.password is None
        ):
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            candidate = ""
            if (
                host == "chatgpt.com"
                and len(parts) >= 3
                and parts[0].lower() == "checkout"
            ):
                # /checkout/<processor_entity>/<oaics_or_cs_id>
                candidate = parts[2]
            elif (
                host in {"checkout.stripe.com", "pay.openai.com"}
                and len(parts) >= 3
                and [part.lower() for part in parts[:2]] == ["c", "pay"]
            ):
                candidate = parts[2]
            candidate = _exact_session_id(candidate)
            if candidate:
                return candidate
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return ""


def _structured_candidates(payload: Any) -> tuple[set[str], set[str]]:
    explicit: set[str] = set()
    trusted_urls: set[str] = set()
    visited: set[int] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 8 or not isinstance(value, (dict, list, tuple)):
            return
        identity = id(value)
        if identity in visited:
            return
        visited.add(identity)
        if isinstance(value, dict):
            for raw_key, nested in value.items():
                key = _canonical_key(raw_key)
                if key in _EXPLICIT_ID_KEYS:
                    for text in _iter_strings(nested):
                        candidate = _exact_session_id(text)
                        if candidate:
                            explicit.add(candidate)
                if key in _TRUSTED_URL_KEYS:
                    for text in _iter_strings(nested):
                        candidate = _session_id_from_trusted_url(text)
                        if candidate:
                            trusted_urls.add(candidate)
                visit(nested, depth + 1)
        else:
            for nested in value:
                visit(nested, depth + 1)

    visit(payload)
    return explicit, trusted_urls


def _resolve(candidates: set[str], source: str) -> CheckoutSessionIdentity | None:
    if len(candidates) > 1:
        raise CheckoutSessionIdentityConflictError(source, candidates)
    if not candidates:
        return None
    session_id = next(iter(candidates))
    return CheckoutSessionIdentity(
        session_id=session_id,
        kind=_session_kind(session_id),
        source=source,
    )


def classify_checkout_session_identity(
    payload: Any,
    response_text: str = "",
) -> CheckoutSessionIdentity | None:
    """Classify a Checkout ID from authoritative structured evidence only.

    ``response_text`` remains in the signature for caller compatibility, but
    unstructured response or diagnostic text is deliberately not inspected.
    """
    del response_text
    explicit, trusted_urls = _structured_candidates(payload)
    resolved = _resolve(explicit, "explicit_id")
    if resolved is not None:
        return resolved
    resolved = _resolve(trusted_urls, "trusted_url")
    if resolved is not None:
        return resolved
    return None


# Short aliases make the classifier easy to discover without changing the
# descriptive public API used by integration code.
classify_checkout_session_id = classify_checkout_session_identity
CheckoutSessionIdentityConflict = CheckoutSessionIdentityConflictError


__all__ = [
    "CheckoutSessionIdentity",
    "CheckoutSessionIdentityError",
    "CheckoutSessionIdentityConflictError",
    "CheckoutSessionIdentityConflict",
    "classify_checkout_session_identity",
    "classify_checkout_session_id",
]
