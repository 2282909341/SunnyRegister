from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping, Protocol, runtime_checkable
from urllib.parse import urlsplit


class PaymentFlowError(RuntimeError):
    """A stable, serializable error raised by the payment proof boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        phase: str = "proof",
        retryable: bool = False,
        rebuild_checkout: bool = False,
        http_status: int | None = None,
    ) -> None:
        normalized_code = re.sub(r"[^A-Z0-9]+", "_", str(code or "").upper()).strip("_")
        if not normalized_code:
            raise ValueError("payment flow error code must not be empty")
        self.code = normalized_code
        self.message = str(message or normalized_code)
        self.phase = str(phase or "proof")
        self.retryable = bool(retryable)
        self.rebuild_checkout = bool(rebuild_checkout)
        self.http_status = int(http_status) if http_status is not None else None
        super().__init__(f"{self.code}: {self.message}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "phase": self.phase,
            "retryable": self.retryable,
            "rebuild_checkout": self.rebuild_checkout,
            "http_status": self.http_status,
        }


class SentinelFlow(str, Enum):
    CHATGPT_CHECKOUT = "chatgpt_checkout"
    CHECKOUT_SESSION_APPROVAL = "checkout_session_approval"


class ProofProviderKind(str, Enum):
    """Known proof-provider labels used in diagnostics and route policy."""

    LEGACY_PYTHON_NODE = "legacy_python_node"
    SUPPORTED_BROWSER = "supported_browser"
    # Compatibility alias for callers that adopted the provisional name.
    PUBLIC_BROWSER = "supported_browser"


class PaymentEndpoint(str, Enum):
    CHECKOUT_CREATE = "/backend-api/payments/checkout"
    CHECKOUT_CONFIRM = "/backend-api/payments/checkout/confirm"
    CHECKOUT_APPROVE = "/backend-api/payments/checkout/approve"
    SENTINEL_PING = "/backend-api/sentinel/ping"


ENDPOINT_FLOW: Mapping[PaymentEndpoint, SentinelFlow] = MappingProxyType({
    PaymentEndpoint.CHECKOUT_CREATE: SentinelFlow.CHATGPT_CHECKOUT,
    PaymentEndpoint.CHECKOUT_CONFIRM: SentinelFlow.CHECKOUT_SESSION_APPROVAL,
    PaymentEndpoint.CHECKOUT_APPROVE: SentinelFlow.CHECKOUT_SESSION_APPROVAL,
    PaymentEndpoint.SENTINEL_PING: SentinelFlow.CHECKOUT_SESSION_APPROVAL,
})


def _endpoint_path(value: PaymentEndpoint | str) -> str:
    if isinstance(value, PaymentEndpoint):
        return value.value
    raw = str(value or "").strip()
    if not raw:
        raise PaymentFlowError(
            "UNKNOWN_PAYMENT_ENDPOINT",
            "payment endpoint must not be empty",
            phase="configuration",
        )
    parsed = urlsplit(raw)
    path = parsed.path or raw
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def payment_endpoint(value: PaymentEndpoint | str) -> PaymentEndpoint:
    path = _endpoint_path(value)
    try:
        return PaymentEndpoint(path)
    except ValueError as exc:
        raise PaymentFlowError(
            "UNKNOWN_PAYMENT_ENDPOINT",
            "payment endpoint has no Sentinel flow mapping",
            phase="configuration",
        ) from exc


def sentinel_flow(value: SentinelFlow | str) -> SentinelFlow:
    if isinstance(value, SentinelFlow):
        return value
    try:
        return SentinelFlow(str(value or "").strip())
    except ValueError as exc:
        raise PaymentFlowError(
            "UNKNOWN_SENTINEL_FLOW",
            "Sentinel flow is empty or unsupported",
            phase="configuration",
        ) from exc


def flow_for_endpoint(value: PaymentEndpoint | str) -> SentinelFlow:
    return ENDPOINT_FLOW[payment_endpoint(value)]


def _required_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise PaymentFlowError(
            "INVALID_CLIENT_CONTEXT",
            f"{field_name} must not be empty",
            phase="configuration",
        )
    return text


def _canonical_name(value: Any, field_name: str) -> str:
    text = _required_text(value, field_name).lower().replace("-", "_")
    normalized = re.sub(r"[^a-z0-9_]+", "_", text).strip("_")
    if not normalized:
        raise PaymentFlowError(
            "INVALID_CLIENT_CONTEXT",
            f"{field_name} must contain an ASCII identifier",
            phase="configuration",
        )
    return normalized


def _validate_device_identity(device_id: str, did: str) -> None:
    if device_id != did:
        raise PaymentFlowError(
            "CLIENT_IDENTITY_MISMATCH",
            "oai-did and OAI-Device-Id must identify the same client",
            phase="configuration",
        )


@dataclass(frozen=True, slots=True)
class ProofRequest:
    endpoint: PaymentEndpoint | str
    flow: SentinelFlow | str
    payment_provider: str
    device_id: str
    did: str
    user_agent: str
    proxy_route: str
    session_owner: str
    proof_provider: str = ProofProviderKind.LEGACY_PYTHON_NODE.value
    cookie_identity: str = ""

    def __post_init__(self) -> None:
        endpoint = payment_endpoint(self.endpoint)
        flow = sentinel_flow(self.flow)
        expected_flow = flow_for_endpoint(endpoint)
        if flow is not expected_flow:
            raise PaymentFlowError(
                "ENDPOINT_FLOW_MISMATCH",
                "Sentinel flow does not match the protected payment endpoint",
                phase="configuration",
            )
        device_id = _required_text(self.device_id, "device_id")
        did = _required_text(self.did, "did")
        _validate_device_identity(device_id, did)
        object.__setattr__(self, "endpoint", endpoint)
        object.__setattr__(self, "flow", flow)
        object.__setattr__(
            self,
            "payment_provider",
            _canonical_name(self.payment_provider, "payment_provider"),
        )
        object.__setattr__(self, "device_id", device_id)
        object.__setattr__(self, "did", did)
        object.__setattr__(self, "user_agent", _required_text(self.user_agent, "user_agent"))
        object.__setattr__(self, "proxy_route", _required_text(self.proxy_route, "proxy_route"))
        object.__setattr__(self, "session_owner", _required_text(self.session_owner, "session_owner"))
        object.__setattr__(
            self,
            "proof_provider",
            _canonical_name(self.proof_provider, "proof_provider"),
        )
        object.__setattr__(self, "cookie_identity", str(self.cookie_identity or "").strip())


_PROOF_HEADER_NAMES = {
    "openai-sentinel-token": "OpenAI-Sentinel-Token",
    "openai-sentinel-so-token": "OpenAI-Sentinel-SO-Token",
}


@dataclass(frozen=True, slots=True)
class ProofBundle:
    endpoint: PaymentEndpoint | str
    flow: SentinelFlow | str
    payment_provider: str
    proof_provider: str
    device_id: str
    did: str
    user_agent: str
    proxy_route: str
    session_owner: str
    headers: Mapping[str, str] = field(default_factory=dict)
    turnstile_required: bool = False
    session_observer_required: bool = False
    cookie_identity: str = ""

    def __post_init__(self) -> None:
        endpoint = payment_endpoint(self.endpoint)
        flow = sentinel_flow(self.flow)
        expected_flow = flow_for_endpoint(endpoint)
        if flow is not expected_flow:
            raise PaymentFlowError(
                "ENDPOINT_FLOW_MISMATCH",
                "proof bundle flow does not match its payment endpoint",
                phase="proof",
            )
        device_id = _required_text(self.device_id, "device_id")
        did = _required_text(self.did, "did")
        _validate_device_identity(device_id, did)
        normalized_headers: dict[str, str] = {}
        for raw_name, raw_value in dict(self.headers or {}).items():
            name = str(raw_name or "").strip().lower()
            if name not in _PROOF_HEADER_NAMES:
                raise PaymentFlowError(
                    "PROOF_HEADER_NOT_ALLOWED",
                    "proof providers may only return Sentinel proof headers",
                    phase="proof",
                )
            value = str(raw_value or "").strip()
            if not value or "\r" in value or "\n" in value:
                raise PaymentFlowError(
                    "PROOF_HEADER_INVALID",
                    "proof header is empty or contains invalid control characters",
                    phase="proof",
                )
            if name in normalized_headers and normalized_headers[name] != value:
                raise PaymentFlowError(
                    "PROOF_HEADER_CONFLICT",
                    "proof provider returned conflicting duplicate headers",
                    phase="proof",
                )
            normalized_headers[name] = value

        object.__setattr__(self, "endpoint", endpoint)
        object.__setattr__(self, "flow", flow)
        object.__setattr__(
            self,
            "payment_provider",
            _canonical_name(self.payment_provider, "payment_provider"),
        )
        object.__setattr__(
            self,
            "proof_provider",
            _canonical_name(self.proof_provider, "proof_provider"),
        )
        object.__setattr__(self, "device_id", device_id)
        object.__setattr__(self, "did", did)
        object.__setattr__(self, "user_agent", _required_text(self.user_agent, "user_agent"))
        object.__setattr__(self, "proxy_route", _required_text(self.proxy_route, "proxy_route"))
        object.__setattr__(self, "session_owner", _required_text(self.session_owner, "session_owner"))
        object.__setattr__(self, "headers", MappingProxyType(normalized_headers))
        object.__setattr__(self, "turnstile_required", bool(self.turnstile_required))
        object.__setattr__(self, "session_observer_required", bool(self.session_observer_required))
        object.__setattr__(self, "cookie_identity", str(self.cookie_identity or "").strip())

    def _json_header(self, name: str) -> dict[str, Any] | None:
        raw = self.headers.get(name)
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise PaymentFlowError(
                "PROOF_HEADER_INVALID",
                "Sentinel proof header must contain a JSON object",
                phase="proof",
            ) from exc
        if not isinstance(payload, dict):
            raise PaymentFlowError(
                "PROOF_HEADER_INVALID",
                "Sentinel proof header must contain a JSON object",
                phase="proof",
            )
        return payload

    @property
    def sentinel_payload(self) -> dict[str, Any] | None:
        return self._json_header("openai-sentinel-token")

    @property
    def session_observer_payload(self) -> dict[str, Any] | None:
        return self._json_header("openai-sentinel-so-token")

    @property
    def has_sentinel_token(self) -> bool:
        return "openai-sentinel-token" in self.headers

    @property
    def has_session_observer_token(self) -> bool:
        return "openai-sentinel-so-token" in self.headers

    @property
    def has_turnstile_proof(self) -> bool:
        payload = self.sentinel_payload or {}
        return bool(str(payload.get("t") or "").strip())

    def http_headers(self) -> dict[str, str]:
        return {
            _PROOF_HEADER_NAMES[name]: value
            for name, value in self.headers.items()
        }


@runtime_checkable
class SentinelProofProvider(Protocol):
    @property
    def name(self) -> str:
        ...

    async def issue(self, request: ProofRequest) -> ProofBundle:
        ...


@dataclass(frozen=True, slots=True)
class CallableSentinelProofProvider:
    """Small adapter for an explicitly selected proof implementation.

    The adapter deliberately does not know how to create a proof.  This keeps
    the payment contract independent from the legacy Python/Node implementation
    and provides a narrow seam for a supported browser provider later.
    """

    name: str
    issuer: Callable[[ProofRequest], Awaitable[ProofBundle]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _canonical_name(self.name, "proof_provider"))
        if not callable(self.issuer):
            raise TypeError("proof provider issuer must be callable")

    async def issue(self, request: ProofRequest) -> ProofBundle:
        bundle = await self.issuer(request)
        if not isinstance(bundle, ProofBundle):
            raise PaymentFlowError(
                "PROOF_PROVIDER_INVALID_RESULT",
                "proof provider did not return a ProofBundle",
                phase="proof",
            )
        return bundle


@dataclass(frozen=True, slots=True)
class CheckoutClientContext:
    payment_provider: str
    device_id: str
    did: str
    user_agent: str
    proxy_route: str
    session_owner: str
    proof_provider: str = ProofProviderKind.LEGACY_PYTHON_NODE.value
    cookies: Mapping[str, str] = field(default_factory=dict)
    proof_issuer: SentinelProofProvider | None = field(
        default=None,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        device_id = _required_text(self.device_id, "device_id")
        did = _required_text(self.did, "did")
        _validate_device_identity(device_id, did)
        object.__setattr__(
            self,
            "payment_provider",
            _canonical_name(self.payment_provider, "payment_provider"),
        )
        object.__setattr__(self, "device_id", device_id)
        object.__setattr__(self, "did", did)
        object.__setattr__(self, "user_agent", _required_text(self.user_agent, "user_agent"))
        object.__setattr__(self, "proxy_route", _required_text(self.proxy_route, "proxy_route"))
        object.__setattr__(self, "session_owner", _required_text(self.session_owner, "session_owner"))
        object.__setattr__(
            self,
            "proof_provider",
            _canonical_name(self.proof_provider, "proof_provider"),
        )
        if self.proof_issuer is not None:
            issuer_name = _canonical_name(
                getattr(self.proof_issuer, "name", ""),
                "proof_provider",
            )
            if issuer_name != self.proof_provider:
                raise PaymentFlowError(
                    "PROOF_PROVIDER_MISMATCH",
                    "proof issuer name must match the Checkout context provider",
                    phase="configuration",
                )
            if not callable(getattr(self.proof_issuer, "issue", None)):
                raise PaymentFlowError(
                    "PROOF_PROVIDER_INVALID",
                    "proof issuer must provide an async issue method",
                    phase="configuration",
                )
        normalized_cookies: dict[str, str] = {}
        for raw_name, raw_value in dict(self.cookies or {}).items():
            name = str(raw_name or "").strip()
            value = str(raw_value or "").strip()
            if not name or "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                raise PaymentFlowError(
                    "INVALID_CLIENT_CONTEXT",
                    "cookie name/value is empty or contains invalid control characters",
                    phase="configuration",
                )
            normalized_cookies[name] = value
        cookie_did = normalized_cookies.get("oai-did") or normalized_cookies.get("OAI-DID")
        if self.payment_provider == "gopay" and not cookie_did:
            raise PaymentFlowError(
                "CLIENT_COOKIE_IDENTITY_REQUIRED",
                "GoPay Checkout context requires an oai-did cookie binding",
                phase="configuration",
            )
        if cookie_did and cookie_did != did:
            raise PaymentFlowError(
                "CLIENT_IDENTITY_MISMATCH",
                "oai-did cookie must identify the same client as OAI-Device-Id",
                phase="configuration",
            )
        object.__setattr__(self, "cookies", MappingProxyType(normalized_cookies))

    @property
    def identity_hash(self) -> str:
        return hashlib.sha256(self.device_id.encode("utf-8")).hexdigest()[:12]

    @property
    def cookie_identity(self) -> str:
        """Return a stable, secret-free digest of the context cookies."""
        encoded = json.dumps(dict(self.cookies), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]

    def proof_request(self, endpoint: PaymentEndpoint | str) -> ProofRequest:
        normalized_endpoint = payment_endpoint(endpoint)
        return ProofRequest(
            endpoint=normalized_endpoint,
            flow=flow_for_endpoint(normalized_endpoint),
            payment_provider=self.payment_provider,
            device_id=self.device_id,
            did=self.did,
            user_agent=self.user_agent,
            proxy_route=self.proxy_route,
            session_owner=self.session_owner,
            proof_provider=self.proof_provider,
            cookie_identity=self.cookie_identity,
        )

    def _context_mismatches(self, value: ProofRequest | ProofBundle) -> list[str]:
        mismatches: list[str] = []
        for field_name in (
            "payment_provider",
            "device_id",
            "did",
            "user_agent",
            "proxy_route",
            "session_owner",
            "proof_provider",
        ):
            if getattr(self, field_name) != getattr(value, field_name):
                mismatches.append(field_name)
        return mismatches

    def validate_request(self, request: ProofRequest) -> None:
        mismatches = self._context_mismatches(request)
        if mismatches:
            raise PaymentFlowError(
                "CLIENT_CONTEXT_MISMATCH",
                "proof request differs from Checkout context: " + ", ".join(mismatches),
                phase="proof",
            )
        if request.cookie_identity != self.cookie_identity:
            raise PaymentFlowError(
                "CLIENT_CONTEXT_MISMATCH",
                "proof request cookie identity differs from Checkout context",
                phase="proof",
            )

    def validate_bundle(self, bundle: ProofBundle) -> None:
        mismatches = self._context_mismatches(bundle)
        if mismatches:
            raise PaymentFlowError(
                "CLIENT_CONTEXT_MISMATCH",
                "proof bundle differs from Checkout context: " + ", ".join(mismatches),
                phase="proof",
            )
        if bundle.cookie_identity != self.cookie_identity:
            raise PaymentFlowError(
                "CLIENT_CONTEXT_MISMATCH",
                "proof bundle cookie identity differs from Checkout context",
                phase="proof",
            )


@dataclass(frozen=True, slots=True)
class ProofPolicy:
    payment_provider: str
    require_sentinel_token: bool = True
    require_turnstile_when_challenged: bool = True
    require_session_observer_when_challenged: bool = True
    allow_empty_fallback: bool = False
    allowed_proof_providers: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        provider = _canonical_name(self.payment_provider, "payment_provider")
        allowed = frozenset(
            _canonical_name(name, "allowed_proof_provider")
            for name in self.allowed_proof_providers
        )
        if self.require_sentinel_token and self.allow_empty_fallback:
            raise ValueError("a required Sentinel token cannot allow an empty fallback")
        object.__setattr__(self, "payment_provider", provider)
        object.__setattr__(self, "allowed_proof_providers", allowed)

    @classmethod
    def strict_gopay(
        cls,
        *,
        allowed_proof_providers: frozenset[str] | None = None,
    ) -> "ProofPolicy":
        if allowed_proof_providers is None:
            allowed_proof_providers = frozenset({
                ProofProviderKind.LEGACY_PYTHON_NODE.value,
                ProofProviderKind.SUPPORTED_BROWSER.value,
            })
        return cls(
            payment_provider="gopay",
            require_sentinel_token=True,
            require_turnstile_when_challenged=True,
            require_session_observer_when_challenged=True,
            allow_empty_fallback=False,
            allowed_proof_providers=allowed_proof_providers,
        )

    def validate(
        self,
        context: CheckoutClientContext,
        request: ProofRequest,
        bundle: ProofBundle | None,
    ) -> ProofBundle | None:
        if context.payment_provider != self.payment_provider:
            raise PaymentFlowError(
                "PROOF_POLICY_PROVIDER_MISMATCH",
                "proof policy does not match the Checkout payment provider",
                phase="configuration",
            )
        context.validate_request(request)
        if bundle is None:
            if self.allow_empty_fallback:
                return None
            raise PaymentFlowError(
                "SENTINEL_PROOF_REQUIRED",
                "the payment route requires a Sentinel proof bundle",
                phase="proof",
            )

        context.validate_bundle(bundle)
        if bundle.endpoint != request.endpoint or bundle.flow != request.flow:
            raise PaymentFlowError(
                "PROOF_REQUEST_MISMATCH",
                "proof bundle does not match the requested endpoint and flow",
                phase="proof",
            )
        if (
            self.allowed_proof_providers
            and bundle.proof_provider not in self.allowed_proof_providers
        ):
            raise PaymentFlowError(
                "PROOF_PROVIDER_NOT_ALLOWED",
                "proof provider is not allowed by the payment route policy",
                phase="configuration",
            )
        if self.require_sentinel_token and not bundle.has_sentinel_token:
            raise PaymentFlowError(
                "SENTINEL_PROOF_REQUIRED",
                "the payment route requires a Sentinel token header",
                phase="proof",
            )

        sentinel_payload = bundle.sentinel_payload
        if sentinel_payload is not None:
            self._validate_token_binding(sentinel_payload, request, "Sentinel")
        if (
            bundle.turnstile_required
            and self.require_turnstile_when_challenged
            and not bundle.has_turnstile_proof
        ):
            raise PaymentFlowError(
                "TURNSTILE_PROOF_REQUIRED",
                "the Sentinel challenge required a turnstile proof",
                phase="proof",
            )

        observer_payload = bundle.session_observer_payload
        if observer_payload is not None:
            self._validate_token_binding(observer_payload, request, "session observer")
        if (
            bundle.session_observer_required
            and self.require_session_observer_when_challenged
            and not bundle.has_session_observer_token
        ):
            raise PaymentFlowError(
                "SESSION_OBSERVER_PROOF_REQUIRED",
                "the Sentinel challenge required a session observer proof",
                phase="proof",
            )
        return bundle

    @staticmethod
    def _validate_token_binding(
        payload: Mapping[str, Any],
        request: ProofRequest,
        label: str,
    ) -> None:
        token_flow = str(payload.get("flow") or "").strip()
        token_device = str(payload.get("id") or "").strip()
        if token_flow != request.flow.value or token_device != request.device_id:
            raise PaymentFlowError(
                "PROOF_BINDING_MISMATCH",
                f"{label} token is not bound to the requested flow and device",
                phase="proof",
            )


_DIAGNOSTIC_PHASES = frozenset({
    "checkout_approval_proof",
    "checkout_confirm_proof",
    "checkout_create_proof",
    "checkout_create_result",
    "failure",
    "payment_result",
})
_DIAGNOSTIC_CHECKOUT_TYPES = frozenset({"cs_live", "cs_test", "oaics", "unknown"})
_DIAGNOSTIC_METHOD_SOURCES = frozenset({
    "checkout_response",
    "elements_explicit",
    "elements_explicit_empty",
    "legacy_fallback",
    "merged_initial",
    "stripe_init_explicit",
    "unknown",
})


def payment_diagnostic_event(
    context: CheckoutClientContext,
    *,
    phase: str,
    flow: SentinelFlow | str | None = None,
    sen_present: bool | None = None,
    so_present: bool | None = None,
    checkout_type: str = "",
    payment_method_source: str = "",
    failure: PaymentFlowError | str | None = None,
    elapsed_ms: int | float | None = None,
    proxy_round: int | None = None,
) -> dict[str, Any]:
    """Build a credential-free metric suitable for logs and counters.

    The event intentionally excludes tokens, challenges, cookies, user agents,
    raw proxy routes and Checkout IDs.  Only fixed labels, booleans, counters
    and the one-way device identity summary can cross this boundary.
    """

    normalized_phase = _canonical_name(phase, "phase")
    if normalized_phase not in _DIAGNOSTIC_PHASES:
        normalized_phase = "failure"
    event: dict[str, Any] = {
        "event": "payment_flow",
        "phase": normalized_phase,
        "runtime_type": (
            context.proof_provider
            if context.proof_provider in {
                ProofProviderKind.LEGACY_PYTHON_NODE.value,
                ProofProviderKind.SUPPORTED_BROWSER.value,
            }
            else "custom"
        ),
        "identity": context.identity_hash,
    }
    if flow is not None:
        event["flow"] = sentinel_flow(flow).value
    if sen_present is not None:
        event["sen_present"] = bool(sen_present)
    if so_present is not None:
        event["so_present"] = bool(so_present)
    if checkout_type:
        normalized_checkout = _canonical_name(checkout_type, "checkout_type")
        event["checkout_type"] = (
            normalized_checkout
            if normalized_checkout in _DIAGNOSTIC_CHECKOUT_TYPES
            else "unknown"
        )
    if payment_method_source:
        normalized_source = _canonical_name(payment_method_source, "payment_method_source")
        event["payment_method_source"] = (
            normalized_source
            if normalized_source in _DIAGNOSTIC_METHOD_SOURCES
            else "unknown"
        )
    if failure is not None:
        if isinstance(failure, PaymentFlowError):
            failure_type = failure.code
        else:
            # Free-form exception text can contain access tokens, cookies or
            # proxy credentials. Only typed error codes may cross the metrics
            # boundary; legacy strings are deliberately collapsed.
            failure_type = "UNCLASSIFIED"
        event["failure_type"] = (
            failure_type[:80]
            if re.fullmatch(r"[A-Z0-9_]+", failure_type or "")
            else "UNCLASSIFIED"
        )
    if elapsed_ms is not None:
        event["elapsed_ms"] = max(0, int(float(elapsed_ms)))
    if proxy_round is not None:
        event["proxy_round"] = max(1, int(proxy_round))
    return event


def render_payment_diagnostic_event(
    context: CheckoutClientContext,
    **kwargs: Any,
) -> str:
    return "[payment-diagnostic] " + json.dumps(
        payment_diagnostic_event(context, **kwargs),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


__all__ = [
    "CallableSentinelProofProvider",
    "CheckoutClientContext",
    "ENDPOINT_FLOW",
    "PaymentEndpoint",
    "PaymentFlowError",
    "ProofBundle",
    "ProofPolicy",
    "ProofProviderKind",
    "ProofRequest",
    "SentinelFlow",
    "SentinelProofProvider",
    "flow_for_endpoint",
    "payment_endpoint",
    "payment_diagnostic_event",
    "render_payment_diagnostic_event",
    "sentinel_flow",
]
