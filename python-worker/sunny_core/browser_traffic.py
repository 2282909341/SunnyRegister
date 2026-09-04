from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


_CURRENT_METER: contextvars.ContextVar["ProxyTrafficMeter | None"] = contextvars.ContextVar(
    "sunny_proxy_traffic_meter", default=None
)
_HTTP_HOOK_SUSPENDED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "sunny_http_traffic_hook_suspended", default=False
)
_HOOKS_LOCK = threading.Lock()
_CACHE_LOCK = threading.Lock()
_HOOKS_INSTALLED = False


def _byte_count(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, (dict, list, tuple)):
        try:
            return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        except Exception:
            pass
    return len(str(value).encode("utf-8"))


def _headers_bytes(headers: Any) -> int:
    if not headers:
        return 0
    try:
        return sum(len(str(k).encode()) + len(str(v).encode()) + 4 for k, v in headers.items()) + 2
    except Exception:
        return 0


def _declared_body_bytes(headers: Any) -> int | None:
    headers = headers or {}
    content_length = str(headers.get("content-length") or headers.get("Content-Length") or "").strip()
    if content_length.isdigit():
        return int(content_length)
    return None


def _response_body_bytes(response: Any) -> int:
    declared = _declared_body_bytes(getattr(response, "headers", {}) or {})
    if declared is not None:
        return declared
    try:
        return len(response.content or b"")
    except Exception:
        return 0


def _host_matches(host: str, suffixes: set[str] | tuple[str, ...]) -> bool:
    normalized = str(host or "").strip(".").lower()
    return any(normalized == suffix or normalized.endswith("." + suffix) for suffix in suffixes)


def _top_breakdown(values: dict[str, dict[str, int]], limit: int = 12) -> dict[str, dict[str, int]]:
    ranked = sorted(values.items(), key=lambda item: (item[1].get("bytes", 0), item[1].get("requests", 0)), reverse=True)
    return {key: dict(details) for key, details in ranked[:limit]}


def _proxy_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(item or "") for item in value.values()]
    return []


@dataclass
class ProxyTrafficMeter:
    """Account application-layer bytes sent through one selected proxy pool entry."""

    proxy_url: str = ""
    tracked_proxy: bool = False
    email: str = ""
    operation: str = ""
    requests: int = 0
    request_header_bytes: int = 0
    request_body_bytes: int = 0
    response_header_bytes: int = 0
    response_body_bytes: int = 0
    by_phase: dict[str, int] = field(default_factory=dict)
    by_kind: dict[str, int] = field(default_factory=dict)
    by_host: dict[str, dict[str, int]] = field(default_factory=dict)
    by_path: dict[str, dict[str, int]] = field(default_factory=dict)
    _phase: str = "initial"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_phase(self, phase: str) -> None:
        self._phase = str(phase or "initial")

    def matches_proxy(self, proxy: Any) -> bool:
        if not self.tracked_proxy or not self.proxy_url:
            return False
        target = self.proxy_url.rstrip("/")
        return any(str(value or "").rstrip("/") == target for value in _proxy_values(proxy))

    def record(
        self,
        method: str,
        url: str,
        request_headers: Any = None,
        request_body: Any = None,
        response_status: int = 0,
        response_headers: Any = None,
        response_body_bytes: int = 0,
        kind: str = "http",
    ) -> None:
        if not self.tracked_proxy:
            return
        parsed = urlsplit(str(url or ""))
        target = f"{parsed.path or '/'}{('?' + parsed.query) if parsed.query else ''}"
        host = (parsed.hostname or "unknown").lower()
        path_key = f"{host}{parsed.path or '/'}"
        req_headers = len(f"{str(method or 'GET').upper()} {target} HTTP/1.1\r\n".encode()) + _headers_bytes(request_headers)
        req_body = _byte_count(request_body)
        resp_headers = len(f"HTTP/1.1 {int(response_status or 0):03d}\r\n".encode()) + _headers_bytes(response_headers)
        total = req_headers + req_body + resp_headers + max(0, int(response_body_bytes or 0))
        with self._lock:
            self.requests += 1
            self.request_header_bytes += req_headers
            self.request_body_bytes += req_body
            self.response_header_bytes += resp_headers
            self.response_body_bytes += max(0, int(response_body_bytes or 0))
            self.by_phase[self._phase] = self.by_phase.get(self._phase, 0) + total
            self.by_kind[kind] = self.by_kind.get(kind, 0) + total
            for bucket, key in ((self.by_host, host), (self.by_path, path_key)):
                details = bucket.setdefault(key, {"bytes": 0, "requests": 0})
                details["bytes"] += total
                details["requests"] += 1

    def snapshot(self) -> dict[str, Any]:
        total = self.request_header_bytes + self.request_body_bytes + self.response_header_bytes + self.response_body_bytes
        return {
            "measurement": "estimated_http_application_bytes_excluding_tls_tcp_overhead",
            "tracked_proxy": bool(self.tracked_proxy),
            "proxy": self.proxy_url,
            "operation": self.operation,
            "requests": self.requests,
            "request_header_bytes": self.request_header_bytes,
            "request_body_bytes": self.request_body_bytes,
            "response_header_bytes": self.response_header_bytes,
            "response_body_bytes": self.response_body_bytes,
            "total_bytes": total,
            "by_phase": dict(self.by_phase),
            "by_kind": dict(self.by_kind),
            "by_host": _top_breakdown(self.by_host),
            "by_path": _top_breakdown(self.by_path),
        }


@contextlib.contextmanager
def use_traffic_meter(meter: ProxyTrafficMeter) -> Iterator[ProxyTrafficMeter]:
    install_http_hooks()
    token = _CURRENT_METER.set(meter)
    try:
        yield meter
    finally:
        _CURRENT_METER.reset(token)


def current_traffic_meter() -> ProxyTrafficMeter | None:
    return _CURRENT_METER.get()


@contextlib.contextmanager
def suspend_http_traffic_hook() -> Iterator[None]:
    token = _HTTP_HOOK_SUSPENDED.set(True)
    try:
        yield
    finally:
        _HTTP_HOOK_SUSPENDED.reset(token)


def _hooked_request(original, session, method: str, url: str, kwargs: dict[str, Any]):
    response = original(session, method, url, **kwargs)
    if _HTTP_HOOK_SUSPENDED.get():
        return response
    meter = current_traffic_meter()
    proxy = kwargs.get("proxies") or getattr(session, "proxies", None)
    if meter and meter.matches_proxy(proxy):
        headers = dict(getattr(session, "headers", {}) or {})
        headers.update(dict(kwargs.get("headers") or {}))
        meter.record(
            method,
            str(getattr(response, "url", "") or url),
            headers,
            kwargs.get("data") if kwargs.get("data") is not None else kwargs.get("json"),
            int(getattr(response, "status_code", 0) or 0),
            getattr(response, "headers", None),
            _response_body_bytes(response),
            "http",
        )
    return response


def _make_session_request_hook(original):
    """Bind one library's original method without late-binding another hook."""
    def request(session, method, url, **kwargs):
        return _hooked_request(original, session, method, url, kwargs)

    request._sunny_traffic_hook = True
    return request


def install_http_hooks() -> None:
    global _HOOKS_INSTALLED
    if _HOOKS_INSTALLED:
        return
    with _HOOKS_LOCK:
        if _HOOKS_INSTALLED:
            return
        try:
            import requests.sessions

            requests_original = requests.sessions.Session.request
            if not getattr(requests_original, "_sunny_traffic_hook", False):
                requests.sessions.Session.request = _make_session_request_hook(requests_original)
        except Exception:
            pass
        try:
            from curl_cffi import requests as curl_requests

            curl_original = curl_requests.Session.request
            if not getattr(curl_original, "_sunny_traffic_hook", False):
                curl_requests.Session.request = _make_session_request_hook(curl_original)
        except Exception:
            pass
        _HOOKS_INSTALLED = True


@dataclass
class BrowserTrafficConfig:
    enabled: bool = True
    block_heavy_resources: bool = True
    static_cache_enabled: bool = True
    cache_ttl_hours: int = 168
    cache_max_mib: int = 256
    cache_object_max_mib: int = 8

    @classmethod
    def from_value(cls, value: Any) -> "BrowserTrafficConfig":
        raw = value if isinstance(value, dict) else {}
        return cls(
            enabled=raw.get("enabled") is not False,
            block_heavy_resources=raw.get("block_heavy_resources") is not False,
            static_cache_enabled=raw.get("static_cache_enabled") is not False,
            cache_ttl_hours=max(1, min(int(raw.get("cache_ttl_hours") or 168), 168)),
            cache_max_mib=max(16, min(int(raw.get("cache_max_mib") or 256), 2048)),
            cache_object_max_mib=max(1, min(int(raw.get("cache_object_max_mib") or 8), 32)),
        )


class BrowserTrafficOptimizer:
    _security_suffixes = {
        "arkose.com", "arkoselabs.com", "challenges.cloudflare.com", "hcaptcha.com",
        "recaptcha.com", "recaptcha.net", "sentinel.openai.com",
    }
    _static_suffixes = {"auth.openai.com", "chatgpt.com", "cdn.openai.com", "oaistatic.com"}
    _telemetry_suffixes = {
        "browser-intake-datadoghq.com", "datadoghq.com", "featuregates.org",
        "segment.com", "segment.io", "sentry.io", "statsigapi.net",
    }
    _heavy_types = {"image", "font", "media", "manifest"}
    _telemetry_markers = ("/telemetry", "/analytics", "/rum", "/events")
    _service_worker_names = {"service-worker.js", "service_worker.js", "sw.js"}
    _session_paths = (
        "/api/auth/callback/",
        "/api/auth/csrf",
        "/api/auth/session",
        "/api/accounts/check",
        "/backend-api/accounts/check",
        "/backend-api/accounts/mfa_info",
    )

    def __init__(self, meter: ProxyTrafficMeter, config: BrowserTrafficConfig | dict[str, Any] | None = None):
        self.meter = meter
        self.config = config if isinstance(config, BrowserTrafficConfig) else BrowserTrafficConfig.from_value(config)
        self.session_only = False
        configured_cache = str(os.getenv("SUNNY_BROWSER_CACHE_DIR") or "").strip()
        if configured_cache:
            self._cache_dir = Path(configured_cache)
        elif os.getenv("SUNNY_CONTAINERIZED", "").strip().lower() in {"1", "true", "yes", "on"}:
            self._cache_dir = Path("/app/data/browser-static-cache")
        else:
            self._cache_dir = Path(tempfile.gettempdir()) / "sunnyregister-browser-static"
        self._cache_lock = _CACHE_LOCK
        self._handlers: list[tuple[Any, Any]] = []
        self._response_listeners: list[tuple[Any, Any]] = []
        self._handled_browser_requests: set[int] = set()
        self.blocked = 0
        self.blocked_by_reason: dict[str, int] = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_saved_bytes = 0
        self.cache_write_errors = 0

    def attach(self, context: Any) -> None:
        if not self.config.enabled:
            return

        def handle(route: Any) -> None:
            request = route.request
            url = str(getattr(request, "url", "") or "")
            kind = str(getattr(request, "resource_type", "") or "")
            method = str(getattr(request, "method", "GET") or "GET").upper()
            reason = self._block_reason(url, kind, method)
            if reason:
                try:
                    route.abort("blockedbyclient")
                    self.blocked += 1
                    self.blocked_by_reason[reason] = self.blocked_by_reason.get(reason, 0) + 1
                    return
                except Exception:
                    pass
            if self._cacheable(url, kind, method, getattr(request, "headers", {})) and self.config.static_cache_enabled:
                request_id = id(request)
                self._handled_browser_requests.add(request_id)
                if self._fulfill_cache(route, url):
                    return
                self._handled_browser_requests.discard(request_id)
                self.cache_misses += 1
                try:
                    self._handled_browser_requests.add(request_id)
                    response = route.fetch()
                    body = response.body()
                    headers = dict(response.headers or {})
                    declared = _declared_body_bytes(headers)
                    network_body_bytes = declared if declared is not None else len(body)
                    self.meter.record(method, url, getattr(request, "headers", {}), getattr(request, "post_data", None), response.status, headers, network_body_bytes, "browser")
                    self._store_cache(url, response.status, headers, body, network_body_bytes)
                    route.fulfill(response=response)
                    return
                except Exception:
                    self._handled_browser_requests.discard(request_id)
                    # The optimizer must never turn a browser request failure into a registration failure.
                    try:
                        route.continue_()
                    except Exception:
                        pass
                    return
            try:
                route.continue_()
            except Exception:
                pass

        try:
            context.route("**/*", handle)
        except Exception:
            self.cache_write_errors += 1
            return
        self._handlers.append((context, handle))

        def on_response(response: Any) -> None:
            request = getattr(response, "request", None)
            if request is None or id(request) in self._handled_browser_requests:
                if request is not None:
                    self._handled_browser_requests.discard(id(request))
                return
            try:
                headers = dict(response.headers or {})
                content_length = str(headers.get("content-length") or "").strip()
                body_length = int(content_length) if content_length.isdigit() else len(response.body())
                self.meter.record(
                    str(getattr(request, "method", "GET") or "GET"),
                    str(getattr(response, "url", "") or getattr(request, "url", "")),
                    getattr(request, "headers", {}),
                    getattr(request, "post_data", None),
                    int(getattr(response, "status", 0) or 0),
                    headers,
                    body_length,
                    "browser",
                )
            except Exception:
                pass

        try:
            context.on("response", on_response)
            self._response_listeners.append((context, on_response))
        except Exception:
            pass

    def activate_session_only(self) -> None:
        self.session_only = True
        self.meter.set_phase("session_only")

    def detach(self) -> None:
        for context, handler in self._handlers:
            try:
                context.unroute("**/*", handler)
            except Exception:
                pass
        self._handlers.clear()
        for context, listener in self._response_listeners:
            try:
                context.remove_listener("response", listener)
            except Exception:
                pass
        self._response_listeners.clear()
        self._handled_browser_requests.clear()

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "blocked": self.blocked,
            "blocked_by_reason": dict(self.blocked_by_reason),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_saved_bytes": self.cache_saved_bytes,
            "cache_write_errors": self.cache_write_errors,
            "cache_dir": str(self._cache_dir),
            "session_only": self.session_only,
        }

    def _should_block(self, url: str, resource_type: str, method: str) -> bool:
        return bool(self._block_reason(url, resource_type, method))

    def _block_reason(self, url: str, resource_type: str, method: str) -> str:
        if not self.config.block_heavy_resources:
            return ""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path.lower()
        if self._is_security(url):
            return ""
        if _host_matches(host, self._telemetry_suffixes) or any(marker in path for marker in self._telemetry_markers):
            return "telemetry"
        if method != "GET":
            return ""
        if resource_type in self._heavy_types:
            return resource_type
        if not self.session_only and _host_matches(host, {"chatgpt.com"}) and resource_type in {"script", "stylesheet"}:
            # The pre-auth landing only needs the response headers (Next-auth
            # CSRF / device cookies). The chatgpt.com SPA bundles are never
            # used: CSRF and sign-in run through API requests. Downloading
            # them costs multiple MB per registration. cdn.openai.com and
            # oaistatic.com stay untouched because the auth.openai.com forms
            # load their scripts from them.
            return f"pre_auth_{resource_type or 'other'}"

        if self.session_only and _host_matches(host, {"chatgpt.com"}):
            if resource_type == "document" or path.startswith(self._session_paths):
                return ""
            return f"post_auth_{resource_type or 'other'}"
        if self.session_only and _host_matches(host, {"auth.openai.com"}):
            # The post-registration LS flow only needs the auth document and
            # its static shell. Its GET/XHR bootstrap data is not needed after
            # the browser has already established the account session.
            if resource_type in {"document", "script", "stylesheet"}:
                return ""
            return f"post_auth_{resource_type or 'other'}"
        return ""

    def _is_security(self, url: str) -> bool:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path.lower()
        return (
            _host_matches(host, self._security_suffixes)
            or any(marker in host for marker in ("arkose", "hcaptcha", "recaptcha"))
            or "/cdn-cgi/challenge-platform/" in path
            or "/sentinel/" in path
            or "/recaptcha/" in path
            or "turnstile" in path
        )

    def _cacheable(self, url: str, resource_type: str, method: str, request_headers: Any = None) -> bool:
        parts = urlsplit(url)
        headers = {str(key).lower() for key in (request_headers or {})}
        path_name = Path(parts.path.lower()).name
        return (
            method == "GET"
            and _host_matches((parts.hostname or "").lower(), self._static_suffixes)
            and resource_type in {"script", "stylesheet"}
            and not self._is_security(url)
            and path_name not in self._service_worker_names
            and "authorization" not in headers
        )

    def _cache_key(self, url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def _cache_paths(self, url: str) -> tuple[Path, Path]:
        key = self._cache_key(url)
        return self._cache_dir / f"{key}.body", self._cache_dir / f"{key}.json"

    def _fulfill_cache(self, route: Any, url: str) -> bool:
        body_path, meta_path = self._cache_paths(url)
        try:
            with self._cache_lock:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                created_at = float(meta.get("created_at", 0))
                expires_at = float(meta.get("expires_at") or (created_at + self.config.cache_ttl_hours * 3600))
                if time.time() > expires_at:
                    return False
                body = body_path.read_bytes()
            headers = {str(key).lower(): str(value) for key, value in dict(meta.get("headers") or {}).items()}
            for key in ("content-encoding", "content-length", "transfer-encoding", "set-cookie"):
                headers.pop(key, None)
            route.fulfill(status=int(meta.get("status", 200)), headers=headers, body=body)
            self.cache_hits += 1
            self.cache_saved_bytes += max(0, int(meta.get("network_body_bytes") or len(body)))
            return True
        except Exception:
            return False

    def _store_cache(self, url: str, status: int, headers: dict[str, Any], body: bytes, network_body_bytes: int | None = None) -> None:
        if status != 200 or len(body) > self.config.cache_object_max_mib * 1024 * 1024:
            return
        lower = {str(k).lower(): str(v) for k, v in headers.items()}
        cache_control = lower.get("cache-control", "").lower()
        content_type = lower.get("content-type", "").lower()
        vary = lower.get("vary", "").lower()
        max_age = re.search(r"(?:s-maxage|max-age)=(\d+)", cache_control)
        publicly_cacheable = "immutable" in cache_control or (max_age is not None and int(max_age.group(1)) > 0)
        if (
            "set-cookie" in lower
            or "private" in cache_control
            or "no-store" in cache_control
            or "no-cache" in cache_control
            or "cookie" in vary
            or "authorization" in vary
            or not publicly_cacheable
            or not any(marker in content_type for marker in ("javascript", "ecmascript", "text/css"))
        ):
            return
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            body_path, meta_path = self._cache_paths(url)
            with self._cache_lock:
                created_at = time.time()
                configured_ttl = self.config.cache_ttl_hours * 3600
                origin_ttl = int(max_age.group(1)) if max_age is not None else configured_ttl
                tmp_body = body_path.with_name(body_path.name + ".tmp")
                tmp_meta = meta_path.with_name(meta_path.name + ".tmp")
                tmp_body.write_bytes(body)
                cache_headers = {
                    str(k).lower(): str(v)
                    for k, v in headers.items()
                    if str(k).lower() not in {"content-encoding", "content-length", "transfer-encoding", "set-cookie"}
                }
                tmp_meta.write_text(
                    json.dumps(
                        {
                            "created_at": created_at,
                            "expires_at": created_at + min(configured_ttl, origin_ttl),
                            "status": status,
                            "headers": cache_headers,
                            "network_body_bytes": max(0, int(network_body_bytes if network_body_bytes is not None else len(body))),
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                tmp_body.replace(body_path)
                tmp_meta.replace(meta_path)
                self._prune_cache()
        except Exception:
            self.cache_write_errors += 1

    def _prune_cache(self) -> None:
        limit = self.config.cache_max_mib * 1024 * 1024
        entries: list[tuple[float, int, Path, Path]] = []
        total = 0
        for body_path in self._cache_dir.glob("*.body"):
            meta_path = body_path.with_suffix(".json")
            try:
                size = body_path.stat().st_size
                entries.append((body_path.stat().st_mtime, size, body_path, meta_path))
                total += size
            except OSError:
                continue
        if total <= limit:
            return
        for _, size, body_path, meta_path in sorted(entries):
            if total <= limit:
                break
            try:
                body_path.unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)
                total -= size
            except OSError:
                pass
