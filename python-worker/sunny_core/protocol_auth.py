from __future__ import annotations

import json
import os
import random
import re
import secrets
import string
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import unquote, urlencode, urlsplit

from .auth_challenges import generate_totp
from .browser_traffic import ProxyTrafficMeter, _response_body_bytes, suspend_http_traffic_hook
from .mailbox import MailAccount, create_mailbox_reader
from .proxy import normalize_proxy_url
from .sentinel import (
    SENTINEL_FRAME_URL,
    SENTINEL_REQ_URL,
    SentinelBrowserRuntime,
    SentinelNodeRuntime,
    SentinelTokenGenerator,
    generate_datadog_trace_headers,
)


AUTH_BASE_URL = "https://auth.openai.com"
CHATGPT_BASE_URL = "https://chatgpt.com"
AUTHORIZE_CONTINUE_URL = f"{AUTH_BASE_URL}/api/accounts/authorize/continue"
REGISTER_PASSWORD_URL = f"{AUTH_BASE_URL}/api/accounts/user/register"
SEND_EMAIL_OTP_URL = f"{AUTH_BASE_URL}/api/accounts/email-otp/send"
VALIDATE_EMAIL_OTP_URL = f"{AUTH_BASE_URL}/api/accounts/email-otp/validate"
CREATE_ACCOUNT_URL = f"{AUTH_BASE_URL}/api/accounts/create_account"
EMAIL_OTP_INITIAL_WAIT_SECONDS = 120
EMAIL_OTP_RESEND_WAIT_SECONDS = 60
_EMAIL_OTP_TIMEOUT_MARKERS = (
    "email otp", "email verification", "email-otp", "邮箱验证码", "协议验证码",
    "openai 邮箱验证码", "openai email code", "重新发送验证码",
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)
_TRANSIENT_TRANSPORT_MARKERS = (
    "curl: (35)",
    "curl: (56)",
    "curl: (28)",
    "connection reset",
    "recv failure",
    "connection aborted",
    "connection refused",
    "ssl connect error",
    "tls handshake",
    "timed out",
)
_ACCOUNT_DEACTIVATED_MARKERS = (
    "account_deactivated", "account disabled", "account has been disabled",
    "account deactivated", "account has been deactivated", "deleted or deactivated",
    "account suspended", "account has been suspended", "account is suspended",
    "account banned", "account has been banned", "account is banned", "account blocked",
    "account is disabled", "account is deactivated",
    "账户已停用", "账户被禁用", "账户已被禁用", "账户已禁用", "账号已封禁", "账号被封禁",
    "账号已被封禁", "账号已被禁用", "账户已封禁", "账户被暂停", "账户已被暂停", "アカウントが無効", "アカウントは無効",
    "アカウントが停止", "アカウントは停止", "利用停止", "계정이 비활성화",
    "계정이 정지", "계정이 차단",
)


class ProtocolRegistrationError(RuntimeError):
    pass


class ProtocolChallengeRequired(ProtocolRegistrationError):
    pass


class ProtocolLoginSecretRejected(ProtocolRegistrationError):
    """The configured ChatGPT password/TOTP was rejected by the auth flow."""


def _is_login_secret_rejection(error: BaseException) -> bool:
    if isinstance(error, ProtocolChallengeRequired) or _is_transient_transport_error(error):
        return False
    message = str(error or "").lower()
    if "account_deactivated" in message or "deleted or deactivated" in message:
        return False
    return any(marker in message for marker in ("http 400", "http 401", "http 422", "invalid", "incorrect", "wrong"))


def _is_email_otp_timeout(error: Any) -> bool:
    """Return true only for mailbox OTP timeouts, not generic auth timeouts."""
    if not isinstance(error, TimeoutError):
        return False
    message = str(error or "").strip().lower()
    return any(marker in message for marker in _EMAIL_OTP_TIMEOUT_MARKERS)


def _is_account_deactivated_payload(value: Any) -> bool:
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        text = str(value or "")
    text = text.strip().lower()
    return any(marker in text for marker in _ACCOUNT_DEACTIVATED_MARKERS)


@dataclass
class ProtocolTrafficMeter:
    requests: int = 0
    request_header_bytes: int = 0
    request_body_bytes: int = 0
    response_header_bytes: int = 0
    response_body_bytes: int = 0

    @staticmethod
    def _header_bytes(headers: Any) -> int:
        if not headers:
            return 0
        try:
            return sum(len(str(key).encode("utf-8")) + len(str(value).encode("utf-8")) + 4 for key, value in headers.items()) + 2
        except Exception:
            return 0

    @staticmethod
    def _body_bytes(kwargs: dict[str, Any]) -> int:
        value = kwargs.get("data")
        if value is None and kwargs.get("json") is not None:
            value = json.dumps(kwargs["json"], separators=(",", ":"), ensure_ascii=False)
        if value is None:
            return 0
        if isinstance(value, bytes):
            return len(value)
        if isinstance(value, str):
            return len(value.encode("utf-8"))
        if isinstance(value, dict):
            return len(urlencode(value, doseq=True).encode("utf-8"))
        return len(str(value).encode("utf-8"))

    def record(self, method: str, url: str, request_headers: Any, kwargs: dict[str, Any], response: Any) -> None:
        self.requests += 1
        request_target = urlsplit(url)
        path = request_target.path or "/"
        if request_target.query:
            path = f"{path}?{request_target.query}"
        self.request_header_bytes += len(f"{method.upper()} {path} HTTP/1.1\r\n".encode("utf-8")) + self._header_bytes(request_headers)
        self.request_body_bytes += self._body_bytes(kwargs)
        response_headers = getattr(response, "headers", None)
        status_code = int(getattr(response, "status_code", 0) or 0)
        self.response_header_bytes += len(f"HTTP/1.1 {status_code:03d}\r\n".encode("ascii")) + self._header_bytes(response_headers)
        content_length = ""
        try:
            content_length = str((response_headers or {}).get("content-length") or "").strip()
        except Exception:
            pass
        if content_length.isdigit():
            self.response_body_bytes += int(content_length)
        else:
            content = getattr(response, "content", b"")
            if isinstance(content, bytes):
                self.response_body_bytes += len(content)
            else:
                self.response_body_bytes += len(str(content or "").encode("utf-8"))

    def snapshot(self) -> dict[str, int | str]:
        total = self.request_header_bytes + self.request_body_bytes + self.response_header_bytes + self.response_body_bytes
        return {
            "measurement": "estimated_http_application_bytes_excluding_tls_tcp_overhead",
            "requests": self.requests,
            "request_header_bytes": self.request_header_bytes,
            "request_body_bytes": self.request_body_bytes,
            "response_header_bytes": self.response_header_bytes,
            "response_body_bytes": self.response_body_bytes,
            "total_bytes": total,
        }


def _json_response(response, step: str) -> dict[str, Any]:
    try:
        payload = response.json()
    except Exception as exc:
        body = str(getattr(response, "text", "") or "")[:500]
        raise ProtocolRegistrationError(f"{step} returned non-JSON content: {body}") from exc
    if not isinstance(payload, dict):
        raise ProtocolRegistrationError(f"{step} returned an invalid JSON object")
    return payload


def _response_error(response, step: str) -> ProtocolRegistrationError:
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")[:800]
    marker = body.lower()
    if _is_account_deactivated_payload(body):
        return ProtocolRegistrationError(f"account_deactivated: {step} reported that the account is disabled: {body}")
    if status in {403, 429} or any(value in marker for value in ("cloudflare", "challenge", "turnstile", "captcha")):
        return ProtocolChallengeRequired(
            f"{step} requires an interactive anti-bot challenge (HTTP {status}); "
            "the upstream HTML challenge page was omitted"
        )
    return ProtocolRegistrationError(f"{step} failed (HTTP {status}): {body}")


def _is_transient_transport_error(error: BaseException) -> bool:
    message = str(error or "").lower()
    return any(marker in message for marker in _TRANSIENT_TRANSPORT_MARKERS)


class _ProtocolCallbackSession:
    """Expose the active protocol request path to post-registration steps."""

    def __init__(self, flow: "ProtocolRegistrationFlow"):
        self._flow = flow

    def request(self, method: str, url: str, **kwargs):
        path = urlsplit(str(url)).path or "/"
        return self._flow._request(method, url, step=f"Post-registration {path}", **kwargs)

    def refresh_session_with_login_secret(self) -> dict[str, Any]:
        return self._flow._refresh_session_with_login_secret()


class ProtocolRegistrationFlow:
    """ChatGPT email registration/login through HTTP requests only.

    The flow owns one TLS-impersonated cookie jar for the complete account
    lifecycle. It never starts Playwright, Chromium, or Camoufox.
    """

    def __init__(
        self,
        account: MailAccount,
        proxy_url: str = "",
        log: Callable[[str], None] | None = None,
        *,
        existing_account: bool = False,
        should_cancel: Callable[[], bool] | None = None,
        on_progress: Callable[[str, dict[str, Any]], None] | None = None,
        session: Any | None = None,
        challenge_strategy: str = "native_headless",
        mailbox_proxy_url: str | None = None,
        traffic_meter: ProxyTrafficMeter | None = None,
        post_registration_callback: Callable[[Any, dict[str, Any]], dict[str, Any] | None] | None = None,
        keep_session: bool = False,
        skip_mailbox: bool = False,
    ):
        self.account = account
        self.proxy_url = normalize_proxy_url(proxy_url)
        self.mailbox_proxy_url = self.proxy_url if mailbox_proxy_url is None else normalize_proxy_url(mailbox_proxy_url)
        self.log = log or (lambda _message: None)
        self.existing_account = existing_account
        self.should_cancel = should_cancel or (lambda: False)
        self.on_progress = on_progress
        self.session = session
        self.reader: Any | None = None
        self.device_id = ""
        self.auth_url = ""
        self.auth_page_url = ""
        self.browser_resume_url = ""
        self.auth_action = "login" if existing_account else "unknown"
        self.generated_password = ""
        self.recent_email_code = ""
        self.recent_email_code_at = 0.0
        self.email_verified = False
        self.traffic = ProtocolTrafficMeter()
        self.traffic_meter = traffic_meter
        self.post_registration_callback = post_registration_callback
        self.keep_session = keep_session
        self.skip_mailbox = skip_mailbox
        self.challenge_strategy = (
            challenge_strategy if challenge_strategy in {"native_headless", "sentinel_protocol"} else "native_headless"
        )
        self._sentinel_runtime: SentinelBrowserRuntime | SentinelNodeRuntime | None = None

    def _check_cancelled(self) -> None:
        if self.should_cancel():
            from .openai_auth import TaskCancelledError

            raise TaskCancelledError("Task cancelled by user")

    def _needs_mailbox_reader(self) -> bool:
        """Return whether this auth attempt may need an email OTP reader."""
        return (
            not self.skip_mailbox
            and (not self.existing_account or not self.account.has_chatgpt_password)
            and not (
                self.account.mailbox_type == "apple"
                and self.account.mailbox_channel == "url_api"
                and not self.account.access_key
            )
        )

    def _emit(self, checkpoint: str, data: dict[str, Any] | None = None) -> None:
        if self.on_progress:
            self.on_progress(checkpoint, dict(data or {}))

    def _new_session(self):
        try:
            from curl_cffi import requests as curl_requests
        except Exception as exc:
            raise ProtocolRegistrationError(
                "Protocol mode requires curl_cffi; reinstall python-worker dependencies"
            ) from exc
        proxies = {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        session = curl_requests.Session(
            impersonate="chrome136",
            proxies=proxies,
            timeout=30,
        )
        session.headers.update(
            {
                "user-agent": USER_AGENT,
                "accept-language": "ja-JP,ja;q=0.9,en;q=0.7",
                "accept-encoding": "gzip, deflate, br",
            }
        )
        return session

    def _request(self, method: str, url: str, *, step: str, **kwargs):
        self._check_cancelled()
        kwargs.setdefault("timeout", 30)
        response = None
        for attempt in range(3):
            try:
                if self.traffic_meter is None:
                    response = self.session.request(method, url, **kwargs)
                else:
                    with suspend_http_traffic_hook():
                        response = self.session.request(method, url, **kwargs)
                break
            except Exception as exc:
                if (
                    attempt < 2
                    and method.upper() in {"GET", "HEAD", "OPTIONS"}
                    and _is_transient_transport_error(exc)
                ):
                    self.log(f"[协议] {step} 遇到临时网络错误，正在重试 ({attempt + 1}/2)")
                    time.sleep(0.35 * (attempt + 1))
                    self._check_cancelled()
                    continue
                error = ProtocolRegistrationError(f"{step} request failed: {exc}")
                error.traffic = self.traffic.snapshot()
                raise error from exc
        if response is None:
            error = ProtocolRegistrationError(f"{step} request failed: empty response")
            error.traffic = self.traffic.snapshot()
            raise error
        request_headers = dict(getattr(self.session, "headers", {}) or {})
        request_headers.update(dict(kwargs.get("headers") or {}))
        self.traffic.record(method, url, request_headers, kwargs, response)
        if self.traffic_meter is not None:
            request_body = kwargs.get("data") if kwargs.get("data") is not None else kwargs.get("json")
            self.traffic_meter.record(
                method,
                str(getattr(response, "url", "") or url),
                request_headers,
                request_body,
                int(getattr(response, "status_code", 0) or 0),
                getattr(response, "headers", None),
                _response_body_bytes(response),
                "protocol_http",
            )
        if os.environ.get("SUNNY_PROTOCOL_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}:
            response_url = str(getattr(response, "url", "") or url)
            parsed = urlsplit(response_url)
            cookie_names: set[str] = set()
            try:
                cookie_names = {str(cookie.name) for cookie in self.session.cookies.jar if getattr(cookie, "name", "")}
            except Exception:
                pass
            self.log(
                f"[协议] {step}: HTTP {getattr(response, 'status_code', 0)} "
                f"{parsed.scheme}://{parsed.netloc}{parsed.path} cookies={','.join(sorted(cookie_names)) or '-'}"
            )
        self._check_cancelled()
        return response

    def _cookie(self, name: str) -> str:
        try:
            value = self.session.cookies.get(name)
            return str(value or "")
        except Exception:
            try:
                for cookie in self.session.cookies.jar:
                    if getattr(cookie, "name", "") == name:
                        return str(getattr(cookie, "value", "") or "")
            except Exception:
                pass
        return ""

    def _browser_handoff_snapshot(self, challenge_flow: str = "") -> dict[str, Any]:
        resume_by_flow = {
            "authorize_continue": f"{AUTH_BASE_URL}/{'log-in' if self.existing_account else 'create-account'}",
            "username_password_create": f"{AUTH_BASE_URL}/create-account/password",
            "password_verify": self.browser_resume_url or self.auth_page_url,
            "oauth_create_account": f"{AUTH_BASE_URL}/about-you",
        }
        resume_url = str(resume_by_flow.get(challenge_flow) or self.browser_resume_url or self.auth_page_url or self.auth_url)
        cookies: list[dict[str, Any]] = []
        try:
            for item in self.session.cookies.jar:
                cookie: dict[str, Any] = {
                    "name": str(item.name),
                    "value": str(item.value),
                    "path": str(getattr(item, "path", "") or "/"),
                    "secure": bool(getattr(item, "secure", False)),
                }
                domain = str(getattr(item, "domain", "") or "").strip()
                if domain:
                    cookie["domain"] = domain
                else:
                    cookie["url"] = AUTH_BASE_URL
                cookies.append(cookie)
        except Exception:
            cookies = []
        return {
            "protocol_browser_handoff": True,
            "protocol_resume_url": resume_url,
            "protocol_challenge_flow": challenge_flow,
            "protocol_email_verified": self.email_verified,
            "storage_state_json": {"cookies": cookies, "origins": []},
            "auth_action": self.auth_action,
            "generated_chatgpt_password": self.generated_password,
            "protocol_traffic": self.traffic.snapshot(),
        }

    def _reset_sentinel_runtime(self) -> None:
        runtime = self._sentinel_runtime
        self._sentinel_runtime = None
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass

    def _sentinel_headers(self, flow: str) -> dict[str, str]:
        """Build Sentinel headers, refreshing the narrow browser runtime once."""
        # A fresh proof is single-use. Three bounded attempts tolerate a
        # transient challenge/runtime failure without looping indefinitely.
        attempts = 3 if self.challenge_strategy == "sentinel_protocol" else 1
        last_error: BaseException | None = None
        for attempt in range(attempts):
            try:
                return self._sentinel_headers_once(flow)
            except ProtocolChallengeRequired as exc:
                last_error = exc
                if attempt + 1 >= attempts or self.should_cancel():
                    raise
                self.log(f"[认证] Sentinel {flow} 证明生成/校验失败，刷新运行时重试 ({attempt + 1}/{attempts - 1})")
                self._reset_sentinel_runtime()
            except Exception as exc:
                last_error = exc
                if attempt + 1 >= attempts or self.should_cancel():
                    raise
                self.log(f"[认证] Sentinel {flow} 运行时异常，刷新运行时重试 ({attempt + 1}/{attempts - 1})")
                self._reset_sentinel_runtime()
        if last_error is not None:
            raise last_error
        raise ProtocolChallengeRequired(f"Sentinel {flow} 未能生成有效证明")

    def _sentinel_headers_once(self, flow: str) -> dict[str, str]:
        self._check_cancelled()
        generator = SentinelTokenGenerator(self.device_id, USER_AGENT)
        requirements_proof = generator.requirements_token()
        runtime: SentinelBrowserRuntime | Any | None = None
        if self.challenge_strategy == "sentinel_protocol":
            try:
                if self._sentinel_runtime is None:
                    try:
                        self._sentinel_runtime = SentinelNodeRuntime(
                            self.session,
                            proxy_url=self.proxy_url,
                            log=self.log,
                            should_cancel=self.should_cancel,
                        )
                    except Exception as node_exc:
                        self.log(f"[认证] Sentinel Node V8 运行时不可用，回退 Camoufox：{node_exc}")
                        self._sentinel_runtime = SentinelBrowserRuntime(
                            self.session,
                            proxy_url=self.proxy_url,
                            log=self.log,
                            should_cancel=self.should_cancel,
                        )
                runtime = self._sentinel_runtime
                sdk_requirements = getattr(runtime, "requirements_token", None)
                if callable(sdk_requirements):
                    try:
                        requirements_proof = str(sdk_requirements() or "").strip()
                    except Exception as runtime_exc:
                        if not isinstance(runtime, SentinelNodeRuntime):
                            raise
                        self.log(f"[认证] Sentinel Node V8 证明生成失败，回退 Camoufox：{runtime_exc}")
                        try:
                            runtime.close()
                        except Exception:
                            pass
                        runtime = SentinelBrowserRuntime(
                            self.session,
                            proxy_url=self.proxy_url,
                            log=self.log,
                            should_cancel=self.should_cancel,
                        )
                        self._sentinel_runtime = runtime
                        requirements_proof = str(runtime.requirements_token() or "").strip()
                    if not requirements_proof:
                        raise RuntimeError("Sentinel SDK returned an empty requirements token")
            except Exception as exc:
                if self.should_cancel():
                    raise
                error = ProtocolChallengeRequired(f"Sentinel 协议运行时初始化失败: {exc}")
                error.challenge_flow = flow
                error.traffic = self.traffic.snapshot()
                raise error from exc
        proof = requirements_proof
        response = self._request(
            "POST",
            SENTINEL_REQ_URL,
            step=f"Sentinel {flow}",
            headers={
                "accept": "*/*",
                "content-type": "text/plain;charset=UTF-8",
                "origin": "https://sentinel.openai.com",
                "referer": SENTINEL_FRAME_URL,
            },
            data=json.dumps(
                {"p": proof, "id": self.device_id, "flow": flow},
                separators=(",", ":"),
            ),
        )
        if response.status_code != 200:
            raise _response_error(response, f"Sentinel {flow}")
        payload = _json_response(response, f"Sentinel {flow}")
        challenge = str(payload.get("token") or "").strip()
        if not challenge:
            raise ProtocolRegistrationError(f"Sentinel {flow} did not return a challenge token")
        pow_meta = payload.get("proofofwork") if isinstance(payload.get("proofofwork"), dict) else {}
        if pow_meta.get("required") and pow_meta.get("seed"):
            proof = generator.proof_token(
                str(pow_meta.get("seed") or ""),
                str(pow_meta.get("difficulty") or "0"),
            )
        turnstile = payload.get("turnstile") if isinstance(payload.get("turnstile"), dict) else {}
        turnstile_required = bool(turnstile.get("required"))
        has_device_challenge = bool(str(turnstile.get("dx") or "").strip())
        self.log(
            f"[认证] Sentinel {flow}：PoW={'是' if bool(pow_meta.get('required')) else '否'}，"
            f"Turnstile={'是' if turnstile_required else '否'}，设备挑战={'是' if has_device_challenge else '否'}"
        )
        if self.challenge_strategy == "sentinel_protocol":
            try:
                if runtime is None:
                    runtime = self._sentinel_runtime
                try:
                    return runtime.build_headers(
                        challenge_payload=payload,
                        cached_proof=requirements_proof,
                        enforcement="",
                        device_id=self.device_id,
                        flow=flow,
                    )
                except Exception as runtime_exc:
                    if not isinstance(runtime, SentinelNodeRuntime):
                        raise
                    self.log(f"[认证] Sentinel Node V8 证明校验失败，回退 Camoufox 重试：{runtime_exc}")
                    try:
                        runtime.close()
                    except Exception:
                        pass
                    runtime = SentinelBrowserRuntime(
                        self.session,
                        proxy_url=self.proxy_url,
                        log=self.log,
                        should_cancel=self.should_cancel,
                    )
                    self._sentinel_runtime = runtime
                    return runtime.build_headers(
                        challenge_payload=payload,
                        cached_proof=requirements_proof,
                        enforcement="",
                        device_id=self.device_id,
                        flow=flow,
                    )
            except Exception as exc:
                if self.should_cancel():
                    raise
                error = ProtocolChallengeRequired(f"Sentinel 协议运行时生成证明失败: {exc}")
                error.challenge_flow = flow
                error.traffic = self.traffic.snapshot()
                raise error from exc
        if turnstile_required or has_device_challenge:
            error = ProtocolChallengeRequired(
                f"Sentinel {flow} requires a browser challenge; protocol mode cannot continue safely"
            )
            error.challenge_flow = flow
            error.traffic = self.traffic.snapshot()
            raise error
        return {
            "openai-sentinel-token": json.dumps({
                "p": proof,
                "t": "",
                "c": challenge,
                "id": self.device_id,
                "flow": flow,
            }, separators=(",", ":"))
        }

    @staticmethod
    def _is_challenge_response(response: Any) -> bool:
        status = int(getattr(response, "status_code", 0) or 0)
        body = str(getattr(response, "text", "") or "").lower()
        if _is_account_deactivated_payload(body):
            return False
        return status in {403, 429} or any(
            marker in body for marker in ("challenge", "turnstile", "captcha", "sentinel")
        )

    def _request_with_sentinel_retry(
        self,
        flow: str,
        url: str,
        *,
        step: str,
        base_headers: dict[str, str],
        data: str,
    ) -> Any:
        """Retry a rejected Sentinel header without rebuilding auth cookies."""
        attempts = 3 if self.challenge_strategy == "sentinel_protocol" else 1
        for attempt in range(attempts):
            headers = dict(base_headers)
            headers.update(self._sentinel_headers(flow))
            response = self._request("POST", url, step=step, headers=headers, data=data)
            if (
                attempt + 1 < attempts
                and self.challenge_strategy == "sentinel_protocol"
                and self._is_challenge_response(response)
            ):
                self.log(f"[认证] {step} 拒绝当前 Sentinel 证明，保留协议 Cookie 刷新证明重试 ({attempt + 1}/{attempts - 1})")
                self._reset_sentinel_runtime()
                continue
            return response
        raise ProtocolChallengeRequired(f"{step} 未能通过 Sentinel 证明")

    def _start_next_auth(self) -> None:
        try:
            landing = self._request(
                "GET",
                f"{CHATGPT_BASE_URL}/",
                step="ChatGPT session initialization",
                allow_redirects=True,
            )
            if landing.status_code >= 500:
                raise _response_error(landing, "ChatGPT session initialization")
        except ProtocolRegistrationError as exc:
            if not _is_transient_transport_error(exc):
                raise
            # The full shell is optional for the protocol flow. Some proxy exits
            # reset that large response while still allowing the auth API.
            self.log("[协议] ChatGPT 首页被代理重置，改用轻量 CSRF 初始化")
        csrf_response = self._request(
            "GET",
            f"{CHATGPT_BASE_URL}/api/auth/csrf",
            step="ChatGPT CSRF initialization",
            headers={"accept": "application/json"},
        )
        if csrf_response.status_code != 200:
            raise _response_error(csrf_response, "ChatGPT CSRF initialization")
        csrf_payload = _json_response(csrf_response, "ChatGPT CSRF initialization")
        csrf_token = str(csrf_payload.get("csrfToken") or "").strip()
        if not csrf_token:
            csrf_cookie = unquote(self._cookie("__Host-next-auth.csrf-token"))
            csrf_token = csrf_cookie.split("|", 1)[0]
        if not csrf_token:
            raise ProtocolRegistrationError("ChatGPT CSRF initialization returned an empty token")
        self.device_id = self._cookie("oai-did") or str(uuid.uuid4())
        query = urlencode(
            {
                "prompt": "login",
                "ext-oai-did": self.device_id,
                "auth_session_logging_id": str(uuid.uuid4()),
                "ext-passkey-client-capabilities": "0111",
                "screen_hint": "login" if self.existing_account else "signup",
                "login_hint": self.account.email,
                "locale": "ja-JP",
            }
        )
        signin = self._request(
            "POST",
            f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}",
            step="OpenAI sign-in initialization",
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "origin": CHATGPT_BASE_URL,
                "referer": f"{CHATGPT_BASE_URL}/",
            },
            data={"callbackUrl": f"{CHATGPT_BASE_URL}/", "csrfToken": csrf_token, "json": "true"},
        )
        if signin.status_code != 200:
            raise _response_error(signin, "OpenAI sign-in initialization")
        self.auth_url = str(_json_response(signin, "OpenAI sign-in initialization").get("url") or "")
        if not self.auth_url:
            raise ProtocolRegistrationError("OpenAI sign-in initialization did not return an authorization URL")
        auth_page = self._request(
            "GET",
            self.auth_url,
            step="OpenAI authorization initialization",
            allow_redirects=True,
            headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        if auth_page.status_code >= 400:
            raise _response_error(auth_page, "OpenAI authorization initialization")
        self.auth_page_url = str(getattr(auth_page, "url", "") or self.auth_url)
        self.browser_resume_url = self.auth_page_url
        self.device_id = self._cookie("oai-did") or self.device_id

    def _rebuild_auth_session_for_retry(self) -> None:
        """Discard stale OAuth cookies and bootstrap a fresh authorization transaction."""
        if self._sentinel_runtime is not None:
            try:
                self._sentinel_runtime.close()
            finally:
                self._sentinel_runtime = None
        old_session = self.session
        if old_session is not None:
            try:
                old_session.close()
            except Exception:
                pass
        self.session = self._new_session()
        self.device_id = ""
        self.auth_url = ""
        self.auth_page_url = ""
        self.browser_resume_url = ""
        self._start_next_auth()

    def _authorize_email(self, *, allow_retry: bool = True) -> dict[str, Any]:
        self.browser_resume_url = f"{AUTH_BASE_URL}/{'log-in' if self.existing_account else 'create-account'}"
        response = self._request_with_sentinel_retry(
            "authorize_continue",
            AUTHORIZE_CONTINUE_URL,
            step="Submit registration email",
            base_headers={
                "accept": "application/json",
                "content-type": "application/json",
                "origin": AUTH_BASE_URL,
                "referer": f"{AUTH_BASE_URL}/{'log-in' if self.existing_account else 'create-account'}",
                "oai-device-id": self.device_id,
                **generate_datadog_trace_headers(),
            },
            data=json.dumps(
                {
                    "username": {"value": self.account.email, "kind": "email"},
                    "screen_hint": "login" if self.existing_account else "signup",
                },
                separators=(",", ":"),
            ),
        )
        if response.status_code != 200:
            body_lower = str(getattr(response, "text", "") or "").lower()
            invalid_state = "invalid_state" in body_lower or "no longer valid" in body_lower
            if allow_retry and response.status_code in {400, 409} and invalid_state:
                self.log("[认证] authorize_continue 会话已失效，正在重建 OAuth 会话并重试一次")
                self._rebuild_auth_session_for_retry()
                return self._authorize_email(allow_retry=False)
            raise _response_error(response, "Submit registration email")
        self._emit("email_submitted")
        return _json_response(response, "Submit registration email")

    def _password_value(self) -> str:
        value = str(self.account.chatgpt_password or "")
        if value:
            return value
        alphabet = string.ascii_letters + string.digits + "._!@#"
        required = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase), secrets.choice(string.digits), secrets.choice("._!@#")]
        required.extend(secrets.choice(alphabet) for _ in range(12))
        random.SystemRandom().shuffle(required)
        self.generated_password = "".join(required)
        self.account.chatgpt_password = self.generated_password
        return self.generated_password

    def _submit_password(self) -> dict[str, Any]:
        self.browser_resume_url = f"{AUTH_BASE_URL}/create-account/password"
        self._request(
            "GET",
            f"{AUTH_BASE_URL}/create-account/password",
            step="Load password stage",
            headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        response = self._request_with_sentinel_retry(
            "username_password_create",
            REGISTER_PASSWORD_URL,
            step="Submit account password",
            base_headers={
                "accept": "application/json",
                "content-type": "application/json",
                "origin": AUTH_BASE_URL,
                "referer": f"{AUTH_BASE_URL}/create-account/password",
                "oai-device-id": self.device_id,
                **generate_datadog_trace_headers(),
            },
            data=json.dumps(
                {"password": self._password_value(), "username": self.account.email},
                separators=(",", ":"),
            ),
        )
        if response.status_code != 200:
            raise _response_error(response, "Submit account password")
        self.auth_action = "register"
        return _json_response(response, "Submit account password")

    def _auth_json_post(self, path: str, payload: dict[str, Any], *, step: str, referer: str = "") -> dict[str, Any]:
        response = self._request(
            "POST",
            f"{AUTH_BASE_URL}{path}",
            step=step,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "origin": AUTH_BASE_URL,
                "referer": referer or self.auth_page_url or AUTH_BASE_URL,
                "oai-device-id": self.device_id,
                **generate_datadog_trace_headers(),
            },
            data=json.dumps(payload, separators=(",", ":")),
        )
        if response.status_code != 200:
            raise _response_error(response, step)
        return _json_response(response, step)

    def _verify_login_password(self, referer: str) -> dict[str, Any]:
        self.browser_resume_url = referer or self.auth_page_url or f"{AUTH_BASE_URL}/log-in/password"
        password = str(self.account.chatgpt_password or "")
        if not password:
            raise ProtocolRegistrationError("ChatGPT password login is required, but no ChatGPT password is configured")
        response = self._request_with_sentinel_retry(
            "password_verify",
            f"{AUTH_BASE_URL}/api/accounts/password/verify",
            step="Verify ChatGPT password",
            base_headers={
                "accept": "application/json",
                "content-type": "application/json",
                "origin": AUTH_BASE_URL,
                "referer": referer or self.auth_page_url or AUTH_BASE_URL,
                "oai-device-id": self.device_id,
                **generate_datadog_trace_headers(),
            },
            data=json.dumps({"password": password}, separators=(",", ":")),
        )
        if response.status_code != 200:
            error = _response_error(response, "Verify ChatGPT password")
            if _is_login_secret_rejection(error):
                raise ProtocolLoginSecretRejected(str(error)) from error
            raise error
        result = _json_response(response, "Verify ChatGPT password")
        if _is_account_deactivated_payload(result):
            raise ProtocolRegistrationError("account_deactivated: OpenAI password verification reported a disabled account")
        self.log("[认证] ChatGPT 密码验证成功")
        return result

    @staticmethod
    def _continue_url(payload: dict[str, Any]) -> str:
        return str(payload.get("continue_url") or payload.get("continueUrl") or "")

    @staticmethod
    def _page_type(payload: dict[str, Any]) -> str:
        page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
        return str(page.get("type") or "")

    def _complete_mfa(self, payload: dict[str, Any]) -> dict[str, Any]:
        if _is_account_deactivated_payload(payload):
            raise ProtocolRegistrationError("account_deactivated: OpenAI reported a disabled account after password verification")
        page_type = self._page_type(payload)
        continue_url = self._continue_url(payload)
        if page_type != "mfa_challenge" and "/mfa-challenge/" not in continue_url:
            return payload
        session = payload.get("oai-client-auth-session") if isinstance(payload.get("oai-client-auth-session"), dict) else {}
        factors = []
        for key in ("mfa_challenge_factors", "mfa_factors"):
            value = session.get(key)
            if isinstance(value, list):
                factors.extend(item for item in value if isinstance(item, dict))
        factor = next((item for item in factors if item.get("factor_type") == "totp" and item.get("id")), None)
        if not factor:
            raise ProtocolLoginSecretRejected("2FA is required, but no TOTP factor was returned")
        if not self.account.totp_secret:
            raise ProtocolRegistrationError("2FA is required, but no TOTP secret is configured")
        try:
            self._auth_json_post(
                "/api/accounts/mfa/issue_challenge",
                {"type": "totp", "id": factor["id"], "force_fresh_challenge": False},
                step="Issue TOTP challenge",
                referer=continue_url,
            )
            result = self._auth_json_post(
                "/api/accounts/mfa/verify",
                {"type": "totp", "id": factor["id"], "code": generate_totp(self.account.totp_secret)},
                step="Verify TOTP challenge",
                referer=continue_url,
            )
        except ProtocolRegistrationError as exc:
            if _is_login_secret_rejection(exc):
                raise ProtocolLoginSecretRejected(str(exc)) from exc
            raise
        except (ValueError, TypeError) as exc:
            raise ProtocolLoginSecretRejected(f"TOTP credential is invalid: {exc}") from exc
        self.log("[认证] 2FA TOTP 验证成功")
        return result

    def _restart_with_email_login(self, auth_started_at: float) -> dict[str, Any]:
        """Start one fresh authorization state and force the mailbox OTP route."""
        self._start_next_auth()
        initial_path = urlsplit(self.auth_page_url).path.rstrip("/")
        initial_otp_redirect = initial_path == "/email-verification"
        if initial_otp_redirect:
            state = {"page": {"type": "email_otp_verification"}, "continue_url": self.auth_page_url}
        else:
            state = self._authorize_email()
        continue_url = self._continue_url(state)
        state = self._verify_email(
            continue_url,
            request_code=not initial_otp_redirect,
            load_page=not initial_otp_redirect,
            min_timestamp=auth_started_at,
        )
        if self._page_type(state) in {"email_otp_verification", "email_otp_send"}:
            state = self._verify_email(self._continue_url(state) or continue_url, min_timestamp=auth_started_at)
        return state

    def _select_workspace(self, payload: dict[str, Any]) -> dict[str, Any]:
        page_type = self._page_type(payload)
        continue_url = self._continue_url(payload)
        if page_type != "workspace" and not continue_url.endswith("/workspace"):
            return payload
        session = payload.get("oai-client-auth-session") if isinstance(payload.get("oai-client-auth-session"), dict) else {}
        workspaces = session.get("workspaces") if isinstance(session.get("workspaces"), list) else []
        workspace = next((item for item in workspaces if isinstance(item, dict) and item.get("id")), None)
        if not workspace:
            self.log("[认证] workspace 页面没有可选项，继续当前授权流程")
            return payload
        result = self._auth_json_post(
            "/api/accounts/workspace/select",
            {"workspace_id": workspace["id"]},
            step="Select ChatGPT workspace",
            referer=continue_url,
        )
        self.log("[认证] 已选择首个可用 workspace")
        return result

    def _wait_for_email_code(self, min_timestamp: float, *, timeout: int = EMAIL_OTP_INITIAL_WAIT_SECONDS) -> str:
        if self.reader is None:
            if self.account.mailbox_type == "apple" and self.account.mailbox_channel == "url_api" and not self.account.access_key:
                raise ProtocolRegistrationError("Email OTP is required, but no url_api mail endpoint is configured")
            self.reader = create_mailbox_reader(self.account, self.log, self.mailbox_proxy_url)
            self.reader.connect()
        deadline = time.monotonic() + max(1, int(timeout))
        while time.monotonic() < deadline:
            self._check_cancelled()
            try:
                return self.reader.wait_for_code(min_timestamp, timeout=10)
            except TimeoutError:
                continue
        raise TimeoutError(f"Timed out waiting for OpenAI email OTP after {int(timeout)} seconds")

    def _send_email_otp(self, verification_url: str, *, resend: bool = False) -> tuple[float, str]:
        requested_at = time.time() - 2
        response = self._request(
            "GET",
            SEND_EMAIL_OTP_URL,
            step="Resend email verification code" if resend else "Send email verification code",
            headers={
                "accept": "application/json, text/plain, */*",
                "referer": verification_url,
                "oai-device-id": self.device_id,
                **generate_datadog_trace_headers(),
            },
        )
        if response.status_code != 200:
            raise _response_error(response, "Resend email verification code" if resend else "Send email verification code")
        try:
            payload = response.json()
            payload = payload if isinstance(payload, dict) else {}
        except Exception:
            payload = {}
        returned_url = str(payload.get("continue_url") or "").strip()
        if returned_url:
            verification_url = returned_url
        self.log(
            "[邮箱] 协议模式已重新发送 OpenAI 邮箱验证码"
            if resend else "[邮箱] 协议模式已请求发送 OpenAI 邮箱验证码"
        )
        return requested_at, (returned_url or verification_url)

    def _verify_email(
        self,
        continue_url: str,
        *,
        request_code: bool = True,
        load_page: bool = True,
        min_timestamp: float = 0.0,
    ) -> dict[str, Any]:
        verification_url = continue_url or f"{AUTH_BASE_URL}/email-verification"
        self.browser_resume_url = verification_url
        if load_page:
            page = self._request(
                "GET",
                verification_url,
                step="Load email verification stage",
                headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            )
            if page.status_code >= 400:
                raise _response_error(page, "Load email verification stage")
        else:
            self.log("[邮箱] 邮箱验证页已由认证初始化加载，跳过重复页面请求")
        sent_at = min_timestamp or (time.time() - 5)
        if request_code:
            sent_at, verification_url = self._send_email_otp(verification_url)
        else:
            self.log("[邮箱] 认证初始化已自动发送验证码，跳过重复发码")
        try:
            code = self._wait_for_email_code(sent_at)
        except TimeoutError as exc:
            resent_at, verification_url = self._send_email_otp(verification_url, resend=True)
            try:
                code = self._wait_for_email_code(resent_at, timeout=EMAIL_OTP_RESEND_WAIT_SECONDS)
            except TimeoutError as resend_exc:
                raise TimeoutError("重新发送协议验证码后等待 60 秒仍未收到验证码") from resend_exc
        self.recent_email_code = str(code or "").strip()
        self.recent_email_code_at = time.time()
        validated = self._request(
            "POST",
            VALIDATE_EMAIL_OTP_URL,
            step="Validate email verification code",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "origin": AUTH_BASE_URL,
                "referer": verification_url,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            },
            data=json.dumps({"code": code}, separators=(",", ":")),
        )
        if validated.status_code != 200:
            raise _response_error(validated, "Validate email verification code")
        result = _json_response(validated, "Validate email verification code")
        self.email_verified = True
        self.browser_resume_url = self._continue_url(result) or verification_url
        self._emit("email_verified")
        return result

    def _create_account(self) -> dict[str, Any]:
        self.browser_resume_url = f"{AUTH_BASE_URL}/about-you"
        name = f"{random.choice(['Mia', 'Ella', 'Luna', 'Noah', 'Leo', 'Mason'])} {random.choice(['Adams', 'Clark', 'Smith', 'Walker', 'Young'])}"
        age = random.randint(25, 34)
        now = datetime.now(timezone.utc)
        birthdate = f"{now.year - age:04d}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        try:
            self._request(
                "GET",
                f"{AUTH_BASE_URL}/api/accounts/client_auth_session_dump",
                step="Advance authorization state",
                headers={"accept": "application/json", "referer": f"{AUTH_BASE_URL}/email-verification"},
            )
        except ProtocolRegistrationError as exc:
            self.log(f"[认证] 协议状态推进请求未成功，继续创建账户：{exc}")
        response = None
        # OpenAI may temporarily reject a fresh registration after the email
        # OTP is accepted while its IP/Sentinel risk window settles. Remail
        # addresses are especially sensitive to this window, so use a bounded
        # long backoff only for that provider; keep legacy mailbox timing intact.
        retry_delays = [8, 20, 45] if str(self.account.mailbox_type or "").lower() == "remail" else [2, 2]
        for attempt in range(len(retry_delays) + 1):
            response = self._request_with_sentinel_retry(
                "oauth_create_account",
                CREATE_ACCOUNT_URL,
                step="Create ChatGPT account",
                base_headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "origin": AUTH_BASE_URL,
                    "referer": f"{AUTH_BASE_URL}/about-you",
                    "oai-device-id": self.device_id,
                    **generate_datadog_trace_headers(),
                },
                data=json.dumps({"name": name, "birthdate": birthdate}, separators=(",", ":")),
            )
            if response.status_code == 200:
                break
            body = str(getattr(response, "text", "") or "")
            if "registration_disallowed" not in body or attempt >= len(retry_delays):
                raise _response_error(response, "Create ChatGPT account")
            delay = retry_delays[attempt]
            self.log(f"[认证] 创建账号被临时拒绝，等待 {delay} 秒后刷新 Sentinel 证明重试 {attempt + 1}/{len(retry_delays) + 1}")
            self._check_cancelled()
            time.sleep(delay)
            self._check_cancelled()
        if response is None:
            raise ProtocolRegistrationError("Create ChatGPT account did not return a response")
        self.auth_action = "register"
        self.log(f"[认证] 协议模式已提交基础资料：{name} / {birthdate}")
        return _json_response(response, "Create ChatGPT account")

    def _finish_session(self, continue_url: str) -> dict[str, Any]:
        target = str(continue_url or self.auth_url or "").strip()
        self.browser_resume_url = target or self.browser_resume_url
        if target:
            response = self._request(
                "GET",
                target,
                step="Complete OpenAI callback",
                allow_redirects=True,
                headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            )
            if response.status_code >= 400:
                raise _response_error(response, "Complete OpenAI callback")
        session_response = self._request(
            "GET",
            f"{CHATGPT_BASE_URL}/api/auth/session",
            step="Read ChatGPT session",
            headers={"accept": "application/json", "referer": f"{CHATGPT_BASE_URL}/"},
        )
        if session_response.status_code != 200:
            raise _response_error(session_response, "Read ChatGPT session")
        session_json = _json_response(session_response, "Read ChatGPT session")
        access_token = str(session_json.get("accessToken") or session_json.get("access_token") or "")
        if not access_token:
            raise ProtocolRegistrationError("ChatGPT session did not return accessToken")
        account_payload = session_json.get("account") if isinstance(session_json.get("account"), dict) else {}
        plan_type = str(account_payload.get("planType") or account_payload.get("plan_type") or "free").lower()
        session_token = self._cookie("__Secure-next-auth.session-token")
        account_id = self._cookie("_account") or str(account_payload.get("id") or "")
        cookies = []
        try:
            cookies = [
                {"name": item.name, "value": item.value, "domain": item.domain, "path": item.path}
                for item in self.session.cookies.jar
            ]
        except Exception:
            pass
        self._emit("auth_completed")
        result = {
            "access_token": access_token,
            "refresh_token": "",
            "id_token": access_token,
            "session_token": session_token,
            "session_json": session_json,
            "storage_state_json": {"cookies": cookies, "origins": []},
            "account_id": account_id,
            "plan_type": plan_type,
            "auth_action": self.auth_action if self.auth_action != "unknown" else "login",
            "execution_mode": "protocol",
            "protocol_challenge_strategy": self.challenge_strategy,
            "sentinel_runtime_used": self._sentinel_runtime is not None,
            "protocol_traffic": self.traffic.snapshot(),
        }
        self._emit("registered", result)
        # Keep the recently used OTP ephemeral. It is returned to the worker
        # only after the registration checkpoint has been persisted.
        if self.recent_email_code and self.recent_email_code_at > 0:
            result["recent_email_code"] = self.recent_email_code
            result["recent_email_code_at"] = self.recent_email_code_at
        return result

    def _refresh_session_with_login_secret(self) -> dict[str, Any]:
        """Issue a new AT through LS login while retaining this protocol cookie jar."""
        self.existing_account = True
        self.auth_action = "login"
        auth_started_at = time.time() - 5
        self._start_next_auth()
        initial_path = urlsplit(self.auth_page_url).path.rstrip("/")
        initial_otp_redirect = initial_path == "/email-verification"
        if initial_otp_redirect:
            state = {"page": {"type": "email_otp_verification"}, "continue_url": self.auth_page_url}
        else:
            state = self._authorize_email()
        page_type = self._page_type(state)
        continue_url = self._continue_url(state) or self.auth_page_url
        if page_type == "login_password":
            state = self._verify_login_password(continue_url)
        elif page_type in {"email_otp_verification", "email_otp_send"}:
            raise ProtocolChallengeRequired(
                "AT 刷新未进入密码登录步骤，已禁止使用邮箱验证码；需要重新建立密码与 2FA 登录事务"
            )
        if self._page_type(state) in {"email_otp_verification", "email_otp_send"}:
            raise ProtocolChallengeRequired(
                "密码验证后未进入 TOTP 步骤，已禁止使用邮箱验证码刷新 AT"
            )
        state = self._complete_mfa(state)
        state = self._select_workspace(state)
        continue_url = self._continue_url(state) or continue_url
        result = self._finish_session(continue_url)
        self.log("[登录密钥] 已在当前协议 Cookie 会话中通过密码与 2FA 重新认证并获取最新 ChatGPT Access Token")
        return result

    def run(self) -> dict[str, Any]:
        self.log(f"[认证] 开始纯协议注册或登录：{self.account.email}")
        if self.challenge_strategy == "sentinel_protocol":
            self.log("[认证] 协议模式使用 Sentinel 协议运行时；仅证明生成可能启动窄范围 Camoufox")
        else:
            self.log("[认证] 协议模式使用本项目原生挑战接管策略")
        if self.existing_account:
            if self.account.has_login_secret:
                self.log("[认证] 检测到完整 LS，协议登录优先使用 ChatGPT 密码与 2FA")
            elif self.account.has_chatgpt_password:
                self.log("[认证] 检测到已保存 ChatGPT 密码，协议登录优先使用密码")
            else:
                self.log("[认证] 未检测到完整 LS，协议登录使用邮箱凭证")
        try:
            self._check_cancelled()
            # A saved ChatGPT password can authenticate without an email OTP.
            # Do not connect or poll the mailbox speculatively; only create the
            # reader after the auth state explicitly enters email OTP.
            if self._needs_mailbox_reader():
                self.reader = create_mailbox_reader(self.account, self.log, self.mailbox_proxy_url)
                self.reader.connect()
            self.session = self.session or self._new_session()
            self._emit("protocol_started")
            auth_started_at = time.time() - 5
            self._start_next_auth()
            initial_path = urlsplit(self.auth_page_url).path.rstrip("/")
            initial_otp_redirect = initial_path == "/email-verification"
            if initial_otp_redirect:
                state = {
                    "page": {"type": "email_otp_verification"},
                    "continue_url": self.auth_page_url,
                }
                self.log("[认证] 初始化已进入邮箱验证阶段，跳过重复提交邮箱")
            else:
                state = self._authorize_email()
            page_type = str((state.get("page") or {}).get("type") or "")
            continue_url = str(state.get("continue_url") or "")
            self.log(f"[认证] 协议认证状态：{page_type or 'unknown'}")

            credential_complete = False
            login_secret_attempted = False
            if page_type in {"password", "create_account_password"}:
                state = self._submit_password()
                page_type = str((state.get("page") or {}).get("type") or page_type)
                continue_url = str(state.get("continue_url") or continue_url)
            elif page_type in {"login_password"}:
                self.auth_action = "login"
                if self.account.has_chatgpt_password:
                    try:
                        state = self._verify_login_password(continue_url or self.auth_page_url)
                        login_secret_attempted = True
                    except ProtocolLoginSecretRejected as exc:
                        self.log(f"[认证] LS 密码验证失败，将改用邮箱凭证登录重试：{str(exc)[:220]}")
                        state = self._verify_email(continue_url, min_timestamp=auth_started_at)
                else:
                    if self.account.chatgpt_password or self.account.totp_secret:
                        self.log("[认证] 登录密钥不完整，本次继续使用邮箱凭证登录")
                    state = self._verify_email(continue_url, min_timestamp=auth_started_at)
                credential_complete = True
            elif page_type in {"email_otp_verification", "email_otp_send"}:
                self.auth_action = "login" if self.existing_account else self.auth_action
                state = self._verify_email(
                    continue_url,
                    request_code=not initial_otp_redirect,
                    load_page=not initial_otp_redirect,
                    min_timestamp=auth_started_at,
                )
                credential_complete = True

            if not credential_complete:
                state = self._verify_email(
                    continue_url,
                    request_code=not initial_otp_redirect,
                    load_page=not initial_otp_redirect,
                    min_timestamp=auth_started_at,
                )

            if self._page_type(state) in {"email_otp_verification", "email_otp_send"}:
                state = self._verify_email(
                    self._continue_url(state) or continue_url,
                    min_timestamp=auth_started_at,
                )

            try:
                state = self._complete_mfa(state)
            except ProtocolLoginSecretRejected as exc:
                if not login_secret_attempted:
                    raise
                self.log(f"[认证] LS 2FA 验证失败，将重新初始化并使用邮箱凭证登录：{str(exc)[:220]}")
                state = self._restart_with_email_login(time.time() - 5)
            page_type = str((state.get("page") or {}).get("type") or "")
            continue_url = str(state.get("continue_url") or continue_url)
            if page_type in {"about_you", "create_account", "name_and_birthdate"} or self.auth_action == "register":
                state = self._create_account()
                continue_url = str(state.get("continue_url") or continue_url)
            else:
                self.auth_action = "login"
            state = self._select_workspace(state)
            continue_url = str(state.get("continue_url") or continue_url)
            result = self._finish_session(continue_url)
            if self.post_registration_callback is not None:
                try:
                    callback_result = self.post_registration_callback(_ProtocolCallbackSession(self), dict(result)) or {}
                except Exception as exc:
                    if self.should_cancel():
                        raise
                    callback_result = {"complete": False, "errors": [str(exc)]}
                    self.log(f"[认证] 协议登录密钥附加步骤失败，保留当前协议登录态：{str(exc)[:300]}")
                result["login_secret_result"] = callback_result
                refreshed = callback_result.get("session") if isinstance(callback_result, dict) else None
                if isinstance(refreshed, dict):
                    try:
                        refreshed["storage_state_json"] = {
                            "cookies": [
                                {"name": item.name, "value": item.value, "domain": item.domain, "path": item.path}
                                for item in self.session.cookies.jar
                            ],
                            "origins": [],
                        }
                    except Exception:
                        pass
                    for key in ("access_token", "session_json", "storage_state_json"):
                        if key in refreshed:
                            result[key] = refreshed[key]
            if self.generated_password:
                result["generated_chatgpt_password"] = self.generated_password
            self.log("[认证] 纯协议注册/登录完成，已读取 ChatGPT Session")
            traffic = result["protocol_traffic"]
            suffix = "；不含 Sentinel 窄浏览器运行时资源" if self._sentinel_runtime is not None else ""
            self.log(
                f"[系统] 协议模式 HTTP 应用层流量：{traffic['total_bytes']} bytes / "
                f"{traffic['requests']} requests（不含 TLS/TCP 开销{suffix}）"
            )
            return result
        except Exception as exc:
            if not hasattr(exc, "traffic"):
                exc.traffic = self.traffic.snapshot()
            if isinstance(exc, ProtocolChallengeRequired) and not hasattr(exc, "browser_handoff"):
                exc.browser_handoff = self._browser_handoff_snapshot(str(getattr(exc, "challenge_flow", "") or ""))
            traffic = exc.traffic
            self.log(
                f"[系统] 协议模式失败前 HTTP 应用层流量估算：{traffic['total_bytes']} bytes / "
                f"{traffic['requests']} requests（不含 TLS/TCP 开销）"
            )
            raise
        finally:
            if self._sentinel_runtime:
                self._sentinel_runtime.close()
            if self.reader and not self.keep_session:
                self.reader.close()
            if self.session and not self.keep_session:
                try:
                    self.session.close()
                except Exception:
                    pass


def login_or_register_protocol(
    account: MailAccount,
    proxy_url: str = "",
    log: Callable[[str], None] | None = None,
    *,
    existing_account: bool = False,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str, dict[str, Any]], None] | None = None,
    challenge_strategy: str = "native_headless",
    mailbox_proxy_url: str | None = None,
    traffic_meter: ProxyTrafficMeter | None = None,
    post_registration_callback: Callable[[Any, dict[str, Any]], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    flow_kwargs = {
        "existing_account": existing_account,
        "should_cancel": should_cancel,
        "on_progress": on_progress,
        "challenge_strategy": challenge_strategy,
        "mailbox_proxy_url": mailbox_proxy_url,
        "traffic_meter": traffic_meter,
        "post_registration_callback": post_registration_callback,
    }
    try:
        return ProtocolRegistrationFlow(account, proxy_url, log, **flow_kwargs).run()
    except TimeoutError as exc:
        if not _is_email_otp_timeout(exc):
            raise
        if log:
            log(
                "[邮箱] 协议模式 OpenAI 邮箱验证码等待超时，已重新建立认证事务并重试一次；"
                "若再次超时将停止当前账户流程"
            )
        return ProtocolRegistrationFlow(account, proxy_url, log, **flow_kwargs).run()
