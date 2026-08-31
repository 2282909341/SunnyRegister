from __future__ import annotations

import json
import random
import re
import secrets
import time
from typing import Any, Callable

from .auth_challenges import generate_totp
from .browser_backend import open_registration_browser
from .browser_traffic import BrowserTrafficOptimizer, ProxyTrafficMeter
from .mailbox import MailAccount, create_mailbox_reader
from .openai_auth import CHATGPT_BASE_URL, generate_register_fingerprint

AUTH_BASE_URL = "https://auth.openai.com"
PASSWORD_ADD_URL = f"{AUTH_BASE_URL}/api/accounts/password/add"
EMAIL_OTP_VALIDATE_URL = f"{AUTH_BASE_URL}/api/accounts/email-otp/validate"
MFA_INFO_URL = f"{CHATGPT_BASE_URL}/backend-api/accounts/mfa_info"
MFA_ENROLL_URL = f"{CHATGPT_BASE_URL}/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE_URL = f"{CHATGPT_BASE_URL}/backend-api/accounts/mfa/user/activate_enrollment"
_AUTH_RATE_LIMIT_MARKERS = (
    "rate_limit_exceeded", "too many requests", "requests are too frequent",
    "request limit exceeded", "リクエストが多すぎ", "请求过多", "请求太频繁",
    "请求频率过高", "요청이 너무 많",
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


def _is_account_deactivated_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return any(marker in text for marker in _ACCOUNT_DEACTIVATED_MARKERS)


class MFAReauthenticationRequired(RuntimeError):
    pass


class LoginSecretRateLimitError(RuntimeError):
    """OpenAI rejected the reauthentication transaction due to request rate limiting."""


def _is_auth_rate_limit_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return any(marker in text for marker in _AUTH_RATE_LIMIT_MARKERS)


def _password_already_set(result: dict[str, Any]) -> bool:
    if not isinstance(result, dict):
        return False
    candidates = [result, result.get("data"), result.get("error")]
    data = result.get("data")
    if isinstance(data, dict):
        candidates.append(data.get("error"))
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        code = str(candidate.get("code") or candidate.get("type") or "").strip().lower()
        message = str(candidate.get("message") or candidate.get("detail") or "").strip().lower()
        if code in {"password_already_set", "password_exists", "already_set"} or "already have a password" in message or "password already exists" in message:
            return True
    return False


def _wrong_email_otp(result: dict[str, Any] | None, text: str = "") -> bool:
    """Recognize an OTP rejected by OpenAI so the mailbox can be rescanned."""
    payload = result if isinstance(result, dict) else {}
    candidates = [payload]
    data = payload.get("data")
    if isinstance(data, dict):
        candidates.append(data)
        if isinstance(data.get("error"), dict):
            candidates.append(data["error"])
    if isinstance(payload.get("error"), dict):
        candidates.append(payload["error"])
    values = [str(text or "").lower()]
    for candidate in candidates:
        values.extend(
            str(candidate.get(key) or "").strip().lower()
            for key in ("code", "type", "message", "detail")
        )
    raw = " ".join(values)
    return any(marker in raw for marker in (
        "wrong_email_otp_code", "invalid_email_otp", "email_otp_invalid",
        "invalid email otp", "email otp is invalid", "wrong code", "incorrect code",
        "invalid code", "code has expired", "验证码错误", "验证码无效", "验证码已过期",
        "コードが正しくありません", "コードの有効期限が切れ",
    ))


def _invalid_auth_state(result: dict[str, Any] | None, text: str = "") -> bool:
    payload = result if isinstance(result, dict) else {}
    candidates = [payload, payload.get("data"), payload.get("error")]
    data = payload.get("data")
    if isinstance(data, dict):
        candidates.append(data.get("error"))
    markers = [str(text or "").lower()]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        markers.extend((
            str(candidate.get("code") or "").lower(),
            str(candidate.get("type") or "").lower(),
            str(candidate.get("message") or candidate.get("detail") or "").lower(),
        ))
    combined = " ".join(markers)
    return "invalid_state" in combined or "sign-in session is no longer valid" in combined


def _invalid_auth_step(result: dict[str, Any] | None, text: str = "") -> bool:
    payload = result if isinstance(result, dict) else {}
    candidates = [payload, payload.get("data"), payload.get("error")]
    data = payload.get("data")
    if isinstance(data, dict):
        candidates.append(data.get("error"))
    markers = [str(text or "").lower()]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        markers.extend((
            str(candidate.get("code") or "").lower(),
            str(candidate.get("type") or "").lower(),
            str(candidate.get("message") or candidate.get("detail") or "").lower(),
        ))
    combined = " ".join(markers)
    return "invalid_auth_step" in combined or "invalid authorization step" in combined


RECENT_EMAIL_CODE_MAX_AGE_SECONDS = 120
EMAIL_OTP_INITIAL_WAIT_SECONDS = 120
EMAIL_OTP_RESEND_WAIT_SECONDS = 60
LOGIN_SECRET_STEP_TIMEOUT_SECONDS = 30


def generate_chatgpt_password(length: int = 16) -> str:
    length = max(12, int(length or 16))
    groups = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghijkmnopqrstuvwxyz",
        "23456789",
        "!@#$%^&*?_-+=",
    )
    chars = [secrets.choice(group) for group in groups]
    pool = "".join(groups)
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


class LoginSecretSetupFlow:
    def __init__(
        self,
        account: MailAccount,
        session: dict[str, Any],
        proxy_url: str,
        log: Callable[[str], None] | None = None,
        *,
        should_cancel: Callable[[], bool] | None = None,
        mailbox_proxy_url: str | None = None,
        traffic_meter: ProxyTrafficMeter | None = None,
        on_progress: Callable[[str], None] | None = None,
        recent_email_code: str = "",
        recent_email_code_at: float = 0.0,
        force_access_token_refresh: bool = False,
        on_credential_saved: Callable[[str, str], None] | None = None,
        on_session_saved: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.account = account
        self.session = dict(session or {})
        self.proxy_url = str(proxy_url or "")
        self.mailbox_proxy_url = self.proxy_url if mailbox_proxy_url is None else str(mailbox_proxy_url or "")
        self.log = log or (lambda _message: None)
        self.should_cancel = should_cancel or (lambda: False)
        self.traffic_meter = traffic_meter
        self.on_progress = on_progress or (lambda _checkpoint: None)
        self.recent_email_code = str(recent_email_code or "").strip()
        self.recent_email_code_at = float(recent_email_code_at or 0.0)
        self.recent_email_code_attempted = False
        self.force_access_token_refresh = bool(force_access_token_refresh)
        self.on_credential_saved = on_credential_saved or (lambda _kind, _value: None)
        self.on_session_saved = on_session_saved or (lambda _session: None)
        self._persisted_credentials: set[tuple[str, str]] = set()
        self.last_access_token_probe_error = ""
        self.traffic_optimizer = BrowserTrafficOptimizer(traffic_meter) if traffic_meter is not None else None
        self.reader: Any | None = None

    def _persist_credential(self, kind: str, value: str) -> None:
        value = str(value or "").strip()
        checkpoint = (str(kind or "").strip(), value)
        if value and checkpoint not in self._persisted_credentials:
            # Persist each completed security step before the next step starts.
            # A later 2FA/AT failure must not roll back a password already set.
            self.on_credential_saved(*checkpoint)
            self._persisted_credentials.add(checkpoint)

    def _check_cancelled(self) -> None:
        if self.should_cancel():
            from .openai_auth import TaskCancelledError

            raise TaskCancelledError("Task cancelled by user")

    def _sleep(self, seconds: float) -> None:
        deadline = time.time() + max(0.0, seconds)
        while time.time() < deadline:
            self._check_cancelled()
            time.sleep(min(0.5, deadline - time.time()))

    def _storage_state(self) -> dict[str, Any]:
        state = self.session.get("storage_state_json")
        if isinstance(state, str):
            try:
                state = json.loads(state)
            except (TypeError, ValueError):
                state = {}
        if not isinstance(state, dict) or not isinstance(state.get("cookies"), list):
            raise RuntimeError("当前账户没有可复用的 ChatGPT 浏览器登录态")
        return state

    def _reader_instance(self):
        if self.reader is None:
            self.reader = create_mailbox_reader(self.account, self.log, self.mailbox_proxy_url)
            self.reader.connect()
        return self.reader

    @staticmethod
    def _wait_for_code(reader, min_timestamp: float, timeout: int) -> str:
        """Call mailbox readers with the bounded timeout while keeping old test/custom readers compatible."""
        try:
            return reader.wait_for_code(min_timestamp, timeout)
        except TypeError as exc:
            # Older injected readers accepted only the timestamp. Do not hide
            # unrelated TypeErrors raised by a reader implementation.
            if "positional" not in str(exc) and "argument" not in str(exc):
                raise
            return reader.wait_for_code(min_timestamp)

    def _wait_for_distinct_code(
        self,
        reader,
        min_timestamp: float,
        excluded_codes: set[str],
        timeout: int,
    ) -> str:
        """Ignore a stale mailbox API result until a different six-digit code arrives."""
        deadline = time.monotonic() + max(1, int(timeout))
        cursor = min_timestamp
        while time.monotonic() < deadline:
            remaining = max(1, min(10, int(deadline - time.monotonic())))
            try:
                code = str(self._wait_for_code(reader, cursor, remaining) or "").strip()
            except TimeoutError:
                continue
            if re.fullmatch(r"\d{6}", code) and code not in excluded_codes:
                return code
            if code:
                self.log("[邮箱] 邮箱读取器返回了历史验证码，继续等待不同的新验证码")
            self._sleep(0.25)
        raise TimeoutError(f"在 {int(timeout)} 秒内未获取到不同的新邮箱验证码")

    @staticmethod
    def _session_json(page) -> dict[str, Any]:
        result = page.evaluate(
            """async () => {
                const response = await fetch('https://chatgpt.com/api/auth/session', {
                    credentials:'include', cache:'no-store',
                    headers:{'Cache-Control':'no-cache','Pragma':'no-cache'}
                });
                const text = await response.text();
                let data = null;
                try { data = JSON.parse(text); } catch (_) {}
                return {ok:response.ok, status:response.status, data, text};
            }"""
        )
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict) or not (data.get("accessToken") or data.get("access_token")):
            raise RuntimeError(f"ChatGPT 登录态已失效: HTTP {result.get('status') if isinstance(result, dict) else 0}")
        return data

    def _access_token_is_valid(self, page, access_token: str) -> bool:
        token = str(access_token or "").strip()
        if not token:
            self.last_access_token_probe_error = "账户没有 Access Token"
            return False
        try:
            from .access_token_probe import probe_access_token

            result = probe_access_token(token, self.proxy_url)
        except Exception as exc:
            self.last_access_token_probe_error = f"AT 探测异常: {exc}"
            return False
        if isinstance(result, dict) and result.get("status") == "valid":
            self.last_access_token_probe_error = ""
            return True
        self.last_access_token_probe_error = str(
            (result or {}).get("error") or (result or {}).get("status") or "AT 未通过有效性检测"
        )
        return False

    def _refresh_session_with_login_secret(self, page) -> dict[str, Any]:
        """Refresh the AT by reauthenticating in the active registration page."""
        self._ensure_chatgpt_page(page)
        def begin_auth() -> str:
            payload = page.evaluate(
                """async ({email}) => {
                    const csrfResponse = await fetch('/api/auth/csrf', {
                        credentials:'include', cache:'no-store',
                        headers:{'Cache-Control':'no-cache','Pragma':'no-cache'}
                    });
                    if (!csrfResponse.ok) return {ok:false,status:csrfResponse.status};
                    const csrf = await csrfResponse.json();
                    const query = new URLSearchParams({
                        connection:'password', login_hint:email, screen_hint:'login',
                        prompt:'login', reauth:'password', max_age:'0'
                    });
                    const body = new URLSearchParams({
                        callbackUrl:'https://chatgpt.com/', csrfToken:csrf.csrfToken, json:'true'
                    });
                    const response = await fetch('/api/auth/signin/openai?' + query.toString(), {
                        method:'POST', credentials:'include', cache:'no-store',
                        headers:{'content-type':'application/x-www-form-urlencoded','Cache-Control':'no-cache','Pragma':'no-cache'},
                        body:body.toString()
                    });
                    const text = await response.text();
                    let data={}; try { data=JSON.parse(text); } catch (_) {}
                    return {ok:response.ok,status:response.status,data};
                }""",
                {"email": self.account.email},
            )
            auth_url = str(((payload or {}).get("data") or {}).get("url") or "")
            if not payload.get("ok") or not auth_url:
                raise RuntimeError(f"发起登录密钥 AT 刷新失败: HTTP {payload.get('status')}")
            return auth_url

        auth_url = begin_auth()
        started_at = time.time()
        page.goto(auth_url, wait_until="domcontentloaded", timeout=60000)
        for attempt in range(2):
            try:
                self._complete_reauthentication(
                    page,
                    started_at,
                    self.account.chatgpt_password,
                    allow_email_fallback=False,
                )
                break
            except LoginSecretRateLimitError:
                if attempt:
                    raise
                self.log("[登录密钥] AT 刷新认证触发请求限流，等待后仅重试一次，不重复设置密码与 2FA")
                self._sleep(15)
                auth_url = begin_auth()
                page.goto(auth_url, wait_until="domcontentloaded", timeout=60000)
        current_session = self._session_json(page)
        previous_token = str(self.session.get("access_token") or "")
        current_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
        if previous_token and current_token == previous_token:
            raise RuntimeError("登录密钥重认证后仍返回注册阶段的旧 Access Token")
        return current_session

    def _updated_session(self, current_session: dict[str, Any], storage_state: dict[str, Any]) -> dict[str, Any]:
        access_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
        if not access_token:
            raise RuntimeError("登录密钥设置完成后未获取到新的 ChatGPT Access Token")
        updated = {
            **self.session,
            "access_token": access_token,
            "session_json": current_session,
            "storage_state_json": storage_state,
        }
        # The first registration checkpoint carries the first AT expiry. Let
        # persistence derive the expiry again only after AT replacement.
        if access_token != str(self.session.get("access_token") or ""):
            updated.pop("expires_at", None)
        if str(updated.get("id_token") or "") == str(self.session.get("access_token") or ""):
            updated["id_token"] = access_token
        return updated

    @staticmethod
    def _is_chatgpt_page(page) -> bool:
        try:
            return str(getattr(page, "url", "") or "").lower().startswith(f"{CHATGPT_BASE_URL}/")
        except Exception:
            return False

    @classmethod
    def _ensure_chatgpt_page(cls, page) -> None:
        if not cls._is_chatgpt_page(page):
            page.goto(CHATGPT_BASE_URL, wait_until="domcontentloaded", timeout=60000)

    @staticmethod
    def _dismiss_continue_gate(page) -> bool:
        """Advance the post-login SPA gate before looking for settings/password UI."""
        try:
            return bool(page.evaluate(
                r"""() => {
                    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                        && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
                        && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
                    const describe = el => [...new Set([el.innerText || el.textContent, el.getAttribute('aria-label'), el.value]
                        .filter(Boolean).map(value => String(value).replace(/\s+/g, ' ').trim()))].join(' ');
                    const buttons = [...document.querySelectorAll('button,[role="button"],input[type="submit"]')].filter(visible);
                    const exact = /^(continue|next|finish|继续|続行|次へ|完了|確認|アカウントの作成を完了する)$/i;
                    const target = buttons.find(el => exact.test(describe(el)))
                        || (buttons.length === 1 && /continue|next|finish|继续|続行|次へ|完了|確認/i.test(describe(buttons[0])) ? buttons[0] : null);
                    if (!target) return false;
                    target.scrollIntoView({block:'center'}); target.click(); return true;
                }"""
            ))
        except Exception:
            return False

    @staticmethod
    def _click_resend_email_code(page) -> bool:
        """Click the resend control on an OpenAI email verification page."""
        selectors = (
            'button[type="submit"][name="intent"][value="resend"]',
            'button[type="submit"][value="resend"]',
            'input[type="submit"][value="resend"]',
            '[data-dd-action-name*="Resend" i]',
        )
        for selector in selectors:
            try:
                target = page.locator(selector).first
                if target.is_visible(timeout=800):
                    target.click(timeout=8000)
                    return True
            except Exception:
                pass
        try:
            return bool(page.evaluate(
                r"""() => {
                    const visible = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden'; };
                    const items = Array.from(document.querySelectorAll('button,input[type="submit"],[role="button"]')).filter(visible);
                    const target = items.find(el => /resend|send again|重新发送|再送信|メールを再送信/i.test(
                        `${el.value || ''} ${el.textContent || ''} ${el.getAttribute('aria-label') || ''}`));
                    if (!target || target.disabled || target.getAttribute('aria-disabled') === 'true') return false;
                    target.click(); return true;
                }"""
            ))
        except Exception:
            return False

    @staticmethod
    def _page_state(page) -> dict[str, Any]:
        try:
            return page.evaluate(
                r"""() => ({
                    url: location.href,
                    text: (document.body?.innerText || '').replace(/\s+/g, ' ').slice(0, 1400),
                    passwordInputs: [...document.querySelectorAll('input[type="password"],input[autocomplete="new-password"]')]
                        .filter(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled).length,
                    codeInputs: [...document.querySelectorAll('input[autocomplete="one-time-code"],input[name*="code" i],input[inputmode="numeric"]')]
                        .filter(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled).length,
                })"""
            )
        except Exception:
            return {"url": str(getattr(page, "url", "") or ""), "text": "", "passwordInputs": 0, "codeInputs": 0}

    @staticmethod
    def _click_password_action(page) -> dict[str, Any]:
        try:
            return page.evaluate(
            r"""() => {
                const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                    && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
                    && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
                const desc = el => [el.innerText, el.textContent, el.getAttribute('aria-label'), el.title,
                    el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.getAttribute('href'), el.id, el.name]
                    .filter(Boolean).join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
                const password = /password|密码|パスワード|비밀번호/;
                const action = /add|create|set|update|change|manage|添加|创建|设置|更新|更改|管理|追加|変更|설정|변경/;
                const items = [...document.querySelectorAll('button,a,[role="button"],[role="link"],[role="tab"]')].filter(visible);
                const hit = items.find(el => {
                    const own = desc(el);
                    if (password.test(own) && action.test(own)) return true;
                    if (!password.test(own)) return false;
                    const parent = el.closest('li,section,form,[role="dialog"],div');
                    return action.test(desc(parent || el));
                }) || items.find(el => /password/.test(String(el.getAttribute('data-testid') || '').toLowerCase()));
                if (!hit) return {ok:false, reason:'password_action_missing', samples:items.map(desc).filter(Boolean).slice(0,40)};
                hit.scrollIntoView({block:'center'}); hit.click();
                return {ok:true, detail:desc(hit).slice(0,180)};
            }"""
            ) or {"ok": False, "reason": "empty_result"}
        except Exception as exc:
            return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def _open_settings_surface(page) -> bool:
        """Open the ChatGPT sidebar/settings surface before searching its actions."""
        try:
            return bool(page.evaluate(
                r"""() => {
                    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                        && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
                        && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
                    const desc = el => [el.innerText, el.textContent, el.getAttribute('aria-label'), el.title,
                        el.getAttribute('data-testid'), el.getAttribute('href')]
                        .filter(Boolean).join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
                    const sidebar = [...document.querySelectorAll('button,[role="button"],a')].find(el =>
                        visible(el) && /sidebar|サイドバー|侧边栏/.test(desc(el)) && /open|開く|打开/.test(desc(el)));
                    if (sidebar) sidebar.click();
                    const settings = [...document.querySelectorAll('a,button,[role="button"],[role="link"],[role="tab"]')].find(el =>
                        visible(el) && /settings|設定|设置|href=.*settings/.test(desc(el)));
                    if (settings) { settings.scrollIntoView({block:'center'}); settings.click(); return true; }
                    const profile = [...document.querySelectorAll('button,[role="button"],a')].find(el =>
                        visible(el) && /accounts-profile-button|profile menu|プロファイルメニュー|账户菜单|个人资料/.test(desc(el)));
                    if (profile) profile.click();
                    return !!sidebar || !!profile;
                }"""
            ))
        except Exception:
            return False

    @staticmethod
    def _click_settings_navigation(page, step: str) -> bool:
        try:
            return bool(page.evaluate(
                r"""step => {
                    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                        && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
                    const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
                    const desc = el => [el.innerText, el.textContent, el.getAttribute('aria-label'), el.title,
                        el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.getAttribute('href')]
                        .filter(Boolean).join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
                    const items = [...document.querySelectorAll('button,a,[role="button"],[role="link"],[role="tab"]')]
                        .filter(el => visible(el) && enabled(el));
                    const patterns = {
                        account: /^(account|账户|アカウント|계정)$/,
                        settings: /settings|设置|設定|설정/,
                        profile: /profile|account menu|user menu|个人资料|账户菜单|プロフィール|프로필/
                    };
                    const hit = items.find(el => patterns[String(step || '')]?.test(desc(el)));
                    if (!hit) return false;
                    hit.scrollIntoView({block:'center'}); hit.click(); return true;
                }""",
                step,
            ))
        except Exception:
            return False

    @staticmethod
    def _add_password_via_protocol(page, password: str) -> dict[str, Any]:
        """Add a password through the authenticated OpenAI account endpoint.

        The reset-password page accepts the existing browser login state and is
        more stable than depending on the ChatGPT settings SPA's button labels.
        """
        try:
            page.goto("https://auth.openai.com/reset-password/new-password", wait_until="domcontentloaded", timeout=60000)
            return page.evaluate(
                r"""async password => {
                    const response = await fetch('https://auth.openai.com/api/accounts/password/add', {
                        method: 'POST', credentials: 'include',
                        headers: {'accept':'application/json', 'content-type':'application/json'},
                        body: JSON.stringify({password})
                    });
                    const text = await response.text();
                    let data = null; try { data = JSON.parse(text); } catch (_) {}
                    return {ok: response.ok && (!data || data.success !== false), status: response.status, data, text: text.slice(0, 500)};
                }""",
                password,
            ) or {"ok": False, "reason": "empty_result"}
        except Exception as exc:
            return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}

    def _progress(self, checkpoint: str) -> None:
        try:
            self.on_progress(checkpoint)
        except Exception:
            pass

    @staticmethod
    def _submit_password(page, password: str) -> bool:
        return bool(page.evaluate(
            r"""password => {
                const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                    && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
                    && !el.disabled && !el.readOnly;
                const inputs = [...document.querySelectorAll('input[type="password"],input[autocomplete="new-password"]')].filter(visible);
                if (!inputs.length) return false;
                for (const input of inputs) {
                    input.focus();
                    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                    if (setter) setter.call(input, password); else input.value = password;
                    input.dispatchEvent(new Event('input', {bubbles:true}));
                    input.dispatchEvent(new Event('change', {bubbles:true}));
                }
                const scope = inputs[0].closest('form') || inputs[0].closest('[role="dialog"]') || document;
                const buttons = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')].filter(visible);
                const desc = el => [el.innerText, el.textContent, el.value, el.getAttribute('aria-label')].filter(Boolean).join(' ').toLowerCase();
                const submit = buttons.find(el => /save|continue|submit|update|change|set|保存|继续|提交|更新|更改|设置|続行|確認/.test(desc(el)))
                    || buttons.find(el => String(el.type || '').toLowerCase() === 'submit');
                if (!submit) return false;
                submit.scrollIntoView({block:'center'}); submit.click(); return true;
            }""",
            password,
        ))

    @staticmethod
    def _fill_code(page, code: str) -> bool:
        return bool(page.evaluate(
            r"""code => {
                const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled;
                const inputs = [...document.querySelectorAll('input[autocomplete="one-time-code"],input[name*="code" i],input[inputmode="numeric"]')].filter(visible);
                if (!inputs.length) return false;
                if (inputs.length === 1) {
                    inputs[0].focus(); inputs[0].value = code;
                    inputs[0].dispatchEvent(new Event('input',{bubbles:true}));
                    inputs[0].dispatchEvent(new Event('change',{bubbles:true}));
                } else {
                    [...code].forEach((digit,index) => { if (inputs[index]) { inputs[index].focus(); inputs[index].value=digit; inputs[index].dispatchEvent(new Event('input',{bubbles:true})); } });
                }
                const scope = inputs[0].closest('form') || document;
                const submit = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')].find(el => visible(el)
                    && /continue|verify|submit|继续|验证|提交|続行|確認/i.test(`${el.innerText||''} ${el.value||''} ${el.getAttribute('aria-label')||''}`));
                submit?.click(); return true;
            }""",
            code,
        ))

    @staticmethod
    def _recent_email_code_usable(code: str, code_at: float, now: float | None = None) -> bool:
        current = time.time() if now is None else float(now)
        age = current - float(code_at or 0.0)
        return bool(re.fullmatch(r"\d{6}", str(code or "").strip()) and 0 <= age <= RECENT_EMAIL_CODE_MAX_AGE_SECONDS)

    @staticmethod
    def _email_code_rejected(state: dict[str, Any]) -> bool:
        text = str(state.get("text") or "").lower()
        return any(marker in text for marker in (
            "incorrect code", "invalid code", "wrong code", "code is incorrect", "code has expired",
            "验证码错误", "验证码无效", "验证码已过期", "コードが正しくありません",
        ))

    def _complete_reauthentication(
        self,
        page,
        min_timestamp: float,
        password: str,
        *,
        recent_email_code: str = "",
        recent_email_code_at: float = 0.0,
        force_fresh_email_code: bool = False,
        allow_email_fallback: bool = True,
    ) -> None:
        deadline = time.time() + EMAIL_OTP_INITIAL_WAIT_SECONDS + EMAIL_OTP_RESEND_WAIT_SECONDS
        resend_attempted = False
        email_code_used = False
        recent_code_submitted_at = 0.0
        submitted_email_code = ""
        submitted_recent_code = False
        rejected_codes: set[str] = set()
        totp_used = False
        totp_submitted_at = 0.0
        password_used = False
        email_code_submitted_at = 0.0
        email_code_min_timestamp = min_timestamp
        while time.time() < deadline:
            self._check_cancelled()
            url = str(page.url or "").lower()
            if "chatgpt.com" in url:
                try:
                    self._session_json(page)
                    # A session cookie can be issued before MFA is completed.
                    # Existing TOTP accounts must remain in the state machine
                    # until the second factor has been accepted.
                    if not (self.account.totp_secret and not totp_used):
                        if submitted_recent_code:
                            self.log("[登录密钥] 已成功复用注册/登录阶段邮箱验证码完成重认证")
                        elif email_code_used:
                            self.log("[登录密钥] 已使用邮箱渠道最新验证码完成重认证")
                        return
                except Exception:
                    pass
            state = self._page_state(page)
            if _is_auth_rate_limit_text(f"{state.get('url', '')} {state.get('text', '')}"):
                raise LoginSecretRateLimitError(
                    "ChatGPT 重认证触发 rate_limit_exceeded：OpenAI 返回请求过多，请稍后重试"
                )
            if _is_account_deactivated_text(f"{state.get('url', '')} {state.get('text', '')}"):
                raise RuntimeError(
                    "account_deactivated: OpenAI 登录页报告账户已停用或封禁；已停止 2FA 验证"
                )
            if state.get("passwordInputs") and not password_used:
                if not password or not self._submit_password(page, password):
                    raise RuntimeError("重认证要求密码，但密码输入未能提交")
                password_used = True
                self.log("[登录密钥] AT 刷新重认证：已提交 ChatGPT 密码")
                self._sleep(2)
                continue
            if state.get("codeInputs"):
                recent_code_stalled = submitted_recent_code and email_code_used and recent_code_submitted_at > 0 and time.time() - recent_code_submitted_at >= 8
                if submitted_recent_code and email_code_used and (self._email_code_rejected(state) or recent_code_stalled):
                    self.log("[登录密钥] 注册阶段验证码无法用于重认证，将等待新的邮箱验证码")
                    rejected_codes.add(submitted_email_code)
                    email_code_used = False
                    submitted_recent_code = False
                    email_code_min_timestamp = min_timestamp
                    continue
                page_text = str(state.get("text") or "").lower()
                explicit_totp = any(marker in f"{url} {page_text}" for marker in (
                    "mfa", "totp", "authenticator", "two-factor", "2fa",
                    "認証アプリ", "認証コード", "两步验证", "双重验证", "身份验证器",
                    "인증 앱", "인증 코드",
                ))
                explicit_email = any(marker in page_text for marker in (
                    "email", "e-mail", "メール", "邮箱", "郵箱", "이메일",
                ))
                is_totp = explicit_totp or bool(
                    self.account.totp_secret
                    and (password_used or (email_code_used and time.time() - email_code_submitted_at >= 3))
                    and not explicit_email
                )
                if is_totp:
                    if not totp_used:
                        if not self.account.totp_secret:
                            raise RuntimeError("重认证要求 TOTP，但账户没有 2FA 密钥")
                        if not self._fill_code(page, generate_totp(self.account.totp_secret)):
                            raise RuntimeError("TOTP 重认证输入失败")
                        totp_used = True
                        totp_submitted_at = time.time()
                        self.log("[登录密钥] AT 刷新重认证：已提交 2FA 动态验证码")
                        self._sleep(2)
                        continue
                    if self._email_code_rejected(state):
                        raise RuntimeError("AT 刷新登录的 2FA 动态验证码未通过验证")
                    if totp_submitted_at > 0 and time.time() - totp_submitted_at >= 30:
                        raise TimeoutError("AT 刷新登录提交 2FA 后 30 秒内未完成跳转")
                    self._sleep(0.75)
                    continue
                if not email_code_used:
                    if not allow_email_fallback:
                        raise RuntimeError(
                            "AT 刷新登录未进入密码与 2FA 验证步骤，已禁止回退邮箱验证码"
                        )
                    use_recent_code = bool(
                        not force_fresh_email_code
                        and not self.recent_email_code_attempted
                        and self._recent_email_code_usable(recent_email_code, recent_email_code_at)
                    )
                    if use_recent_code:
                        code = recent_email_code
                        self.recent_email_code_attempted = True
                        self.log("[登录密钥] 优先复用本次注册刚使用的邮箱验证码")
                    else:
                        if (
                            not force_fresh_email_code
                            and not self.recent_email_code_attempted
                            and str(recent_email_code or "").strip()
                        ):
                            self.recent_email_code_attempted = True
                            self.log("[登录密钥] 注册/登录阶段邮箱验证码已超过复用窗口，将读取最新验证码")
                        try:
                            code = self._wait_for_distinct_code(
                                self._reader_instance(), email_code_min_timestamp,
                                rejected_codes, EMAIL_OTP_INITIAL_WAIT_SECONDS,
                            ) if rejected_codes else self._wait_for_code(
                                self._reader_instance(), email_code_min_timestamp,
                                EMAIL_OTP_INITIAL_WAIT_SECONDS,
                            )
                        except TimeoutError as exc:
                            if resend_attempted or not self._click_resend_email_code(page):
                                raise TimeoutError(
                                    "邮箱验证码等待 120 秒后超时，重新发送验证码不可用"
                                ) from exc
                            resend_attempted = True
                            email_code_min_timestamp = time.time() - 2
                            self.log("[邮箱] 120 秒未收到重认证验证码，已重新发送，继续等待 60 秒")
                            try:
                                code = self._wait_for_distinct_code(
                                    self._reader_instance(), email_code_min_timestamp,
                                    rejected_codes, EMAIL_OTP_RESEND_WAIT_SECONDS,
                                ) if rejected_codes else self._wait_for_code(
                                    self._reader_instance(), email_code_min_timestamp,
                                    EMAIL_OTP_RESEND_WAIT_SECONDS,
                                )
                            except TimeoutError as resend_exc:
                                raise TimeoutError("重新发送重认证验证码后等待 60 秒仍未收到验证码") from resend_exc
                    if not self._fill_code(page, code):
                        raise RuntimeError("邮箱重认证验证码输入失败")
                    email_code_used = True
                    submitted_email_code = str(code).strip()
                    submitted_recent_code = use_recent_code
                    email_code_submitted_at = time.time()
                    recent_code_submitted_at = email_code_submitted_at if use_recent_code else 0.0
                    self._sleep(2)
                    continue
            self._sleep(0.75)
        raise TimeoutError(f"ChatGPT 重认证超时: {self._page_state(page)}")

    def _complete_existing_totp_after_email_reauth(self, page) -> None:
        """Finish an existing-account TOTP challenge after email reauth.

        Password enrollment and 2FA enrollment both start from an email
        reauthentication transaction. For an account that already has a TOTP
        factor, the email factor may leave a second MFA page mounted briefly;
        wait for that page and submit the stored secret before returning to the
        caller so it can safely perform the protected account operation.
        """
        if not self.account.totp_secret:
            return
        deadline = time.time() + EMAIL_OTP_RESEND_WAIT_SECONDS
        submitted = False
        submitted_at = 0.0
        no_challenge_started = 0.0
        while time.time() < deadline:
            self._check_cancelled()
            state = self._page_state(page)
            url = str(state.get("url") or "").lower()
            text = str(state.get("text") or "").lower()
            if _is_auth_rate_limit_text(f"{url} {text}"):
                raise LoginSecretRateLimitError(
                    "ChatGPT 重认证触发 rate_limit_exceeded：OpenAI 返回请求过多，请稍后重试"
                )
            if _is_account_deactivated_text(f"{url} {text}"):
                raise RuntimeError("account_deactivated: OpenAI 登录页报告账户已停用或封禁；已停止 2FA 验证")
            # The email transaction has already returned a continue_url. Any
            # remaining one-time-code form belongs to the existing TOTP factor,
            # including localized pages that expose no MFA label.
            if state.get("codeInputs"):
                no_challenge_started = 0.0
                if not submitted:
                    if not self._fill_code(page, generate_totp(self.account.totp_secret)):
                        raise RuntimeError("邮箱重认证后未找到可用的 TOTP 输入控件")
                    submitted = True
                    submitted_at = time.time()
                    self.log("[登录密钥] 邮箱重认证成功，已提交账户已有 2FA 动态验证码")
                    self._sleep(2)
                    continue
                if self._email_code_rejected(state):
                    raise RuntimeError("邮箱重认证后的 2FA 动态验证码未通过验证")
                if time.time() - submitted_at >= LOGIN_SECRET_STEP_TIMEOUT_SECONDS:
                    raise TimeoutError("邮箱重认证提交 2FA 后 30 秒内未完成跳转")
                self._sleep(0.75)
                continue
            if submitted:
                if "chatgpt.com" in url:
                    try:
                        self._session_json(page)
                        return
                    except Exception:
                        pass
            elif "chatgpt.com" in url and not state.get("codeInputs"):
                # The transaction did not request MFA for this session. Do not
                # hold a valid reauthentication indefinitely, but allow the
                # challenge a short time to mount after the continue redirect.
                if not no_challenge_started:
                    no_challenge_started = time.time()
                if time.time() - no_challenge_started >= 8:
                    return
            self._sleep(0.75)
        raise TimeoutError("邮箱重认证后的 2FA 验证超时")

    def _add_password(self, page) -> str:
        password = generate_chatgpt_password()
        protocol_result: dict[str, Any] = {"ok": False, "status": 0}
        try:
            # Password enrollment is a separate reauthentication flow. Try the
            # just-used registration code once, then require a distinct mailbox
            # code if OpenAI rejects it.
            self._dismiss_continue_gate(page)
            self._reauth_for_password(
                page,
                password,
                recent_email_code=self.recent_email_code,
                recent_email_code_at=self.recent_email_code_at,
            )
            protocol_result = self._add_password_via_protocol(page, password)
            status = int(protocol_result.get("status") or 0)
            if not protocol_result.get("ok") and not _password_already_set(protocol_result):
                if status == 409:
                    self.log("[登录密钥] 密码协议接口正在同步认证状态，将保持当前登录态后重试")
                    self._sleep(1.5)
                    protocol_result = self._add_password_via_protocol(page, password)
                elif status in {401, 403}:
                    self.log("[登录密钥] 密码协议接口要求重新认证，将最多重认证一次后重试")
                    self._sleep(1.5)
                    self._reauth_for_password(
                        page,
                        password,
                        recent_email_code=self.recent_email_code,
                        recent_email_code_at=self.recent_email_code_at,
                    )
                    protocol_result = self._add_password_via_protocol(page, password)
        except Exception as exc:
            protocol_result = {"ok": False, "status": 0, "reason": f"{type(exc).__name__}: {exc}"}
        if protocol_result.get("ok"):
            self.account.chatgpt_password = password
            self._persist_credential("password", password)
            self.log("[登录密钥] 已通过 OpenAI 协议接口添加 ChatGPT 密码（内容不写日志）")
            return password
        if _password_already_set(protocol_result):
            raise RuntimeError("远端 ChatGPT 已存在密码，但本地没有密码凭证，无法恢复原密码；请在账户管理中手动录入或重置后重试")
        self.log(
            "[登录密钥] 协议添加密码接口未完成，将回退账户设置页："
            f"HTTP {protocol_result.get('status', 0)} {self._protocol_error_detail(protocol_result)}".strip()
        )
        page.goto(f"{CHATGPT_BASE_URL}/#settings/Account", wait_until="domcontentloaded", timeout=60000)
        if self._dismiss_continue_gate(page):
            self._sleep(1)
        self._sleep(2)
        deadline = time.time() + 60
        navigation_steps = ("account", "settings", "profile")
        navigation_index = 0
        last_result: dict[str, Any] = {}
        while time.time() < deadline:
            self._check_cancelled()
            self._open_settings_surface(page)
            result = self._click_password_action(page)
            last_result = result if isinstance(result, dict) else {"ok": bool(result)}
            if last_result.get("ok"):
                break
            if navigation_index < len(navigation_steps) and self._click_settings_navigation(page, navigation_steps[navigation_index]):
                navigation_index += 1
            self._sleep(1)
        else:
            samples = " | ".join(str(item) for item in (last_result.get("samples") or [])[:8])
            detail = f"；可见控件: {samples}" if samples else ""
            raise RuntimeError(f"账户设置中未找到添加密码入口{detail}")
        submitted = False
        disappeared_at = 0.0
        otp_min_timestamp = time.time()
        while time.time() < deadline + 120:
            state = self._page_state(page)
            url = str(state.get("url") or "").lower()
            if "auth.openai.com" in url and (state.get("codeInputs") or state.get("passwordInputs")):
                self._complete_reauthentication(
                    page,
                    otp_min_timestamp,
                    password,
                    recent_email_code=self.recent_email_code,
                    recent_email_code_at=self.recent_email_code_at,
                )
                continue
            if state.get("passwordInputs") and self._submit_password(page, password):
                submitted = True
                # Preserve the exact generated value before any cancellable
                # wait or browser transition. A successful remote submission
                # followed by a disconnected browser must remain recoverable.
                self.account.chatgpt_password = password
                self._persist_credential("password", password)
                self.log("[登录密钥] 已提交新 ChatGPT 密码（内容不写日志）")
                self._sleep(2)
                continue
            if submitted and not state.get("passwordInputs"):
                if not disappeared_at:
                    disappeared_at = time.time()
                elif time.time() - disappeared_at >= 3:
                    self.account.chatgpt_password = password
                    self._persist_credential("password", password)
                    return password
            self._sleep(0.75)
        raise TimeoutError(f"添加 ChatGPT 密码超时: {self._page_state(page)}")

    @staticmethod
    def _protocol_error_detail(result: dict[str, Any]) -> str:
        data = result.get("data") if isinstance(result, dict) else None
        if isinstance(data, dict):
            for key in ("error", "message", "code", "detail"):
                value = str(data.get(key) or "").strip()
                if value:
                    return value[:240]
        return str(result.get("reason", ""))[:240] if isinstance(result, dict) else ""

    def _reauthenticate_with_fresh_email_code(
        self,
        page,
        auth_url: str,
        min_timestamp: float,
        *,
        recent_email_code: str = "",
        recent_email_code_at: float = 0.0,
        prefer_recent_email_code: bool = False,
    ) -> dict[str, Any]:
        """Validate reauth OTP, optionally trying the just-used registration code first."""
        # url_api readers establish a latest-message baseline in connect().
        # Connect before loading auth_url because that navigation sends the new
        # OTP; otherwise the newly delivered mail can be mistaken for history.
        reader = self._reader_instance()
        page.goto(auth_url, wait_until="domcontentloaded", timeout=60000)
        code_timestamp = min_timestamp
        resend_attempted = False
        rejected_codes: set[str] = set()
        for attempt in range(2):
            using_recent_code = False
            if (
                prefer_recent_email_code
                and not self.recent_email_code_attempted
                and self._recent_email_code_usable(recent_email_code, recent_email_code_at)
            ):
                code = str(recent_email_code).strip()
                self.recent_email_code_attempted = True
                using_recent_code = True
                self.log("[登录密钥] 优先复用注册/登录阶段刚使用的邮箱验证码进行密码重认证")
            else:
                if (
                    prefer_recent_email_code
                    and not self.recent_email_code_attempted
                    and str(recent_email_code or "").strip()
                ):
                    self.recent_email_code_attempted = True
                    self.log("[登录密钥] 注册/登录阶段邮箱验证码已超过复用窗口，将读取最新验证码")
                try:
                    if attempt > 0 and rejected_codes:
                        code = self._wait_for_distinct_code(
                            reader,
                            code_timestamp,
                            rejected_codes,
                            EMAIL_OTP_INITIAL_WAIT_SECONDS,
                        )
                    else:
                        code = self._wait_for_code(reader, code_timestamp, EMAIL_OTP_INITIAL_WAIT_SECONDS)
                except TimeoutError as exc:
                    if resend_attempted or not self._click_resend_email_code(page):
                        raise TimeoutError("邮箱验证码等待 120 秒后超时，重新发送验证码不可用") from exc
                    resend_attempted = True
                    code_timestamp = time.time() - 2
                    self.log("[邮箱] 120 秒未收到重认证验证码，已重新发送，继续等待 60 秒")
                    try:
                        code = self._wait_for_distinct_code(
                            reader,
                            code_timestamp,
                            rejected_codes,
                            EMAIL_OTP_RESEND_WAIT_SECONDS,
                        ) if rejected_codes else self._wait_for_code(
                            reader, code_timestamp, EMAIL_OTP_RESEND_WAIT_SECONDS
                        )
                    except TimeoutError as resend_exc:
                        raise TimeoutError("重新发送重认证验证码后等待 60 秒仍未收到验证码") from resend_exc
            result = page.evaluate(
                r"""async code => {
                    const response = await fetch('https://auth.openai.com/api/accounts/email-otp/validate', {
                        method:'POST', credentials:'include',
                        headers:{'accept':'application/json','content-type':'application/json'},
                        body:JSON.stringify({code})
                    });
                    const text = await response.text();
                    let data = null; try { data = JSON.parse(text); } catch (_) {}
                    return {ok:response.ok, status:response.status, data, text:text.slice(0,500)};
                }""",
                code,
            ) or {"ok": False, "status": 0}
            data = result.get("data") if isinstance(result, dict) else None
            continue_url = str((data or {}).get("continue_url") or "") if isinstance(data, dict) else ""
            if result.get("ok") and continue_url:
                if using_recent_code:
                    self.log("[登录密钥] 已成功复用注册/登录阶段邮箱验证码完成重认证")
                else:
                    self.log("[登录密钥] 已使用邮箱渠道最新验证码完成重认证")
                break
            if attempt == 0 and _wrong_email_otp(result, result.get("text", "") if isinstance(result, dict) else ""):
                rejected_codes.add(str(code).strip())
                if using_recent_code:
                    self.log("[登录密钥] 注册/登录阶段验证码未通过密码重认证，将通过当前邮箱渠道读取新验证码后重试")
                else:
                    self.log("[登录密钥] 重认证验证码无效，将重新读取最新邮箱验证码后重试")
                code_timestamp = min_timestamp
                continue
            raise RuntimeError(f"邮箱重认证验证码校验失败: HTTP {result.get('status', 0)} {self._protocol_error_detail(result)}".strip())
        else:
            raise RuntimeError("邮箱重认证验证码校验失败: 未获取到有效验证码")
        page.goto(continue_url, wait_until="domcontentloaded", timeout=60000)
        self._ensure_chatgpt_page(page)
        if self._dismiss_continue_gate(page):
            self._sleep(1)
        self._complete_existing_totp_after_email_reauth(page)
        return self._session_json(page)

    def _reauth_for_password(
        self,
        page,
        password: str,
        *,
        recent_email_code: str = "",
        recent_email_code_at: float = 0.0,
    ) -> dict[str, Any]:
        """Start the dedicated post-registration password reauthentication flow."""
        self._ensure_chatgpt_page(page)
        if self._dismiss_continue_gate(page):
            self._sleep(1)
        payload = page.evaluate(
            """async ({email}) => {
                const csrfResponse = await fetch('/api/auth/csrf', {credentials:'include'});
                if (!csrfResponse.ok) return {ok:false,status:csrfResponse.status};
                const csrf = await csrfResponse.json();
                const query = new URLSearchParams({
                    connection:'password', login_hint:email, reauth:'password',
                    post_login_add_password:'true', max_age:'0'
                });
                const body = new URLSearchParams({
                    callbackUrl:'https://chatgpt.com/?action=add_password',
                    csrfToken:csrf.csrfToken, json:'true'
                });
                const response = await fetch('/api/auth/signin/openai?' + query.toString(), {
                    method:'POST', credentials:'include',
                    headers:{'content-type':'application/x-www-form-urlencoded'},
                    body:body.toString()
                });
                const text = await response.text();
                let data={}; try { data=JSON.parse(text); } catch (_) {}
                return {ok:response.ok,status:response.status,data};
            }""",
            {"email": self.account.email},
        )
        auth_url = str(((payload or {}).get("data") or {}).get("url") or "")
        if not payload.get("ok") or not auth_url:
            raise RuntimeError(f"发起添加密码重认证失败: HTTP {payload.get('status')}")
        # Set the lower bound before navigation because loading auth_url triggers
        # delivery of the new OTP email.
        min_timestamp = time.time()
        return self._reauthenticate_with_fresh_email_code(
            page,
            auth_url,
            min_timestamp,
            recent_email_code=recent_email_code,
            recent_email_code_at=recent_email_code_at,
            prefer_recent_email_code=bool(recent_email_code),
        )

    def _reauth_for_2fa(
        self,
        page,
        password: str,
        *,
        recent_email_code: str = "",
        recent_email_code_at: float = 0.0,
    ) -> dict[str, Any]:
        self._ensure_chatgpt_page(page)
        payload = page.evaluate(
            """async ({email}) => {
                const csrfResponse = await fetch('/api/auth/csrf', {credentials:'include'});
                if (!csrfResponse.ok) return {ok:false,status:csrfResponse.status};
                const csrf = await csrfResponse.json();
                const query = new URLSearchParams({connection:'password',login_hint:email,reauth:'password',max_age:'0'});
                const body = new URLSearchParams({callbackUrl:'https://chatgpt.com/?action=enable&factor=totp',csrfToken:csrf.csrfToken,json:'true'});
                const response = await fetch('/api/auth/signin/openai?' + query.toString(), {
                    method:'POST',credentials:'include',headers:{'content-type':'application/x-www-form-urlencoded'},body:body.toString()
                });
                const text = await response.text();
                let data={}; try { data=JSON.parse(text); } catch (_) {}
                return {ok:response.ok,status:response.status,data};
            }""",
            {"email": self.account.email},
        )
        auth_url = str(((payload or {}).get("data") or {}).get("url") or "")
        if not payload.get("ok") or not auth_url:
            raise RuntimeError(f"发起 2FA 重认证失败: HTTP {payload.get('status')}")
        min_timestamp = time.time()
        # The reference flow validates this new OTP through the protocol and
        # follows continue_url so pwd_auth_time is refreshed before MFA calls.
        return self._reauthenticate_with_fresh_email_code(
            page,
            auth_url,
            min_timestamp,
            prefer_recent_email_code=False,
        )

    @staticmethod
    def _mfa_info(page, access_token: str) -> dict[str, Any]:
        return page.evaluate(
            """async token => {
                const headers = {'accept':'application/json'};
                if (token) headers.authorization = 'Bearer ' + token;
                const response = await fetch('/backend-api/accounts/mfa_info', {credentials:'include',headers});
                const text=await response.text(); let data={}; try { data=JSON.parse(text); } catch (_) {}
                return {ok:response.ok,status:response.status,data,text:text.slice(0,500)};
            }""",
            access_token,
        )

    @staticmethod
    def _enroll_totp(page, access_token: str) -> dict[str, Any]:
        return page.evaluate(
            """async token => {
                const headers = {'accept':'application/json','content-type':'application/json'};
                if (token) headers.authorization = 'Bearer ' + token;
                const response = await fetch('/backend-api/accounts/mfa/enroll', {
                    method:'POST',credentials:'include',headers,body:JSON.stringify({factor_type:'totp'})
                });
                const text=await response.text(); let data={}; try { data=JSON.parse(text); } catch (_) {}
                return {ok:response.ok,status:response.status,data,text:text.slice(0,500)};
            }""",
            access_token,
        )

    @staticmethod
    def _activate_totp(page, access_token: str, code: str, session_id: str) -> dict[str, Any]:
        return page.evaluate(
            """async ({token,code,sessionId}) => {
                const headers = {'accept':'application/json','content-type':'application/json'};
                if (token) headers.authorization = 'Bearer ' + token;
                const response = await fetch('/backend-api/accounts/mfa/user/activate_enrollment', {
                    method:'POST',credentials:'include',headers,
                    body:JSON.stringify({code,factor_type:'totp',session_id:sessionId})
                });
                const text=await response.text(); let data={}; try { data=JSON.parse(text); } catch (_) {}
                return {ok:response.ok,status:response.status,data,text:text.slice(0,500)};
            }""",
            {"token": access_token, "code": code, "sessionId": session_id},
        )

    @staticmethod
    def _totp_factors(info: dict[str, Any]) -> list[dict[str, Any]]:
        data = info.get("data") if isinstance(info, dict) else {}
        factors = (data or {}).get("factors") if isinstance(data, dict) else {}
        items = (factors or {}).get("totp") if isinstance(factors, dict) else []
        return [item for item in (items or []) if isinstance(item, dict)]

    def _fresh_totp_code(self, secret: str, *, force_next_window: bool = False) -> str:
        remaining = 30 - (time.time() % 30)
        if force_next_window or remaining <= 5:
            self._sleep(remaining + 0.25)
        return generate_totp(secret)

    @staticmethod
    def _require_mfa_response(result: dict[str, Any], operation: str) -> None:
        status = int(result.get("status") or 0) if isinstance(result, dict) else 0
        if status in {401, 403}:
            raise MFAReauthenticationRequired(f"{operation}要求重新认证: HTTP {status}")
        if not isinstance(result, dict) or not result.get("ok"):
            raise RuntimeError(f"{operation}失败: HTTP {status}")

    def _setup_2fa_protocol(self, page, access_token: str) -> tuple[str, dict[str, Any]]:
        info_before = self._mfa_info(page, access_token)
        self._require_mfa_response(info_before, "查询 2FA 状态")
        info_data = info_before.get("data") or {}
        if not isinstance(info_data, dict):
            raise RuntimeError("查询 2FA 状态失败: 响应不是有效 JSON 对象")
        if info_data.get("mfa_enabled") is True or self._totp_factors(info_before):
            raise RuntimeError("ChatGPT 已启用 TOTP，但本地没有对应 2FA 密钥，无法恢复原密钥")

        result = self._enroll_totp(page, access_token)
        self._require_mfa_response(result, "2FA enroll")
        enroll = result.get("data") if isinstance(result, dict) else {}
        secret = str((enroll or {}).get("secret") or "").strip()
        session_id = str((enroll or {}).get("session_id") or "").strip()
        factor_id = str(((enroll or {}).get("factor") or {}).get("id") or "").strip()
        if not secret or not session_id:
            raise RuntimeError("2FA enroll 响应缺少 secret 或 session_id")

        activation: dict[str, Any] = {}
        for attempt in range(2):
            code = self._fresh_totp_code(secret, force_next_window=attempt > 0)
            activation = self._activate_totp(page, access_token, code, session_id)
            status = int((activation or {}).get("status") or 0)
            if status in {401, 403}:
                if status == 401 and attempt == 0:
                    self.log("[登录密钥] 2FA 动态验证码可能已过期，等待下一个验证码窗口后重试")
                    continue
                raise MFAReauthenticationRequired(f"2FA activate 要求重新认证: HTTP {status}")
            activation_data = activation.get("data") if isinstance(activation, dict) else {}
            if isinstance(activation, dict) and activation.get("ok") and isinstance(activation_data, dict) and activation_data.get("success") is True:
                break
        else:
            status = activation.get("status") if isinstance(activation, dict) else 0
            raise RuntimeError(f"2FA activate 失败: HTTP {status}")

        info_after = self._mfa_info(page, access_token)
        self._require_mfa_response(info_after, "确认 2FA 状态")
        info_after_data = info_after.get("data") or {}
        if not isinstance(info_after_data, dict):
            raise RuntimeError("确认 2FA 状态失败: 响应不是有效 JSON 对象")
        confirmed_factors = self._totp_factors(info_after)
        confirmed = bool(info_after_data.get("mfa_enabled") is True and confirmed_factors)
        if factor_id:
            confirmed = confirmed and any(str(item.get("id") or "") == factor_id for item in confirmed_factors)
        if not confirmed:
            raise RuntimeError("2FA activate 返回成功，但 mfa_info 未确认 TOTP 已启用")
        self.account.totp_secret = secret
        self._persist_credential("totp_secret", secret)
        return secret, self._session_json(page)

    def _setup_2fa(self, page, password: str) -> tuple[str, dict[str, Any]]:
        self._ensure_chatgpt_page(page)
        session_json = self._session_json(page)
        access_token = str(session_json.get("accessToken") or session_json.get("access_token") or "")
        try:
            return self._setup_2fa_protocol(page, access_token)
        except MFAReauthenticationRequired:
            self.log("[登录密钥] 2FA 协议接口要求重新认证，将使用当前邮箱渠道完成一次重认证后重试")
        session_json = self._reauth_for_2fa(
            page,
            password,
            recent_email_code=self.recent_email_code,
            recent_email_code_at=self.recent_email_code_at,
        )
        access_token = str(session_json.get("accessToken") or session_json.get("access_token") or "")
        return self._setup_2fa_protocol(page, access_token)

    def _run_on_page(self, page, context) -> dict[str, Any]:
        result: dict[str, Any] = {
            "password": self.account.chatgpt_password,
            "totp_secret": self.account.totp_secret,
            "password_added": False,
            "totp_added": False,
            "errors": [],
            "access_token_refreshed": False,
        }
        if result["password"] and result["totp_secret"] and not self.force_access_token_refresh:
            result["skipped"] = True
            result["complete"] = True
            self.log("[登录密钥] 已存在完整密码与 2FA，跳过设置步骤")
            return result
        self._progress("login_secret_started")
        self._ensure_chatgpt_page(page)
        if self._dismiss_continue_gate(page):
            self._sleep(1)
        current_session = self._session_json(page)
        if not self.account.chatgpt_password:
            self._progress("login_secret_password")
            self.log("[登录密钥] 开始添加 ChatGPT 密码")
            try:
                password = self._add_password(page)
                self.account.chatgpt_password = password
                self._persist_credential("password", password)
                result.update({"password": password, "password_added": True})
                self.log("[登录密钥] ChatGPT 密码添加成功，继续复用当前认证状态添加 2FA")
            except Exception as exc:
                result["errors"].append(f"添加密码失败: {exc}")
                self.log(f"[登录密钥] ChatGPT 密码添加失败，停止后续 2FA：{str(exc)[:240]}")
        else:
            self.log("[登录密钥] 账户已有 ChatGPT 密码，跳过密码添加阶段")
        if not self.account.totp_secret:
            self._progress("login_secret_2fa")
            if not self.account.chatgpt_password:
                result["errors"].append("添加2FA未执行: ChatGPT 密码尚未完成")
                self.log("[登录密钥] ChatGPT 密码尚未完成，跳过 2FA 设置")
            else:
                self.log("[登录密钥] 开始添加 ChatGPT 2FA（复用密码添加成功后的当前认证状态）")
                try:
                    secret, current_session = self._setup_2fa(page, self.account.chatgpt_password)
                    self._persist_credential("totp_secret", secret)
                    result.update({"totp_secret": secret, "totp_added": True})
                    self.log("[登录密钥] ChatGPT 2FA 添加成功")
                except Exception as exc:
                    result["errors"].append(f"添加2FA失败: {exc}")
                    self.log(f"[登录密钥] ChatGPT 2FA 添加失败，保留已完成的密码：{str(exc)[:240]}")
        else:
            self.log("[登录密钥] 账户已有 2FA 密钥，跳过 2FA 添加阶段")
        security_changed = bool(result["password_added"] or result["totp_added"])
        security_complete = bool(result.get("password") and result.get("totp_secret"))
        should_refresh_access_token = security_complete and (security_changed or self.force_access_token_refresh)
        if should_refresh_access_token:
            self._progress("login_secret_at_refresh")
            candidate_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
            try:
                if self._access_token_is_valid(page, candidate_token):
                    self.log("[登录密钥] 添加密码与 2FA 后检测到当前 Access Token 仍有效，直接更新存储")
                else:
                    self.log("[登录密钥] 当前 Access Token 已失效，使用密码与 2FA 协议重新登录获取最新 Access Token")
                    current_session = self._refresh_session_with_login_secret(page)
                    refreshed_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
                    if not self._access_token_is_valid(page, refreshed_token):
                        raise RuntimeError(
                            "密码与 2FA 重新登录后获取的 Access Token 未通过有效性检测"
                            f"：{self.last_access_token_probe_error}"
                        )
                    self.on_session_saved(current_session)
                result["access_token_refreshed"] = True
                self.log("[登录密钥] 已确认有效的 ChatGPT Access Token，将替换旧 AT 存储")
            except Exception as exc:
                result["errors"].append(f"刷新 ChatGPT Access Token 失败: {exc}")
                self.log(f"[登录密钥] ChatGPT Access Token 刷新失败：{str(exc)[:240]}")
                # Do not persist the post-security-change session unless its AT
                # passed the probe. Keep the registration checkpoint as-is so a
                # later LS retry can replace it with a confirmed token.
                original_token = str(self.session.get("access_token") or "")
                if original_token:
                    current_session = {
                        **(
                            self.session.get("session_json")
                            if isinstance(self.session.get("session_json"), dict)
                            else {}
                        ),
                        "accessToken": original_token,
                    }
        elif security_changed or self.force_access_token_refresh:
            self.log("[登录密钥] 密码与 2FA 尚未同时完成，跳过 Access Token 刷新，避免重复等待邮箱验证码")
        result["session"] = self._updated_session(current_session, context.storage_state())
        result["complete"] = bool(
            result.get("password")
            and result.get("totp_secret")
            and (not should_refresh_access_token or result["access_token_refreshed"])
        )
        at_status = "已更新" if result.get("access_token_refreshed") else (
            "更新失败" if should_refresh_access_token else "未触发"
        )
        self.log(
            "[登录密钥] 流程完成："
            f"密码={'已完成' if result.get('password') else '未完成'}，"
            f"2FA={'已完成' if result.get('totp_secret') else '未完成'}，"
            f"AT={at_status}"
        )
        self._progress("login_secret_completed" if result["complete"] else "login_secret_failed")
        return result

    def run(self, *, browser_page=None, browser_context=None) -> dict[str, Any]:
        """Set up LS, reusing an active registration browser when supplied.

        The registration flow owns the browser in that case. Standalone add-LS
        tasks continue to use an isolated Camoufox context as before.
        """
        if browser_page is not None or browser_context is not None:
            if browser_page is None or browser_context is None:
                raise ValueError("browser_page and browser_context must be supplied together")
            try:
                return self._run_on_page(browser_page, browser_context)
            finally:
                if self.reader:
                    self.reader.close()
        if self.account.chatgpt_password and self.account.totp_secret and not self.force_access_token_refresh:
            self.log("[登录密钥] 已存在完整密码与 2FA，跳过设置步骤")
            return {
                "password": self.account.chatgpt_password,
                "totp_secret": self.account.totp_secret,
                "password_added": False,
                "totp_added": False,
                "skipped": True,
                "complete": True,
                "errors": [],
            }
        try:
            with open_registration_browser(
                headless=True,
                proxy_url=self.proxy_url,
                fingerprint=generate_register_fingerprint(),
                log=self.log,
                storage_state=self._storage_state(),
            ) as browser_session:
                context = browser_session.context
                if self.traffic_optimizer is not None:
                    self.traffic_optimizer.attach(context)
                page = context.new_page()
                return self._run_on_page(page, context)
        finally:
            if self.reader:
                self.reader.close()


class ProtocolLoginSecretSetupFlow:
    """Set up LS through the protocol session that completed registration.

    This flow deliberately does not create a Playwright/Camoufox context. The
    protocol registration cookie jar is kept alive by ProtocolRegistrationFlow
    until this callback returns.
    """

    def __init__(
        self,
        account: MailAccount,
        session: dict[str, Any],
        protocol_session: Any,
        log: Callable[[str], None] | None = None,
        *,
        should_cancel: Callable[[], bool] | None = None,
        mailbox_proxy_url: str | None = None,
        on_progress: Callable[[str], None] | None = None,
        recent_email_code: str = "",
        recent_email_code_at: float = 0.0,
        on_credential_saved: Callable[[str, str], None] | None = None,
        on_session_saved: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.account = account
        self.session = dict(session or {})
        self.http = protocol_session
        self.log = log or (lambda _message: None)
        self.should_cancel = should_cancel or (lambda: False)
        self.mailbox_proxy_url = mailbox_proxy_url or ""
        self.on_progress = on_progress or (lambda _checkpoint: None)
        self.recent_email_code = str(recent_email_code or "").strip()
        self.recent_email_code_at = float(recent_email_code_at or 0.0)
        self.recent_email_code_attempted = False
        self.on_credential_saved = on_credential_saved or (lambda _kind, _value: None)
        self.on_session_saved = on_session_saved or (lambda _session: None)
        self._persisted_credentials: set[tuple[str, str]] = set()
        self.last_access_token_probe_error = ""
        self.reader: Any | None = None

    def _persist_credential(self, kind: str, value: str) -> None:
        value = str(value or "").strip()
        checkpoint = (str(kind or "").strip(), value)
        if value and checkpoint not in self._persisted_credentials:
            self.on_credential_saved(*checkpoint)
            self._persisted_credentials.add(checkpoint)

    def _check_cancelled(self) -> None:
        if self.should_cancel():
            from .openai_auth import TaskCancelledError

            raise TaskCancelledError("Task cancelled by user")

    def _reader_instance(self):
        if self.reader is None:
            self.reader = create_mailbox_reader(self.account, self.log, self.mailbox_proxy_url)
            self.reader.connect()
        return self.reader

    _recent_email_code_usable = staticmethod(LoginSecretSetupFlow._recent_email_code_usable)

    @staticmethod
    def _wait_for_code(reader, min_timestamp: float, timeout: int) -> str:
        try:
            return reader.wait_for_code(min_timestamp, timeout)
        except TypeError as exc:
            if "positional" not in str(exc) and "argument" not in str(exc):
                raise
            return reader.wait_for_code(min_timestamp)

    def _wait_for_distinct_code(
        self,
        reader,
        min_timestamp: float,
        excluded_codes: set[str],
        timeout: int,
    ) -> str:
        deadline = time.monotonic() + max(1, int(timeout))
        cursor = min_timestamp
        while time.monotonic() < deadline:
            remaining = max(1, min(10, int(deadline - time.monotonic())))
            try:
                code = str(self._wait_for_code(reader, cursor, remaining) or "").strip()
            except TimeoutError:
                continue
            if re.fullmatch(r"\d{6}", code) and code not in excluded_codes:
                return code
            if code:
                self.log("[邮箱] 邮箱读取器返回了历史验证码，继续等待不同的新验证码")
            time.sleep(0.25)
        raise TimeoutError(f"在 {int(timeout)} 秒内未获取到不同的新邮箱验证码")

    def _request(self, method: str, url: str, **kwargs) -> tuple[int, Any, str]:
        self._check_cancelled()
        kwargs.setdefault("timeout", 30)
        response = self.http.request(method, url, **kwargs)
        text = str(getattr(response, "text", "") or "")
        try:
            data = response.json()
        except Exception:
            data = None
        return int(getattr(response, "status_code", 0) or 0), data, text[:800]

    @staticmethod
    def _require_ok(status: int, data: Any, text: str, operation: str) -> Any:
        if status < 200 or status >= 300:
            raise RuntimeError(f"{operation}失败: HTTP {status} {text[:240]}")
        return data

    def _session_json(self) -> dict[str, Any]:
        status, data, text = self._request(
            "GET",
            f"{CHATGPT_BASE_URL}/api/auth/session",
            headers={"accept": "application/json", "cache-control": "no-cache", "pragma": "no-cache"},
        )
        payload = self._require_ok(status, data, text, "读取 ChatGPT Session")
        if not isinstance(payload, dict) or not (payload.get("accessToken") or payload.get("access_token")):
            raise RuntimeError("ChatGPT 登录态已失效")
        return payload

    def _access_token_is_valid(self, access_token: str) -> bool:
        token = str(access_token or "").strip()
        if not token:
            self.last_access_token_probe_error = "账户没有 Access Token"
            return False
        try:
            from .access_token_probe import probe_access_token

            protocol_flow = getattr(self.http, "_flow", None)
            proxy_url = str(getattr(protocol_flow, "proxy_url", "") or "")
            result = probe_access_token(token, proxy_url)
        except Exception as exc:
            self.last_access_token_probe_error = f"AT 探测异常: {exc}"
            return False
        if isinstance(result, dict) and result.get("status") == "valid":
            self.last_access_token_probe_error = ""
            return True
        self.last_access_token_probe_error = str(
            (result or {}).get("error") or (result or {}).get("status") or "AT 未通过有效性检测"
        )
        return False

    def _refresh_session_with_login_secret(self) -> dict[str, Any]:
        refresh = getattr(self.http, "refresh_session_with_login_secret", None)
        if not callable(refresh):
            raise RuntimeError("当前协议登录态不支持使用登录密钥刷新 ChatGPT Session")
        result = refresh()
        session_json = result.get("session_json") if isinstance(result, dict) else None
        if not isinstance(session_json, dict) or not (session_json.get("accessToken") or session_json.get("access_token")):
            raise RuntimeError("协议登录密钥重认证未返回新的 ChatGPT Access Token")
        previous_token = str(self.session.get("access_token") or "")
        current_token = str(session_json.get("accessToken") or session_json.get("access_token") or "")
        if previous_token and current_token == previous_token:
            raise RuntimeError("协议登录密钥重认证后仍返回注册阶段的旧 Access Token")
        return session_json

    def _updated_session(self, current_session: dict[str, Any]) -> dict[str, Any]:
        access_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
        if not access_token:
            raise RuntimeError("登录密钥设置完成后未获取到新的 ChatGPT Access Token")
        updated = {
            **self.session,
            "access_token": access_token,
            "session_json": current_session,
        }
        if access_token != str(self.session.get("access_token") or ""):
            updated.pop("expires_at", None)
        if str(updated.get("id_token") or "") == str(self.session.get("access_token") or ""):
            updated["id_token"] = access_token
        return updated

    def _complete_existing_totp_protocol(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Complete an MFA page returned by the password reauth transaction."""
        if not self.account.totp_secret or not isinstance(payload, dict):
            return payload
        page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
        continue_url = str(payload.get("continue_url") or payload.get("continueUrl") or "")
        page_type = str(page.get("type") or "")
        if page_type != "mfa_challenge" and "/mfa-challenge/" not in continue_url:
            return payload
        auth_session = payload.get("oai-client-auth-session")
        auth_session = auth_session if isinstance(auth_session, dict) else {}
        factors: list[dict[str, Any]] = []
        for key in ("mfa_challenge_factors", "mfa_factors"):
            values = auth_session.get(key)
            if isinstance(values, list):
                factors.extend(item for item in values if isinstance(item, dict))
        factor = next((item for item in factors if item.get("factor_type") == "totp" and item.get("id")), None)
        if not factor:
            raise RuntimeError("邮箱重认证后要求 2FA，但协议响应没有可用的 TOTP 因子")
        common_headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "origin": AUTH_BASE_URL,
            "referer": continue_url or AUTH_BASE_URL,
        }
        status, _issued, text = self._request(
            "POST",
            f"{AUTH_BASE_URL}/api/accounts/mfa/issue_challenge",
            headers=common_headers,
            json={"type": "totp", "id": factor["id"], "force_fresh_challenge": False},
        )
        self._require_ok(status, _issued, text, "Issue TOTP challenge")
        status, verified, text = self._request(
            "POST",
            f"{AUTH_BASE_URL}/api/accounts/mfa/verify",
            headers=common_headers,
            json={"type": "totp", "id": factor["id"], "code": generate_totp(self.account.totp_secret)},
        )
        verified = self._require_ok(status, verified, text, "Verify TOTP challenge")
        self.log("[登录密钥] 邮箱重认证成功，已通过协议提交账户已有 2FA 动态验证码")
        return verified if isinstance(verified, dict) else payload

    def _reauthenticate(
        self,
        callback_url: str,
        *,
        prefer_recent_email_code: bool = False,
        post_login_add_password: bool = False,
    ) -> dict[str, Any]:
        status, csrf, text = self._request("GET", f"{CHATGPT_BASE_URL}/api/auth/csrf", headers={"accept": "application/json"})
        csrf = self._require_ok(status, csrf, text, "读取 ChatGPT CSRF")
        csrf_token = str((csrf or {}).get("csrfToken") or "") if isinstance(csrf, dict) else ""
        if not csrf_token:
            raise RuntimeError("ChatGPT CSRF 响应缺少 csrfToken")
        from urllib.parse import urlencode

        query_params = {
            "connection": "password",
            "login_hint": self.account.email,
            "reauth": "password",
            "max_age": "0",
        }
        protocol_flow = getattr(self.http, "_flow", None)
        device_id = str(getattr(protocol_flow, "device_id", "") or "").strip()
        if device_id:
            query_params["ext-oai-did"] = device_id
        if post_login_add_password:
            query_params["post_login_add_password"] = "true"
        query = urlencode(query_params)
        body = urlencode({"callbackUrl": callback_url, "csrfToken": csrf_token, "json": "true"})
        status, payload, text = self._request(
            "POST",
            f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}",
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "origin": CHATGPT_BASE_URL,
                "referer": f"{CHATGPT_BASE_URL}/",
            },
            data=body,
        )
        payload = self._require_ok(status, payload, text, "发起 ChatGPT 重认证")
        auth_url = str(((payload or {}).get("url") or ((payload or {}).get("data") or {}).get("url") or "")) if isinstance(payload, dict) else ""
        if not auth_url:
            raise RuntimeError("ChatGPT 重认证响应缺少认证地址")
        # Snapshot the mailbox before GET auth_url triggers OTP delivery. This
        # prevents URL-based readers from recording the new OTP as baseline.
        reader = self._reader_instance()
        sent_at = time.time()
        status, _data, text = self._request(
            "GET",
            auth_url,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "referer": f"{CHATGPT_BASE_URL}/",
            },
            allow_redirects=True,
        )
        if status >= 400:
            raise RuntimeError(f"加载 ChatGPT 重认证页面失败: HTTP {status} {text[:180]}")
        code_timestamp = sent_at
        rejected_codes: set[str] = set()
        resend_attempted = False
        for attempt in range(2):
            using_recent_code = False
            if (
                prefer_recent_email_code
                and not self.recent_email_code_attempted
                and self._recent_email_code_usable(self.recent_email_code, self.recent_email_code_at)
            ):
                code = self.recent_email_code
                self.recent_email_code_attempted = True
                using_recent_code = True
                self.log("[登录密钥] 优先复用注册/登录阶段刚使用的邮箱验证码进行密码重认证")
            else:
                if (
                    prefer_recent_email_code
                    and not self.recent_email_code_attempted
                    and str(self.recent_email_code or "").strip()
                ):
                    self.recent_email_code_attempted = True
                    self.log("[登录密钥] 注册/登录阶段邮箱验证码已超过复用窗口，将读取最新验证码")
                try:
                    code = self._wait_for_distinct_code(
                        reader,
                        code_timestamp,
                        rejected_codes,
                        EMAIL_OTP_INITIAL_WAIT_SECONDS,
                    ) if rejected_codes else self._wait_for_code(
                        reader, code_timestamp, EMAIL_OTP_INITIAL_WAIT_SECONDS
                    )
                except TimeoutError as exc:
                    if resend_attempted:
                        raise TimeoutError("邮箱验证码等待 120 秒后超时，重认证重发次数已用尽") from exc
                    sent_at = time.time() - 2
                    resend_status, _resend_payload, resend_text = self._request(
                        "GET",
                        f"{AUTH_BASE_URL}/api/accounts/email-otp/send",
                        headers={
                            "accept": "application/json, text/plain, */*",
                            "origin": AUTH_BASE_URL,
                            "referer": auth_url,
                        },
                    )
                    if resend_status != 200:
                        raise RuntimeError(
                            f"重新发送 OpenAI 邮箱验证码失败: HTTP {resend_status} {resend_text[:180]}"
                        ) from exc
                    resend_attempted = True
                    self.log("[邮箱] 120 秒未收到协议重认证验证码，已重新发送，继续等待 60 秒")
                    code_timestamp = sent_at
                    try:
                        code = self._wait_for_distinct_code(
                            reader,
                            code_timestamp,
                            rejected_codes,
                            EMAIL_OTP_RESEND_WAIT_SECONDS,
                        ) if rejected_codes else self._wait_for_code(
                            reader, code_timestamp, EMAIL_OTP_RESEND_WAIT_SECONDS
                        )
                    except TimeoutError as resend_exc:
                        raise TimeoutError("重新发送协议重认证验证码后等待 60 秒仍未收到验证码") from resend_exc
            status, payload, text = self._request(
                "POST",
                EMAIL_OTP_VALIDATE_URL,
                headers={"accept": "application/json", "content-type": "application/json", "origin": AUTH_BASE_URL, "referer": auth_url},
                json={"code": code},
            )
            if 200 <= status < 300:
                if using_recent_code:
                    self.log("[登录密钥] 已成功复用注册/登录阶段邮箱验证码完成重认证")
                else:
                    self.log("[登录密钥] 已使用邮箱渠道最新验证码完成重认证")
                break
            if attempt == 0 and _wrong_email_otp({"data": payload}, text):
                rejected_codes.add(str(code).strip())
                if using_recent_code:
                    self.log("[登录密钥] 注册/登录阶段验证码未通过密码重认证，将通过当前邮箱渠道读取新验证码后重试")
                else:
                    self.log("[登录密钥] 重认证验证码无效，将重新读取最新邮箱验证码后重试")
                code_timestamp = sent_at
                continue
            self._require_ok(status, payload, text, "邮箱重认证验证码校验")
        else:
            self._require_ok(status, payload, text, "邮箱重认证验证码校验")
        payload = self._require_ok(status, payload, text, "邮箱重认证验证码校验")
        payload = self._complete_existing_totp_protocol(payload)
        continue_url = str((payload or {}).get("continue_url") or "") if isinstance(payload, dict) else ""
        if not continue_url:
            raise RuntimeError("邮箱重认证验证码校验成功，但响应缺少 continue_url")
        self._request(
            "GET",
            continue_url,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "referer": f"{AUTH_BASE_URL}/email-verification",
            },
            allow_redirects=True,
        )
        return self._session_json()

    def _add_password(self, password: str) -> dict[str, Any]:
        self._reauthenticate(
            f"{CHATGPT_BASE_URL}/?action=add_password",
            prefer_recent_email_code=True,
            post_login_add_password=True,
        )
        for attempt in range(2):
            status, data, text = self._request(
                "POST",
                PASSWORD_ADD_URL,
                headers={"accept": "application/json", "content-type": "application/json", "origin": AUTH_BASE_URL},
                json={"password": password},
            )
            result = {"status": status, "data": data, "error": data.get("error") if isinstance(data, dict) else None}
            if _password_already_set(result):
                raise RuntimeError("远端 ChatGPT 已存在密码，但本地没有密码凭证，无法恢复原密码；请在账户管理中手动录入或重置后重试")
            if 200 <= status < 300:
                self.log("[登录密钥] 已通过同一协议登录态添加 ChatGPT 密码（内容不写日志）")
                self.account.chatgpt_password = password
                self._persist_credential("password", password)
                return self._session_json()
            invalid_step = _invalid_auth_step(result, text)
            invalid_state = _invalid_auth_state(result, text)
            if invalid_step or invalid_state:
                from .protocol_auth import ProtocolChallengeRequired

                reason = "认证步骤不匹配" if invalid_step else "认证状态已失效"
                self.log(
                    f"[登录密钥] 邮箱重认证已成功，但添加密码专用认证事务{reason}，"
                    "将携带当前 Cookie 会话由浏览器设置页接管，不再重复获取邮箱验证码"
                )
                raise ProtocolChallengeRequired(
                    "OpenAI 拒绝协议添加密码专用认证事务，需由当前 Cookie 会话的浏览器设置页接管"
                )
            if attempt == 0 and status == 409:
                self.log("[登录密钥] 密码协议接口正在同步认证状态，将保持当前登录态后重试")
                time.sleep(1.5)
                continue
            if attempt == 0 and status in {401, 403}:
                self.log("[登录密钥] 密码协议接口要求重新认证，将最多重认证一次后重试")
                self._reauthenticate(
                    f"{CHATGPT_BASE_URL}/?action=add_password",
                    prefer_recent_email_code=True,
                    post_login_add_password=True,
                )
                continue
            self._require_ok(status, data, text, "添加 ChatGPT 密码")
        raise RuntimeError("添加 ChatGPT 密码失败: 未获得有效响应")

    @staticmethod
    def _auth_headers(access_token: str, *, json_body: bool = False) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if json_body:
            headers["content-type"] = "application/json"
        if access_token:
            headers["authorization"] = f"Bearer {access_token}"
        return headers

    def _mfa_request(self, method: str, url: str, access_token: str, **kwargs) -> tuple[int, Any, str]:
        kwargs["headers"] = {**self._auth_headers(access_token, json_body=method.upper() == "POST"), **(kwargs.get("headers") or {})}
        return self._request(method, url, **kwargs)

    @staticmethod
    def _totp_factors(data: Any) -> list[dict[str, Any]]:
        factors = data.get("factors") if isinstance(data, dict) else {}
        items = factors.get("totp") if isinstance(factors, dict) else []
        return [item for item in (items or []) if isinstance(item, dict)]

    def _setup_2fa(self, access_token: str) -> tuple[str, dict[str, Any]]:
        status, info, text = self._mfa_request("GET", MFA_INFO_URL, access_token)
        if status in {401, 403}:
            session_json = self._reauthenticate(
                f"{CHATGPT_BASE_URL}/?action=enable&factor=totp",
                prefer_recent_email_code=False,
            )
            access_token = str(session_json.get("accessToken") or session_json.get("access_token") or "")
            status, info, text = self._mfa_request("GET", MFA_INFO_URL, access_token)
        info = self._require_ok(status, info, text, "查询 2FA 状态")
        info_data = info if isinstance(info, dict) else {}
        if info_data.get("mfa_enabled") is True or self._totp_factors(info_data):
            raise RuntimeError("ChatGPT 已启用 TOTP，但本地没有对应 2FA 密钥，无法恢复原密钥")
        status, enrolled, text = self._mfa_request("POST", MFA_ENROLL_URL, access_token, json={"factor_type": "totp"})
        enrolled = self._require_ok(status, enrolled, text, "2FA enroll")
        secret = str((enrolled or {}).get("secret") or "") if isinstance(enrolled, dict) else ""
        session_id = str((enrolled or {}).get("session_id") or "") if isinstance(enrolled, dict) else ""
        factor_id = str(((enrolled or {}).get("factor") or {}).get("id") or "") if isinstance(enrolled, dict) else ""
        if not secret or not session_id:
            raise RuntimeError("2FA enroll 响应缺少 secret 或 session_id")
        activation = None
        for attempt in range(2):
            remaining = 30 - (time.time() % 30)
            if attempt > 0 or remaining <= 5:
                time.sleep(remaining + 0.25)
            code = generate_totp(secret)
            status, activation, text = self._mfa_request(
                "POST", MFA_ACTIVATE_URL, access_token,
                json={"code": code, "factor_type": "totp", "session_id": session_id},
            )
            data = activation if isinstance(activation, dict) else {}
            if status == 401 and attempt == 0:
                self.log("[登录密钥] 2FA 动态验证码可能已过期，等待下一个验证码窗口后重试")
                continue
            if status in {401, 403}:
                raise MFAReauthenticationRequired(f"2FA activate 要求重新认证: HTTP {status}")
            if status == 200 and data.get("success") is True:
                break
        else:
            raise RuntimeError(f"2FA activate 失败: HTTP {status}")
        status, confirmed, text = self._mfa_request("GET", MFA_INFO_URL, access_token)
        confirmed = self._require_ok(status, confirmed, text, "确认 2FA 状态")
        confirmed_factors = self._totp_factors(confirmed)
        confirmed_ok = bool(isinstance(confirmed, dict) and confirmed.get("mfa_enabled") is True and confirmed_factors)
        if factor_id:
            confirmed_ok = confirmed_ok and any(str(item.get("id") or "") == factor_id for item in confirmed_factors)
        if not confirmed_ok:
            raise RuntimeError("2FA activate 返回成功，但 mfa_info 未确认 TOTP 已启用")
        self.account.totp_secret = secret
        self._persist_credential("totp_secret", secret)
        return secret, self._session_json()

    def run(self) -> dict[str, Any]:
        result: dict[str, Any] = {"password": self.account.chatgpt_password, "totp_secret": self.account.totp_secret, "password_added": False, "totp_added": False, "access_token_refreshed": False, "errors": []}
        if result["password"] and result["totp_secret"]:
            result.update({"skipped": True, "complete": True})
            self.log("[登录密钥] 已存在完整密码与 2FA，跳过设置步骤")
            return result
        self.on_progress("login_secret_started")
        try:
            current_session = self._session_json()
            if not self.account.chatgpt_password:
                self.on_progress("login_secret_password")
                self.log("[登录密钥] 开始添加 ChatGPT 密码")
                try:
                    password = generate_chatgpt_password()
                    current_session = self._add_password(password)
                    self.account.chatgpt_password = password
                    self._persist_credential("password", password)
                    result.update({"password": password, "password_added": True})
                    self.log("[登录密钥] ChatGPT 密码添加成功，继续复用当前认证状态添加 2FA")
                except Exception as exc:
                    result["errors"].append(f"添加密码失败: {exc}")
                    self.log(f"[登录密钥] ChatGPT 密码添加失败，停止后续 2FA：{str(exc)[:240]}")
                    if exc.__class__.__name__ == "ProtocolChallengeRequired":
                        result["browser_challenge_required"] = True
            else:
                self.log("[登录密钥] 账户已有 ChatGPT 密码，跳过密码添加阶段")
            if not self.account.totp_secret:
                self.on_progress("login_secret_2fa")
                if not self.account.chatgpt_password:
                    result["errors"].append("添加2FA未执行: ChatGPT 密码尚未完成")
                    self.log("[登录密钥] ChatGPT 密码尚未完成，跳过 2FA 设置")
                else:
                    self.log("[登录密钥] 开始添加 ChatGPT 2FA（复用密码添加成功后的当前认证状态）")
                    try:
                        access_token = str(current_session.get("accessToken") or current_session.get("access_token") or self.session.get("access_token") or "")
                        secret, current_session = self._setup_2fa(access_token)
                        # Keep the shared task account in sync. A later
                        # browser takeover for AT refresh reuses this object
                        # to decide whether security setup is still required.
                        self.account.totp_secret = secret
                        self._persist_credential("totp_secret", secret)
                        result.update({"totp_secret": secret, "totp_added": True})
                        self.log("[登录密钥] ChatGPT 2FA 添加成功")
                    except Exception as exc:
                        result["errors"].append(f"添加2FA失败: {exc}")
                        self.log(f"[登录密钥] ChatGPT 2FA 添加失败，保留已完成的密码：{str(exc)[:240]}")
                        if exc.__class__.__name__ == "ProtocolChallengeRequired":
                            result["browser_challenge_required"] = True
            else:
                self.log("[登录密钥] 账户已有 2FA 密钥，跳过 2FA 添加阶段")
            security_changed = bool(result["password_added"] or result["totp_added"])
            security_complete = bool(result.get("password") and result.get("totp_secret"))
            should_refresh_access_token = security_complete and security_changed
            if should_refresh_access_token:
                self.on_progress("login_secret_at_refresh")
                candidate_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
                try:
                    if self._access_token_is_valid(candidate_token):
                        self.log("[登录密钥] 添加密码与 2FA 后检测到当前 Access Token 仍有效，直接更新存储")
                    else:
                        self.log("[登录密钥] 当前 Access Token 已失效，使用密码与 2FA 协议重新登录获取最新 Access Token")
                        current_session = self._refresh_session_with_login_secret()
                        refreshed_token = str(current_session.get("accessToken") or current_session.get("access_token") or "")
                        if not self._access_token_is_valid(refreshed_token):
                            raise RuntimeError(
                                "密码与 2FA 重新登录后获取的 Access Token 未通过有效性检测"
                                f"：{self.last_access_token_probe_error}"
                            )
                        self.on_session_saved(current_session)
                    result["access_token_refreshed"] = True
                    self.log("[登录密钥] 已确认有效的 ChatGPT Access Token，将替换旧 AT 存储")
                except Exception as exc:
                    result["errors"].append(f"刷新 ChatGPT Access Token 失败: {exc}")
                    self.log(f"[登录密钥] ChatGPT Access Token 刷新失败：{str(exc)[:240]}")
                    original_token = str(self.session.get("access_token") or "")
                    if original_token:
                        current_session = {
                            **(
                                self.session.get("session_json")
                                if isinstance(self.session.get("session_json"), dict)
                                else {}
                            ),
                            "accessToken": original_token,
                        }
                    if exc.__class__.__name__ == "ProtocolChallengeRequired":
                        result["browser_challenge_required"] = True
            elif security_changed:
                self.log("[登录密钥] 密码与 2FA 尚未同时完成，跳过 Access Token 刷新，避免重复等待邮箱验证码")
            result["session"] = self._updated_session(current_session)
            result["complete"] = bool(
                result.get("password")
                and result.get("totp_secret")
                and (not should_refresh_access_token or result["access_token_refreshed"])
            )
            at_status = "已更新" if result.get("access_token_refreshed") else (
                "更新失败" if should_refresh_access_token else "未触发"
            )
            self.log(
                "[登录密钥] 流程完成："
                f"密码={'已完成' if result.get('password') else '未完成'}，"
                f"2FA={'已完成' if result.get('totp_secret') else '未完成'}，"
                f"AT={at_status}"
            )
            self.on_progress("login_secret_completed" if result["complete"] else "login_secret_failed")
            return result
        finally:
            if self.reader:
                self.reader.close()


def setup_login_secret(
    account: MailAccount,
    session: dict[str, Any],
    proxy_url: str = "",
    log: Callable[[str], None] | None = None,
    *,
    should_cancel: Callable[[], bool] | None = None,
    mailbox_proxy_url: str | None = None,
    traffic_meter: ProxyTrafficMeter | None = None,
    on_progress: Callable[[str], None] | None = None,
    recent_email_code: str = "",
    recent_email_code_at: float = 0.0,
    force_access_token_refresh: bool = False,
    browser_page=None,
    browser_context=None,
    on_credential_saved: Callable[[str, str], None] | None = None,
    on_session_saved: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    return LoginSecretSetupFlow(
        account,
        session,
        proxy_url,
        log,
        should_cancel=should_cancel,
        mailbox_proxy_url=mailbox_proxy_url,
        traffic_meter=traffic_meter,
        on_progress=on_progress,
        recent_email_code=recent_email_code,
        recent_email_code_at=recent_email_code_at,
        force_access_token_refresh=force_access_token_refresh,
        on_credential_saved=on_credential_saved,
        on_session_saved=on_session_saved,
    ).run(browser_page=browser_page, browser_context=browser_context)


def setup_login_secret_protocol(
    account: MailAccount,
    session: dict[str, Any],
    protocol_session: Any,
    log: Callable[[str], None] | None = None,
    *,
    should_cancel: Callable[[], bool] | None = None,
    mailbox_proxy_url: str | None = None,
    on_progress: Callable[[str], None] | None = None,
    recent_email_code: str = "",
    recent_email_code_at: float = 0.0,
    on_credential_saved: Callable[[str, str], None] | None = None,
    on_session_saved: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    return ProtocolLoginSecretSetupFlow(
        account,
        session,
        protocol_session,
        log,
        should_cancel=should_cancel,
        mailbox_proxy_url=mailbox_proxy_url,
        on_progress=on_progress,
        recent_email_code=recent_email_code,
        recent_email_code_at=recent_email_code_at,
        on_credential_saved=on_credential_saved,
        on_session_saved=on_session_saved,
    ).run()
