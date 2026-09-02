from __future__ import annotations

import base64
import http.client
import json
import os
import random
import secrets
import shutil
import subprocess
import threading
import tempfile
import time
import uuid
import queue
from typing import Any, Callable

from .proxy import playwright_proxy


SENTINEL_BASE = os.environ.get("SENTINEL_BASE_URL", "https://sentinel.openai.com")
SENTINEL_SDK_VERSION = os.environ.get("SENTINEL_SDK_VERSION", "20260124ceb8")
SENTINEL_FRAME_VERSION = os.environ.get("SENTINEL_FRAME_VERSION", "20260219f9f6")
SENTINEL_SDK_URL = f"{SENTINEL_BASE}/sentinel/{SENTINEL_SDK_VERSION}/sdk.js"
SENTINEL_REQ_URL = f"{SENTINEL_BASE}/backend-api/sentinel/req"
SENTINEL_FRAME_URL = f"{SENTINEL_BASE}/backend-api/sentinel/frame.html?sv={SENTINEL_FRAME_VERSION}"
SENTINEL_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)


def generate_datadog_trace_headers() -> dict[str, str]:
    trace_hex = secrets.token_hex(8).rjust(16, "0")
    parent_hex = secrets.token_hex(8).rjust(16, "0")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": str(int(parent_hex, 16)),
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(int(trace_hex, 16)),
    }


class SentinelTokenGenerator:
    def __init__(self, device_id: str, user_agent: str, *, persona: Any | None = None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent
        self.persona = persona
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a32(text: str) -> str:
        value = 2166136261
        for char in text:
            value ^= ord(char)
            value = (value * 16777619) & 0xFFFFFFFF
        value ^= value >> 16
        value = (value * 2246822507) & 0xFFFFFFFF
        value ^= value >> 13
        value = (value * 3266489909) & 0xFFFFFFFF
        value ^= value >> 16
        return f"{value & 0xFFFFFFFF:08x}"

    @staticmethod
    def _b64(data: Any) -> str:
        payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(payload).decode("ascii")

    def _config(self) -> list[Any]:
        perf_now = 1000 + random.random() * 49000
        persona = self.persona
        screen = str(getattr(persona, "screen", "") or "1920x1080")
        locale = str(getattr(persona, "locale", "") or "ja-JP")
        languages = str(getattr(persona, "sentinel_languages", "") or "ja-JP,ja")
        return [
            screen,
            time.strftime("%a, %d %b %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime()),
            4294705152,
            random.random(),
            self.user_agent,
            SENTINEL_SDK_URL,
            None,
            None,
            locale,
            languages,
            random.random(),
            "webkitTemporaryStorage√undefined",
            "location",
            "Object",
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            int(time.time() * 1000 - perf_now),
        ]

    def requirements_token(self) -> str:
        config = self._config()
        config[3] = 1
        config[9] = round(5 + random.random() * 45)
        return "gAAAAAC" + self._b64(config)

    def proof_token(self, seed: str, difficulty: str) -> str:
        config = self._config()
        started = int(time.time() * 1000)
        target = str(difficulty or "0")
        for nonce in range(500000):
            config[3] = nonce
            config[9] = round(int(time.time() * 1000) - started)
            encoded = self._b64(config)
            if self._fnv1a32((seed or "") + encoded)[: len(target)] <= target:
                return "gAAAAAB" + encoded + "~S"
        return "gAAAAAB" + self._b64(None)


class SentinelBrowserRuntime:
    """Generate Sentinel VM tokens while registration requests stay HTTP-only."""

    _sdk_lock = threading.Lock()
    _sdk_code: str | None = None

    def __init__(
        self,
        session: Any,
        *,
        proxy_url: str = "",
        log: Callable[[str], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        persona: Any | None = None,
    ) -> None:
        self.log = log or (lambda _message: None)
        self.should_cancel = should_cancel or (lambda: False)
        self.persona = persona
        self._manager: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._owns_context = False
        try:
            from camoufox.sync_api import Camoufox  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "Sentinel 协议运行时需要 Camoufox；请安装 python-worker 依赖并执行 python -m camoufox fetch"
            ) from exc

        self._check_cancelled()
        locale = str(getattr(persona, "locale", "") or "ja-JP")
        launch_options: dict[str, Any] = {
            "headless": "virtual" if os.getenv("SUNNY_CONTAINERIZED", "").lower() in {"1", "true", "yes"} else True,
            "locale": locale,
            "block_webrtc": True,
        }
        proxy = playwright_proxy(proxy_url)
        if proxy:
            launch_options["proxy"] = proxy
            launch_options["geoip"] = True
        self._manager = Camoufox(**launch_options)
        try:
            self._browser = self._manager.__enter__()
            if hasattr(self._browser, "new_context"):
                # Camoufox's patched Firefox protocol does not accept Playwright's
                # isMobile viewport field. Disabling the default viewport prevents
                # Browser.setDefaultViewport from emitting that incompatible field.
                self._context = self._browser.new_context(no_viewport=True, locale=locale)
                self._owns_context = True
            else:
                self._context = self._browser
            self._page = self._context.new_page()
            try:
                self._page.goto(
                    "https://auth.openai.com/about-you",
                    wait_until="domcontentloaded",
                    timeout=30_000,
                )
            except Exception:
                self._page.goto("about:blank", wait_until="domcontentloaded", timeout=10_000)
            sdk_code = self._load_sdk(session)
            hook = "t.token=ye,t}({});"
            replacement = "t.___n=_n,t.__Nt=Nt,t.__D=D,t.__jt=jt,t.token=ye,t}({});"
            patched = sdk_code.replace(hook, replacement) if hook in sdk_code else sdk_code
            # Keep the SDK's own PoW state alongside its browser-proof helpers.
            # The reference free-registration flow uses this instance for both
            # requirements and enforcement tokens; Python-generated PoW only
            # passes the Sentinel endpoint's shallow validation.
            patched = patched.replace("var P=new _;", "var P=new _;globalThis.__debugP=P;")
            self._page.evaluate("code => window.eval(code)", patched)
            if self._page.evaluate("typeof window.SentinelSDK") != "object":
                raise RuntimeError("Sentinel SDK 初始化失败")
            self.log("[认证] 已启动 Sentinel 协议运行时；仅浏览器证明生成使用 Camoufox，注册请求仍走 HTTP/TLS")
        except Exception:
            self.close()
            raise

    def _check_cancelled(self) -> None:
        if self.should_cancel():
            from .openai_auth import TaskCancelledError

            raise TaskCancelledError("Task cancelled by user")

    @classmethod
    def _load_sdk(cls, session: Any) -> str:
        with cls._sdk_lock:
            if cls._sdk_code:
                return cls._sdk_code
            bundled = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "tools", "pay153_checkout", "sentinel_sdk_full.js")
            )
            if os.path.isfile(bundled):
                try:
                    with open(bundled, "r", encoding="utf-8") as handle:
                        code = handle.read()
                except OSError:
                    code = ""
                if code:
                    cls._sdk_code = code
                    return code
            response = session.get(SENTINEL_SDK_URL, timeout=30)
            if int(getattr(response, "status_code", 0) or 0) >= 400:
                raise RuntimeError(f"Sentinel SDK 获取失败: HTTP {getattr(response, 'status_code', 0)}")
            code = str(getattr(response, "text", "") or "")
            if not code:
                raise RuntimeError("Sentinel SDK 返回为空")
            cls._sdk_code = code
            return code

    @staticmethod
    def _valid_observer_token(value: str) -> str:
        if not value:
            return ""
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", errors="ignore").lower()
        except Exception:
            return value
        if any(marker in decoded for marker in ("syntaxerror", "typeerror", "error:")):
            return ""
        return value

    def requirements_token(self) -> str:
        """Return the real SDK requirements token for the next `/req` call."""
        self._check_cancelled()
        value = self._page.evaluate(
            """async () => {
              const runtime = window.__debugP;
              if (!runtime || typeof runtime.getRequirementsToken !== 'function') {
                throw new Error('Sentinel SDK requirements API unavailable');
              }
              return await runtime.getRequirementsToken();
            }"""
        )
        token = str(value or "").strip()
        if not token:
            raise RuntimeError("Sentinel SDK returned an empty requirements token")
        return token

    def build_headers(
        self,
        *,
        challenge_payload: dict[str, Any],
        cached_proof: str,
        enforcement: str,
        device_id: str,
        flow: str,
    ) -> dict[str, str]:
        self._check_cancelled()
        result = self._page.evaluate(
            """async ({chatReq, cachedProof, flow}) => {
              const sdk = window.SentinelSDK;
              const runtime = window.__debugP;
              if (runtime && typeof runtime.getEnforcementToken === 'function' &&
                  typeof sdk.__D === 'function' && typeof sdk.___n === 'function') {
                const enforcement = await runtime.getEnforcementToken(chatReq);
                sdk.__D(chatReq, cachedProof);
                const turnstile = chatReq.turnstile || {};
                const observer = chatReq.so || {};
                const t = turnstile.dx ? await sdk.___n(chatReq, turnstile.dx) : '';
                let so = '';
                if (observer.collector_dx && typeof sdk.__Nt === 'function') {
                  so = await sdk.__Nt(observer.collector_dx);
                }
                if (!so && observer.snapshot_dx && typeof sdk.__jt === 'function') {
                  so = await sdk.__jt(observer.snapshot_dx, cachedProof);
                }
                return {mode: 'internal', enforcement, t, so};
              }
              const token = await sdk.token(flow);
              const so = typeof sdk.sessionObserverToken === 'function'
                ? await sdk.sessionObserverToken(flow)
                : null;
              return {mode: 'public', token, so};
            }""",
            {"chatReq": challenge_payload, "cachedProof": cached_proof, "flow": flow},
        )
        result = result if isinstance(result, dict) else {}
        if result.get("mode") == "public":
            token = result.get("token")
            if isinstance(token, str):
                token = json.loads(token)
            if not isinstance(token, dict):
                raise RuntimeError("Sentinel SDK 未返回有效 token")
        else:
            turnstile = challenge_payload.get("turnstile")
            turnstile = turnstile if isinstance(turnstile, dict) else {}
            t_value = str(result.get("t") or "")
            if turnstile.get("required") and not t_value:
                raise RuntimeError("Sentinel Turnstile VM 未生成 t token")
            token = {
                "p": str(result.get("enforcement") or enforcement),
                "t": t_value,
                "c": str(challenge_payload.get("token") or ""),
                "id": device_id,
                "flow": flow,
            }
        # The SDK returns null enforcement when the server did not request a
        # second PoW. In that case the requirements proof is the same value the
        # official client keeps in the payload; do not emit an empty `p` field.
        token["p"] = token.get("p") or cached_proof
        headers = {"openai-sentinel-token": json.dumps(token, separators=(",", ":"))}
        so_value = result.get("so")
        if isinstance(so_value, str):
            try:
                parsed_so = json.loads(so_value)
            except json.JSONDecodeError:
                parsed_so = None
            if isinstance(parsed_so, dict):
                headers["openai-sentinel-so-token"] = json.dumps(parsed_so, separators=(",", ":"))
            else:
                observer = self._valid_observer_token(so_value)
                if observer:
                    headers["openai-sentinel-so-token"] = json.dumps(
                        {"so": observer, "c": str(challenge_payload.get("token") or ""), "id": device_id, "flow": flow},
                        separators=(",", ":"),
                    )
        self._check_cancelled()
        return headers

    def close(self) -> None:
        context, manager = self._context, self._manager
        self._page = None
        self._context = None
        self._browser = None
        self._manager = None
        if self._owns_context and context is not None:
            try:
                context.close()
            except Exception:
                pass
        if manager is not None:
            try:
                manager.__exit__(None, None, None)
            except Exception:
                pass


class SentinelNodeRuntime:
    """Generate Sentinel proofs in an isolated Node V8/jsdom process.

    Firefox exposes cross-origin values through Xray wrappers.  The Sentinel
    SDK's TypedArray-heavy device challenge is rejected by that boundary on
    some Camoufox versions, which makes the protocol path fail before the
    account login request is sent.  Running the same bundled SDK in Node keeps
    the proof generation inside one JavaScript realm and avoids that failure.
    """

    def __init__(
        self,
        session: Any,
        *,
        proxy_url: str = "",
        log: Callable[[str], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        persona: Any | None = None,
    ) -> None:
        del session, proxy_url
        self.log = log or (lambda _message: None)
        self.should_cancel = should_cancel or (lambda: False)
        self.persona = persona
        self._node = os.environ.get("SUNNY_NODE_BINARY") or os.environ.get("NODE_BINARY") or shutil.which("node")
        if not self._node:
            raise RuntimeError("Sentinel Node V8 runtime requires Node.js, but no node executable was found")
        self._script = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "tools", "pay153_checkout", "gen_token_jsdom.js")
        )
        self._server_script = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "tools", "pay153_checkout", "sentinel_vm", "sentinel-server.js")
        )
        if not os.path.isfile(self._script) or not os.path.isfile(self._server_script):
            raise RuntimeError("Sentinel Node VM scripts are missing from the deployment")
        self._server_dir = os.path.dirname(self._server_script)
        self._sdk_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "tools", "pay153_checkout", "sentinel_sdk_full.js")
        )
        self._server_process: subprocess.Popen[str] | None = None
        self._server_port = 0
        self._server_lock = threading.Lock()
        self.log("[认证] Sentinel Node V8 运行时已就绪；证明生成不经过 Firefox Xray")

    def _check_cancelled(self) -> None:
        if self.should_cancel():
            from .openai_auth import TaskCancelledError

            raise TaskCancelledError("Task cancelled by user")

    def _run(self, payload: dict[str, Any], *, timeout: int = 60) -> dict[str, Any]:
        self._check_cancelled()
        fd, input_file = tempfile.mkstemp(prefix="sunny_sentinel_", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            try:
                result = subprocess.run(
                    [self._node, self._script, input_file],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    cwd=os.path.dirname(self._script),
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"Sentinel Node VM timed out after {timeout} seconds") from exc
            self._check_cancelled()
            output = str(result.stdout or "")
            marker = "=== JSON_OUTPUT ==="
            if result.returncode != 0:
                detail = str(result.stderr or output).strip().replace("\r", " ").replace("\n", " ")
                raise RuntimeError(f"Sentinel Node VM exited with code {result.returncode}: {detail[:500]}")
            if marker not in output:
                detail = str(result.stderr or output).strip().replace("\r", " ").replace("\n", " ")
                raise RuntimeError(f"Sentinel Node VM produced no JSON output: {detail[:500]}")
            raw = output.split(marker, 1)[1].strip()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Sentinel Node VM returned invalid JSON: {exc}") from exc
            if not isinstance(data, dict):
                raise RuntimeError("Sentinel Node VM returned a non-object result")
            return data
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

    def requirements_token(self) -> str:
        result = self._run({"action": "requirements", "userAgent": self._persona_user_agent()})
        token = str(result.get("request_p") or "").strip()
        if not token:
            raise RuntimeError("Sentinel Node SDK returned an empty requirements token")
        return token

    def _persona_user_agent(self) -> str:
        return str(getattr(self.persona, "user_agent", "") or "") or SENTINEL_USER_AGENT

    def _persona_locale(self) -> str:
        return str(getattr(self.persona, "locale", "") or "") or "ja-JP"

    def _persona_languages(self) -> str:
        return str(getattr(self.persona, "sentinel_languages", "") or "") or "ja-JP,ja"

    def build_headers(
        self,
        *,
        challenge_payload: dict[str, Any],
        cached_proof: str,
        enforcement: str,
        device_id: str,
        flow: str,
    ) -> dict[str, str]:
        del enforcement
        challenge = dict(challenge_payload)
        challenge["_python_proof"] = cached_proof
        persona = self.persona
        result = self._v8_request(
            {
                "challenge": challenge,
                "flow": flow,
                "device_id": device_id,
                "user_agent": self._persona_user_agent(),
                "page_url": "https://auth.openai.com/about-you",
                "script_src": SENTINEL_SDK_URL,
                "sdk": self._sdk_path if os.path.isfile(self._sdk_path) else None,
                "width": int(getattr(persona, "screen_width", 0) or 0) or 1920,
                "height": int(getattr(persona, "screen_height", 0) or 0) or 1080,
                "cores": int(getattr(persona, "hardware_concurrency", 0) or 0) or 8,
                "language": self._persona_locale(),
                "languages": self._persona_languages() + ",en",
                "no_cookie": True,
            }
        )
        final_p = str(result.get("p") or cached_proof or "").strip()
        if final_p != str(cached_proof or "").strip() and not final_p.startswith("gAAAAAB"):
            raise RuntimeError("Sentinel Node SDK returned an invalid enforcement token")
        turnstile = challenge_payload.get("turnstile") if isinstance(challenge_payload.get("turnstile"), dict) else {}
        t_value = str(result.get("t") or "").strip()
        if turnstile.get("required") and not t_value:
            raise RuntimeError("Sentinel Node VM did not generate the required Turnstile token")
        if not final_p:
            raise RuntimeError("Sentinel Node SDK returned an empty enforcement token")
        token = {
            "p": final_p,
            "c": str(challenge_payload.get("token") or ""),
            "id": device_id,
            "flow": flow,
        }
        if t_value:
            token["t"] = t_value
        headers = {"openai-sentinel-token": json.dumps(token, separators=(",", ":"))}
        so_value = result.get("so")
        if isinstance(so_value, str) and so_value.strip():
            try:
                parsed_so = json.loads(so_value)
            except json.JSONDecodeError:
                parsed_so = None
            if isinstance(parsed_so, dict):
                headers["openai-sentinel-so-token"] = json.dumps(parsed_so, separators=(",", ":"))
            else:
                headers["openai-sentinel-so-token"] = json.dumps(
                    {"so": so_value, "c": str(challenge_payload.get("token") or ""), "id": device_id, "flow": flow},
                    separators=(",", ":"),
                )
        return headers

    def _ensure_v8_server(self) -> None:
        if self._server_process is not None and self._server_process.poll() is None and self._server_port:
            return
        with self._server_lock:
            if self._server_process is not None and self._server_process.poll() is None and self._server_port:
                return
            self._stop_v8_server()
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            process = subprocess.Popen(
                [self._node, self._server_script],
                cwd=self._server_dir,
                env={**os.environ, "SENTINEL_SERVER_PORT": "0"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creation_flags,
            )
            self._server_process = process
            if process.stderr is not None:
                def drain_stderr(stream: Any) -> None:
                    for _line in stream:
                        pass

                threading.Thread(
                    target=drain_stderr,
                    args=(process.stderr,),
                    daemon=True,
                    name="sentinel-v8-stderr",
                ).start()
            ready: queue.Queue[str] = queue.Queue(maxsize=1)

            def read_ready() -> None:
                line = process.stdout.readline() if process.stdout else ""
                try:
                    ready.put_nowait(line)
                except queue.Full:
                    pass

            threading.Thread(target=read_ready, daemon=True, name="sentinel-v8-ready").start()
            try:
                line = ready.get(timeout=15)
                payload = json.loads(line)
                port = int(payload.get("port") or 0)
                if not payload.get("ready") or port <= 0:
                    raise RuntimeError("invalid Sentinel V8 server ready response")
                self._server_port = port
            except Exception as exc:
                self._stop_v8_server()
                raise RuntimeError(f"Sentinel V8 server failed to start: {exc}") from exc

    def _stop_v8_server(self) -> None:
        process = self._server_process
        self._server_process = None
        self._server_port = 0
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass

    def _v8_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._ensure_v8_server()
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            connection = http.client.HTTPConnection("127.0.0.1", self._server_port, timeout=60)
            try:
                connection.request("POST", "/token", body=body, headers={"content-type": "application/json", "content-length": str(len(body))})
                response = connection.getresponse()
                raw = response.read().decode("utf-8", errors="replace")
            finally:
                connection.close()
            data = json.loads(raw)
            if response.status >= 400 or not data.get("ok"):
                raise RuntimeError(str(data.get("error") or f"Sentinel V8 HTTP {response.status}"))
            token = json.loads(str(data.get("token") or "{}"))
            if not isinstance(token, dict):
                raise RuntimeError("Sentinel V8 server returned an invalid token")
            return token
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
            with self._server_lock:
                self._stop_v8_server()
            raise RuntimeError(f"Sentinel V8 worker request failed: {exc}") from exc

    def close(self) -> None:
        with self._server_lock:
            self._stop_v8_server()


def browser_fetch(
    page,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout_ms: int = 30000,
) -> dict[str, Any]:
    return page.evaluate(
        """async ({url, method, headers, body, timeoutMs}) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          try {
            const response = await fetch(url, {
              method, headers: headers || {},
              body: body === null ? undefined : body,
              credentials: 'include', redirect: 'follow', signal: controller.signal,
            });
            const text = await response.text();
            let data = null;
            try { data = JSON.parse(text); } catch (_) {}
            return {ok: response.ok, status: response.status, url: response.url || url, text, data};
          } catch (error) {
            return {ok: false, status: 0, url, text: String(error && error.message || error), data: null};
          } finally { clearTimeout(timer); }
        }""",
        {"url": url, "method": method, "headers": headers or {}, "body": body, "timeoutMs": timeout_ms},
    )


def build_sentinel_token(
    page,
    device_id: str,
    flow: str,
    user_agent: str,
    *,
    timeout_ms: int = 60000,
) -> str:
    generator = SentinelTokenGenerator(device_id, user_agent)
    request_body = json.dumps(
        {"p": generator.requirements_token(), "id": device_id, "flow": flow},
        separators=(",", ":"),
    )
    result = browser_fetch(
        page,
        SENTINEL_REQ_URL,
        method="POST",
        headers={
            "accept": "*/*",
            "accept-language": "ja-JP,ja;q=0.9",
            "content-type": "text/plain;charset=UTF-8",
            "origin": SENTINEL_BASE,
            "referer": SENTINEL_FRAME_URL,
        },
        body=request_body,
        timeout_ms=timeout_ms,
    )
    data = result.get("data") if isinstance(result, dict) else None
    data = data if isinstance(data, dict) else {}
    challenge = str(data.get("token") or "").strip()
    if not challenge:
        return ""
    proof = data.get("proofofwork") if isinstance(data.get("proofofwork"), dict) else {}
    if proof.get("required") and proof.get("seed"):
        value = generator.proof_token(str(proof.get("seed")), str(proof.get("difficulty") or "0"))
    else:
        value = generator.requirements_token()
    return json.dumps(
        {"p": value, "t": "", "c": challenge, "id": device_id, "flow": flow},
        separators=(",", ":"),
    )
