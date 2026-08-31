import json
import re
import os
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "app" / "src"))

from opai.core.payment_inbox import (  # noqa: E402
    InboxStore,
    ProxyPreflightError,
    _ManualRegisterManager,
    _PinManager,
    _WebPaymentManager,
    _find_gopay_account,
    _load_gopay_accounts,
    _load_gopay_accounts_raw,
    _normalize_proxy_url,
    _preflight_gopay_proxy,
    _proxy_preflight_error,
    _release_gopay_sms,
    _refresh_gopay_balance,
    _refresh_gopay_pin_status,
    _sms_api_status,
    _write_sms_config,
    _write_gopay_accounts_raw,
)
from opai.core.captcha_provider import (  # noqa: E402
    captcha_config_status,
    write_captcha_config,
)

POOL = Path(os.environ.get("OPAI_GOPAY_PHONE_POOL_FILE", str(ROOT / "config" / "gopay_phone_pool.json"))).expanduser()


def _sanitize_public_error(value):
    text = str(value or "")
    text = re.sub(r"://[^/@\s]+@", "://***@", text)
    text = re.sub(
        r"(?i)((?:api[_-]?key|apikey|key)(?:=|%3[dD]))[^&\s\"']+",
        r"\1***",
        text,
    )
    return text[:500]


def _paypal_manager():
    """Load the isolated PayPal protocol module only when its feature is used."""
    from paypal_runtime import manager
    return manager


def _direct_card_manager():
    """Load the isolated direct-card protocol module only when requested."""
    from direct_card_runtime import manager
    return manager


def _parse_proxy_list(value):
    raw_items = value if isinstance(value, list) else str(value or "").splitlines()
    proxies = []
    seen = set()
    for line_number, raw in enumerate(raw_items, 1):
        text = str(raw or "").strip()
        if not text:
            continue
        proxy = _normalize_proxy_url(text)
        try:
            parsed = urlsplit(proxy)
            port = parsed.port
        except ValueError:
            parsed = None
            port = None
        if (
            parsed is None
            or parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"}
            or not parsed.hostname
            or port is None
        ):
            raise ValueError(f"第 {line_number} 条代理格式无效，请使用 http://、https:// 或 socks5:// 地址")
        if proxy not in seen:
            seen.add(proxy)
            proxies.append(proxy)
        if len(proxies) > 100:
            raise ValueError("代理最多填写 100 条")
    return proxies


def _check_proxy_pool(proxies):
    def check(item):
        index, proxy = item
        try:
            result = _preflight_gopay_proxy(proxy)
        except Exception as exc:
            result = {"ok": False, "status": 0, "error": str(exc)}
        error = "" if result.get("ok") else _proxy_preflight_error(proxy, result)
        error = _sanitize_public_error(error)[:300]
        return {
            "index": index,
            "proxy": proxy,
            "ok": bool(result.get("ok")),
            "ip": str(result.get("ip") or ""),
            "error": error,
        }

    if not proxies:
        return {"total": 0, "available": 0, "unavailable": 0, "healthy": [], "results": []}
    with ThreadPoolExecutor(max_workers=min(10, len(proxies))) as executor:
        results = list(executor.map(check, enumerate(proxies)))
    healthy = [row["proxy"] for row in results if row["ok"]]
    public_results = [
        {"line": row["index"] + 1, "ok": row["ok"], "ip": row["ip"], "error": row["error"]}
        for row in results
    ]
    return {
        "total": len(proxies),
        "available": len(healthy),
        "unavailable": len(proxies) - len(healthy),
        "healthy": healthy,
        "results": public_results,
    }


def _load_gopay_phone_pool():
    try:
        data = json.loads(POOL.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _poll_imported_sms_code(phone, _seen=None):
    target = "".join(ch for ch in str(phone or "") if ch.isdigit())
    row = next((x for x in _load_gopay_phone_pool() if "".join(ch for ch in str(x.get("phone") or "") if ch.isdigit()) == target), None)
    url = str((row or {}).get("sms_url") or "").strip()
    if not url:
        return ""
    try:
        body = urllib.request.urlopen(url, timeout=8).read().decode("utf-8", "ignore")
        seen = {str(code) for code in (_seen or set())}
        codes = re.findall(r"(?<!\d)(\d{4,6})(?!\d)", body)
        return next((code for code in reversed(codes) if code not in seen), "")
    except Exception:
        return ""


def _import_gopay_phone_pool(raw):
    rows = _load_gopay_phone_pool()
    inserted = 0
    for line in raw.splitlines():
        if "----" not in line:
            continue
        phone, url = [x.strip() for x in line.split("----", 1)]
        if phone and not any(x.get("phone") == phone for x in rows):
            rows.append({"phone": phone, "sms_url": url, "status": "available"})
            inserted += 1
    POOL.parent.mkdir(exist_ok=True)
    POOL.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"inserted": inserted, "total": len(rows)}


def _delete_gopay_phone(phone):
    target = "".join(ch for ch in str(phone or "") if ch.isdigit())
    rows = _load_gopay_phone_pool()
    kept = [row for row in rows if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit()) != target]
    removed = len(rows) - len(kept)
    if removed:
        POOL.parent.mkdir(exist_ok=True)
        POOL.write_text(json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8")
    return removed


def _clear_gopay_phone_pool():
    removed = len(_load_gopay_phone_pool())
    POOL.parent.mkdir(exist_ok=True)
    POOL.write_text("[]\n", encoding="utf-8")
    return removed


register = _ManualRegisterManager()
payment = _WebPaymentManager(InboxStore())
pin_manager = _PinManager()
batch_jobs = {}
batch_jobs_lock = threading.RLock()


def _auto_feed_relogin_otp(job_id, phone, timeout=180):
    deadline = time.time() + timeout
    seen = set()
    while time.time() < deadline:
        job = next((x for x in register.list() if str(x.get("id")) == str(job_id)), None)
        if not job or str(job.get("status")) in {"success", "failed", "already_registered"}:
            return
        if str(job.get("status")) == "waiting_otp":
            code = _poll_imported_sms_code(phone, seen)
            if code and code not in seen:
                seen.add(code)
                register.submit_otp(job_id, code)
        time.sleep(3)


def _delete_gopay_account(phone):
    target = "".join(ch for ch in str(phone or "") if ch.isdigit())
    rows = _load_gopay_accounts_raw()
    kept = [row for row in rows if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit()) != target]
    removed = len(rows) - len(kept)
    if removed:
        _write_gopay_accounts_raw(kept)
    return removed


def _delete_all_gopay_accounts():
    rows = _load_gopay_accounts_raw()
    _write_gopay_accounts_raw([])
    return len(rows)


def _page():
    return (ROOT / "gopay" / "index.html").read_text(encoding="utf-8")


def _safe_register_jobs():
    rows = []
    for item in register.list():
        clean = dict(item)
        clean.pop("pin", None)
        if isinstance(clean.get("result"), dict):
            clean["result"] = {key: value for key, value in clean["result"].items() if key != "pin"}
        rows.append(clean)
    return rows


class Handler(BaseHTTPRequestHandler):
    def send(self, code, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            raw = _page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if path == "/api/accounts":
            self.send(200, {"accounts": _load_gopay_accounts()})
            return
        if path == "/api/phone-pool":
            self.send(200, {"phones": _load_gopay_phone_pool()})
            return
        if path == "/api/sms-status":
            self.send(200, _sms_api_status(include_balance=False))
            return
        if path == "/api/captcha-status":
            self.send(200, captcha_config_status())
            return
        if path == "/api/paypal-config":
            self.send(200, _paypal_manager().public_config())
            return
        if path == "/api/paypal-jobs":
            self.send(200, {"jobs": _paypal_manager().list_jobs()})
            return
        if path.startswith("/api/paypal-jobs/"):
            job_id = unquote(path[len("/api/paypal-jobs/"):].strip("/"))
            job = _paypal_manager().get(job_id)
            self.send(200, job) if job else self.send(404, {"error": "paypal_job_not_found"})
            return
        if path == "/api/direct-card/info":
            self.send(200, _direct_card_manager().info())
            return
        if path == "/api/direct-card/jobs":
            self.send(200, {"jobs": _direct_card_manager().list_tasks()})
            return
        if path.startswith("/api/direct-card/jobs/"):
            job_id = unquote(path[len("/api/direct-card/jobs/"):].strip("/"))
            job = _direct_card_manager().get(job_id)
            self.send(200, {"ok": True, "task": job}) if job else self.send(404, {"error": "direct_card_job_not_found"})
            return
        if path.startswith("/api/accounts/") and path.endswith("/sms-code"):
            phone = unquote(path[len("/api/accounts/"):-len("/sms-code")].strip("/"))
            self.send(200, {"phone": phone, "code": _poll_imported_sms_code(phone)})
            return
        if path == "/api/register-jobs":
            rows = _safe_register_jobs()
            with batch_jobs_lock:
                batches = [dict(batch) for batch in batch_jobs.values()]
            for batch in batches:
                rows.insert(0, {
                    "id": batch["id"],
                    "phone": f"批量 {batch.get('started', 0)}/{batch.get('count', 0)}",
                    "source": batch.get("source"),
                    "login_existing": bool(batch.get("login_existing")),
                    "status": batch.get("status"),
                    "message": batch.get("message") or batch.get("error") or f"完成 {batch.get('finished', 0)}/{batch.get('count', 0)}",
                })
            self.send(200, {"jobs": rows, "batches": batches})
            return
        if path == "/api/payment-jobs":
            self.send(200, {"jobs": payment.list()})
            return
        if path == "/api/pin-tasks":
            self.send(200, {"jobs": pin_manager.list()})
            return
        if path.startswith("/api/pin-tasks/"):
            job_id = unquote(path[len("/api/pin-tasks/"):].strip("/"))
            job = pin_manager.get(job_id)
            if job:
                self.send(200, job)
            else:
                self.send(404, {"error": "pin_task_not_found"})
            return
        self.send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        try:
            size = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(size) or b"{}") if size else {}
        except Exception:
            data = {}
        try:
            if path == "/api/tasks/clear-finished":
                scope = str(data.get("scope") or "").strip().lower()
                if scope not in {"all", "register", "payment"}:
                    raise ValueError("清理范围无效")
                removed = {"register": 0, "batches": 0, "payment": 0}
                if scope in {"all", "register"}:
                    removed["register"] = register.clear_finished()
                    with batch_jobs_lock:
                        finished_batches = [
                            job_id
                            for job_id, job in batch_jobs.items()
                            if str(job.get("status") or "").strip().lower() in {"done", "failed", "cancelled", "canceled", "error"}
                        ]
                        for job_id in finished_batches:
                            batch_jobs.pop(job_id, None)
                    removed["batches"] = len(finished_batches)
                if scope in {"all", "payment"}:
                    removed["payment"] = payment.clear_finished()
                self.send(200, {
                    "ok": True,
                    "scope": scope,
                    "removed": removed,
                    "total": sum(removed.values()),
                })
                return
            if path == "/api/phone-pool/import":
                self.send(201, _import_gopay_phone_pool(str(data.get("text") or "")))
                return
            if path == "/api/phone-pool/clear":
                self.send(200, {"ok": True, "removed": _clear_gopay_phone_pool()})
                return
            if path == "/api/phone-pool/delete":
                phone = str(data.get("phone") or "").strip()
                removed = _delete_gopay_phone(phone)
                if not removed: raise ValueError(f"号码不存在: {phone}")
                self.send(200, {"ok": True, "phone": phone, "removed": removed})
                return
            if path == "/api/sms-config":
                self.send(200, _write_sms_config(data))
                return
            if path == "/api/captcha-config":
                self.send(200, write_captcha_config(data))
                return
            if path == "/api/paypal-config":
                self.send(200, _paypal_manager().update_config(data))
                return
            if path == "/api/paypal-jobs":
                self.send(201, _paypal_manager().start(data))
                return
            if path.startswith("/api/paypal-jobs/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/paypal-jobs/"):-len("/otp")].strip("/"))
                job = _paypal_manager().submit_otp(job_id, str(data.get("value") or data.get("code") or "").strip())
                if not job:
                    raise ValueError("PayPal 任务不存在或当前不在等待短信验证码")
                self.send(200, job)
                return
            if path.startswith("/api/paypal-jobs/") and path.endswith("/cancel"):
                job_id = unquote(path[len("/api/paypal-jobs/"):-len("/cancel")].strip("/"))
                job = _paypal_manager().cancel(job_id)
                if not job:
                    raise ValueError("PayPal 任务不存在")
                self.send(200, job)
                return
            if path == "/api/direct-card/preflight":
                self.send(200, _direct_card_manager().preflight(data))
                return
            if path == "/api/direct-card/fingerprint":
                self.send(200, _direct_card_manager().allocate_fingerprint(data))
                return
            if path == "/api/direct-card/fingerprints":
                self.send(200, _direct_card_manager().allocate_fingerprints(data))
                return
            if path == "/api/direct-card/address":
                self.send(200, _direct_card_manager().address(data))
                return
            if path == "/api/direct-card/jobs":
                self.send(202, _direct_card_manager().start(data))
                return
            if path == "/api/direct-card/jobs/batch":
                self.send(202, _direct_card_manager().start_batch(data))
                return
            if path == "/api/direct-card/jobs/clear":
                self.send(200, _direct_card_manager().clear())
                return
            if path == "/api/proxies/check":
                proxies = _parse_proxy_list(data.get("proxies"))
                if not proxies:
                    raise ValueError("请先输入至少一条代理")
                checked = _check_proxy_pool(proxies)
                checked.pop("healthy", None)
                self.send(200, checked)
                return
            if path == "/api/register":
                job = register.start(
                    source=str(data.get("source") or "pool"),
                    phone=str(data.get("phone") or ""),
                    pin=str(data.get("pin") or "").strip(),
                    login_existing=bool(data.get("login_existing")),
                    change_pin_after_login=bool(data.get("change_pin_after_login") or data.get("change_existing_pin")),
                    new_pin=str(data.get("new_pin") or "").strip(),
                    proxy=str(data.get("proxy") or ""),
                )
                self.send(201, job)
                return
            if path == "/api/batch-register":
                source = str(data.get("source") or "pool")
                if source not in {"pool", "smsbower", "smspool"}:
                    raise ValueError("号码来源无效")
                count = min(500, max(1, int(data.get("count") or 1)))
                workers = min(50, max(1, int(data.get("workers") or 1)))
                pin = str(data.get("pin") or "").strip()
                if not re.fullmatch(r"\d{6}", pin):
                    raise ValueError("PIN 必须是 6 位数字")
                change_pin_after_login = bool(data.get("change_pin_after_login") or data.get("change_existing_pin"))
                new_pin = str(data.get("new_pin") or "").strip()
                if change_pin_after_login and not bool(data.get("login_existing")):
                    raise ValueError("只有“登录已有号”模式可以在登录后修改 PIN")
                if change_pin_after_login:
                    if not re.fullmatch(r"\d{6}", new_pin):
                        raise ValueError("新 PIN 必须是 6 位数字")
                    if new_pin == pin:
                        raise ValueError("新 PIN 不能和原 PIN 相同")
                proxy_value = data.get("proxies") if "proxies" in data else data.get("proxy")
                proxies = _parse_proxy_list(proxy_value)
                login_existing = bool(data.get("login_existing"))
                phones = [x.get("phone") for x in _load_gopay_phone_pool() if x.get("status", "available") in {"available", "registered"}][:count]
                if source == "pool" and len(phones) < count:
                    mode_label = "登录" if login_existing else "注册"
                    raise ValueError(f"号码池可用号码不足：{mode_label} {count} 个账号需要 {count} 个号码，当前只有 {len(phones)} 个。请先导入号码，或改用 SMSBower。")
                bid = uuid.uuid4().hex[:12]
                with batch_jobs_lock:
                    batch_jobs[bid] = {
                        "id": bid,
                        "source": source,
                        "count": count,
                        "workers": workers,
                        "login_existing": login_existing,
                        "change_pin_after_login": change_pin_after_login,
                        "status": "running",
                        "started": 0,
                        "finished": 0,
                        "succeeded": 0,
                        "failed": 0,
                        "proxy_total": len(proxies),
                        "proxy_checked": 0,
                        "proxy_available": 0,
                        "proxy_unavailable": 0,
                        "message": f"正在检测 {len(proxies)} 条代理" if proxies else "任务运行中",
                    }
                def run_batch():
                    healthy_proxies = [""]
                    if proxies:
                        checked = _check_proxy_pool(proxies)
                        healthy_proxies = checked["healthy"]
                        with batch_jobs_lock:
                            batch = batch_jobs[bid]
                            batch["proxy_checked"] = checked["total"]
                            batch["proxy_available"] = checked["available"]
                            batch["proxy_unavailable"] = checked["unavailable"]
                            batch["message"] = f"代理可用 {checked['available']}/{checked['total']}，准备执行任务"
                            if not healthy_proxies:
                                batch["status"] = "failed"
                                batch["finished"] = count
                                batch["failed"] = count
                                batch["error"] = f"{checked['total']} 条代理全部不可用，未购买 {('SMSPool' if source == 'smspool' else 'SMSBower')} 号码"
                                batch["message"] = batch["error"]
                        if not healthy_proxies:
                            return
                    task_queue = list(phones) if source == "pool" else [""] * count
                    lock = threading.Lock()
                    proxy_condition = threading.Condition()
                    available_proxies = list(healthy_proxies) if proxies else []
                    disabled_proxies = set()

                    def acquire_proxy():
                        if not proxies:
                            return ""
                        with proxy_condition:
                            while not available_proxies and len(disabled_proxies) < len(healthy_proxies):
                                proxy_condition.wait()
                            if not available_proxies:
                                return None
                            return available_proxies.pop(0)

                    def release_proxy(candidate, usable=True):
                        if not proxies or candidate is None:
                            return
                        with proxy_condition:
                            if usable:
                                available_proxies.append(candidate)
                            else:
                                disabled_proxies.add(candidate)
                            proxy_condition.notify_all()
                        if not usable:
                            with batch_jobs_lock:
                                batch = batch_jobs[bid]
                                batch["proxy_available"] = max(0, checked["available"] - len(disabled_proxies))
                                batch["proxy_unavailable"] = checked["unavailable"] + len(disabled_proxies)

                    def one():
                        while True:
                            with lock:
                                if not task_queue: return
                                phone = task_queue.pop(0)
                            with batch_jobs_lock:
                                batch_jobs[bid]["started"] += 1
                            job = None
                            current = {}
                            last_error = ""
                            candidate = acquire_proxy()
                            while candidate is not None:
                                try:
                                    job = register.start(
                                        source=source,
                                        phone=phone,
                                        pin=pin,
                                        proxy=candidate,
                                        login_existing=login_existing,
                                        change_pin_after_login=change_pin_after_login,
                                        new_pin=new_pin,
                                    )
                                except ProxyPreflightError as exc:
                                    last_error = _sanitize_public_error(exc)
                                    release_proxy(candidate, usable=False)
                                    candidate = acquire_proxy()
                                    continue
                                except Exception as exc:
                                    last_error = _sanitize_public_error(exc)
                                    release_proxy(candidate, usable=True)
                                    break

                                # register.start() only creates the worker thread;
                                # keep the proxy leased until this account is terminal.
                                job_id = str(job.get("id") or "")
                                while job_id:
                                    current = register.get(job_id) or {}
                                    if current.get("status") not in {"running", "waiting_otp"}:
                                        break
                                    time.sleep(1)
                                release_proxy(candidate, usable=True)
                                break
                            if candidate is None and not last_error:
                                last_error = f"可用代理已全部失效，未购买 {('SMSPool' if source == 'smspool' else 'SMSBower')} 号码"
                            with batch_jobs_lock:
                                batch = batch_jobs[bid]
                                batch["finished"] += 1
                                terminal_status = str(current.get("status") or (job.get("status") if job else ""))
                                if terminal_status == "success":
                                    batch["succeeded"] += 1
                                else:
                                    batch["failed"] += 1
                                    if last_error:
                                        batch["last_error"] = last_error
                                proxy_text = ""
                                if batch.get("proxy_total"):
                                    proxy_text = f"；代理可用 {batch.get('proxy_available', 0)}/{batch.get('proxy_total', 0)}"
                                batch["message"] = (
                                    f"完成 {batch['finished']}/{count}，成功 {batch['succeeded']}，失败 {batch['failed']}{proxy_text}"
                                )
                    thread_count = min(workers, count, len(healthy_proxies)) if proxies else min(workers, count)
                    threads = [threading.Thread(target=one, daemon=True) for _ in range(thread_count)]
                    for thread in threads: thread.start()
                    for thread in threads: thread.join()
                    with batch_jobs_lock:
                        batch = batch_jobs[bid]
                        batch["status"] = "failed" if batch["succeeded"] == 0 and batch["failed"] else "done"
                        if batch["status"] == "done" and batch["failed"]:
                            batch["message"] = f"部分完成：成功 {batch['succeeded']}，失败 {batch['failed']}"
                threading.Thread(target=run_batch, daemon=True).start()
                with batch_jobs_lock:
                    response = dict(batch_jobs[bid])
                self.send(201, response); return
            if path == "/api/payment":
                job = payment.start(phone=str(data.get("phone") or ""), pin=str(data.get("pin") or "").strip(), midtrans_url=str(data.get("midtrans_url") or ""), proxy=str(data.get("proxy") or ""))
                self.send(201, job); return
            if path == "/api/pin-tasks":
                mode = str(data.get("mode") or "known").strip()
                if mode != "known":
                    raise ValueError("当前只支持知道旧 PIN 时修改；忘记 PIN 请使用 GoPay 官方找回流程")
                job = pin_manager.start(
                    phone=str(data.get("phone") or "").strip(),
                    old_pin=str(data.get("old_pin") or "").strip(),
                    new_pin=str(data.get("new_pin") or "").strip(),
                    mode=mode,
                )
                self.send(201, job); return
            if path.startswith("/api/payment-jobs/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/payment-jobs/"):-len("/otp")].strip("/"))
                code = str(data.get("code") or "").strip()
                if not re.fullmatch(r"\d{4,6}", code):
                    raise ValueError("OTP 必须是 4 到 6 位数字")
                job = payment.submit_otp(job_id, code)
                if not job:
                    raise ValueError(f"该支付任务当前不在等待 OTP，可能已经失败、完成或超时: {job_id}")
                self.send(200, job); return
            if path.startswith("/api/register-jobs/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/register-jobs/"):-len("/otp")].strip("/"))
                code = str(data.get("code") or "").strip()
                if not re.fullmatch(r"\d{4,6}", code):
                    raise ValueError("验证码必须是 4 到 6 位数字")
                job = register.submit_otp(job_id, code)
                if not job:
                    raise ValueError(f"注册任务不存在或不能接收验证码: {job_id}")
                clean = dict(job)
                clean.pop("pin", None)
                self.send(200, clean); return
            if path == "/api/accounts/delete-all":
                self.send(200, {"ok": True, "removed": _delete_all_gopay_accounts()}); return
            if path.startswith("/api/accounts/") and path.endswith("/delete"):
                phone = unquote(path[len("/api/accounts/"):-len("/delete")].strip("/"))
                removed = _delete_gopay_account(phone)
                if not removed: raise ValueError(f"账号不存在: {phone}")
                self.send(200, {"ok": True, "phone": phone, "removed": removed}); return
            if path.startswith("/api/accounts/") and path.endswith("/balance"):
                phone = unquote(path[len("/api/accounts/"):-len("/balance")].strip("/"))
                self.send(200, _refresh_gopay_balance(phone)); return
            if path.startswith("/api/accounts/") and path.endswith("/pin-status"):
                phone = unquote(path[len("/api/accounts/"):-len("/pin-status")].strip("/"))
                self.send(200, _refresh_gopay_pin_status(phone)); return
            if path.startswith("/api/accounts/") and path.endswith("/release-sms"):
                phone = unquote(path[len("/api/accounts/"):-len("/release-sms")].strip("/"))
                self.send(200, _release_gopay_sms(phone)); return
            if path.startswith("/api/accounts/") and path.endswith("/relogin"):
                phone = unquote(path[len("/api/accounts/"):-len("/relogin")].strip("/"))
                account, _ = _find_gopay_account(phone)
                if not account: raise ValueError(f"账号不存在: {phone}")
                job = register.start(source="pool", phone=phone, pin=str(data.get("pin") or account.get("pin") or "").strip(), login_existing=True, proxy=str(account.get("proxy") or ""))
                threading.Thread(target=_auto_feed_relogin_otp, args=(job.get("id"), phone), daemon=True).start()
                self.send(201, job); return
            self.send(404, {"error": "not_found"})
        except Exception as exc:
            self.send(400, {"error": _sanitize_public_error(exc)})

    def log_message(self, *_args):
        pass


def main():
    ThreadingHTTPServer(("127.0.0.1", 19080), Handler).serve_forever()


def start_embedded():
    """Start the unchanged GoPay HTTP handler on an ephemeral loopback port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, name="gopay-http", daemon=True).start()
    return server


if __name__ == "__main__":
    main()
