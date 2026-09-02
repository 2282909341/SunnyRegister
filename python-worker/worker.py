from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

os.environ.setdefault("PYTHONUTF8", "1")

def _secret_value(env_key: str, file_key: str) -> str:
    file_name = os.getenv(file_key, "").strip()
    if file_name:
        try:
            return Path(file_name).read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return os.getenv(env_key, "").strip()


WORKER_TOKEN = _secret_value("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE")


def _configure_gopay_runtime() -> None:
    worker_dir = Path(__file__).resolve().parent
    runtime_dir = worker_dir / "gopay_runtime"
    data_root = Path(os.getenv("SUNNY_DATA_DIR") or ("/app/data" if Path("/app/data").is_dir() else worker_dir.parent / "data"))
    gopay_data = data_root / "gopay"
    gopay_data.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("OPAI_GOPAY_ACCOUNTS_FILE", str(gopay_data / "accounts.json"))
    os.environ.setdefault("OPAI_GOPAY_PHONE_POOL_FILE", str(gopay_data / "phone_pool.json"))
    os.environ.setdefault("OPAI_GOPAY_SMS_ENV_FILE", str(gopay_data / "sms.env"))
    os.environ.setdefault("OPAI_MIDTRANS_CAPTCHA_ENV_FILE", str(gopay_data / "captcha.env"))
    os.environ.setdefault("OPAI_PAYMENT_INBOX_PATH", str(gopay_data / "payment_inbox.json"))
    os.environ.setdefault("OPAI_PAYMENT_INBOX_DB_PATH", str(gopay_data / "payment_inbox.db"))
    os.environ.setdefault("OPAI_GOPAY_ENVELOPE_STORE", str(gopay_data / "envelope_links.json"))
    os.environ.setdefault("OPAI_MIDTRANS_SNAP_STATE_FILE", str(gopay_data / "midtrans_snap_state.json"))
    os.environ.setdefault("OPAI_PAYMENT_TASK_STATE_FILE", str(gopay_data / "payment_tasks.json"))
    os.environ.setdefault("OPAI_GOPAY_SUPPORT_BODY_CORPUS", str(runtime_dir / "config" / "support_sdk_body_corpus.json"))
    os.environ.setdefault("PAYPAL_AGREEMENT_CONFIG_PATH", str(gopay_data / "paypal_agreement.json"))
    os.environ.setdefault("DIRECT_CARD_FINGERPRINT_STORE_PATH", str(gopay_data / "direct_card_fingerprints.json"))


_configure_gopay_runtime()
# A browser driver can occasionally remain busy after its browser disconnects. The
# worker already runs each task in a dedicated process; reclaim an inactive child
# after 30 minutes so transient upstream/network stalls do not terminate a
# legitimate long-running account operation. Deployments can tune this with
# SUNNY_TASK_IDLE_TIMEOUT_SECONDS when a shorter leak-recovery window is needed.
TASK_IDLE_TIMEOUT_SECONDS = max(60, int(os.getenv("SUNNY_TASK_IDLE_TIMEOUT_SECONDS", "1800")))
TASK_WATCH_INTERVAL_SECONDS = max(5, int(os.getenv("SUNNY_TASK_WATCH_INTERVAL_SECONDS", "15")))

app = FastAPI(title="SunnyRegister Python Automation Worker", version="1.0.0")
_state_lock = threading.Lock()
_running: set[str] = set()
_processes: dict[str, subprocess.Popen] = {}
_gopay_server = None


def _check_token(auth: str | None) -> None:
    if not WORKER_TOKEN:
        return
    expected = f"Bearer {WORKER_TOKEN}"
    if auth != expected:
        raise HTTPException(status_code=401, detail="Unauthorized worker token")


@app.on_event("startup")
def on_startup() -> None:
    # Do not import or validate Playwright/Camoufox here. Browser automation is
    # lazy-loaded by the isolated task subprocess only when a task is accepted.
    global _gopay_server
    from gopay_runtime.gopay.server import start_embedded

    _gopay_server = start_embedded()
    print("[worker] SunnyRegister automation worker ready (browser lazy loading enabled, payment runtimes enabled)", flush=True)


@app.api_route("/gopay/{path:path}", methods=["GET", "POST"])
async def gopay_proxy(path: str, request: Request, authorization: str | None = Header(default=None)) -> Response:
    _check_token(authorization)
    if _gopay_server is None:
        raise HTTPException(status_code=503, detail="GoPay service is not ready")
    if "\\" in path or any(segment in {".", ".."} for segment in path.split("/")):
        raise HTTPException(status_code=404, detail="Not found")
    body = await request.body()
    query = f"?{request.url.query}" if request.url.query else ""
    target = f"http://127.0.0.1:{_gopay_server.server_port}/api/{path}{query}"
    upstream = urllib.request.Request(
        target,
        data=body if request.method == "POST" else None,
        method=request.method,
        headers={"Content-Type": request.headers.get("content-type", "application/json")},
    )

    def send() -> Response:
        try:
            with urllib.request.urlopen(upstream, timeout=300) as result:
                return Response(content=result.read(), status_code=result.status, media_type="application/json")
        except urllib.error.HTTPError as exc:
            return Response(content=exc.read(), status_code=exc.code, media_type="application/json")
        except OSError as exc:
            raise HTTPException(status_code=502, detail=f"GoPay service unavailable: {exc}") from exc

    return await run_in_threadpool(send)


class ExecuteRequest(BaseModel):
    task_id: str
    task_type: str = ""


class CancelRequest(BaseModel):
    task_id: str


class ProbeAccessTokenRequest(BaseModel):
    access_token: str
    proxy_url: str = ""


class ProbeTrialRequest(BaseModel):
    access_token: str
    proxy_url: str = ""


class ProbeCommerceRequest(BaseModel):
    access_token: str
    proxy_url: str = ""
    promotion_proxy_url: str = ""
    checkout_proxy_url: str = ""
    country: str = "DE"
    currency: str = "EUR"


class ProbePaymentMethodsRequest(BaseModel):
    access_token: str
    proxy_url: str = ""
    country: str = "US"
    currency: str = "USD"
    use_trial_promotion: bool = False


class CheckoutRequest(BaseModel):
    token: str
    checkout_proxies: list[str]
    promotion_proxies: list[str]
    checkout_kind: str = "unknown"
    plan: str = "plus"
    link_type: str = "hosted"
    country: str = "US"
    currency: str = "USD"
    retry_count: int = 3
    use_promo: bool = True
    promo_campaign: str = ""
    promo_country: str = ""
    promo_code: str = ""
    workspace_name: str = ""
    workspace_id: str = ""
    seat_quantity: int = 5
    price_interval: str = "month"
    credit_quantity: int = 13
    ideal_bank: str = ""
    pix_tax_id: str = ""
    pix_auto_kind: str = "cpf"


@app.get("/health")
def health() -> dict:
    with _state_lock:
        for task_id, process in list(_processes.items()):
            if process.poll() is not None:
                _processes.pop(task_id, None)
                _running.discard(task_id)
        running = sorted(_running)
    sunny_db_identity = ""
    sunny_db_error = ""
    try:
        from sunny_core.db import database_identity

        sunny_db_identity = database_identity()
    except Exception as exc:
        sunny_db_error = str(exc)
    return {
        "ok": sunny_db_error == "",
        "running": running,
        "cwd": os.getcwd(),
        "python": sys.executable,
        "sunny_db_identity": sunny_db_identity,
        "sunny_db_error": sunny_db_error,
        "task_isolation": "subprocess",
        "task_idle_timeout_seconds": TASK_IDLE_TIMEOUT_SECONDS,
    }


@app.post("/execute")
def execute(req: ExecuteRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    if not req.task_id.strip():
        raise HTTPException(status_code=400, detail="task_id is required")
    if not req.task_type.startswith("sunny_"):
        raise HTTPException(status_code=400, detail="only sunny_* task types are supported")
    with _state_lock:
        if req.task_id in _running:
            return {"ok": True, "accepted": False, "already_running": True, "task_id": req.task_id}
        process = _start_task_process(req.task_id)
        _running.add(req.task_id)
        _processes[req.task_id] = process
    threading.Thread(
        target=_watch_task_process,
        args=(req.task_id, process),
        name=f"sunny-task-watch-{req.task_id}",
        daemon=True,
    ).start()
    return {"ok": True, "accepted": True, "task_id": req.task_id, "task_type": req.task_type}


@app.post("/cancel")
def cancel(req: CancelRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    task_id = req.task_id.strip()
    if not task_id:
        raise HTTPException(status_code=400, detail="task_id is required")
    _set_cancel_requested(task_id)
    with _state_lock:
        process = _processes.get(task_id)
    forced = False
    if process and process.poll() is None:
        deadline = time.monotonic() + 1.0
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is None:
            forced = True
            _terminate_process_tree(process)
    summary = _mark_task_cancelled(task_id)
    with _state_lock:
        _running.discard(task_id)
        if _processes.get(task_id) is process:
            _processes.pop(task_id, None)
    return {"ok": True, "task_id": task_id, "cancelled": True, "forced": forced, **summary}


@app.post("/probe-access-token")
def probe_access_token(req: ProbeAccessTokenRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from sunny_core.access_token_probe import probe_access_token as run_probe

    return run_probe(req.access_token, req.proxy_url)


@app.post("/probe-trial")
def probe_trial(req: ProbeTrialRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from sunny_core.commerce_probe import probe_trial as run_probe

    return run_probe(req.access_token, req.proxy_url)


@app.post("/probe-commerce")
def probe_commerce(req: ProbeCommerceRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from sunny_core.commerce_probe import probe_commerce as run_probe

    return run_probe(
        req.access_token,
        req.proxy_url,
        req.country,
        req.currency,
        promotion_proxy_url=req.promotion_proxy_url,
        checkout_proxy_url=req.checkout_proxy_url,
    )


@app.post("/probe-payment-methods")
def probe_payment_methods(req: ProbePaymentMethodsRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from sunny_core.commerce_probe import probe_payment_methods as run_probe

    return run_probe(req.access_token, req.proxy_url, req.country, req.currency, req.use_trial_promotion)


@app.post("/checkout/jobs")
def start_checkout(req: CheckoutRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from tools.pay153_checkout.sunny_adapter import start_checkout as run_checkout

    return {"ok": True, "job_id": run_checkout(req.model_dump())}


@app.get("/checkout/jobs/{job_id}")
def checkout_job(job_id: str, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from tools.pay153_checkout.sunny_adapter import checkout_status

    result = checkout_status(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="checkout job not found")
    return result


@app.post("/checkout/jobs/{job_id}/cancel")
def cancel_checkout_job(job_id: str, authorization: str | None = Header(default=None)) -> dict:
    _check_token(authorization)
    from tools.pay153_checkout.sunny_adapter import cancel_checkout

    return {"ok": cancel_checkout(job_id), "job_id": job_id}


@app.on_event("shutdown")
def on_shutdown() -> None:
    global _gopay_server
    if _gopay_server is not None:
        _gopay_server.shutdown()
        _gopay_server.server_close()
        _gopay_server = None
    with _state_lock:
        processes = list(_processes.values())
        _processes.clear()
        _running.clear()
    for process in processes:
        if process.poll() is None:
            _terminate_process_tree(process)


def _start_task_process(task_id: str) -> subprocess.Popen:
    worker_dir = Path(__file__).resolve().parent
    kwargs: dict = {
        "cwd": str(worker_dir),
        "env": os.environ.copy(),
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen([sys.executable, "-m", "sunny_runner", task_id], **kwargs)


def _watch_task_process(task_id: str, process: subprocess.Popen) -> None:
    last_signature: tuple[str, str, str, str] | None = None
    last_activity = time.monotonic()
    reclaimed_reason = ""
    while process.poll() is None:
        try:
            from sunny_core.db import SunnyDB

            db = SunnyDB(task_id, ensure_schema=False)
            try:
                task = db.task()
                event_row = db.conn.execute(
                    "select max(created_at) as latest_event_at from task_events where task_id=?",
                    (task_id,),
                ).fetchone()
                if isinstance(event_row, dict):
                    latest_event_at = str(event_row.get("latest_event_at") or "")
                elif event_row:
                    latest_event_at = str(event_row["latest_event_at"] or "")
                else:
                    latest_event_at = ""
                signature = (
                    str(task.get("updated_at") or ""),
                    str(task.get("progress_current") or ""),
                    str(task.get("status") or ""),
                    latest_event_at,
                )
            finally:
                db.close()
            if signature != last_signature:
                last_signature = signature
                last_activity = time.monotonic()
        except Exception:
            # SQLite may briefly be locked by the task; avoid false-positive cleanup.
            last_activity = time.monotonic()
        if time.monotonic() - last_activity >= TASK_IDLE_TIMEOUT_SECONDS:
            reclaimed_reason = f"Python 自动化任务连续 {TASK_IDLE_TIMEOUT_SECONDS // 60} 分钟无状态更新，已自动终止卡死子进程并释放浏览器/邮件资源"
            print(f"[worker] reclaiming stalled task {task_id}", flush=True)
            _terminate_process_tree(process)
            break
        time.sleep(TASK_WATCH_INTERVAL_SECONDS)

    return_code = process.wait()
    with _state_lock:
        if _processes.get(task_id) is process:
            _processes.pop(task_id, None)
        _running.discard(task_id)
    try:
        from sunny_core.db import SunnyDB, now_sql

        db = SunnyDB(task_id)
        try:
            status = db.task_status()
            if status == "cancel_requested":
                db.mark_cancelled("用户已停止注册任务")
            elif return_code != 0 and status not in {"succeeded", "failed", "cancelled", "interrupted"}:
                message = reclaimed_reason or f"SunnyRegister Worker 子进程异常退出，退出码 {return_code}"
                summary = db.fail_unfinished_mailboxes(message)
                db.update_task(
                    status="failed",
                    error=message,
                    progress_current=summary["completed"] + summary["failed"],
                    success_count=summary["completed"],
                    error_count=summary["failed"],
                    finished_at=now_sql(),
                )
                db.event(message, "error", detail={"return_code": return_code})
        finally:
            db.close()
    except Exception as exc:
        print(f"[worker] failed to reconcile child task {task_id}: {exc}", flush=True)


def _set_cancel_requested(task_id: str) -> None:
    try:
        from sunny_core.db import SunnyDB

        db = SunnyDB(task_id)
        try:
            if db.task_status() not in {"succeeded", "failed", "cancelled", "interrupted"}:
                db.update_task(status="cancel_requested")
        finally:
            db.close()
    except Exception as exc:
        print(f"[worker] failed to set cancel_requested for {task_id}: {exc}", flush=True)


def _mark_task_cancelled(task_id: str) -> dict:
    try:
        from sunny_core.db import SunnyDB

        db = SunnyDB(task_id)
        try:
            return db.mark_cancelled("用户已停止注册任务")
        finally:
            db.close()
    except Exception as exc:
        print(f"[worker] failed to finalize cancelled task {task_id}: {exc}", flush=True)
        return {"completed": 0, "failed": 0, "completed_mailbox_ids": [], "failed_mailbox_ids": []}


def _terminate_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=3)
        except Exception:
            pass


def _run_task(task_id: str, task_type: str = "") -> None:
    try:
        if not task_type.startswith("sunny_"):
            raise RuntimeError(f"unsupported task type: {task_type}")
        from sunny_runner import run_sunny_task

        run_sunny_task(task_id)
    except Exception as exc:
        tb = traceback.format_exc()
        print(f"[worker] task {task_id} failed:\n{tb}", flush=True)
        _finish_sunny_task_failed(task_id, exc, tb)
    finally:
        with _state_lock:
            _running.discard(task_id)


def _finish_sunny_task_failed(task_id: str, exc: Exception, tb: str) -> None:
    try:
        from sunny_core.db import SunnyDB, database_identity, now_sql

        db = SunnyDB(task_id)
        try:
            message = f"SunnyRegister Worker 启动任务失败: {exc}"
            detail = {"traceback": tb[-4000:], "worker_db_identity": database_identity()}
            db.update_task(status="failed", error=message, result_json='{"error":"worker failed before startup"}', finished_at=now_sql())
            db.event(message, "error", detail=detail)
        finally:
            db.close()
    except Exception as inner:
        print(f"[worker] failed to write SunnyRegister failure to DB: {inner}", flush=True)
