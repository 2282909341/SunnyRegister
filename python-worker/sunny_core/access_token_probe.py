from __future__ import annotations

from typing import Any

from curl_cffi import requests as curl_requests

from .browser_traffic import ProxyTrafficMeter, use_traffic_meter
from .ca_bundle import ca_bundle_path


MODELS_URL = "https://chatgpt.com/backend-api/models"


def _error_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict):
        return " ".join(str(error.get(key) or "") for key in ("code", "type", "message")).strip()
    return str(error or "").strip()


def _is_auth_error(payload: Any) -> bool:
    value = _error_text(payload).lower()
    return any(marker in value for marker in ("token", "auth", "expired", "invalidated", "invalid"))


def _preview(response) -> str:
    text = " ".join(str(getattr(response, "text", "") or "").split())
    if len(text) > 300:
        text = text[:300] + "..."
    return f"HTTP {response.status_code}, {text or 'empty response'}"


def _classify(response) -> dict[str, Any]:
    try:
        payload = response.json()
    except Exception:
        payload = None
    if response.status_code == 401:
        return {"status": "invalid", "error": f"AT 已失效: {_preview(response)}", "http_status": 401}
    if response.status_code == 403:
        if _is_auth_error(payload):
            return {"status": "invalid", "error": f"AT 已失效: {_preview(response)}", "http_status": 403}
        return {"status": "blocked", "error": f"AT 检测请求在到达模型接口前被 Cloudflare/上游边缘拦截: {_preview(response)}", "http_status": 403}
    if response.status_code == 429:
        return {"status": "valid", "http_status": 429}
    if 200 <= response.status_code < 300:
        if isinstance(payload, dict) and "models" in payload:
            return {"status": "valid", "http_status": response.status_code}
        return {"status": "probe_failed", "error": "AT 检测响应缺少 models 字段", "http_status": response.status_code}
    return {"status": "probe_failed", "error": f"AT 检测上游响应异常: {_preview(response)}", "http_status": response.status_code}


def _request(access_token: str, proxy_url: str) -> dict[str, Any]:
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    session = curl_requests.Session(impersonate="chrome136", proxies=proxies, timeout=18, verify=ca_bundle_path())
    try:
        response = session.get(
            MODELS_URL,
            headers={
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Authorization": f"Bearer {access_token}",
                "Cache-Control": "no-cache",
                "Origin": "https://chatgpt.com",
                "Referer": "https://chatgpt.com/",
                "oai-language": "en-US",
            },
            allow_redirects=False,
        )
        return _classify(response)
    finally:
        session.close()


def probe_access_token(access_token: str, proxy_url: str = "") -> dict[str, Any]:
    token = str(access_token or "").strip()
    if not token:
        return {"status": "invalid", "error": "账户没有可用的 Access Token"}

    configured_proxy = str(proxy_url or "").strip()
    attempts = [("配置代理", configured_proxy), ("服务器直连", "")] if configured_proxy else [("服务器直连", "")]
    meter = ProxyTrafficMeter(
        proxy_url=configured_proxy,
        tracked_proxy=bool(configured_proxy),
        operation="access_token_probe",
    )
    errors: list[str] = []
    all_blocked = True
    for source, proxy in attempts:
        try:
            with use_traffic_meter(meter):
                result = _request(token, proxy)
        except Exception as exc:
            all_blocked = False
            errors.append(f"{source}={exc}")
            continue
        result["source"] = source
        if result.get("status") in {"valid", "invalid"}:
            result["traffic"] = meter.snapshot()
            return result
        if result.get("status") != "blocked":
            all_blocked = False
        errors.append(f"{source}={result.get('error') or '未得到可判定响应'}")
    if all_blocked:
        return {
            "status": "blocked",
            "error": "AT 检测被 Cloudflare/上游边缘拦截，未判定令牌失效；" + "; ".join(errors),
            "traffic": meter.snapshot(),
        }
    return {
        "status": "probe_failed",
        "error": "AT 检测未能到达官方模型接口，未判定令牌失效；" + "; ".join(errors),
        "traffic": meter.snapshot(),
    }
