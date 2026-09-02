from __future__ import annotations

import dataclasses
import base64
import ipaddress
import socket
import ssl
import time
from typing import Any
from urllib.parse import quote, unquote, urlparse

import requests


@dataclasses.dataclass
class ProxyConfig:
    local_proxy: str = ""
    dynamic_proxy: str = ""
    chain_url: str = ""

    @property
    def url(self) -> str:
        return self.chain_url or self.dynamic_proxy or self.local_proxy


def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return value if parsed.scheme and parsed.netloc else value
    if "@" in value:
        left, right = value.split("@", 1)
        left_parts = left.split(":")
        right_parts = right.split(":")
        if len(left_parts) >= 2 and len(right_parts) >= 2 and left_parts[1].isdigit() and _looks_like_host(left_parts[0]):
            return _proxy_url(default_scheme, right_parts[0], ":".join(right_parts[1:]), left_parts[0], left_parts[1])
        return f"{default_scheme}://{value}"
    parts = value.split(":")
    if len(parts) >= 4:
        if parts[-1].isdigit() and _looks_like_host(parts[-2]):
            user = parts[0]
            password = ":".join(parts[1:-2])
            host = parts[-2]
            port = parts[-1]
            return _proxy_url(default_scheme, user, password, host, port)
        if len(parts) >= 4 and parts[1].isdigit() and _looks_like_host(parts[0]):
            host = parts[0]
            port = parts[1]
            user = parts[2]
            password = ":".join(parts[3:])
            return _proxy_url(default_scheme, user, password, host, port)
    return f"{default_scheme}://{value}"


def _looks_like_host(value: str) -> bool:
    host = str(value or "").strip("[]")
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        pass
    return host.lower() == "localhost" or "." in host


def _proxy_url(scheme: str, user: str, password: str, host: str, port: str) -> str:
    return f"{scheme}://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"


def build_proxy(local_proxy: str = "", dynamic_proxy: str = "") -> ProxyConfig:
    # 当前项目内重写版不再依赖 sunny 的本地链式 socket server。
    # 运行时优先使用 dynamic_proxy；未配置则使用 local_proxy。
    local_proxy = normalize_proxy_url(local_proxy)
    dynamic_proxy = normalize_proxy_url(dynamic_proxy)
    return ProxyConfig(local_proxy=local_proxy, dynamic_proxy=dynamic_proxy, chain_url=dynamic_proxy or local_proxy)


def proxy_dict(proxy_url: str) -> dict[str, str]:
    proxy_url = normalize_proxy_url(proxy_url)
    return {"http": proxy_url, "https": proxy_url} if proxy_url else {}


def playwright_proxy(proxy_url: str) -> dict[str, str] | None:
    proxy_url = normalize_proxy_url(proxy_url)
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    if not parsed.scheme or not parsed.hostname:
        return {"server": proxy_url}
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    server = f"{parsed.scheme}://{host}"
    if parsed.port:
        server += f":{parsed.port}"
    data: dict[str, str] = {"server": server}
    if parsed.username:
        data["username"] = unquote(parsed.username)
    if parsed.password:
        data["password"] = unquote(parsed.password)
    return data


def redact_proxy_url(proxy_url: str) -> str:
    proxy_url = normalize_proxy_url(proxy_url)
    parsed = urlparse(proxy_url)
    if not parsed.username:
        return proxy_url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parsed.port:
        netloc += f":{parsed.port}"
    return f"{parsed.scheme}://{unquote(parsed.username)}:***@{netloc}"


def proxy_target_tls_check(proxy_url: str, target_host: str = "chatgpt.com", target_port: int = 443, timeout: float = 10) -> dict[str, Any]:
    """Lightweight registration-path check.

    It only establishes the proxy tunnel and performs a TLS ClientHello/handshake
    to the target host. No web page is downloaded, so it avoids the high traffic
    cost of loading chatgpt.com during batch proxy checks.
    """
    proxy_url = normalize_proxy_url(proxy_url)
    started = time.time()
    result: dict[str, Any] = {
        "ok": False,
        "proxy": proxy_url,
        "target": f"{target_host}:{target_port}",
        "mode": "connect_tls_handshake",
        "latency_ms": 0,
    }
    if not proxy_url:
        result["error"] = "proxy is empty"
        return result
    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname
    port = parsed.port
    if not host:
        result["error"] = "proxy host is empty"
        return result
    if not port:
        port = 1080 if scheme in {"socks5", "socks5h"} else 80
    sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.settimeout(timeout)
        if scheme in {"http", "https"}:
            connect_host = f"{target_host}:{int(target_port)}"
            headers = [
                f"CONNECT {connect_host} HTTP/1.1",
                f"Host: {connect_host}",
                "User-Agent: SunnyRegister/1.0",
                "Proxy-Connection: keep-alive",
            ]
            if parsed.username:
                raw_auth = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}".encode("utf-8")
                headers.append("Proxy-Authorization: Basic " + base64.b64encode(raw_auth).decode("ascii"))
            sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
            response = b""
            while b"\r\n\r\n" not in response and len(response) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            first_line = response.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
            if " 200 " not in f" {first_line} ":
                result["error"] = f"proxy CONNECT failed: {first_line or 'empty response'}"
                return result
        elif scheme in {"socks5", "socks5h"}:
            username = unquote(parsed.username or "")
            password = unquote(parsed.password or "")
            methods = [0]
            if username:
                methods.append(2)
            sock.sendall(bytes([5, len(methods), *methods]))
            resp = sock.recv(2)
            if len(resp) != 2 or resp[0] != 5 or resp[1] == 0xFF:
                result["error"] = "SOCKS5 method negotiation failed"
                return result
            if resp[1] == 2:
                u = username.encode("utf-8")
                p = password.encode("utf-8")
                sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
                auth_resp = sock.recv(2)
                if len(auth_resp) != 2 or auth_resp[1] != 0:
                    result["error"] = "SOCKS5 authentication failed"
                    return result
            host_bytes = target_host.encode("idna")
            port_bytes = int(target_port).to_bytes(2, "big")
            sock.sendall(bytes([5, 1, 0, 3, len(host_bytes)]) + host_bytes + port_bytes)
            resp = sock.recv(10)
            if len(resp) < 2 or resp[1] != 0:
                result["error"] = f"SOCKS5 connect failed: code={resp[1] if len(resp) > 1 else 'no response'}"
                return result
        else:
            result["error"] = f"unsupported proxy scheme: {scheme}"
            return result

        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)
        tls_sock.settimeout(timeout)
        result["ok"] = True
        result["tls_version"] = tls_sock.version()
        result["latency_ms"] = int((time.time() - started) * 1000)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["latency_ms"] = int((time.time() - started) * 1000)
        return result
    finally:
        try:
            if tls_sock:
                tls_sock.close()
            elif sock:
                sock.close()
        except Exception:
            pass


def detect_proxy_health(proxy_url: str, timeout: int = 15) -> dict[str, Any]:
    proxies = proxy_dict(proxy_url)
    result: dict[str, Any] = {"success": False, "proxy": proxy_url}
    try:
        ip = requests.get("https://ipinfo.io/json", proxies=proxies, timeout=timeout).json()
        result.update({k: ip.get(k, "") for k in ("ip", "country", "region", "city", "timezone", "org")})
        cg = requests.get("https://chatgpt.com/", proxies=proxies, timeout=timeout)
        st = requests.get("https://chatgpt.com/", proxies=proxies, timeout=timeout)
        result.update({"chatgpt_status": cg.status_code, "status": st.status_code, "success": cg.status_code < 500 and st.status_code not in (407, 429)})
    except Exception as exc:
        result["error"] = str(exc)
    return result
