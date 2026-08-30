from __future__ import annotations

import os
import shutil
from pathlib import Path

import certifi


def ca_bundle_path() -> str:
    """Return a CA bundle path that native libcurl can open.

    curl_cffi hands CURLOPT_CAINFO to native libcurl, which on Windows
    resolves the file with the ANSI code page (e.g. cp936/GBK on zh-CN
    systems). When PYTHONUTF8=1, curl_cffi encodes a non-ASCII certifi
    path (such as one under a Chinese-named project directory) as UTF-8
    bytes, so libcurl cannot find the file and every HTTPS request fails
    with CURLE_SSL_CACERT_BADFILE (curl error 77).

    This mirrors the certifi bundle onto a pure-ASCII path (an explicit
    SUNNY_CA_BUNDLE override, or %LOCALAPPDATA%\\SunnyRegister\\cacert.pem)
    when the certifi path itself is non-ASCII, falling back to certifi.
    """
    override = os.environ.get("SUNNY_CA_BUNDLE")
    if override:
        override_path = Path(override)
        if override_path.is_file():
            return str(override_path)

    certifi_path = Path(certifi.where())
    if _is_ascii_path(certifi_path):
        return str(certifi_path)

    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    ascii_ca = Path(local_app_data) / "SunnyRegister" / "cacert.pem"
    try:
        if not ascii_ca.is_file():
            ascii_ca.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(certifi_path, ascii_ca)
        return str(ascii_ca)
    except Exception:
        return str(certifi_path)


def _is_ascii_path(path: Path) -> bool:
    try:
        str(path).encode("ascii")
        return True
    except UnicodeEncodeError:
        return False
