from __future__ import annotations

from unittest.mock import patch

import pytest

from sunny_core.sentinel import SentinelBrowserRuntime, SentinelNodeRuntime


class FakePage:
    def goto(self, *_args, **_kwargs):
        return None

    def evaluate(self, expression, *_args):
        if expression == "typeof window.SentinelSDK":
            return "object"
        return None


class FakeContext:
    def __init__(self) -> None:
        self.page = FakePage()
        self.closed = False

    def new_page(self):
        return self.page

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self) -> None:
        self.context = FakeContext()
        self.context_options = None

    def new_context(self, **kwargs):
        self.context_options = kwargs
        return self.context


class FakeManager:
    last_options = None
    last_browser = None

    def __init__(self, **options) -> None:
        self.__class__.last_options = options
        self.__class__.last_browser = FakeBrowser()

    def __enter__(self):
        return self.__class__.last_browser

    def __exit__(self, *_args):
        return None


def test_sentinel_runtime_disables_default_viewport_for_camoufox_context() -> None:
    with (
        patch("camoufox.sync_api.Camoufox", FakeManager),
        patch.object(SentinelBrowserRuntime, "_load_sdk", return_value="window.SentinelSDK = {};"),
    ):
        runtime = SentinelBrowserRuntime(object())
        runtime.close()

    assert FakeManager.last_browser.context_options == {
        "no_viewport": True,
        "locale": "ja-JP",
    }
    assert FakeManager.last_browser.context.closed is True


def test_sentinel_node_runtime_builds_headers_and_reuses_requirements_proof() -> None:
    with patch("sunny_core.sentinel.shutil.which", return_value="node"):
        runtime = SentinelNodeRuntime(object())
    with patch.object(runtime, "_run", return_value={"request_p": "requirements"}), patch.object(
        runtime, "_v8_request", return_value={"p": None, "t": "", "so": None}
    ):
        assert runtime.requirements_token() == "requirements"
        headers = runtime.build_headers(
            challenge_payload={"token": "challenge", "turnstile": {"required": False}},
            cached_proof="requirements",
            enforcement="",
            device_id="device",
            flow="authorize_continue",
        )
    assert '"p":"requirements"' in headers["openai-sentinel-token"]
    assert '"c":"challenge"' in headers["openai-sentinel-token"]


def test_sentinel_node_runtime_requires_node() -> None:
    with patch("sunny_core.sentinel.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="Node.js"):
            SentinelNodeRuntime(object())
