from sunny_core import mailbox as mailbox_module
from sunny_core.mailbox import IcMeiGoICloudReader, account_from_row

import pytest

# 2033-05-18 UTC 之后才算“本次发码之后到达”，用于区分旧验证码邮件与新验证码邮件
_MIN_TS = 2_000_000_000


def _reader():
    return IcMeiGoICloudReader(
        account_from_row(
            {"email": "fresh@icloud.com", "mailbox_type": "apple", "mailbox_channel": "icmeigo", "access_key": "card-key"}
        ),
        None,
    )


def test_icmeigo_reader_skips_stale_code_then_returns_new_code(monkeypatch):
    monkeypatch.setattr(mailbox_module, "ICMEIGO_POLL_INTERVAL_SECONDS", 0.01)
    reader = _reader()
    messages = iter(
        [
            # 上一次尝试(旧发码时间之前)留下的旧验证码邮件，必须先于本次新验证码到达
            {"otp": "111111", "date": "2020-01-01T00:00:00Z"},
            {"otp": "222222", "date": "2099-01-01T00:00:00Z"},
        ]
    )
    monkeypatch.setattr(reader, "latest_message", lambda: next(messages))
    assert reader.wait_for_code(_MIN_TS, timeout=30) == "222222"
    assert len(reader.seen_codes) == 2


def test_icmeigo_reader_times_out_when_only_stale_code_exists(monkeypatch):
    monkeypatch.setattr(mailbox_module, "ICMEIGO_POLL_INTERVAL_SECONDS", 0.01)
    reader = _reader()
    stale = {"otp": "111111", "date": "2020-01-01T00:00:00Z"}
    monkeypatch.setattr(reader, "latest_message", lambda: stale)
    with pytest.raises(TimeoutError):
        reader.wait_for_code(_MIN_TS, timeout=0.05)


def test_icmeigo_reader_accepts_old_mail_when_no_baseline(monkeypatch):
    # min_timestamp=0 表示无基线（无需时间过滤的调用方），旧码也直接可用
    monkeypatch.setattr(mailbox_module, "ICMEIGO_POLL_INTERVAL_SECONDS", 0.01)
    reader = _reader()
    old = {"otp": "111111", "date": "2020-01-01T00:00:00Z"}
    monkeypatch.setattr(reader, "latest_message", lambda: old)
    assert reader.wait_for_code(0, timeout=30) == "111111"