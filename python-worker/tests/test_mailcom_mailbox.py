# -*- coding: utf-8 -*-
"""mail.com 分裂邮箱（mailbox_type=mailcom / mailbox_channel=mailcom_code）的行解析与读取器路由。"""
from __future__ import annotations

import pytest

from sunny_core.mailbox import MailAccount, MailComCodeReader, account_from_row, create_mailbox_reader

CODE_URL = "https://mailcom.example/code/AbC-123_xyz"

ROW = {
    "email": "alias@icloud.com",
    "mailbox_type": "mailcom",
    "mailbox_channel": "mailcom_code",
    "access_key": CODE_URL,
    "chat_gpt_password": "ChatGPT-password",
    "totp_secret": "JBSWY3DPEHPK3PXP",
}


def test_account_from_row_parses_mailcom_code_credential() -> None:
    """换绑到 mail.com 分裂邮箱后，邮箱行必须仍能解析出可登录的账户对象。"""
    account = account_from_row(dict(ROW))

    assert isinstance(account, MailAccount)
    assert account.email == "alias@icloud.com"
    assert account.mailbox_type == "mailcom"
    assert account.mailbox_channel == "mailcom_code"
    assert account.access_key == CODE_URL
    assert account.has_login_secret is True


def test_account_from_row_recovers_mailcom_credential_from_raw() -> None:
    account = account_from_row({
        "email": "",
        "mailbox_type": "mailcom",
        "mailbox_channel": "mailcom_code",
        "raw": f"alias@icloud.com----{CODE_URL}",
    })

    assert account.email == "alias@icloud.com"
    assert account.access_key == CODE_URL


def test_account_from_row_routes_mailcom_by_channel() -> None:
    account = account_from_row({
        "email": "alias@icloud.com",
        "mailbox_type": "",
        "mailbox_channel": "mailcom_code",
        "access_key": CODE_URL,
    })

    assert account.mailbox_type == "mailcom"


def test_account_from_row_rejects_mailcom_row_without_code_url() -> None:
    with pytest.raises(ValueError, match="Mail.com"):
        account_from_row({
            "email": "alias@icloud.com",
            "mailbox_type": "mailcom",
            "mailbox_channel": "mailcom_code",
        })


def test_create_mailbox_reader_routes_mailcom_account_to_code_reader() -> None:
    reader = create_mailbox_reader(account_from_row(dict(ROW)), None)

    assert isinstance(reader, MailComCodeReader)
