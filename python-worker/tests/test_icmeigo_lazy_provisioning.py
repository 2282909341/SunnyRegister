import json
from unittest.mock import Mock, patch

from sunny_core import worker


def test_icmeigo_provisioner_releases_then_generates_replacement():
    db = Mock()
    db.task_id = "task-icmeigo"
    db.create_icmeigo_mailbox.return_value = {"id": 2, "email": "next@icloud.com"}
    released = Mock(ok=True)
    released.json.return_value = {"data": {"success": 1}}
    generated = Mock(ok=True)
    generated.json.return_value = {"data": {"email": "next@icloud.com"}}

    mailbox = {"id": 1, "email": "done@icloud.com", "access_key": "api_card", "group_id": 7}
    with patch.object(worker.requests, "post", side_effect=[released, generated]) as request:
        result = worker.IcMeigoMailboxProvisioner(
            db, {"icmeigo_remaining_quota": {"api_card": 1}}
        ).rotate(mailbox)

    assert result["email"] == "next@icloud.com"
    assert [call.args[0] for call in request.call_args_list] == [
        "https://ic.meiguo.lol/api/hme/release-all",
        "https://ic.meiguo.lol/api/hme/generate",
    ]
    db.mark_icmeigo_released.assert_called_once_with(1)
    db.create_icmeigo_mailbox.assert_called_once_with("next@icloud.com", "api_card", 7)


class FakeTaskDB:
    instance = None

    def __init__(self, task_id):
        self.task_id = task_id
        self.payload = {
            "identity": "icmeigo",
            "icmeigo_auto": True,
            "icmeigo_remaining_quota": {f"api_card_{card}": 9 for card in range(1, 11)},
            "mailbox_ids": list(range(1, 11)),
            "count": 100,
            "concurrency": 1,
            "proxy_enabled": False,
            "setup_login_secret": True,
        }
        self.updates = []
        self.events = []
        FakeTaskDB.instance = self

    def task(self):
        return {"type": "sunny_register", "payload_json": json.dumps(self.payload), "status": "pending"}

    def fetch_mailboxes(self, _ids=None, _count=0):
        return [
            {"id": card * 100, "email": f"card{card}-1@icloud.com", "access_key": f"api_card_{card}", "group_id": 1}
            for card in range(1, 11)
        ]

    def cancel_requested(self):
        return False

    def ensure_not_cancelled(self):
        return None

    def update_task(self, **fields):
        self.updates.append(fields)

    def event(self, message, level="info", typ="log", detail=None):
        self.events.append((message, level, detail))

    def close(self):
        return None


def test_icmeigo_task_continues_until_all_detected_quota_is_registered():
    rotations = []
    generated = {f"api_card_{card}": 1 for card in range(1, 11)}

    class Provisioner:
        def __init__(self, _db, _payload):
            pass

        def rotate(self, mailbox):
            rotations.append(mailbox["id"])
            key = mailbox["access_key"]
            generated[key] += 1
            sequence = generated[key]
            card = int(key.rsplit("_", 1)[1])
            return None if sequence > 10 else {
                "id": card * 100 + sequence,
                "email": f"card{card}-{sequence}@icloud.com",
                "access_key": key,
                "group_id": 1,
            }

    def run_one(_db, _task_type, _payload, mailbox, _idx, _total, _policy):
        return True, {"email": mailbox["email"], "auth_action": "register", "login_secret_complete": True}

    with (
        patch.object(worker, "SunnyDB", FakeTaskDB),
        patch.object(worker, "IcMeigoMailboxProvisioner", Provisioner),
        patch.object(worker, "_run_one", side_effect=run_one),
        patch.object(worker, "_log_proxy_startup"),
    ):
        worker.run_sunny_task("task-icmeigo-auto")

    assert len(rotations) == 100
    assert all(count == 11 for count in generated.values())
    final = FakeTaskDB.instance.updates[-1]
    assert final["status"] == "succeeded"
    assert json.loads(final["result_json"])["success"] == 100


def test_icmeigo_provisioner_refills_after_failure_without_releasing():
    db = Mock()
    db.task_id = "task-icmeigo"
    db.create_icmeigo_mailbox.return_value = {"id": 2, "email": "next@icloud.com"}
    generated = Mock(ok=True)
    generated.json.return_value = {"data": {"email": "next@icloud.com"}}

    mailbox = {"id": 1, "email": "failed@icloud.com", "access_key": "api_card", "group_id": 7}
    with patch.object(worker.requests, "post", return_value=generated) as request:
        result = worker.IcMeigoMailboxProvisioner(
            db, {"icmeigo_remaining_quota": {"api_card": 2}}
        ).refill_after_failure(mailbox)

    assert result["email"] == "next@icloud.com"
    # 失败补位不发 release-all（失败邮箱保留待重试），只 generate 一个新邮箱
    assert [call.args[0] for call in request.call_args_list] == ["https://ic.meiguo.lol/api/hme/generate"]
    db.mark_icmeigo_released.assert_not_called()
    db.create_icmeigo_mailbox.assert_called_once_with("next@icloud.com", "api_card", 7)
    assert db.event.call_count >= 1


def test_icmeigo_provisioner_refill_returns_none_when_quota_gone():
    db = Mock()
    db.task_id = "task-icmeigo"
    mailbox = {"id": 1, "email": "failed@icloud.com", "access_key": "api_card", "group_id": 7}
    with patch.object(worker.requests, "post") as request:
        result = worker.IcMeigoMailboxProvisioner(
            db, {"icmeigo_remaining_quota": {"api_card": 0}}
        ).refill_after_failure(mailbox)

    assert result is None
    request.assert_not_called()


def test_icmeigo_task_continues_after_failure_by_refilling():
    refills = []
    generated = {f"api_card_{card}": 1 for card in range(1, 11)}

    def make_replacement(mailbox):
        key = mailbox["access_key"]
        generated[key] += 1
        sequence = generated[key]
        card = int(key.rsplit("_", 1)[1])
        return None if sequence > 10 else {
            "id": card * 100 + sequence,
            "email": f"card{card}-{sequence}@icloud.com",
            "access_key": key,
            "group_id": 1,
        }

    class Provisioner:
        def __init__(self, _db, _payload):
            pass

        def rotate(self, mailbox):
            return make_replacement(mailbox)

        def refill_after_failure(self, mailbox):
            refills.append(mailbox["id"])
            return make_replacement(mailbox)

    def run_one(_db, _task_type, _payload, mailbox, _idx, _total, _policy):
        if mailbox["id"] == 100:  # card1-1 第一个邮箱注册失败（如旧验证码 401）
            return False, "Validate email verification code failed (HTTP 401): Wrong code"
        return True, {"email": mailbox["email"], "auth_action": "register", "login_secret_complete": True}

    with (
        patch.object(worker, "SunnyDB", FakeTaskDB),
        patch.object(worker, "IcMeigoMailboxProvisioner", Provisioner),
        patch.object(worker, "_run_one", side_effect=run_one),
        patch.object(worker, "_log_proxy_startup"),
    ):
        worker.run_sunny_task("task-icmeigo-auto")

    # 失败邮箱补位一次后流水线继续跑完全部 100 个额度，不再卡在单个失败邮箱
    assert refills == [100]
    assert max(u.get("progress_current", 0) for u in FakeTaskDB.instance.updates) == 100
    assert max(u.get("success_count", 0) for u in FakeTaskDB.instance.updates) == 99
    assert max(u.get("error_count", 0) for u in FakeTaskDB.instance.updates) == 1
    final = FakeTaskDB.instance.updates[-1]
    assert final["status"] == "failed"  # 严格失败判定保持原语义：仍有 1 个失败
    assert json.loads(final["result_json"])["success"] == 99
