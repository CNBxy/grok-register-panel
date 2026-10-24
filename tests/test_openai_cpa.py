# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import random
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import openai_cpa


def _pool(tmp: str) -> str:
    path = Path(tmp) / "pool"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


RAW_PLAIN = (
    "From: xAI <noreply@x.ai>\r\n"
    "To: user@example.test\r\n"
    "Subject: Your code\r\n"
    "\r\n"
    "Your verification code is ABC-DEF\r\n"
)

RAW_MULTIPART = (
    "From: xAI <noreply@x.ai>\r\n"
    "To: user@example.test\r\n"
    "Content-Type: multipart/alternative; boundary=\"bound\"\r\n"
    "\r\n"
    "--bound\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "WW91ciBjb2RlOiBHT0QtWkZB\r\n"  # base64("Your code: GOD-ZFA")
    "--bound\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><body><p>Code</p> <span>QWQ-ZZZ</span></body></html>\r\n"
    "--bound--\r\n"
)

NO_CODE = (
    "From: a@b.example.test\r\n"
    "Subject: newsletter 100-200\r\n"
    "\r\n"
    "padding grid 100-200 bar\r\n"
)


def test_parse_domains_and_rotation():
    openai_cpa._domain_index = 0
    assert openai_cpa.parse_domains("@One.Example.com，two.example extra.example") == [
        "one.example.com",
        "two.example",
        "extra.example",
    ]
    assert openai_cpa.parse_domains("") == []
    try:
        openai_cpa.create_mailbox("")
    except Exception as exc:
        assert "域名" in str(exc)
    else:
        raise AssertionError("expected domain error")

    first, label = openai_cpa.create_mailbox("one.example, two.example", "tester")
    assert first == "tester@one.example"
    assert label == openai_cpa.SOURCE_LABEL
    second, _ = openai_cpa.create_mailbox("one.example, two.example", "tester")
    assert second == "tester@two.example"
    auto, _ = openai_cpa.create_mailbox("mail.example.test")
    local, _, domain = auto.partition("@")
    assert domain == "mail.example.test"
    assert "@" in local or ("." in local or "_" in local or local.isalnum())


def test_random_subdomain_levels():
    rng = random.Random(42)
    openai_cpa._domain_index = 0
    address, _ = openai_cpa.create_mailbox(
        "example.com",
        "tester",
        random_subdomain_levels="0",
        rng=rng,
    )
    assert address == "tester@example.com"

    openai_cpa._domain_index = 0
    address, _ = openai_cpa.create_mailbox(
        "example.com",
        "tester",
        random_subdomain_levels="3",
        rng=rng,
    )
    local, domain = address.split("@", 1)
    labels = domain.split(".")
    assert local == "tester"
    assert len(labels) == 2 + 3
    for label in labels[:3]:
        assert re.fullmatch(r"[a-z][a-z0-9]{3,9}", label), label
    assert labels[-2:] == ["example", "com"]

    openai_cpa._domain_index = 0
    address, _ = openai_cpa.create_mailbox(
        "example.com",
        "tester",
        random_subdomain_levels="1-7",
        rng=rng,
    )
    extra = len(address.split("@", 1)[1].split(".")) - 2
    assert 1 <= extra <= 7

    openai_cpa._domain_index = 0
    address, _ = openai_cpa.create_mailbox(
        "example.com",
        "tester",
        random_subdomain_levels=True,
        rng=rng,
    )
    extra = len(address.split("@", 1)[1].split(".")) - 2
    assert 1 <= extra <= 7


def test_random_subdomain_level_count_modes():
    rng = random.Random(7)
    assert openai_cpa.random_subdomain_level_count("0", rng) == 0
    assert openai_cpa.random_subdomain_level_count("off", rng) == 0
    assert openai_cpa.random_subdomain_level_count("", rng) == 0
    assert openai_cpa.random_subdomain_level_count("3", rng) == 3
    assert openai_cpa.random_subdomain_level_count("1-7", rng) in range(1, 8)
    assert openai_cpa.random_subdomain_level_count("1-3", rng) in range(1, 4)
    assert openai_cpa.random_subdomain_level_count("99", rng) == 7
    assert openai_cpa.random_subdomain_level_count("garbage", rng) == 0


def test_store_pop_and_expiry():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        openai_cpa.store_code(pool, "user@example.test", "ABC-DEF", message_id="m1")
        code = openai_cpa.pop_code(pool, "USER@EXAMPLE.TEST")
        assert code == "ABC-DEF"
        # 读后即删
        assert openai_cpa.pop_code(pool, "user@example.test") == ""

        # 过期视为无码且文件被清理
        old = time.time() - openai_cpa.POOL_TTL_SECONDS - 5
        openai_cpa.store_code(pool, "old@example.test", "XXX-YYY", received_at=old)
        assert openai_cpa.pop_code(pool, "old@example.test") == ""
        assert not list(Path(pool).glob("*.json"))

        # 损坏数据不抛错
        corrupt = openai_cpa._entry_path(pool, "corrupt@example.test")
        corrupt.write_text("{not json", encoding="utf-8")
        assert openai_cpa.pop_code(pool, "corrupt@example.test") == ""
        assert not corrupt.exists()


def test_decode_raw_email():
    subject, text = openai_cpa.decode_raw_email(RAW_PLAIN)
    assert subject == "Your code"
    assert "ABC-DEF" in text

    subject, text = openai_cpa.decode_raw_email(RAW_MULTIPART)
    assert "GOD-ZFA" in text
    assert "QWQ-ZZZ" in text
    assert "<" not in text

    # HTML 主体 + 编码主题
    raw_html = (
        "From: noreply@x.ai\r\n"
        'Subject: =?utf-8?b?U3BhY2VYQUkgY29uZmlybWF0aW9uIGNvZGU6IDI0Ny01Nzg=?=\r\n'
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body><strong>confirmation code: 247-578</strong></body></html>\r\n"
    )
    subject, text = openai_cpa.decode_raw_email(raw_html)
    assert "confirmation" in subject.lower()
    assert "247-578" in text

    # 异常输入直接回退为原文
    subject, text = openai_cpa.decode_raw_email("Subject: x\r\nrandom")
    assert "random" in text


def test_accept_webhook_validation_matrix():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        good = {"to_addr": "user@example.test", "raw_content": RAW_PLAIN, "message_id": "m" * 600}

        status, resp = openai_cpa.accept_webhook(
            dict(good), "wrong-secret", "right-secret", pool_dir=pool
        )
        assert status == 401 and resp["error"]

        status, resp = openai_cpa.accept_webhook(dict(good), "right-secret", "", pool_dir=pool)
        assert status == 503

        status, resp = openai_cpa.accept_webhook(
            "not-a-dict", "right-secret", "right-secret", pool_dir=pool
        )
        assert status == 400

        status, resp = openai_cpa.accept_webhook(
            {"to_addr": "bad..addr", "raw_content": RAW_PLAIN},
            "right-secret",
            "right-secret",
            pool_dir=pool,
        )
        assert status == 400 and "邮箱" in resp["error"]

        status, resp = openai_cpa.accept_webhook(
            {"to_addr": "user@example.test", "raw_content": ""},
            "right-secret",
            "right-secret",
            pool_dir=pool,
        )
        assert status == 400

        status, resp = openai_cpa.accept_webhook(
            {"to_addr": "user@example.test", "raw_content": "x" * (openai_cpa.RAW_EMAIL_LIMIT_BYTES + 10)},
            "right-secret",
            "right-secret",
            pool_dir=pool,
        )
        assert status == 413

        # 无验证码邮件：202 不存储
        status, resp = openai_cpa.accept_webhook(
            {"to_addr": "user@example.test", "raw_content": NO_CODE},
            "right-secret",
            "right-secret",
            pool_dir=pool,
        )
        assert status == 202 and resp["stored"] is False

        # 正常存储：message_id 截断 512
        status, resp = openai_cpa.accept_webhook(dict(good), "right-secret", "right-secret", pool_dir=pool)
        assert status == 200 and resp["stored"] is True
        assert openai_cpa.pop_code(pool, "user@example.test") == "ABC-DEF"


def test_accept_web_hook_prunes_and_caps():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        base = time.time() - 30
        # 虚拟时间间隔 0.1s，总跨度 < TTL：只触发容量上限，不触发过期清理
        for index in range(openai_cpa.POOL_MAX_ENTRIES + 10):
            email = f"user{index:04d}@example.test"
            body = RAW_PLAIN.replace("user@example.test", email)
            status, _ = openai_cpa.accept_webhook(
                {"to_addr": email, "raw_content": body},
                "s",
                "s",
                pool_dir=pool,
                now=base + index * 0.1,
            )
            assert status == 200
        entries = list(Path(pool).glob("*.json"))
        assert len(entries) == openai_cpa.POOL_MAX_ENTRIES
        # 最早写入的条目被挤出（received_at 最小），新条目保留
        assert openai_cpa.pop_code(pool, "user0000@example.test") == ""
        assert openai_cpa.pop_code(pool, "user0009@example.test") == ""
        assert openai_cpa.pop_code(pool, "user0100@example.test") == "ABC-DEF"
        assert openai_cpa.pop_code(pool, "user1009@example.test") == "ABC-DEF"
        stats = openai_cpa.pool_stats(pool)
        assert stats["ttl_seconds"] == openai_cpa.POOL_TTL_SECONDS
        assert stats["pending"] <= openai_cpa.POOL_MAX_ENTRIES


def test_accept_web_hook_ttl_expiry():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        base = time.time() - 10
        now = base
        for index in range(openai_cpa.POOL_MAX_ENTRIES + 10):
            email = f"user{index:04d}@example.test"
            body = RAW_PLAIN.replace("user@example.test", email)
            status, _ = openai_cpa.accept_webhook(
                {"to_addr": email, "raw_content": body},
                "s",
                "s",
                pool_dir=pool,
                now=now,
            )
            now += 1
        # 虚拟时间跨越 TTL：TTL 过期清理把超龄条目挤出
        stats = openai_cpa.pool_stats(pool, now=now)
        assert 0 < stats["pending"] <= openai_cpa.POOL_TTL_SECONDS
        assert openai_cpa.pop_code(pool, "user0000@example.test") == ""


def test_pool_stats_counts_pending():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        assert openai_cpa.pool_stats(pool)["pending"] == 0
        openai_cpa.store_code(pool, "a@example.test", "ABC-DEF")
        openai_cpa.store_code(pool, "b@example.test", "QWQ-AAA")
        assert openai_cpa.pool_stats(pool)["pending"] == 2
        assert openai_cpa.pool_stats(str(Path(tmp) / "missing"))["pending"] == 0


class _FakeCancel:
    def __init__(self, after_calls: int = 0):
        self.calls = 0

    def __call__(self, cancel_callback=None):
        return


def test_wait_for_code_returns_popped_code():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        openai_cpa.store_code(pool, "user@example.test", "ABC-DEF")
        seen_logs = []

        def raise_cancel(cb=None):
            return

        def sleep_with_cancel(seconds, cb=None):
            return

        code = openai_cpa.wait_for_code(
            pool,
            "user@example.test",
            timeout=5,
            poll_interval=0.1,
            raise_if_cancelled=raise_cancel,
            sleep_with_cancel=sleep_with_cancel,
            log_callback=seen_logs.append,
        )
        assert code == "ABC-DEF"


def test_wait_for_code_timeout_message():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        resends = []

        def raise_cancel(cb=None):
            return

        def sleep_with_cancel(seconds, cb=None):
            time.sleep(0.05)

        try:
            openai_cpa.wait_for_code(
                pool,
                "user@example.test",
                timeout=0.3,
                poll_interval=0.1,
                raise_if_cancelled=raise_cancel,
                sleep_with_cancel=sleep_with_cancel,
                resend_callback=lambda: resends.append(1),
            )
        except Exception as exc:
            assert "Webhook 内存池" in str(exc)
            assert "api/webhook/email" in str(exc)
        else:
            raise AssertionError("expected timeout error")


def test_wait_for_code_requires_email_and_pool_dir():
    def raise_cancel(cb=None):
        return

    def sleep_with_cancel(seconds, cb=None):
        return

    for args in (("", "pool"), ("mail@example.test", "")):
        try:
            openai_cpa.wait_for_code(
                args[1],
                args[0],
                raise_if_cancelled=raise_cancel,
                sleep_with_cancel=sleep_with_cancel,
            )
        except Exception:
            pass
        else:
            raise AssertionError("expected config error")


def test_default_pool_env_override(monkeypatch=None):
    previous = os.environ.get("OPENAI_CPA_POOL_DIR")
    try:
        os.environ["OPENAI_CPA_POOL_DIR"] = "C:/temp/pool-dir"
        assert openai_cpa.default_pool_dir() == "C:/temp/pool-dir"
        os.environ.pop("OPENAI_CPA_POOL_DIR", None)
        assert openai_cpa.default_pool_dir().endswith("openai_cpa_pool")
    finally:
        if previous is None:
            os.environ.pop("OPENAI_CPA_POOL_DIR", None)
        else:
            os.environ["OPENAI_CPA_POOL_DIR"] = previous


def test_connectivity_check():
    import connectivity

    ok = connectivity.check_email_api(
        "openai_cpa",
        {"openai_cpa_webhook_secret": "abc", "defaultDomains": "mail.example.test"},
        lambda *a, **k: None,
        lambda *a, **k: None,
    )
    assert ok[1] is True and "/api/webhook/email" in ok[2]

    missing_secret = connectivity.check_email_api(
        "openai_cpa", {"defaultDomains": "mail.example.test"}, None, None
    )
    assert missing_secret[1] is False and "openai_cpa_webhook_secret" in missing_secret[2]

    missing_domains = connectivity.check_email_api(
        "openai_cpa", {"openai_cpa_webhook_secret": "abc"}, None, None
    )
    assert missing_domains[1] is False and "域名" in missing_domains[2]


def test_pool_file_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        pool = _pool(tmp)
        openai_cpa.store_code(pool, "user@example.test", "ABC-DEF")
        entry = next(Path(pool).glob("*.json"))
        if os.name == "posix":
            import stat

            assert stat.S_IMODE(entry.stat().st_mode) == 0o600
            assert stat.S_IMODE(Path(pool).stat().st_mode) == 0o700


if __name__ == "__main__":
    test_parse_domains_and_rotation()
    test_random_subdomain_levels()
    test_random_subdomain_level_count_modes()
    test_store_pop_and_expiry()
    test_decode_raw_email()
    test_accept_webhook_validation_matrix()
    test_accept_web_hook_prunes_and_caps()
    test_accept_web_hook_ttl_expiry()
    test_pool_stats_counts_pending()
    test_wait_for_code_returns_popped_code()
    test_wait_for_code_timeout_message()
    test_wait_for_code_requires_email_and_pool_dir()
    test_default_pool_env_override()
    test_connectivity_check()
    test_pool_file_permissions()
    print("OK openai_cpa")
