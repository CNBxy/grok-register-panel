"""OpenAI-CPA 内存池邮箱（Webhook 推送模式）。

工作方式：
- 收信域名走 Cloudflare Email Routing catch-all，邮件 Worker 把原始邮件
  POST 到面板 `/api/webhook/email`，头 `X-Webhook-Secret` 与本地
  `openai_cpa_webhook_secret` 一致。
- 面板从原始 RFC822 邮件提取 xAI 验证码，按收件地址写入共享内存池目录
  （跨进程：面板接收、批量 worker 取码），TTL 过期自动清理。
- 注册时按域名生成随机 catch-all 地址（无需建号 API），随后轮询取码。

面板 HTTP 层只负责鉴权与请求体校验；邮件解码 / 取码 / 池管理在本模块。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

from email_providers.common import extract_verification_code, generate_username

try:
    from secure_files import atomic_write_json, ensure_private_dir
except ImportError:  # running from email_providers/
    import sys

    ROOT = Path(__file__).resolve().parent.parent
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from secure_files import atomic_write_json, ensure_private_dir

ROOT = Path(__file__).resolve().parent.parent

WEBHOOK_PATH = "/api/webhook/email"
WEBHOOK_SECRET_HEADER = "X-Webhook-Secret"
# Worker 推送整封邮件时请求体接近 2MB，HTTP 层预留少量头部空间
RAW_EMAIL_LIMIT_BYTES = 2 * 1024 * 1024
WEBHOOK_BODY_LIMIT_BYTES = RAW_EMAIL_LIMIT_BYTES + 4096
MESSAGE_ID_MAX_LENGTH = 512
POOL_TTL_SECONDS = 300
POOL_MAX_ENTRIES = 1000
SOURCE_LABEL = "openai_cpa_catch_all"
NO_CODE_REASON = "邮件中未识别到验证码"

EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,255}")

_domain_index = 0
_domain_lock = threading.Lock()


def default_pool_dir() -> str:
    """共享取码池目录（面板接收、worker 读取，同一项目根即可）。"""
    configured = str(os.environ.get("OPENAI_CPA_POOL_DIR", "") or "").strip()
    if configured:
        return configured
    return str(ROOT / "log" / "openai_cpa_pool")


def _entry_path(pool_dir: str | os.PathLike[str], email: str) -> Path:
    digest = hashlib.sha256(str(email or "").strip().lower().encode("utf-8")).hexdigest()
    return Path(pool_dir) / f"{digest[:24]}.json"


def _decode_header_value(raw: str) -> str:
    from email.header import decode_header, make_header

    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw


def decode_raw_email(raw_content: str) -> Tuple[str, str]:
    """解析原始 RFC822 邮件 → (subject, 纯文本正文聚合)。"""
    from email import policy
    from email.parser import Parser

    raw = str(raw_content or "")
    subject = ""
    body_parts = []
    try:
        message = Parser(policy=policy.default).parsestr(raw)
        raw_subject = str(message.get("Subject", "") or "")
        if raw_subject:
            subject = _decode_header_value(raw_subject)
        parts = list(message.walk()) if message.is_multipart() else [message]
        for part in parts:
            try:
                content_type = str(part.get_content_type() or "").lower()
                disposition = str(part.get_content_disposition() or "").lower()
            except Exception:
                continue
            if content_type not in {"text/plain", "text/html"} or disposition == "attachment":
                continue
            try:
                text = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                else:
                    text = str(payload or "")
            if content_type == "text/html":
                text = re.sub(r"<[^>]+>", " ", str(text))
            if str(text).strip():
                body_parts.append(str(text))
    except Exception:
        return "", raw
    return subject, ("\n".join(body_parts) or raw)


def _prune_pool(pool_dir: Path, now: float | None = None) -> int:
    """清理过期条目并限制最大条目数，返回存活条数。"""
    now = time.time() if now is None else float(now)
    entries = []
    for path in pool_dir.glob("*.json"):
        try:
            received_at = float(path.stat().st_mtime)
        except OSError:
            continue
        if now - received_at > POOL_TTL_SECONDS:
            try:
                path.unlink()
            except OSError:
                pass
            continue
        entries.append((received_at, path))
    overflow = len(entries) - POOL_MAX_ENTRIES
    dropped_oldest = 0
    if overflow > 0:
        for _received_at, path in sorted(entries)[:overflow]:
            try:
                path.unlink()
            except OSError:
                pass
            dropped_oldest += 1
    return len(entries) - dropped_oldest


def store_code(
    pool_dir: str | os.PathLike[str],
    email: str,
    code: str,
    *,
    message_id: str = "",
    received_at: float | None = None,
) -> Path:
    """写入一条取码记录（同一地址覆盖旧码，仅保留最新）。"""
    target = Path(pool_dir)
    ensure_private_dir(target)
    received_at = time.time() if received_at is None else float(received_at)
    payload = {
        "code": str(code or "").strip(),
        "message_id": str(message_id or "")[:MESSAGE_ID_MAX_LENGTH],
        "received_at": received_at,
    }
    # mtime 是过期判据：写入后固定到 received_at，避免文件系统粒度误差
    path = atomic_write_json(_entry_path(target, email), payload)
    try:
        os.utime(path, (received_at, received_at))
    except OSError:
        pass
    return path


def pop_code(
    pool_dir: str | os.PathLike[str],
    email: str,
    *,
    now: float | None = None,
) -> str:
    """取出该邮箱的一次性验证码（读完即删，过期视为无码）。"""
    path = _entry_path(pool_dir, email)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    try:
        path.unlink()
    except OSError:
        pass
    import json

    try:
        data = json.loads(raw)
    except Exception:
        return ""
    if not isinstance(data, dict) or not str(data.get("code") or "").strip():
        return ""
    now = time.time() if now is None else float(now)
    try:
        received_at = float(data.get("received_at") or 0)
    except (TypeError, ValueError):
        received_at = 0.0
    if not received_at or now - received_at > POOL_TTL_SECONDS:
        return ""
    return str(data["code"]).strip()


def pool_stats(pool_dir: str | os.PathLike[str], *, now: float | None = None) -> dict:
    """当前池中待取验证码数量（过期清理后统计）。"""
    target = Path(pool_dir)
    if not target.is_dir():
        return {"pending": 0, "ttl_seconds": POOL_TTL_SECONDS}
    return {"pending": _prune_pool(target, now), "ttl_seconds": POOL_TTL_SECONDS}


def accept_webhook(
    payload: Any,
    provided_secret: str,
    expected_secret: str,
    *,
    pool_dir: str | os.PathLike[str],
    now: float | None = None,
) -> Tuple[int, dict]:
    """Worker 推送入口：校验密钥并把验证码写入内存池。

    HTTP 层提供 payload（JSON 对象）、`X-Webhook-Secret` 头值与本地配置的
    期望密钥；返回 (http_status, response_json)。
    """
    expected = str(expected_secret or "").strip()
    if not expected:
        return 503, {"ok": False, "error": "邮件 Webhook 通信密钥未配置（openai_cpa_webhook_secret）"}
    if not hmac.compare_digest(str(provided_secret or ""), expected):
        return 401, {"ok": False, "error": "Webhook 密钥无效"}
    if not isinstance(payload, dict):
        return 400, {"ok": False, "error": "请求体必须是 JSON 对象"}

    to_addr = str(payload.get("to_addr") or "").strip().lower()
    raw_content = payload.get("raw_content")
    message_id = str(payload.get("message_id") or "")[:MESSAGE_ID_MAX_LENGTH]
    if len(to_addr) > 320 or not EMAIL_RE.fullmatch(to_addr):
        return 400, {"ok": False, "error": "收件邮箱格式无效"}
    if not isinstance(raw_content, str) or not raw_content:
        return 400, {"ok": False, "error": "raw_content 不能为空"}
    if len(raw_content.encode("utf-8", errors="ignore")) > RAW_EMAIL_LIMIT_BYTES:
        return 413, {"ok": False, "error": "邮件内容超过 2MB 限制"}

    subject, decoded_text = decode_raw_email(raw_content)
    code = extract_verification_code(decoded_text, subject)
    if not code:
        return 202, {"ok": True, "stored": False, "reason": NO_CODE_REASON}

    target = Path(pool_dir)
    with _pool_write_lock(target):
        store_code(target, to_addr, code, message_id=message_id, received_at=now)
        # 写入后统一修剪：TTL 过期与容量上限都在静止状态保持成立
        _prune_pool(target, now)
    return 200, {"ok": True, "stored": True}


_pool_write_locks: dict[str, threading.Lock] = {}
_pool_write_locks_guard = threading.Lock()


def _pool_write_lock(pool_dir: Path) -> threading.Lock:
    key = str(pool_dir)
    with _pool_write_locks_guard:
        return _pool_write_locks.setdefault(key, threading.Lock())


def parse_domains(raw: object) -> list[str]:
    parts = re.split(r"[,，\s]+", str(raw or "").strip())
    seen: set[str] = set()
    domains = []
    for part in parts:
        domain = part.strip().lstrip("@").rstrip(".").lower()
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def create_mailbox(domains: object, username: str = "") -> Tuple[str, str]:
    """catch-all 模式：随机地址即建即用，无需邮箱创建接口。"""
    cleaned = parse_domains(domains)
    if not cleaned:
        raise Exception(
            "OpenAI-CPA 需要在域名池或 defaultDomains 中配置可用收信域名"
        )
    global _domain_index
    with _domain_lock:
        domain = cleaned[_domain_index % len(cleaned)]
        _domain_index += 1
    address = f"{(username or generate_username(10)).lower()}@{domain}"
    return address, SOURCE_LABEL


def wait_for_code(
    pool_dir: str | os.PathLike[str],
    email: str,
    *,
    timeout: int = 300,
    poll_interval: float = 0.3,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    """轮询共享取码池；等待期间每 60s 触发一次重发（触发 Worker 跟进推送）。"""
    target_email = str(email or "").strip().lower()
    if not target_email:
        raise Exception("OpenAI-CPA 邮箱地址为空")
    if not str(pool_dir or "").strip():
        raise Exception("OpenAI-CPA 取码池目录未配置")

    deadline = time.time() + timeout
    interval = max(0.1, min(float(poll_interval or 0.3), 1.0))
    next_resend_at = time.time() + 60
    if log_callback:
        stats = pool_stats(pool_dir)
        log_callback(
            f"[Debug] OpenAI-CPA 等待验证码: {target_email}"
            f"（内存池待取 {stats['pending']}，TTL {stats['ttl_seconds']}s）"
        )

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        code = pop_code(pool_dir, target_email)
        if code:
            if log_callback:
                log_callback(f"[*] OpenAI-CPA 内存池提取到验证码: {code}")
            return code
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 60
        sleep_with_cancel(interval, cancel_callback)

    stats = pool_stats(pool_dir)
    raise Exception(
        f"OpenAI-CPA 在 {timeout}s 内未从 Webhook 内存池收到验证码"
        f"（待取 {stats['pending']}；确认邮件 Worker 已推送至面板 {WEBHOOK_PATH}）"
    )
