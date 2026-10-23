# -*- coding: utf-8 -*-
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import monitor
from webui import email_domain_store
from webui import email_provider_store
from webui import process_utils
from webui import proxy_store
from email_providers import openai_cpa


def test_compat_process_roots_require_existing_absolute_paths():
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        current = base / "current"
        previous = base / "previous"
        current.mkdir()
        previous.mkdir()
        roots = monitor._configured_process_roots(
            current,
            {
                "GROK_COMPAT_PROCESS_ROOTS": os.pathsep.join(
                    [str(previous), "relative-release", str(base / "missing"), str(current)]
                )
            },
        )
        assert roots == (current.resolve(), previous.resolve())


def test_process_discovery_aggregates_explicit_release_roots():
    previous_roots = monitor.MANAGED_PROCESS_ROOTS
    previous_find = monitor.find_managed_processes
    roots = (Path("/test/current"), Path("/test/previous"))
    calls = []

    def fake_find(root, script_names):
        calls.append((root, script_names))
        pid = 101 if root == roots[0] else 202
        return [{"pid": pid, "pgid": pid, "etime": "00:01", "cmd": "test"}]

    monitor.MANAGED_PROCESS_ROOTS = roots
    monitor.find_managed_processes = fake_find
    try:
        found = monitor._find_managed_processes(("run_until_100.py",))
    finally:
        monitor.MANAGED_PROCESS_ROOTS = previous_roots
        monitor.find_managed_processes = previous_find

    assert [item["pid"] for item in found] == [101, 202]
    assert [call[0] for call in calls] == list(roots)


def request(url: str, *, token: str = "", method: str = "GET", body: bytes | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=5)
        return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_monitor_http_auth_and_headers():
    token = "test-monitor-token-123456"
    previous = os.environ.get("MONITOR_TOKEN")
    os.environ["MONITOR_TOKEN"] = token
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, headers, _ = request(base + "/api/health")
        assert status == 200
        assert headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")

        status, _, body = request(base + "/api/status")
        assert status == 401
        assert json.loads(body)["ok"] is False

        status, _, body = request(base + "/api/status", token=token)
        assert status == 200
        status_payload = json.loads(body)
        assert "process" in status_payload
        assert "traffic" in status_payload
        assert "bytes_up" in status_payload["traffic"]
        assert "traffic_summary" in status_payload
        assert "bytes_per_batch" in status_payload["traffic_summary"]
        assert "bytes_per_success" in status_payload["traffic_summary"]

        status, _, _ = request(base + "/api/recovery")
        assert status == 401
        status, _, body = request(base + "/api/recovery", token=token)
        assert status == 200
        assert "pending_count" in json.loads(body)

        status, _, _ = request(base + "/api/sso-state")
        assert status == 401
        status, _, body = request(base + "/api/sso-state", token=token)
        assert status == 200
        assert "sources" in json.loads(body)
        status, _, body = request(
            base + "/api/sso-state/start",
            method="POST",
            body=b'{"source":"paste","text":""}',
        )
        assert status == 401

        status, _, body = request(base + "/api/proxies")
        assert status == 401

        status, _, _ = request(
            base + "/api/control",
            method="POST",
            body=b"not-json",
        )
        assert status == 401

        status, _, _ = request(
            base + "/api/control",
            token=token,
            method="POST",
            body=b"not-json",
        )
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if previous is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous


def test_panel_registration_env_enables_guarded_cache():
    previous_enabled = os.environ.pop("GROK_STATIC_ASSET_CACHE", None)
    previous_dir = os.environ.pop("GROK_STATIC_CACHE_DIR", None)
    try:
        env = monitor._registration_env()
        assert env["GROK_STATIC_ASSET_CACHE"] == "1"
        assert Path(env["GROK_STATIC_CACHE_DIR"]).as_posix().endswith("log/static-asset-cache")
        node_path = Path(str(env.get("PLAYWRIGHT_NODEJS_PATH") or ""))
        if os.name == "nt":
            assert env.get("GROK_HEADLESS") == "1"
            assert env.get("PYTHONUTF8") == "1"
            assert node_path.name != "playwright-node"
        os.environ["GROK_STATIC_ASSET_CACHE"] = "0"
        assert monitor._registration_env()["GROK_STATIC_ASSET_CACHE"] == "0"
    finally:
        if previous_enabled is None:
            os.environ.pop("GROK_STATIC_ASSET_CACHE", None)
        else:
            os.environ["GROK_STATIC_ASSET_CACHE"] = previous_enabled
        if previous_dir is None:
            os.environ.pop("GROK_STATIC_CACHE_DIR", None)
        else:
            os.environ["GROK_STATIC_CACHE_DIR"] = previous_dir


def test_proxy_api_auth_mutations_and_redaction():
    token = "test-proxy-token-123456"
    secret = "proxy-secret-value-99"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        proxy_store.STATE_PATH = base_path / "log" / "proxy_pool.json"
        proxy_store.LOCK_PATH = base_path / "log" / "proxy_pool.json.lock"
        proxy_store.LEGACY_PATH = base_path / "proxies.txt"
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            payload = json.dumps(
                {"proxies": f"proxy.example:8080:worker:{secret}"}
            ).encode("utf-8")
            status, _, _ = request(
                base + "/api/proxies/import",
                method="POST",
                body=payload,
            )
            assert status == 401

            status, _, body = request(
                base + "/api/proxies/import",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            imported = json.loads(body)
            assert imported["imported_count"] == 1
            assert secret not in body.decode("utf-8")
            proxy_id = imported["items"][0]["id"]

            status, _, body = request(base + "/api/proxies", token=token)
            assert status == 200
            assert secret not in body.decode("utf-8")
            assert json.loads(body)["items"][0]["has_auth"] is True

            status, _, body = request(
                base + f"/api/proxies/{proxy_id}",
                token=token,
                method="PATCH",
                body=b'{"enabled":false}',
            )
            assert status == 200
            assert json.loads(body)["items"][0]["enabled"] is False

            status, _, _ = request(
                base + f"/api/proxies/{proxy_id}",
                method="DELETE",
            )
            assert status == 401
            status, _, body = request(
                base + f"/api/proxies/{proxy_id}",
                token=token,
                method="DELETE",
            )
            assert status == 200
            assert json.loads(body)["summary"]["total"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_email_domain_api_auth_and_mutations():
    token = "test-domain-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        email_domain_store.STATE_PATH,
        email_domain_store.LOCK_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        email_domain_store.STATE_PATH = base_path / "log" / "email_domain_pool.json"
        email_domain_store.LOCK_PATH = base_path / "log" / "email_domain_pool.json.lock"
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            status, _, _ = request(base + "/api/email-domains")
            assert status == 401

            payload = json.dumps(
                {
                    "provider": "cloudmail",
                    "domains": "mail.example.com\nmail.example.com\nbad-value",
                }
            ).encode("utf-8")
            status, _, _ = request(
                base + "/api/email-domains/import",
                method="POST",
                body=payload,
            )
            assert status == 401
            status, _, body = request(
                base + "/api/email-domains/import",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            imported = json.loads(body)
            assert imported["imported_count"] == 1
            assert imported["duplicate_count"] == 1
            assert len(imported["errors"]) == 1
            domain_id = imported["items"][0]["id"]

            status, _, body = request(base + "/api/email-domains", token=token)
            assert status == 200
            assert json.loads(body)["items"][0]["provider"] == "cloudmail"

            status, _, body = request(
                base + "/api/email-domains/settings",
                token=token,
                method="POST",
                body=b'{"failure_threshold":2,"max_active_domains":1}',
            )
            assert status == 200
            assert json.loads(body)["settings"]["failure_threshold"] == 2

            status, _, body = request(
                base + f"/api/email-domains/{domain_id}",
                token=token,
                method="PATCH",
                body=b'{"enabled":false}',
            )
            assert status == 200
            assert json.loads(body)["items"][0]["enabled"] is False

            status, _, body = request(
                base + "/api/email-domains/reset",
                token=token,
                method="POST",
                body=json.dumps({"id": domain_id}).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["items"][0]["consecutive_rejections"] == 0

            status, _, _ = request(
                base + f"/api/email-domains/{domain_id}",
                method="DELETE",
            )
            assert status == 401
            status, _, body = request(
                base + f"/api/email-domains/{domain_id}",
                token=token,
                method="DELETE",
            )
            assert status == 200
            assert json.loads(body)["summary"]["total"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_email_provider_api_auth_secret_masking_and_probe():
    token = "test-email-provider-token-123456"
    secret = "provider-secret-value"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        email_provider_store.CONFIG_PATH,
        email_provider_store.LOCK_PATH,
    )
    previous_test = monitor.test_email_provider_config
    calls = []
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        email_provider_store.CONFIG_PATH = base_path / "config.json"
        email_provider_store.LOCK_PATH = base_path / "config.json.lock"

        def fake_test(provider, settings, *, clear_secrets=None):
            calls.append((provider, settings, clear_secrets))
            return {
                "ok": True,
                "provider": provider,
                "provider_label": "CloudMail",
                "detail": "CloudMail HTTP 200",
                "checked_at": "2026-07-31T00:00:00Z",
            }

        monitor.test_email_provider_config = fake_test
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        payload = json.dumps(
            {
                "provider": "cloudmail",
                "settings": {
                    "cloudmail_url": "https://mail.example.com",
                    "cloudmail_admin_email": "admin@example.com",
                    "cloudmail_password": secret,
                    "defaultDomains": "mail.example.com",
                },
            }
        ).encode("utf-8")
        try:
            status, _, _ = request(base + "/api/email-provider")
            assert status == 401
            status, _, _ = request(
                base + "/api/email-provider",
                method="POST",
                body=payload,
            )
            assert status == 401

            status, _, body = request(
                base + "/api/email-provider",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            assert secret not in body.decode("utf-8")
            saved = json.loads(body)
            assert saved["provider"] == "cloudmail"
            assert saved["secret_configured"]["cloudmail_password"] is True

            status, _, body = request(base + "/api/email-provider", token=token)
            assert status == 200
            assert secret not in body.decode("utf-8")
            assert json.loads(body)["values"]["cloudmail_password"] == ""

            status, _, body = request(
                base + "/api/email-provider/test",
                token=token,
                method="POST",
                body=json.dumps(
                    {
                        "provider": "cloudmail",
                        "settings": {"cloudmail_password": ""},
                    }
                ).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["detail"] == "CloudMail HTTP 200"
            assert calls == [("cloudmail", {"cloudmail_password": ""}, None)]

            status, _, _ = request(
                base + "/api/email-provider",
                token=token,
                method="POST",
                body=b'{"provider":"cloudmail","settings":{"proxy":"bad"}}',
            )
            assert status == 400
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            monitor.test_email_provider_config = previous_test
            email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_non_loopback_requires_token():
    env = dict(os.environ)
    env.pop("MONITOR_TOKEN", None)
    env["MONITOR_HOST"] = "192.0.2.10"
    env["MONITOR_PORT"] = "0"
    result = subprocess.run(
        [sys.executable, "-m", "webui.monitor"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "MONITOR_TOKEN is required" in (result.stdout + result.stderr)


def test_start_reports_unavailable_process_table():
    token = "test-runtime-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_find = monitor.find_managed_processes

    def unavailable(*_args, **_kwargs):
        raise process_utils.ProcessInspectionError(
            "无法读取系统进程列表；Linux 容器请确认 /proc 已挂载"
        )

    os.environ["MONITOR_TOKEN"] = token
    monitor.find_managed_processes = unavailable
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = request(
            f"http://127.0.0.1:{server.server_port}/api/start",
            token=token,
            method="POST",
            body=b"{}",
        )
        payload = json.loads(body)
        assert status == 500
        assert "/proc" in payload["error"]
        assert "已挂载" in payload["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        monitor.find_managed_processes = previous_find
        if previous_token is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous_token


def test_monitor_server_swallows_connection_aborts():
    server = monitor.MonitorHTTPServer(("127.0.0.1", 0), monitor.Handler)
    try:
        with contextlib.redirect_stderr(io.StringIO()) as captured:
            for exc in (
                ConnectionAbortedError(10053, "aborted"),
                ConnectionResetError(10054, "reset"),
                BrokenPipeError(32, "broken pipe"),
            ):
                try:
                    raise exc
                except Exception:
                    server.handle_error(("req", ("127.0.0.1", 51000)), ("127.0.0.1", 51001))
        assert captured.getvalue() == ""

        with contextlib.redirect_stderr(io.StringIO()) as captured:
            try:
                raise RuntimeError("boom")
            except Exception:
                server.handle_error(("req", ("127.0.0.1", 51000)), ("127.0.0.1", 51001))
        assert "RuntimeError: boom" in captured.getvalue()
    finally:
        server.server_close()


def test_process_running_groups_single_scan_and_cache():
    calls = []

    def fake_scan(root, script_names):
        calls.append(tuple(script_names))
        return [
            {
                "pid": 4321,
                "pgid": 4321,
                "etime": "00:01",
                "cmd": "python run_until_100.py",
                "scripts": ["run_until_100.py"],
            },
            {
                "pid": 4322,
                "pgid": 4323,
                "etime": "00:02",
                "cmd": "python run_batch_headless.py 20 3",
                "scripts": ["run_batch_headless.py"],
            },
        ]

    previous_scan = monitor.find_managed_processes_detailed
    previous_cache = dict(monitor._PROC_RUNNING_CACHE)
    monitor.find_managed_processes_detailed = fake_scan
    monitor._PROC_RUNNING_CACHE.update({"at": 0.0, "info": None})
    try:
        info = monitor.process_running(max_age=0.0)
        assert info["running"] is True
        assert info["orch_running"] is True and info["orch_pid"] == 4321
        assert info["batch_running"] is True and info["batch_pid"] == 4322
        assert info["pid"] == 4321
        assert calls == [("run_until_100.py", "run_batch_headless.py")]

        calls.clear()
        second = monitor.process_running(max_age=60.0)
        assert second == info
        assert calls == []

        third = monitor.process_running(max_age=0.0)
        assert calls == [("run_until_100.py", "run_batch_headless.py")]
        assert third["pid"] == 4321
    finally:
        monitor.find_managed_processes_detailed = previous_scan
        monitor._PROC_RUNNING_CACHE.clear()
        monitor._PROC_RUNNING_CACHE.update(previous_cache)


def test_manage_processes_detailed_reports_scripts_only_for_cwd_root():
    class FakeProcess:
        def __init__(self, pid, cwd, command):
            self.info = {
                "pid": pid,
                "cwd": str(cwd),
                "cmdline": command,
                "create_time": time.time() - 65,
            }

    roots = (
        monitor.ROOT if hasattr(monitor, "ROOT") else Path(__file__).resolve().parents[1]
    )
    processes = [
        FakeProcess(5511, roots, [sys.executable, str(monitor.ORCH_SCRIPT)]),
        FakeProcess(5522, roots, [sys.executable, str(monitor.ORCH_SCRIPT), str(roots / "run_batch_headless.py"), "20"]),
    ]
    original_process_iter = process_utils.psutil.process_iter
    try:
        process_utils.psutil.process_iter = lambda **_kwargs: iter(processes)
        found = process_utils.find_managed_processes_detailed(
            roots, ("run_until_100.py", "run_batch_headless.py")
        )
        plain = process_utils.find_managed_processes(
            roots, ("run_until_100.py", "run_batch_headless.py")
        )
    finally:
        process_utils.psutil.process_iter = original_process_iter

    assert [item["pid"] for item in found] == [5511, 5522]
    assert found[0]["scripts"] == ["run_until_100.py"]
    assert found[1]["scripts"] == ["run_batch_headless.py", "run_until_100.py"]
    assert all("scripts" not in item for item in plain)


def test_email_webhook_auth_and_pool_ingestion():
    token = "test-webhook-token-123456"
    secret = "webhook-secret-value"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_config = (email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH)
    previous_pool = os.environ.get("OPENAI_CPA_POOL_DIR")
    os.environ["MONITOR_TOKEN"] = token
    raw_email = (
        "From: xAI <noreply@x.ai>\n"
        "Subject: Your code\n"
        "\n"
        "Your verification code: ABC-XYZ\n"
    )
    try:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            email_provider_store.CONFIG_PATH = base / "config.json"
            email_provider_store.LOCK_PATH = base / "config.json.lock"
            os.environ["OPENAI_CPA_POOL_DIR"] = str(base / "pool")
            email_provider_store.atomic_write_json(
                email_provider_store.CONFIG_PATH,
                {"openai_cpa_webhook_secret": secret},
            )
            server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"

            def post(path: str, *, payload=None, secret_header: str = "x", token_value: str = ""):
                headers = {}
                if secret_header is not None:
                    headers["X-Webhook-Secret"] = secret_header
                if token_value:
                    headers["Authorization"] = f"Bearer {token_value}"
                data = json.dumps(payload).encode("utf-8") if payload is not None else b""
                req = urllib.request.Request(
                    base_url + path, data=data, headers=headers, method="POST"
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as exc:
                    return exc.code, json.loads(exc.read())

            push = {"to_addr": "user@example.test", "raw_content": raw_email}

            # 未配置/email-provider config 缺密钥的路径已在本用例保证；先验鉴权矩阵
            status, body = post(monitor.WEBHOOK_EMAIL_PATH, payload=push, secret_header="wrong")
            assert status == 401 and body["ok"] is False

            status, body = post(
                monitor.WEBHOOK_EMAIL_PATH, payload=push, secret_header=secret
            )
            assert status == 200 and body["stored"] is True
            code = openai_cpa.pop_code(str(base / "pool"), "user@example.test")
            assert code == "ABC-XYZ"

            # 无效收件地址
            status, _ = post(
                monitor.WEBHOOK_EMAIL_PATH,
                payload={"to_addr": "..", "raw_content": raw_email},
                secret_header=secret,
            )
            assert status == 400
            # 非 JSON
            req = urllib.request.Request(
                base_url + monitor.WEBHOOK_EMAIL_PATH,
                data=b"{-not json",
                headers={"X-Webhook-Secret": secret},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                raise AssertionError("expected 400")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400

            # 其他 POST 仍需 MONITOR_TOKEN
            status, _ = post("/api/control", payload={}, secret_header=None)
            assert status == 401
            status, _ = post("/api/control", payload={}, secret_header=None, token_value=token)
            assert status == 200

            # GET 状态端点受运维 token 保护，不回显密钥
            status, _, body_bytes = request(base_url + "/api/email-webhook")
            assert status == 401
            status, _, body_bytes = request(base_url + "/api/email-webhook", token=token)
            payload = json.loads(body_bytes)
            assert status == 200
            assert payload["secret_configured"] is True
            assert payload["path"] == "/api/webhook/email"
            assert "webhook-secret-value" not in body_bytes.decode("utf-8")
            assert raw_email not in body_bytes.decode("utf-8")
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    finally:
        if previous_token is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous_token
        email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = previous_config
        if previous_pool is None:
            os.environ.pop("OPENAI_CPA_POOL_DIR", None)
        else:
            os.environ["OPENAI_CPA_POOL_DIR"] = previous_pool


def test_email_webhook_fails_closed_without_secret():
    class FakeMain:
        pass

    previous_config = (email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH)
    try:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            email_provider_store.CONFIG_PATH = base / "missing.json"
            email_provider_store.LOCK_PATH = base / "missing.json.lock"
            server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"
            try:
                req = urllib.request.Request(
                    base_url + monitor.WEBHOOK_EMAIL_PATH,
                    data=b"{}",
                    headers={"X-Webhook-Secret": "anything", "Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
                raise AssertionError("expected 503 fail-closed")
            except urllib.error.HTTPError as exc:
                assert exc.code == 503
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    finally:
        email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = previous_config


if __name__ == "__main__":
    test_compat_process_roots_require_existing_absolute_paths()
    test_process_discovery_aggregates_explicit_release_roots()
    test_monitor_http_auth_and_headers()
    test_panel_registration_env_enables_guarded_cache()
    test_proxy_api_auth_mutations_and_redaction()
    test_email_domain_api_auth_and_mutations()
    test_email_provider_api_auth_secret_masking_and_probe()
    test_non_loopback_requires_token()
    test_start_reports_unavailable_process_table()
    test_monitor_server_swallows_connection_aborts()
    test_process_running_groups_single_scan_and_cache()
    test_manage_processes_detailed_reports_scripts_only_for_cwd_root()
    test_email_webhook_auth_and_pool_ingestion()
    test_email_webhook_fails_closed_without_secret()
    print("OK monitor http")
