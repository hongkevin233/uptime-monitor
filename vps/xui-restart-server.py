#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x-ui 重启 HTTP 服务 —— 供浏览器前端直连调用。
监听 TCP 端口，收到 `POST /restart` 后校验 HMAC 短时密钥并执行 `x-ui restart`。

协议（浏览器/前端）：
  POST https://<vps>:39332/restart
  Content-Type: application/json
  {"key": "<hmac>", "ts": 1750000000}

校验：
  hmac = HMAC-SHA256(RESTART_KEY, "xui-restart:" + ts) 的前 24 hex
  时间窗 |now - ts| <= 60 秒（防重放）

响应：JSON + 宽松 CORS（允许 uptime 管理后台跨域调用）。

密钥由 uptime-monitor Worker 在管理员登录后签发，前端拿到后调用本接口。
用 systemd 常驻（见 xui-restart.service）。
"""
import socket
import subprocess
import os
import sys
import hmac
import hashlib
import json
import time

KEY = os.environ.get("RESTART_KEY", "")
HOST = os.environ.get("RESTART_HOST", "0.0.0.0")
PORT = int(os.environ.get("RESTART_PORT", "39333"))
ALLOW_ORIGIN = os.environ.get("ALLOW_ORIGIN", "*")
TIME_WINDOW = 60  # 秒

BODY = "xui-restart"  # 签名用途串（固定）


def http(resp_bytes, code=b"200 OK", ctype=b"application/json"):
    return (b"HTTP/1.1 " + code + b"\r\n"
            b"Access-Control-Allow-Origin: " + ALLOW_ORIGIN.encode() + b"\r\n"
            b"Access-Control-Allow-Methods: POST, OPTIONS\r\n"
            b"Access-Control-Allow-Headers: Content-Type\r\n"
            b"Access-Control-Max-Age: 600\r\n"
            b"Content-Type: " + ctype + b"\r\n"
            b"Content-Length: " + str(len(resp_bytes)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + resp_bytes)


def verify(ts, sig):
    """校验签名与时间窗，返回 (ok, msg)。"""
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return False, "bad-ts"
    if abs(int(time.time()) - ts) > TIME_WINDOW:
        return False, "expired"
    expect = hmac.new(KEY.encode(), (BODY + ":" + str(ts)).encode(), hashlib.sha256).hexdigest()[:24]
    try:
        ok = hmac.compare_digest(sig, expect)
    except Exception:
        ok = False
    return (True, "ok") if ok else (False, "bad-key")


def handle(conn):
    try:
        conn.settimeout(10)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", "replace").split("\r\n")
        method, path, _ver = (lines[0].split(" ", 2) + ["", ""])[:3] if lines else ("", "", "")
        if not KEY:
            conn.sendall(http(json.dumps({"ok": False, "error": "server-not-configured"}).encode(), b"500 Internal Server Error"))
            return
        # CORS 预检
        if method == "OPTIONS":
            conn.sendall(http(b"", b"204 No Content", b"text/plain"))
            return
        if method != "POST" or path.rstrip("/") != "/restart":
            conn.sendall(http(json.dumps({"ok": False, "error": "method-or-path"}).encode(), b"405 Method Not Allowed"))
            return
        try:
            payload = json.loads(body.decode("utf-8", "replace") or "{}")
        except Exception:
            payload = {}
        ts = payload.get("ts")
        sig = payload.get("key", "")
        ok, msg = verify(ts, sig)
        if not ok:
            conn.sendall(http(json.dumps({"ok": False, "error": msg}).encode(), b"403 Forbidden"))
            return
        p = subprocess.run("/usr/bin/x-ui restart", shell=True,
                           capture_output=True, text=True, timeout=60)
        out = (p.stdout + p.stderr).strip() or "(no output)"
        conn.sendall(http(json.dumps({"ok": p.returncode == 0, "code": p.returncode, "output": out}).encode()))
    except Exception as e:  # noqa: BLE001
        try:
            conn.sendall(http(json.dumps({"ok": False, "error": str(e)}).encode(), b"500 Internal Server Error"))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    if not KEY:
        print("FATAL: RESTART_KEY 未设置，拒绝启动", file=sys.stderr)
        sys.exit(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(16)
    print("listening on %s:%d" % (HOST, PORT), flush=True)
    while True:
        try:
            conn, _ = s.accept()
        except Exception:
            continue
        try:
            handle(conn)
        except Exception:
            pass


if __name__ == "__main__":
    main()