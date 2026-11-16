"""IttisalX FileServer - a small open-source file portal. Python standard library only.
Copyright (C) IttisalX. Licensed under the GNU General Public License v3.0 or later (see LICENSE).

HTTPS is optional: set TLS_CERT and TLS_KEY to a certificate and key file to enable it.

Run:             python3 server.py
Reset password:  python3 server.py reset-password [new-password]
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.0"
WEBSITE = "https://ittisal.com"
BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE, "upload")
WEB_DIR = os.path.join(BASE, "web")
CONFIG = os.path.join(BASE, "config.json")
PORT = int(os.environ.get("PORT", 8921))
TLS_CERT, TLS_KEY = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
COOKIE_FLAGS = "; Secure" if TLS_CERT and TLS_KEY else ""
DEFAULT_PASSWORD = "ittisalx"
SESSION_TTL = 8 * 3600
MB = 1048576

lock = threading.Lock()
sessions = {}   # token -> {"exp": ts, "epoch": n}
failures = {}   # ip -> [count, locked_until]


# ---------- config (one JSON file, no database) ----------

def hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return {"salt": salt, "hash": digest}


def check_pw(cfg, password):
    got = hash_pw(password, cfg["password"]["salt"])["hash"]
    return hmac.compare_digest(got, cfg["password"]["hash"])


def load():
    if not os.path.exists(CONFIG):
        save({"password": hash_pw(DEFAULT_PASSWORD), "must_change": True, "epoch": 0,
              "totp_secret": None, "totp_last": 0, "upload_limit_mb": 1024, "download_limit_mb": 0})
    with open(CONFIG) as f:
        return json.load(f)


def save(cfg):
    tmp = CONFIG + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG)


# ---------- TOTP (RFC 6238) ----------

def totp_code(secret, counter):
    key = base64.b32decode(secret)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7fffffff) % 10**6:06d}"


def totp_verify(cfg, code):
    """Return the matching time-step counter (to block replay), or None."""
    now = int(time.time() // 30)
    for c in (now - 1, now, now + 1):
        if c > cfg.get("totp_last", 0) and hmac.compare_digest(totp_code(cfg["totp_secret"], c), code.strip()):
            return c
    return None


# ---------- helpers ----------

def safe_path(rel):
    """Resolve a relative path inside UPLOAD_DIR, or return None."""
    root = os.path.realpath(UPLOAD_DIR)
    full = os.path.realpath(os.path.join(root, rel.lstrip("/")))
    return full if full == root or full.startswith(root + os.sep) else None


def unique_name(folder, name):
    stem, ext = os.path.splitext(name)
    candidate, i = name, 1
    while os.path.exists(os.path.join(folder, candidate)):
        candidate, i = f"{stem} ({i}){ext}", i + 1
    return candidate


def render(name, **values):
    with open(os.path.join(WEB_DIR, name), encoding="utf-8") as f:
        page = f.read()
    values = {"version": VERSION, "website": WEBSITE, **values}
    for k, v in values.items():
        page = page.replace("{{" + k + "}}", v)
    return page.encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "IttisalXFileServer/" + VERSION

    # ----- plumbing -----
    def send(self, status, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, data, status=200, headers=None):
        self.send(status, json.dumps(data).encode(), "application/json", headers)

    def error_json(self, status, message):
        self.close_connection = True
        self.json({"error": message}, status, {"Connection": "close"})

    def redirect(self, where):
        self.send(303, b"", headers={"Location": where})

    def body_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def authed(self):
        morsel = SimpleCookie(self.headers.get("Cookie", "")).get("sid")
        s = sessions.get(morsel.value) if morsel else None
        if s and s["exp"] > time.time() and s["epoch"] == load()["epoch"]:
            return True
        return False

    def csrf_ok(self):
        # Browsers always send Origin on cross-site POSTs; require it to match our host.
        origin = self.headers.get("Origin")
        return origin is None or urllib.parse.urlparse(origin).netloc == self.headers.get("Host")

    # ----- GET -----
    do_HEAD = lambda self: self.do_GET()

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path, query = url.path, urllib.parse.parse_qs(url.query)
        if path.startswith("/static/"):
            return self.static(path[8:])
        if path == "/login":
            return self.send(200, render("login.html"))
        if not self.authed():
            if path.startswith("/api/") or path in ("/download",):
                return self.error_json(401, "Please sign in again.")
            return self.redirect("/login")
        cfg = load()
        if path == "/":
            return self.redirect("/settings") if cfg["must_change"] else self.send(200, render("portal.html"))
        if path == "/settings":
            return self.send(200, render("settings.html"))
        if path == "/api/state":
            return self.json(self.state(cfg))
        if cfg["must_change"]:
            return self.error_json(403, "Change the default password first.")
        if path == "/api/files":
            return self.list_files(query.get("path", [""])[0])
        if path == "/download":
            return self.download(query.get("path", [""])[0], cfg)
        self.send(404, b"Not found", "text/plain")

    def static(self, name):
        full = os.path.realpath(os.path.join(WEB_DIR, "static", name))
        if not full.startswith(os.path.join(os.path.realpath(WEB_DIR), "static") + os.sep) or not os.path.isfile(full):
            return self.send(404, b"Not found", "text/plain")
        ctype = {".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml",
                 ".png": "image/png", ".ico": "image/x-icon"}.get(os.path.splitext(full)[1], "application/octet-stream")
        with open(full, "rb") as f:
            self.send(200, f.read(), ctype, {"Cache-Control": "public, max-age=300"})

    def state(self, cfg):
        return {"totp_enabled": bool(cfg["totp_secret"]), "must_change": cfg["must_change"],
                "upload_limit_mb": cfg["upload_limit_mb"], "download_limit_mb": cfg["download_limit_mb"]}

    def list_files(self, rel):
        folder = safe_path(rel)
        if not folder or not os.path.isdir(folder):
            return self.error_json(404, "Folder not found.")
        items = []
        for name in sorted(os.listdir(folder), key=str.lower):
            full = os.path.join(folder, name)
            if name.endswith(".part") or name.startswith("."):
                continue
            st = os.stat(full)
            items.append({"name": name, "dir": os.path.isdir(full), "size": st.st_size, "mtime": int(st.st_mtime)})
        items.sort(key=lambda i: not i["dir"])
        rel = os.path.relpath(folder, os.path.realpath(UPLOAD_DIR))
        self.json({"path": "" if rel == "." else rel, "items": items})

    def download(self, rel, cfg):
        full = safe_path(rel)
        if not full or not os.path.isfile(full):
            return self.error_json(404, "File not found.")
        size = os.path.getsize(full)
        limit = cfg["download_limit_mb"] * MB
        if limit and size > limit:
            return self.error_json(413, f"This file is larger than the {cfg['download_limit_mb']} MB download limit.")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(os.path.basename(full)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with open(full, "rb") as f:
            while chunk := f.read(MB):
                self.wfile.write(chunk)

    # ----- POST -----
    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        if not self.csrf_ok():
            return self.error_json(403, "Cross-site request blocked.")
        if url.path == "/api/login":
            return self.login()
        if not self.authed():
            return self.error_json(401, "Please sign in again.")
        if url.path == "/api/logout":
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get("sid")
            sessions.pop(morsel.value if morsel else None, None)
            return self.json({"ok": True}, headers={"Set-Cookie": "sid=; Path=/; Max-Age=0"})
        with lock:
            cfg = load()
            if url.path == "/api/password":
                return self.change_password(cfg)
            if cfg["must_change"]:
                return self.error_json(403, "Change the default password first.")
            if url.path == "/upload":
                pass  # handled below, outside the lock
            elif url.path == "/api/limits":
                return self.set_limits(cfg)
            elif url.path.startswith("/api/2fa/"):
                return self.two_factor(url.path[9:], cfg)
            elif url.path == "/api/delete":
                return self.delete(cfg)
            else:
                return self.error_json(404, "Not found.")
        self.upload(url, cfg)

    def login(self):
        ip = self.client_address[0]
        count, until = failures.get(ip, [0, 0])
        if until > time.time():
            return self.error_json(429, f"Too many attempts. Try again in {int(until - time.time()) + 1} seconds.")
        data = self.body_json()
        with lock:
            cfg = load()
        ok = data.get("username") == "admin" and check_pw(cfg, str(data.get("password", "")))
        if ok and cfg["totp_secret"]:
            code = str(data.get("code", ""))
            if not code:
                return self.json({"need_code": True})
            with lock:
                cfg = load()
                step = totp_verify(cfg, code)
                if step:
                    cfg["totp_last"] = step
                    save(cfg)
            ok = step is not None
        if not ok:
            count += 1
            failures[ip] = [count, time.time() + 60 if count >= 5 else 0]
            if count >= 5:
                failures[ip][0] = 0
            return self.error_json(401, "Wrong username, password or code.")
        failures.pop(ip, None)
        token = secrets.token_urlsafe(32)
        sessions[token] = {"exp": time.time() + SESSION_TTL, "epoch": cfg["epoch"]}
        self.json({"ok": True, "must_change": cfg["must_change"]},
                  headers={"Set-Cookie": f"sid={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{COOKIE_FLAGS}"})

    def change_password(self, cfg):
        data = self.body_json()
        new = str(data.get("new", ""))
        if not check_pw(cfg, str(data.get("current", ""))):
            return self.error_json(400, "Current password is wrong.")
        if len(new) < 8 or new == DEFAULT_PASSWORD:
            return self.error_json(400, "Use at least 8 characters, and not the default password.")
        cfg.update(password=hash_pw(new), must_change=False, epoch=cfg["epoch"] + 1)
        save(cfg)
        token = secrets.token_urlsafe(32)   # keep this browser signed in, drop all others
        sessions.clear()
        sessions[token] = {"exp": time.time() + SESSION_TTL, "epoch": cfg["epoch"]}
        self.json({"ok": True}, headers={"Set-Cookie": f"sid={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{COOKIE_FLAGS}"})

    def set_limits(self, cfg):
        data = self.body_json()
        try:
            up, down = int(data["upload_limit_mb"]), int(data["download_limit_mb"])
            assert 0 <= up <= 10**7 and 0 <= down <= 10**7
        except (KeyError, ValueError, TypeError, AssertionError):
            return self.error_json(400, "Enter whole numbers in MB (0 means no limit).")
        cfg.update(upload_limit_mb=up, download_limit_mb=down)
        save(cfg)
        self.json({"ok": True})

    def two_factor(self, action, cfg):
        data = self.body_json()
        if action == "setup":
            secret = base64.b32encode(os.urandom(20)).decode()
            pending[0] = secret
            uri = "otpauth://totp/IttisalX%20FileServer:admin?secret=" + secret + "&issuer=IttisalX%20FileServer"
            return self.json({"secret": secret, "uri": uri})
        if action == "enable":
            secret = pending[0]
            if not secret or not hmac.compare_digest(totp_code(secret, int(time.time() // 30)), str(data.get("code", "")).strip()):
                return self.error_json(400, "That code didn't match. Check your authenticator app and try again.")
            cfg.update(totp_secret=secret, totp_last=int(time.time() // 30))
            pending[0] = None
            save(cfg)
            return self.json({"ok": True})
        if action == "disable":
            if not check_pw(cfg, str(data.get("password", ""))):
                return self.error_json(400, "Password is wrong.")
            cfg.update(totp_secret=None)
            save(cfg)
            return self.json({"ok": True})
        self.error_json(404, "Not found.")

    def delete(self, cfg):
        full = safe_path(str(self.body_json().get("path", "")))
        if not full or full == os.path.realpath(UPLOAD_DIR) or not os.path.isfile(full):
            return self.error_json(404, "File not found.")
        os.remove(full)
        self.json({"ok": True})

    def upload(self, url, cfg):
        query = urllib.parse.parse_qs(url.query)
        name = os.path.basename(query.get("name", [""])[0])
        folder = safe_path(query.get("dir", [""])[0])
        length = int(self.headers.get("Content-Length") or -1)
        limit = cfg["upload_limit_mb"] * MB
        if not name or name.startswith(".") or name.endswith(".part") or length < 0:
            return self.error_json(400, "Missing or invalid file name.")
        if not folder or not os.path.isdir(folder):
            return self.error_json(400, "Invalid folder.")
        if limit and length > limit:
            return self.error_json(413, f"{name} is larger than the {cfg['upload_limit_mb']} MB upload limit.")
        final = os.path.join(folder, unique_name(folder, name))
        part = final + ".part"
        remaining = length
        with open(part, "wb") as out:
            while remaining > 0:
                chunk = self.rfile.read(min(MB, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
        if remaining:
            os.remove(part)
            return self.error_json(400, "Upload was interrupted.")
        os.replace(part, final)
        self.json({"ok": True, "name": os.path.basename(final)})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))


pending = [None]  # 2FA secret awaiting confirmation


def reset_password(new=None):
    cfg = load()
    cfg.update(password=hash_pw(new or DEFAULT_PASSWORD), must_change=new is None,
               totp_secret=None, epoch=cfg["epoch"] + 1)
    save(cfg)
    print("Admin password reset to " + (f"the one you gave." if new else f"'{DEFAULT_PASSWORD}' (you must change it at next login)."))
    print("Two-factor authentication was turned off and all sessions were signed out.")


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    if sys.argv[1:2] == ["reset-password"]:
        if len(sys.argv) > 2 and len(sys.argv[2]) < 8:
            sys.exit("Password must be at least 8 characters.")
        reset_password(sys.argv[2] if len(sys.argv) > 2 else None)
        sys.exit(0)
    if sys.argv[1:2] in (["--version"], ["version"]):
        sys.exit(f"IttisalX FileServer {VERSION}")
    first = not os.path.exists(CONFIG)
    load()
    if first:
        print(f"First install: sign in as admin / {DEFAULT_PASSWORD} (you will be asked to change it).")
    print(f"IttisalX FileServer {VERSION} ({WEBSITE}) serving {UPLOAD_DIR} on port {PORT}", flush=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print("HTTPS enabled", flush=True)
    httpd.serve_forever()
