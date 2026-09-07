#!/usr/bin/env python3
"""
Recon / OSINT Lab Template
==========================

Scoped recon helper: DNS-ish checks, TCP connect scan (allowlisted CIDR/hosts),
HTTP probe. Hard scope gate. No mass internet scanning.

Category: Red Team / Recon
Author: Security Research Lab
Version: 1.0.0
Date: 2026-09-06

Usage:
    python recon_osint_template.py --scope 127.0.0.1 --ports 80,443,5055 --mode full
    python recon_osint_template.py --scope 10.10.10.0/24 --ports 22,88,389 --mode check

Legal: In-scope lab assets only. See 03 / 14.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger("recon_lab")
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")


def parse_scope(scope: str) -> list[str]:
    scope = scope.strip()
    hosts: list[str] = []
    if "/" in scope:
        net = ipaddress.ip_network(scope, strict=False)
        if net.num_addresses > 256:
            raise SystemExit("Refusing scopes larger than /24 in this lab template")
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    else:
        hosts = [scope]
    return hosts


def tcp_check(host: str, port: int, timeout: float) -> dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        banner = b""
        try:
            s.sendall(b"\r\n")
            banner = s.recv(64)
        except Exception:
            pass
        return {"host": host, "port": port, "open": True, "banner": banner.decode(errors="replace")[:64]}
    except Exception:
        return {"host": host, "port": port, "open": False}
    finally:
        s.close()


def http_probe(url: str, timeout: float) -> dict[str, Any]:
    try:
        req = Request(url, method="GET", headers={"User-Agent": "SRL-ReconLab/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return {"url": url, "status": getattr(resp, "status", 200), "ok": True}
    except Exception as exc:
        return {"url": url, "ok": False, "error": str(exc)[:200]}


def dns_lookup(host: str) -> dict[str, Any]:
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({i[4][0] for i in infos})
        return {"host": host, "addrs": addrs}
    except Exception as exc:
        return {"host": host, "error": str(exc)}


def main() -> None:
    p = argparse.ArgumentParser(description="Scoped recon lab template")
    p.add_argument("--scope", required=True, help="Host or CIDR (<= /24)")
    p.add_argument("--ports", default="22,80,443", help="Comma-separated ports")
    p.add_argument("--mode", choices=["check", "full"], default="check")
    p.add_argument("--http-paths", default="/,/health", help="Paths to probe on open 80/443/8080/5055")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--workers", type=int, default=32)
    p.add_argument("--output")
    args = p.parse_args()

    start = datetime.now()
    hosts = parse_scope(args.scope)
    ports = [int(x) for x in args.ports.split(",") if x.strip()]
    logger.info("Scope hosts=%d ports=%s", len(hosts), ports)

    # check mode: DNS + limited ports on first host only if many
    targets = hosts if args.mode == "full" else hosts[: min(5, len(hosts))]

    dns = [dns_lookup(h) for h in targets[:10]]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(tcp_check, h, port, args.timeout) for h in targets for port in ports]
        for fut in as_completed(futs):
            r = fut.result()
            if r.get("open"):
                logger.info("OPEN %s:%s", r["host"], r["port"])
                results.append(r)

    http = []
    if args.mode == "full":
        paths = [x for x in args.http_paths.split(",") if x.strip()]
        for r in results:
            if r["port"] in (80, 443, 8080, 8000, 5055, 3000, 5000):
                scheme = "https" if r["port"] == 443 else "http"
                for path in paths:
                    http.append(http_probe(f"{scheme}://{r['host']}:{r['port']}{path}", args.timeout))

    out = {
        "mode": args.mode,
        "scope": args.scope,
        "dns": dns,
        "open_ports": results,
        "http": http,
        "start_time": start.isoformat(),
        "end_time": datetime.now().isoformat(),
        "duration": (datetime.now() - start).total_seconds(),
    }
    print(json.dumps(out, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
