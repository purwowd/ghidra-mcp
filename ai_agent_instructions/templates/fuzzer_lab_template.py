#!/usr/bin/env python3
"""
Fuzzer Lab Template
===================

Minimal mutation fuzzer for file/socket targets in the lab.
Tracks crashes (nonzero exit / timeout / connection reset). Not AFL-grade —
use for harness bootstrapping before afl++/libFuzzer.

Category: Research / Fuzzing
Author: Security Research Lab
Version: 1.0.0
Date: 2026-09-06

Usage:
    python fuzzer_lab_template.py --bin ./parse --seed-dir seeds/ --mode full --iterations 100
    python fuzzer_lab_template.py --host 127.0.0.1 --port 9999 --seed 'AAAA' --mode check

Legal: Lab targets only. See 15_VULN_RESEARCH_METHODOLOGY.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("fuzz_lab")
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")


def mutate(data: bytes, rng: random.Random) -> bytes:
    if not data:
        data = b"A"
    data = bytearray(data)
    op = rng.randrange(4)
    if op == 0 and data:
        data[rng.randrange(len(data))] = rng.randrange(256)
    elif op == 1:
        data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
    elif op == 2 and len(data) > 1:
        del data[rng.randrange(len(data))]
    else:
        data += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
    return bytes(data)


def load_seeds(seed_dir: str | None, seed: str | None) -> list[bytes]:
    seeds: list[bytes] = []
    if seed is not None:
        seeds.append(seed.encode())
    if seed_dir:
        for p in Path(seed_dir).glob("*"):
            if p.is_file():
                seeds.append(p.read_bytes()[:65536])
    if not seeds:
        seeds = [b"TEST", b"AAAA", b"%s%n", b"\x00\x01\xff"]
    return seeds


def run_bin(bin_path: str, payload: bytes, timeout: float) -> dict[str, Any]:
    try:
        p = subprocess.run(
            [bin_path],
            input=payload,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "crash": p.returncode < 0 or p.returncode > 128,
            "returncode": p.returncode,
            "stderr": (p.stderr or b"")[:200].decode(errors="replace"),
        }
    except subprocess.TimeoutExpired:
        return {"crash": True, "returncode": None, "stderr": "timeout"}
    except Exception as exc:
        return {"crash": False, "error": str(exc)}


def run_net(host: str, port: int, payload: bytes, timeout: float) -> dict[str, Any]:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(payload)
        try:
            s.recv(16)
        except Exception:
            pass
        s.close()
        return {"crash": False}
    except (ConnectionResetError, BrokenPipeError) as exc:
        return {"crash": True, "error": str(exc)}
    except Exception as exc:
        return {"crash": False, "error": str(exc)}


def main() -> None:
    p = argparse.ArgumentParser(description="Lab mutation fuzzer scaffold")
    p.add_argument("--mode", choices=["check", "full"], default="check")
    p.add_argument("--bin", help="Binary reading payload on stdin")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--seed-dir")
    p.add_argument("--seed")
    p.add_argument("--iterations", type=int, default=50)
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--crash-dir", default="crashes")
    p.add_argument("--output")
    args = p.parse_args()

    if not args.bin and not (args.host and args.port):
        p.error("Need --bin and/or --host/--port")

    seeds = load_seeds(args.seed_dir, args.seed)
    rng = random.Random(1337)
    iters = 1 if args.mode == "check" else args.iterations
    crashes = []
    start = datetime.now()
    crash_dir = Path(args.crash_dir)
    crash_dir.mkdir(exist_ok=True)

    for i in range(iters):
        base = seeds[i % len(seeds)]
        payload = base if args.mode == "check" else mutate(base, rng)
        if args.bin:
            result = run_bin(args.bin, payload, args.timeout)
        else:
            result = run_net(args.host, args.port, payload, args.timeout)
        if result.get("crash"):
            name = crash_dir / f"crash_{int(time.time())}_{i}.bin"
            name.write_bytes(payload)
            crashes.append({"file": str(name), **result})
            logger.info("CRASH saved %s", name)

    out = {
        "mode": args.mode,
        "iterations": iters,
        "crashes": crashes,
        "crash_count": len(crashes),
        "start_time": start.isoformat(),
        "end_time": datetime.now().isoformat(),
        "duration": (datetime.now() - start).total_seconds(),
    }
    print(json.dumps(out, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
    sys.exit(0 if crashes or args.mode == "check" else 0)


if __name__ == "__main__":
    main()
