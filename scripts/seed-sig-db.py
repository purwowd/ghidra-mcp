#!/usr/bin/env python3
"""Seed ~/.ghidra-mcp/function_sigs.json from the current Ghidra program via MCP.

Requires CodeBrowser + GhidraMCP (default http://127.0.0.1:8089) with a program open
that has meaningful function names (e.g. chal_symbols after Analyze).

Usage:
  ./scripts/seed-sig-db.py
  ./scripts/seed-sig-db.py --url http://127.0.0.1:8089 --program chal_symbols
  ./scripts/seed-sig-db.py --apply-match   # also rename FUN_* on current program
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def http_json(url: str, method: str = "GET", body: dict | None = None) -> dict:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089"))
    ap.add_argument("--program", default="", help="Program name (empty = current)")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--apply-match", action="store_true", help="After seeding, run sig_db_match apply=true")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    try:
        health = http_json(f"{base}/mcp/health")
    except Exception as e:
        print(f"MCP unreachable @ {base}: {e}", file=sys.stderr)
        return 1

    q = urllib.parse.urlencode(
        {"offset": 0, "limit": args.limit, "filter": "documented", "program": args.program}
    )
    bulk = http_json(f"{base}/get_bulk_function_hashes?{q}")
    if "error" in bulk:
        print("Error:", bulk["error"], file=sys.stderr)
        return 1

    funcs = bulk.get("functions") or []
    added = 0
    skipped = 0
    for f in funcs:
        name = f.get("name") or ""
        addr = f.get("address") or ""
        if not name or not addr:
            skipped += 1
            continue
        # skip still-auto names if filter failed
        if name.startswith(("FUN_", "LAB_", "thunk_")):
            skipped += 1
            continue
        try:
            r = http_json(
                f"{base}/sig_db_add",
                method="POST",
                body={"address": addr, "name": name, "program": args.program or bulk.get("program", "")},
            )
            if "error" in r:
                print(f"  skip {name}@{addr}: {r['error']}")
                skipped += 1
            else:
                print(f"  + {name}  hash={r.get('hash', '?')[:12]}…")
                added += 1
        except urllib.error.HTTPError as e:
            print(f"  fail {name}: {e}", file=sys.stderr)
            skipped += 1

    info = http_json(f"{base}/sig_db_info")
    print(f"\nSeeded {added} (skipped {skipped}). DB: {info.get('path')} count={info.get('count')}")

    if args.apply_match:
        q2 = urllib.parse.urlencode({"apply": "true", "limit": args.limit, "program": args.program})
        match = http_json(f"{base}/sig_db_match?{q2}")
        print("sig_db_match:", json.dumps({k: match.get(k) for k in ("match_count", "renamed", "checked")}, indent=2))

    db = Path.home() / ".ghidra-mcp" / "function_sigs.json"
    if db.is_file():
        print(f"Local file OK: {db} ({db.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
