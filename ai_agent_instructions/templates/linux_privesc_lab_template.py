#!/usr/bin/env python3
"""
Linux Privilege Escalation Lab Template
=======================================

Enumerate + (optional) exploit common Linux privesc misconfigs in a lab VM/container.
Default is check/enum only. Exploit paths require explicit flags.

Category: Red Team / PrivEsc
Author: Security Research Lab
Version: 1.0.0
Date: 2026-09-06

Usage:
    python linux_privesc_lab_template.py --mode check
    python linux_privesc_lab_template.py --mode full --enable-sudo-nopasswd-check
    python linux_privesc_lab_template.py --mode full --enable-suid-abuse --confirm-lab

Legal: Lab hosts only. See 02 / 14.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import argparse
import json
import logging
import os
import stat
import subprocess
import sys

MARKER = "LAB_PRIVESC_MARKER=srl-linux-privesc"


def setup_log(verbose: bool = False) -> logging.Logger:
    log = logging.getLogger("linux_privesc")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[*] %(message)s"))
        log.addHandler(h)
    return log


logger = setup_log()


@dataclass
class Finding:
    technique: str
    attck: str
    severity: str
    detail: str
    evidence: str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    whoami_before: str = ""
    whoami_after: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "whoami_before": self.whoami_before,
            "whoami_after": self.whoami_after,
            "findings": [f.__dict__ for f in self.findings],
            "evidence": self.evidence,
            "marker": MARKER,
        }


def run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out.strip()
    except Exception as exc:
        return 1, str(exc)


def whoami_blob() -> str:
    code, out = run(["id"])
    if code != 0:
        _, out = run(["whoami"])
    return out


class LinuxPrivEscLab:
    INTERESTING_SUID = {
        "nmap", "vim", "find", "bash", "python", "python3", "perl", "ruby",
        "less", "more", "nano", "cp", "mv", "awk", "env", "busybox",
    }

    def __init__(self, options: dict | None = None):
        self.options = options or {}
        self.report = Report()

    def check(self) -> Report:
        self.report.whoami_before = whoami_blob()
        self.report.evidence.append(f"id: {self.report.whoami_before}")
        logger.info("Current identity: %s", self.report.whoami_before)
        self._enum_sudo()
        self._enum_suid()
        self._enum_writable_cron()
        self._enum_docker_sock()
        self._enum_capabilities()
        return self.report

    def _enum_sudo(self) -> None:
        code, out = run(["sudo", "-n", "-l"])
        if code == 0 and out:
            self.report.findings.append(
                Finding("sudo_nopasswd", "T1548.003", "HIGH", "sudo -n -l succeeded", out[:500])
            )
            self.report.evidence.append("sudo -n -l OK")
        else:
            logger.info("No passwordless sudo (or sudo missing)")

    def _enum_suid(self) -> None:
        # Limited walk — lab friendly; avoid full FS crawl by default
        roots = self.options.get("suid_roots") or ["/usr/bin", "/usr/sbin", "/bin"]
        hits = []
        for root in roots:
            p = Path(root)
            if not p.exists():
                continue
            for f in p.iterdir():
                try:
                    st = f.stat()
                    if st.st_mode & stat.S_ISUID:
                        hits.append(str(f))
                        if f.name in self.INTERESTING_SUID:
                            self.report.findings.append(
                                Finding(
                                    "suid_interesting",
                                    "T1548.001",
                                    "HIGH",
                                    f"Interesting SUID binary: {f}",
                                    str(f),
                                )
                            )
                except OSError:
                    continue
        self.report.evidence.append(f"suid_count_scanned={len(hits)}")
        logger.info("SUID binaries scanned in roots: %d", len(hits))

    def _enum_writable_cron(self) -> None:
        for path in ("/etc/cron.d", "/var/spool/cron", "/etc/crontab"):
            p = Path(path)
            if p.exists() and os.access(p, os.W_OK):
                self.report.findings.append(
                    Finding("writable_cron", "T1053.003", "CRITICAL", f"Writable: {path}", path)
                )

    def _enum_docker_sock(self) -> None:
        sock = Path("/var/run/docker.sock")
        if sock.exists() and os.access(sock, os.R_OK):
            self.report.findings.append(
                Finding("docker_sock", "T1611", "CRITICAL", "Readable docker.sock", str(sock))
            )

    def _enum_capabilities(self) -> None:
        code, out = run(["getcap", "-r", "/usr/bin"])
        if code == 0 and out:
            if "cap_setuid" in out.lower() or "cap_sys_admin" in out.lower():
                self.report.findings.append(
                    Finding("caps", "T1548", "HIGH", "Dangerous capabilities seen", out[:500])
                )

    def exploit(self) -> Report:
        """Opt-in demonstrations — still non-destructive where possible."""
        if not self.options.get("confirm_lab"):
            logger.warning("Refuse exploit steps without --confirm-lab")
            return self.report

        # Demo: if passwordless sudo ALL, run id via sudo (lab)
        if self.options.get("enable_sudo_nopasswd_check"):
            code, out = run(["sudo", "-n", "id"])
            if code == 0:
                self.report.whoami_after = out
                self.report.evidence.append(f"sudo id => {out}")
                self.report.evidence.append(MARKER)
                logger.info("sudo priv proof: %s", out)

        # Placeholder for GTFOBins-style abuse — researcher implements carefully
        if self.options.get("enable_suid_abuse"):
            logger.info("SUID abuse enabled — implement GTFOBins path for lab binary only")
            self.report.evidence.append("suid_abuse_flag_set_implement_me")

        if not self.report.whoami_after:
            self.report.whoami_after = self.report.whoami_before
        return self.report

    def execute(self, mode: str) -> dict[str, Any]:
        start = datetime.now()
        self.check()
        if mode in ("exploit", "full"):
            self.exploit()
        end = datetime.now()
        data = self.report.to_dict()
        data.update(
            {
                "mode": mode,
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "duration": (end - start).total_seconds(),
                "result": "VULNERABLE" if self.report.findings else "NOT_VULNERABLE",
            }
        )
        return data


def main() -> None:
    p = argparse.ArgumentParser(description="Linux privesc lab enum/exploit scaffold")
    p.add_argument("--mode", choices=["check", "exploit", "full"], default="check")
    p.add_argument("--confirm-lab", action="store_true")
    p.add_argument("--enable-sudo-nopasswd-check", action="store_true")
    p.add_argument("--enable-suid-abuse", action="store_true")
    p.add_argument("--output")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    lab = LinuxPrivEscLab(
        {
            "confirm_lab": args.confirm_lab,
            "enable_sudo_nopasswd_check": args.enable_sudo_nopasswd_check,
            "enable_suid_abuse": args.enable_suid_abuse,
        }
    )
    result = lab.execute(args.mode)
    print(json.dumps(result, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    sys.exit(0 if result.get("findings") or result.get("result") == "VULNERABLE" else 1)


if __name__ == "__main__":
    main()
