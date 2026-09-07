#!/usr/bin/env python3
"""
Kubernetes / Container Escape Lab Template
==========================================

Enumerate container context and optional Docker socket / K8s API abuse paths.
Default: check only. Privileged actions require --confirm-lab flags.

Category: Red Team / Cloud-Native
Author: Security Research Lab
Version: 1.0.0
Date: 2026-09-06

Usage:
    python k8s_container_lab_template.py --mode check
    python k8s_container_lab_template.py --mode full --confirm-lab --enable-docker-sock-check

Legal: Lab clusters only (kind/k3d/minikube). See 19_CONTAINER_K8S_LAB.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import argparse
import json
import logging
import os
import socket
import sys

logger = logging.getLogger("k8s_lab")
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")

MARKER = "LAB_K8S_MARKER=srl-container-lab"


@dataclass
class Finding:
    technique: str
    attck: str
    severity: str
    detail: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.__dict__ for f in self.findings],
            "evidence": self.evidence,
            "marker": MARKER,
        }


class ContainerK8sLab:
    def __init__(self, options: dict | None = None):
        self.options = options or {}
        self.report = Report()

    def check(self) -> Report:
        self._cgroup_container()
        self._docker_sock()
        self._k8s_service_account()
        self._privileged_hints()
        self._cloud_metadata_route()
        return self.report

    def _cgroup_container(self) -> None:
        cgroup = Path("/proc/1/cgroup")
        if cgroup.exists():
            text = cgroup.read_text(errors="replace")
            in_container = any(x in text for x in ("docker", "kubepods", "containerd", "libpod"))
            self.report.evidence.append(f"cgroup_container_hint={in_container}")
            if in_container:
                self.report.findings.append(
                    Finding("container_context", "T1610", "INFO", "Process appears containerized")
                )

    def _docker_sock(self) -> None:
        sock = Path("/var/run/docker.sock")
        if sock.exists():
            accessible = os.access(sock, os.R_OK)
            self.report.evidence.append(f"docker.sock exists readable={accessible}")
            if accessible:
                self.report.findings.append(
                    Finding("docker_sock", "T1611", "CRITICAL", "docker.sock readable — escape candidate")
                )

    def _k8s_service_account(self) -> None:
        token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        ns = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        if token.exists():
            self.report.evidence.append("k8s_sa_token=present")
            namespace = ns.read_text().strip() if ns.exists() else "?"
            self.report.findings.append(
                Finding(
                    "k8s_sa",
                    "T1552.007",
                    "HIGH",
                    f"ServiceAccount token present (ns={namespace})",
                )
            )
            if self.options.get("enable_k8s_api_check") and self.options.get("confirm_lab"):
                # Soft probe: resolve kubernetes
                try:
                    socket.getaddrinfo("kubernetes.default.svc", 443)
                    self.report.evidence.append("kubernetes.default.svc=resolvable")
                except OSError as exc:
                    self.report.evidence.append(f"k8s_dns={exc}")

    def _privileged_hints(self) -> None:
        # Cap bounding set peek
        status = Path("/proc/self/status")
        if status.exists():
            for line in status.read_text().splitlines():
                if line.startswith("CapEff:"):
                    self.report.evidence.append(line.strip())
                    # ffff... often means wide caps
                    if "ffffffffff" in line.lower():
                        self.report.findings.append(
                            Finding("wide_caps", "T1548", "HIGH", "Effective capabilities look broad")
                        )

    def _cloud_metadata_route(self) -> None:
        self.report.evidence.append("imds_note=use lab metadata stub only")

    def exploit(self) -> Report:
        if not self.options.get("confirm_lab"):
            logger.warning("No --confirm-lab; skipping invasive steps")
            return self.report
        if self.options.get("enable_docker_sock_check"):
            sock = Path("/var/run/docker.sock")
            if sock.exists() and os.access(sock, os.R_OK):
                # Non-destructive: attempt docker version via HTTP to unix socket needs http client;
                # record intent marker for lab operators.
                self.report.evidence.append("docker_sock_abuse_path_available")
                self.report.evidence.append(MARKER)
                logger.info("docker.sock path confirmed for lab escape demo (implement docker API call)")
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
                "result": "VULNERABLE" if any(f.severity in ("HIGH", "CRITICAL") for f in self.report.findings) else "INFO",
            }
        )
        return data


def main() -> None:
    p = argparse.ArgumentParser(description="K8s/container lab template")
    p.add_argument("--mode", choices=["check", "exploit", "full"], default="check")
    p.add_argument("--confirm-lab", action="store_true")
    p.add_argument("--enable-docker-sock-check", action="store_true")
    p.add_argument("--enable-k8s-api-check", action="store_true")
    p.add_argument("--output")
    args = p.parse_args()
    lab = ContainerK8sLab(
        {
            "confirm_lab": args.confirm_lab,
            "enable_docker_sock_check": args.enable_docker_sock_check,
            "enable_k8s_api_check": args.enable_k8s_api_check,
        }
    )
    result = lab.execute(args.mode)
    print(json.dumps(result, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
