#!/usr/bin/env python3
"""
Proof of Concept (PoC) Template
================================

Standard template for creating vulnerability Proof-of-Concept scripts.
Follows 04_POC_GENERATION_PROTOCOL.md and 13_LAB_POC_STANDARD.md.
Red↔blue extras (docs 10–12):
- Evidence directory conventions (pcap/log/diff)
- Optional detection pack skeleton generation
- Optional report generation aligned to reporting standard

Prefer scaffolding a package with:
    python scripts/new_poc.py CVE-YYYY-XXXXX --name "..." --port 8080

Category: PoC Development
Author: Security Research Lab
Version: 2.0.0
Date: 2026-09-06

Usage:
    1. Prefer scripts/new_poc.py, or copy this template into pocs/<NAME>/poc.py
    2. Fill in VULN_INFO with vulnerability details
    3. Implement check(), exploit(), verify(), and cleanup()
    4. Add vulnerable-app/ harness when feasible
    5. Run with: python poc.py <target> --mode check|exploit|full

Legal:
    Authorized security testing only. See 02_LEGAL_CONTEXT.md.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

import argparse
import json
import logging
from pathlib import Path
import sys
import traceback

# ──────────────────────────────────────────────
# Configuration: Fill this in for each PoC
# ──────────────────────────────────────────────

VULN_INFO = {
    "name": "Vulnerability Name",
    "cve": "CVE-YYYY-XXXXX",           # or "N/A"
    "cwe": "CWE-XXX",                  # e.g., CWE-89 (SQL Injection)
    "severity": "CRITICAL",             # CRITICAL, HIGH, MEDIUM, LOW
    "cvss_score": 0.0,                  # CVSS 3.1 score
    "cvss_vector": "",                  # e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    "affected_software": "",            # e.g., "Apache HTTP Server"
    "affected_versions": "",            # e.g., "2.4.49 - 2.4.50"
    "fixed_version": "",                # e.g., "2.4.51"
    "description": "",                  # Detailed vulnerability description
    "impact": "",                       # What an attacker can achieve
    "attack_vector": "Network",         # Network, Adjacent, Local, Physical
    "authentication": "None",           # None, Low, High
    "author": "Security Research Lab",
    "date": "2026-02-08",
    "references": [],                   # List of reference URLs
}


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class PocResult(str, Enum):
    """PoC execution results."""
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class Severity(str, Enum):
    """Severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ──────────────────────────────────────────────
# Logging with PoC conventions
# ──────────────────────────────────────────────

class PocFormatter(logging.Formatter):
    """PoC-style log formatter using security convention symbols."""

    SYMBOLS = {
        logging.DEBUG: "\033[36m[D]\033[0m",
        logging.INFO: "\033[37m[*]\033[0m",
        logging.WARNING: "\033[33m[!]\033[0m",
        logging.ERROR: "\033[31m[-]\033[0m",
        logging.CRITICAL: "\033[1;31m[!!]\033[0m",
    }

    # Custom levels
    SUCCESS = 25  # Between INFO and WARNING
    ACTION = 15   # Between DEBUG and INFO

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == self.SUCCESS:
            symbol = "\033[32m[+]\033[0m"
        elif record.levelno == self.ACTION:
            symbol = "\033[35m[>]\033[0m"
        else:
            symbol = self.SYMBOLS.get(record.levelno, "[?]")

        return f"{symbol} {record.getMessage()}"


def setup_poc_logging(verbose: bool = False) -> logging.Logger:
    """Setup PoC-style logging."""
    logger = logging.getLogger("poc")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Add custom levels
    logging.addLevelName(PocFormatter.SUCCESS, "SUCCESS")
    logging.addLevelName(PocFormatter.ACTION, "ACTION")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(PocFormatter())
    logger.addHandler(handler)

    # Add convenience methods
    def success(self, message, *args, **kwargs):
        self.log(PocFormatter.SUCCESS, message, *args, **kwargs)

    def action(self, message, *args, **kwargs):
        self.log(PocFormatter.ACTION, message, *args, **kwargs)

    logger.success = success.__get__(logger)
    logger.action = action.__get__(logger)

    return logger


logger = setup_poc_logging()

@dataclass
class EvidencePaths:
    """
    Standardized evidence paths for a PoC run.

    The PoC may choose to populate any/all of these artifacts.
    """
    base_dir: Path
    run_log: Path
    before_after: Path
    pcap: Path
    validation_md: Path


def init_evidence_paths(base_dir: str | Path) -> EvidencePaths:
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    (base / "logs").mkdir(parents=True, exist_ok=True)
    (base / "detection").mkdir(parents=True, exist_ok=True)
    return EvidencePaths(
        base_dir=base,
        run_log=base / "run.log",
        before_after=base / "before_after.txt",
        pcap=base / "traffic.pcapng",
        validation_md=base / "validation.md",
    )


def write_detection_pack_skeleton(base_dir: str | Path) -> Path:
    """
    Create a detection pack skeleton consistent with doc 10.
    Intended to be filled by the specific PoC (marker-based signatures).
    """
    root = Path(base_dir) / "detection"
    (root / "sigma").mkdir(parents=True, exist_ok=True)
    (root / "suricata").mkdir(parents=True, exist_ok=True)
    (root / "zeek").mkdir(parents=True, exist_ok=True)
    (root / "yara").mkdir(parents=True, exist_ok=True)

    (root / "suricata" / "rule.rules").write_text(
        "# Suricata rule stub\n"
        "# Add content markers (e.g. header/body marker) produced by the PoC/harness.\n"
        "# alert http any any -> any any (msg:\"LAB marker\"; flow:established,to_server; content:\"X-Lab-Marker\"; http_header; sid:1000001; rev:1;)\n"
    )
    (root / "sigma" / "rule.yml").write_text(
        "title: LAB marker detection (stub)\n"
        "id: 00000000-0000-0000-0000-000000000000\n"
        "status: experimental\n"
        "description: Detect lab marker in logs (customize)\n"
        "author: Security Research Lab\n"
        "logsource:\n"
        "  product: linux\n"
        "  service: application\n"
        "detection:\n"
        "  selection:\n"
        "    message|contains: \"LAB_MARKER\"\n"
        "  condition: selection\n"
        "falsepositives:\n"
        "  - Test traffic\n"
        "level: medium\n"
    )
    (root / "zeek" / "notice.zeek").write_text(
        "# Zeek notice stub\n"
        "# Define a Notice::Type and raise it on marker match.\n"
    )
    (root / "yara" / "rule.yar").write_text(
        "rule LAB_Marker_Stub {\n"
        "  meta:\n"
        "    author = \"Security Research Lab\"\n"
        "    description = \"Stub rule - replace strings/condition\"\n"
        "  strings:\n"
        "    $m = \"LAB_MARKER\"\n"
        "  condition:\n"
        "    $m\n"
        "}\n"
    )

    (Path(base_dir) / "validation.md").write_text(
        "## Validation (stub)\n\n"
        "- Run PoC in exploit/full mode\n"
        "- Capture evidence (pcap/logs)\n"
        "- Confirm rules trigger (positive)\n"
        "- Run negative control (benign) and confirm rules do NOT trigger\n"
    )
    return root


# ──────────────────────────────────────────────
# PoC Base Class
# ──────────────────────────────────────────────

class PocBase(ABC):
    """
    Base class for Proof-of-Concept implementations.

    Lifecycle:
        1. check()   — Non-destructive vulnerability check
        2. exploit()  — Demonstrate exploitation
        3. verify()   — Verify exploitation success
        4. cleanup()  — Remove artifacts

    Subclasses MUST implement check() and exploit().
    verify() and cleanup() have default implementations.
    """

    def __init__(self, target: str, options: dict | None = None):
        """
        Initialize the PoC.

        Args:
            target: Target URL/IP/hostname.
            options: Additional options.
        """
        self.target = target
        self.options = options or {}
        self.vuln_info = VULN_INFO
        self.result = PocResult.UNKNOWN
        self.evidence: list[str] = []
        self.artifacts: list[str] = []  # Track created artifacts for cleanup
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.evidence_paths = init_evidence_paths(self.options.get("evidence_dir", "evidence"))

    def print_banner(self):
        """Print PoC banner with vulnerability info."""
        v = self.vuln_info
        print()
        print("=" * 60)
        print(f" PoC: {v['cve']} - {v['name']}")
        print("=" * 60)
        print(f" Target:    {self.target}")
        print(f" Severity:  {v['severity']} (CVSS: {v['cvss_score']})")
        print(f" Affected:  {v['affected_software']} {v['affected_versions']}")
        print(f" Author:    {v['author']}")
        print(f" Date:      {v['date']}")
        print("=" * 60)
        print()

    @abstractmethod
    def check(self) -> bool:
        """
        Non-destructive check if the target is vulnerable.

        This should NOT exploit the vulnerability — only determine
        if the target is likely vulnerable (e.g., version check,
        behavior analysis).

        Returns:
            True if the target appears vulnerable, False otherwise.
        """
        pass

    @abstractmethod
    def exploit(self) -> dict:
        """
        Demonstrate the vulnerability exploitation.

        Returns:
            Dict with exploitation results:
            {
                "success": bool,
                "evidence": str,
                "details": dict,
            }
        """
        pass

    def verify(self, exploit_result: dict) -> bool:
        """
        Verify that exploitation was successful.

        Default implementation checks the 'success' key from exploit().
        Override for more sophisticated verification.

        Args:
            exploit_result: Result dict from exploit().

        Returns:
            True if exploitation was verified successful.
        """
        return exploit_result.get("success", False)

    def cleanup(self):
        """
        Clean up artifacts from exploitation.

        Default implementation logs tracked artifacts.
        Override to implement actual cleanup.
        """
        if self.artifacts:
            logger.info("Cleaning up artifacts...")
            for artifact in self.artifacts:
                logger.info(f"  Artifact: {artifact}")
            logger.info("Note: Manual cleanup may be required")
        else:
            logger.info("No artifacts to clean up")

        # Best-effort: write run log artifact
        try:
            self.evidence_paths.run_log.write_text("\n".join(self.evidence) + "\n")
        except Exception:
            pass

    def add_evidence(self, evidence: str):
        """Record evidence of exploitation."""
        self.evidence.append(evidence)
        logger.success(f"Evidence: {evidence[:200]}")

    def track_artifact(self, artifact: str):
        """Track an artifact created during exploitation."""
        self.artifacts.append(artifact)
        logger.debug(f"Artifact tracked: {artifact}")

    def execute(self, mode: str = "full") -> dict:
        """
        Execute the PoC with the specified mode.

        Args:
            mode: Execution mode:
                - "check": Only check, don't exploit
                - "exploit": Check and exploit
                - "full": Check, exploit, verify, and cleanup

        Returns:
            Dict with complete execution results.
        """
        self.start_time = datetime.now()
        self.print_banner()

        result = {
            "target": self.target,
            "vuln_info": self.vuln_info,
            "mode": mode,
            "phases": {},
            "result": PocResult.UNKNOWN.value,
            "evidence": [],
            "start_time": self.start_time.isoformat(),
            "end_time": None,
            "duration": 0,
        }

        # Phase 1: Check
        logger.info("Phase 1: Checking vulnerability...")
        try:
            is_vulnerable = self.check()
            result["phases"]["check"] = {
                "completed": True,
                "vulnerable": is_vulnerable,
            }

            if is_vulnerable:
                logger.success("Target appears VULNERABLE")
            else:
                logger.info("Target does NOT appear vulnerable")
                self.result = PocResult.NOT_VULNERABLE
                result["result"] = self.result.value
                if mode == "check":
                    self._finalize(result)
                    return result
                logger.warning("Proceeding anyway (target may still be vulnerable)")
        except Exception as e:
            logger.error(f"Check failed: {e}")
            result["phases"]["check"] = {"completed": False, "error": str(e)}
            if mode == "check":
                self.result = PocResult.ERROR
                result["result"] = self.result.value
                self._finalize(result)
                return result

        if mode == "check":
            self._finalize(result)
            return result

        # Phase 2: Exploit
        logger.info("Phase 2: Exploiting...")
        exploit_result = {}
        try:
            exploit_result = self.exploit()
            result["phases"]["exploit"] = {
                "completed": True,
                "result": exploit_result,
            }

            if exploit_result.get("success"):
                logger.success("Exploitation successful")
                self.add_evidence(exploit_result.get("evidence", "Exploitation succeeded"))
            else:
                logger.error("Exploitation failed")
                logger.error(f"Details: {exploit_result.get('error', 'Unknown')}")
        except Exception as e:
            logger.error(f"Exploitation error: {e}")
            logger.debug(traceback.format_exc())
            result["phases"]["exploit"] = {"completed": False, "error": str(e)}

        if mode == "exploit":
            result["evidence"] = self.evidence
            self.result = (
                PocResult.VULNERABLE
                if exploit_result.get("success")
                else PocResult.NOT_VULNERABLE
            )
            result["result"] = self.result.value
            self._finalize(result)
            return result

        # Phase 3: Verify
        logger.info("Phase 3: Verifying exploitation...")
        try:
            verified = self.verify(exploit_result)
            result["phases"]["verify"] = {
                "completed": True,
                "verified": verified,
            }

            if verified:
                logger.success("Exploitation VERIFIED")
                self.result = PocResult.VULNERABLE
            else:
                logger.warning("Exploitation could NOT be verified")
                self.result = PocResult.UNKNOWN
        except Exception as e:
            logger.error(f"Verification error: {e}")
            result["phases"]["verify"] = {"completed": False, "error": str(e)}

        # Phase 4: Cleanup
        logger.info("Phase 4: Cleaning up...")
        try:
            self.cleanup()
            result["phases"]["cleanup"] = {"completed": True}
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")
            result["phases"]["cleanup"] = {"completed": False, "error": str(e)}

        result["evidence"] = self.evidence
        result["result"] = self.result.value
        self._finalize(result)
        return result

    def _finalize(self, result: dict):
        """Finalize execution results."""
        self.end_time = datetime.now()
        result["end_time"] = self.end_time.isoformat()
        result["duration"] = (self.end_time - self.start_time).total_seconds()

        # Print final result
        print()
        print("=" * 60)
        severity_color = {
            PocResult.VULNERABLE: "\033[1;31m",      # Bold Red
            PocResult.NOT_VULNERABLE: "\033[1;32m",   # Bold Green
            PocResult.UNKNOWN: "\033[1;33m",          # Bold Yellow
            PocResult.ERROR: "\033[1;35m",            # Bold Magenta
        }
        color = severity_color.get(self.result, "\033[0m")
        print(f" Result: {color}{self.result.value}\033[0m")
        print(f" Duration: {result['duration']:.2f}s")

        if self.evidence:
            print(f" Evidence:")
            for e in self.evidence:
                print(f"   - {e[:100]}")

        if self.result == PocResult.VULNERABLE:
            print(f" Impact: {self.vuln_info['impact']}")
            if self.vuln_info['fixed_version']:
                print(f" Fix: Upgrade to {self.vuln_info['fixed_version']}")

        print("=" * 60)
        print()

    def generate_report(self) -> str:
        """
        Generate a disclosure-ready report.

        Returns:
            Markdown-formatted vulnerability report.
        """
        v = self.vuln_info
        evidence_text = "\n".join(f"- {e}" for e in self.evidence) or "N/A"

        report = f"""# Vulnerability Report: {v['cve']} - {v['name']}

## Executive Summary

A {v['severity'].lower()} severity vulnerability ({v['cve']}) was discovered in
{v['affected_software']} versions {v['affected_versions']}. {v['description']}

**CVSS Score**: {v['cvss_score']} ({v['severity']})
**CVSS Vector**: {v['cvss_vector']}

## Vulnerability Details

| Field | Value |
|-------|-------|
| **CVE** | {v['cve']} |
| **CWE** | {v['cwe']} |
| **Severity** | {v['severity']} |
| **CVSS Score** | {v['cvss_score']} |
| **Attack Vector** | {v['attack_vector']} |
| **Authentication** | {v['authentication']} |
| **Affected Software** | {v['affected_software']} |
| **Affected Versions** | {v['affected_versions']} |
| **Fixed Version** | {v['fixed_version'] or 'N/A'} |

## Description

{v['description']}

## Impact

{v['impact']}

## Proof of Concept

### Prerequisites
- Python 3.10+
- Required dependencies (see requirements.txt)

### Reproduction Steps

1. Set up the vulnerable target ({v['affected_software']} {v['affected_versions']})
2. Run the PoC:
   ```
   python poc.py <target> --mode exploit
   ```
3. Observe the exploitation output

### Evidence

{evidence_text}

## Remediation

1. **Immediate**: Upgrade {v['affected_software']} to version {v['fixed_version'] or '[latest]'}
2. **Mitigation**: [Specific mitigation steps]

## Timeline

| Date | Event |
|------|-------|
| {v['date']} | Vulnerability discovered |
| | Vendor notified |
| | Vendor acknowledged |
| | Patch released |
| | Public disclosure |

## References

"""
        for ref in v.get('references', []):
            report += f"- {ref}\n"

        report += f"\n---\n*Report generated by {v['author']} on {datetime.now().isoformat()}*\n"
        return report


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def create_poc_parser() -> argparse.ArgumentParser:
    """Create standard PoC argument parser."""
    parser = argparse.ArgumentParser(
        description=f"PoC: {VULN_INFO['cve']} - {VULN_INFO['name']}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s https://target.com --mode check
  %(prog)s https://target.com --mode exploit
  %(prog)s https://target.com --mode full --output report.json

Vulnerability: {VULN_INFO['cve']}
Severity: {VULN_INFO['severity']} (CVSS: {VULN_INFO['cvss_score']})
Affected: {VULN_INFO['affected_software']} {VULN_INFO['affected_versions']}
        """,
    )

    parser.add_argument(
        "target",
        help="Target URL/IP/hostname",
    )

    parser.add_argument(
        "--mode",
        choices=["check", "exploit", "full"],
        default="check",
        help="Execution mode (default: check)",
    )

    parser.add_argument(
        "--output",
        help="Save results to file (JSON)",
    )

    parser.add_argument(
        "--report",
        help="Generate disclosure report (Markdown)",
    )

    parser.add_argument(
        "--evidence-dir",
        default="evidence",
        help="Evidence directory (default: evidence/)",
    )

    parser.add_argument(
        "--write-detection-pack",
        action="store_true",
        help="Create detection pack skeleton under <evidence-dir>/detection/ (doc 10)",
    )

    parser.add_argument(
        "--proxy",
        help="HTTP proxy (e.g., http://127.0.0.1:8080)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


# ──────────────────────────────────────────────
# Example PoC Implementation
# ──────────────────────────────────────────────

class ExamplePoC(PocBase):
    """
    Example PoC implementation.
    Replace this with your actual vulnerability PoC.
    """

    def check(self) -> bool:
        """Check if target is vulnerable."""
        logger.action(f"Connecting to {self.target}...")

        # Example: Check version or behavior
        # response = requests.get(self.target)
        # if "vulnerable-version" in response.text:
        #     return True

        logger.info("Implement check() for your specific vulnerability")
        return False

    def exploit(self) -> dict:
        """Exploit the vulnerability."""
        logger.action(f"Sending exploit payload to {self.target}...")

        # Example: Send exploit payload
        # payload = craft_payload()
        # response = requests.post(self.target, data=payload)
        # if response.status_code == 200 and "success_indicator" in response.text:
        #     self.add_evidence(f"RCE achieved: {response.text[:100]}")
        #     return {"success": True, "evidence": response.text}

        logger.info("Implement exploit() for your specific vulnerability")
        return {"success": False, "error": "Not implemented"}


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = create_poc_parser()
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create and execute PoC
    poc = ExamplePoC(
        target=args.target,
        options={
            "proxy": args.proxy,
            "timeout": args.timeout,
            "verbose": args.verbose,
            "evidence_dir": args.evidence_dir,
        },
    )

    result = poc.execute(mode=args.mode)

    # Save results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info(f"Results saved to {args.output}")

    # Detection pack skeleton
    if args.write_detection_pack:
        root = write_detection_pack_skeleton(args.evidence_dir)
        logger.info(f"Detection pack skeleton created under {root}")

    # Generate report
    if args.report:
        report = poc.generate_report()
        with open(args.report, "w") as f:
            f.write(report)
        logger.info(f"Report saved to {args.report}")

    # Exit code based on result
    if result["result"] == PocResult.VULNERABLE.value:
        sys.exit(0)  # Vulnerable (success for a PoC)
    elif result["result"] == PocResult.NOT_VULNERABLE.value:
        sys.exit(1)  # Not vulnerable
    else:
        sys.exit(2)  # Unknown/Error
