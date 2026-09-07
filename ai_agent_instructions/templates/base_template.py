#!/usr/bin/env python3
"""
Base Security Tool Template
============================

This is the foundational template for all security tools in the lab.
All tools should inherit from the SecurityToolBase class defined here.

Category: Base Template
Author: Security Research Lab
Version: 1.0.0
Date: 2026-02-08

Usage:
    Inherit from SecurityToolBase and implement the required abstract methods.
    See other templates for specific implementations.

Legal:
    Authorized security testing only. See 02_LEGAL_CONTEXT.md.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import argparse
import json
import logging
import sys
import fnmatch
import ipaddress

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

VERSION = "1.0.0"

BANNER = """
╔══════════════════════════════════════════════╗
║        Security Research Lab - Tool          ║
║                  v{version}                  ║
╚══════════════════════════════════════════════╝
"""


# ──────────────────────────────────────────────
# Enums & Data Classes
# ──────────────────────────────────────────────

class Severity(str, Enum):
    """Finding severity levels aligned with CVSS."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OutputFormat(str, Enum):
    """Supported output formats."""
    CONSOLE = "console"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"

class TargetError(Exception):
    """Raised when target is out-of-scope or invalid."""


class ScopeValidator:
    """
    Scope enforcement helper (see 08_SAFETY_OVERRIDES.md).

    Use this in tools that accept targets/hosts/CIDRs.
    """

    def __init__(self, scope: list[str] | None, exclusions: list[str] | None = None):
        self.scope = scope or []
        self.exclusions = exclusions or []

    def is_in_scope(self, target: str) -> bool:
        if any(self._matches(target, exc) for exc in self.exclusions):
            return False
        if not self.scope:
            # If no scope provided, treat as "unknown" and require explicit confirmation in the calling tool.
            return True
        return any(self._matches(target, s) for s in self.scope)

    def validate_or_abort(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise TargetError(f"Target out of scope: {target} (scope={self.scope}, exclusions={self.exclusions})")

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            tip = ipaddress.ip_address(target)
            return tip in net
        except ValueError:
            return fnmatch.fnmatch(target, pattern)


class EvidenceWriter:
    """
    Lightweight helper to standardize evidence artifacts (docs 11–12).
    """

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.evidence_dir = self.base_dir / "evidence"
        self.logs_dir = self.evidence_dir / "logs"
        self.pcaps_dir = self.evidence_dir / "pcaps"
        self.diffs_dir = self.evidence_dir / "diffs"
        for d in (self.evidence_dir, self.logs_dir, self.pcaps_dir, self.diffs_dir):
            d.mkdir(parents=True, exist_ok=True)

    def write_log(self, name: str, content: str) -> Path:
        p = self.logs_dir / name
        p.write_text(content)
        return p

    def write_diff(self, name: str, content: str) -> Path:
        p = self.diffs_dir / name
        p.write_text(content)
        return p

    def reserve_pcap_path(self, name: str = "traffic.pcapng") -> Path:
        return self.pcaps_dir / name


@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe": self.cwe,
            "references": self.references,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class ToolResult:
    """Standard result container for tool operations."""
    success: bool
    message: str = ""
    data: Any = None
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: float = 0.0

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "timestamp": self.timestamp,
            "duration": self.duration,
        }


# ──────────────────────────────────────────────
# Logging Setup
# ──────────────────────────────────────────────

class SecurityToolFormatter(logging.Formatter):
    """Custom formatter with security tool conventions."""

    SYMBOLS = {
        logging.DEBUG: "[D]",
        logging.INFO: "[*]",
        logging.WARNING: "[!]",
        logging.ERROR: "[-]",
        logging.CRITICAL: "[!!]",
    }

    COLORS = {
        logging.DEBUG: "\033[36m",       # Cyan
        logging.INFO: "\033[37m",        # White
        logging.WARNING: "\033[33m",     # Yellow
        logging.ERROR: "\033[31m",       # Red
        logging.CRITICAL: "\033[1;31m",  # Bold Red
    }

    RESET = "\033[0m"

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        symbol = self.SYMBOLS.get(record.levelno, "[?]")
        timestamp = datetime.now().strftime("%H:%M:%S")

        if self.use_color:
            color = self.COLORS.get(record.levelno, "")
            return f"{color}{symbol}{self.RESET} [{timestamp}] {record.getMessage()}"
        return f"{symbol} [{timestamp}] {record.getMessage()}"


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    use_color: bool = True,
) -> logging.Logger:
    """Configure logging for security tools."""
    logger = logging.getLogger("security_tool")
    logger.setLevel(getattr(logging, level.upper()))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(SecurityToolFormatter(use_color=use_color))
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(file_handler)

    return logger


# ──────────────────────────────────────────────
# Base Tool Class
# ──────────────────────────────────────────────

class SecurityToolBase(ABC):
    """
    Abstract base class for all security tools.

    Subclasses must implement:
        - validate_target()
        - run()

    Optional overrides:
        - setup()
        - cleanup()
        - generate_report()
    """

    NAME: str = "SecurityTool"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "Base security tool"
    AUTHOR: str = "Security Research Lab"

    def __init__(self, target: str, options: dict | None = None):
        """
        Initialize the security tool.

        Args:
            target: Primary target (IP, URL, hostname, etc.)
            options: Additional options dictionary.
        """
        self.target = target
        self.options = options or {}
        self.results: list[ToolResult] = []
        self.findings: list[Finding] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.evidence = EvidenceWriter(self.options.get("work_dir", "."))
        self.scope_validator = ScopeValidator(
            scope=self.options.get("scope"),
            exclusions=self.options.get("exclude"),
        )

        # Setup logging
        self.logger = setup_logging(
            level=self.options.get("log_level", "INFO"),
            log_file=self.options.get("log_file"),
            use_color=self.options.get("color", True),
        )

    def print_banner(self):
        """Print tool banner."""
        print(BANNER.format(version=self.VERSION))
        self.logger.info(f"{self.NAME} v{self.VERSION} - {self.DESCRIPTION}")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Started: {datetime.now().isoformat()}")
        print("─" * 50)

    @abstractmethod
    def validate_target(self) -> bool:
        """
        Validate that the target is reachable and in scope.

        Returns:
            True if target is valid, False otherwise.
        """
        pass

    def setup(self):
        """
        Optional setup before execution.
        Override to initialize connections, sessions, etc.
        """
        pass

    @abstractmethod
    def run(self) -> list[ToolResult]:
        """
        Execute the tool's main functionality.

        Returns:
            List of ToolResult objects.
        """
        pass

    def cleanup(self):
        """
        Optional cleanup after execution.
        Override to close connections, remove artifacts, etc.
        """
        pass

    def execute(self) -> list[ToolResult]:
        """
        Full execution lifecycle: validate → setup → run → cleanup.

        Returns:
            List of ToolResult objects.
        """
        self.start_time = datetime.now()
        self.print_banner()

        # Validate
        self.logger.info("Validating target...")
        if not self.validate_target():
            self.logger.error("Target validation failed")
            return [ToolResult(success=False, error="Target validation failed")]

        self.logger.info("Target validated successfully")

        # Setup
        try:
            self.setup()
        except Exception as e:
            self.logger.error(f"Setup failed: {e}")
            return [ToolResult(success=False, error=f"Setup failed: {e}")]

        # Run
        try:
            self.results = self.run()
        except KeyboardInterrupt:
            self.logger.warning("Interrupted by user (Ctrl+C)")
            self.results = [ToolResult(success=False, error="User interrupted")]
        except Exception as e:
            self.logger.error(f"Execution error: {e}")
            self.results = [ToolResult(success=False, error=str(e))]

        # Cleanup
        try:
            self.cleanup()
        except Exception as e:
            self.logger.warning(f"Cleanup error: {e}")

        # Finalize
        self.end_time = datetime.now()
        elapsed = (self.end_time - self.start_time).total_seconds()
        self.logger.info(f"Completed in {elapsed:.2f}s")

        # Collect all findings
        for result in self.results:
            self.findings.extend(result.findings)

        self._print_summary()
        return self.results

    def _print_summary(self):
        """Print execution summary."""
        print("\n" + "─" * 50)
        self.logger.info("SUMMARY")

        total = len(self.findings)
        if total == 0:
            self.logger.info("No findings")
            return

        by_severity = {}
        for f in self.findings:
            by_severity.setdefault(f.severity.value, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(by_severity.get(sev, []))
            if count > 0:
                self.logger.info(f"  {sev}: {count}")

        self.logger.info(f"  Total: {total}")

    def generate_report(self, format: OutputFormat = OutputFormat.JSON) -> str:
        """
        Generate a report of findings.

        Args:
            format: Output format (json, csv, markdown, console).

        Returns:
            Formatted report string.
        """
        if format == OutputFormat.JSON:
            return self._report_json()
        elif format == OutputFormat.MARKDOWN:
            return self._report_markdown()
        elif format == OutputFormat.CSV:
            return self._report_csv()
        else:
            return self._report_console()

    def _report_json(self) -> str:
        """Generate JSON report."""
        report = {
            "tool": self.NAME,
            "version": self.VERSION,
            "target": self.target,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "findings": [f.to_dict() for f in self.findings],
            "results": [r.to_dict() for r in self.results],
        }
        return json.dumps(report, indent=2)

    def _report_markdown(self) -> str:
        """Generate Markdown report."""
        lines = [
            f"# {self.NAME} Report",
            "",
            f"**Target**: {self.target}",
            f"**Date**: {self.start_time.isoformat() if self.start_time else 'N/A'}",
            f"**Version**: {self.VERSION}",
            "",
            "## Findings",
            "",
        ]
        for i, f in enumerate(self.findings, 1):
            lines.append(f"### {i}. [{f.severity.value}] {f.title}")
            lines.append("")
            lines.append(f"**Description**: {f.description}")
            if f.evidence:
                lines.append("")
                lines.append("**Evidence**:")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
            if f.remediation:
                lines.append("")
                lines.append(f"**Remediation**: {f.remediation}")
            lines.append("")

        return "\n".join(lines)

    def _report_csv(self) -> str:
        """Generate CSV report."""
        lines = ["severity,title,description,cvss,cwe,evidence"]
        for f in self.findings:
            evidence = f.evidence.replace('"', '""')
            desc = f.description.replace('"', '""')
            lines.append(
                f'{f.severity.value},"{f.title}","{desc}",'
                f'{f.cvss_score},"{f.cwe}","{evidence}"'
            )
        return "\n".join(lines)

    def _report_console(self) -> str:
        """Generate console-friendly report."""
        lines = []
        for f in self.findings:
            lines.append(f"[{f.severity.value}] {f.title}")
            lines.append(f"  Description: {f.description}")
            if f.evidence:
                lines.append(f"  Evidence: {f.evidence}")
            if f.remediation:
                lines.append(f"  Fix: {f.remediation}")
            lines.append("")
        return "\n".join(lines)

    def save_report(self, filepath: str, format: OutputFormat = OutputFormat.JSON):
        """Save report to file."""
        report = self.generate_report(format)
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report)
        self.logger.info(f"Report saved to {filepath}")


# ──────────────────────────────────────────────
# CLI Helper
# ──────────────────────────────────────────────

def create_base_parser(tool_name: str, description: str) -> argparse.ArgumentParser:
    """
    Create a standard argument parser with common options.

    Args:
        tool_name: Name of the tool.
        description: Tool description.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog=tool_name,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required
    parser.add_argument(
        "target",
        help="Target (IP, URL, hostname, etc.)",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o", "--output",
        help="Output file path",
    )
    output_group.add_argument(
        "-f", "--format",
        choices=["console", "json", "csv", "markdown"],
        default="console",
        help="Output format (default: console)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output",
    )

    # Network options
    net_group = parser.add_argument_group("network options")
    net_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Connection timeout in seconds (default: 30)",
    )
    net_group.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)",
    )
    net_group.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # Rate limiting
    rate_group = parser.add_argument_group("rate limiting")
    rate_group.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        help="Max requests per second (default: 10)",
    )
    rate_group.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Max concurrent connections (default: 10)",
    )

    return parser


# ──────────────────────────────────────────────
# Example Usage
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("This is a base template. Import and extend SecurityToolBase in your tool.")
    print()
    print("Example:")
    print("  from base_template import SecurityToolBase, ToolResult, Finding, Severity")
    print()
    print("  class MyTool(SecurityToolBase):")
    print("      NAME = 'MyTool'")
    print("      VERSION = '1.0.0'")
    print("      DESCRIPTION = 'My custom security tool'")
    print()
    print("      def validate_target(self) -> bool:")
    print("          # Validate target")
    print("          return True")
    print()
    print("      def run(self) -> list[ToolResult]:")
    print("          # Tool logic here")
    print("          return [ToolResult(success=True, message='Done')]")
