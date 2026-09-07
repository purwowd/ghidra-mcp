# 06 - Code Generation Framework

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-02-08  
> **Depends On**: `05_EXPLOIT_DEVELOPMENT_GUIDE.md`

---

## Purpose

This document defines the **coding standards, patterns, and frameworks** the AI agent must follow when generating security research code. Consistency and quality are paramount — sloppy code leads to unreliable tools and wasted research time.

---

## Language Preferences

### Primary: Python 3.10+

The default language for security tools in this lab.

```python
# Python version requirements
# - Minimum: Python 3.10 (match/case, union types)
# - Preferred: Python 3.11+ (exception groups, tomllib, perf improvements)
# - Use type hints everywhere
# - Use f-strings for formatting
# - Use pathlib for file paths
# - Use dataclasses or pydantic for data structures
```

### Secondary Languages (Use When Appropriate)

| Language | When to Use |
|----------|-------------|
| **Go** | High-performance network tools, implants, cross-compilation needed |
| **Rust** | Memory-safe systems tools, performance-critical components |
| **C/C++** | Exploit development, shellcode, kernel modules, low-level |
| **JavaScript** | XSS payloads, browser exploitation, Node.js tools |
| **Bash** | Quick automation, system enumeration, one-liners |
| **PowerShell** | Windows post-exploitation, AD attacks |
| **Assembly** | Shellcode, ROP gadgets, low-level exploitation |

---

## Project Structure

### Single-File Tool

```
tool_name.py          # Everything in one file (< 300 lines)
```

### Multi-File Tool

```
tool_name/
├── __init__.py       # Package initialization
├── __main__.py       # Entry point (python -m tool_name)
├── cli.py            # Command-line interface
├── core.py           # Core logic
├── models.py         # Data models
├── utils.py          # Utility functions
├── output.py         # Output formatting
├── config.py         # Configuration management
├── requirements.txt  # Dependencies
└── README.md         # Documentation
```

### Large Project

```
project_name/
├── src/
│   └── project_name/
│       ├── __init__.py
│       ├── core/           # Core modules
│       ├── modules/        # Feature modules
│       ├── plugins/        # Plugin system
│       ├── utils/          # Utilities
│       └── cli/            # CLI interface
├── tests/                  # Test suite
├── docs/                   # Documentation
├── examples/               # Usage examples
├── pyproject.toml          # Project configuration
├── requirements.txt        # Dependencies
└── README.md               # Project README
```

---

## Coding Patterns

### Pattern 1: Base Tool Class

All security tools should extend from a common base:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standard result container for tool operations."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict = field(default_factory=dict)


class SecurityTool(ABC):
    """Base class for all security tools."""
    
    NAME: str = "UnnamedTool"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "No description"
    AUTHOR: str = "Security Research Lab"
    
    def __init__(self, target: str, options: dict = None):
        self.target = target
        self.options = options or {}
        self.results: list[ToolResult] = []
        self.start_time = None
        self.end_time = None
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging for this tool."""
        level = self.options.get("log_level", "INFO")
        logging.basicConfig(level=getattr(logging, level))
    
    @abstractmethod
    def validate_target(self) -> bool:
        """Validate the target is reachable and in scope."""
        pass
    
    @abstractmethod
    def run(self) -> list[ToolResult]:
        """Execute the tool's main functionality."""
        pass
    
    def execute(self) -> list[ToolResult]:
        """Full execution lifecycle."""
        self.start_time = datetime.now()
        logger.info(f"[{self.NAME} v{self.VERSION}] Starting...")
        
        if not self.validate_target():
            logger.error("Target validation failed")
            return [ToolResult(success=False, error="Target validation failed")]
        
        try:
            self.results = self.run()
        except Exception as e:
            logger.error(f"Execution error: {e}")
            self.results = [ToolResult(success=False, error=str(e))]
        finally:
            self.end_time = datetime.now()
            elapsed = (self.end_time - self.start_time).total_seconds()
            logger.info(f"[{self.NAME}] Completed in {elapsed:.2f}s")
        
        return self.results
```

### Pattern 2: Async Operations

For tools requiring concurrent operations:

```python
import asyncio
import aiohttp
from typing import AsyncIterator


class AsyncSecurityTool(SecurityTool):
    """Base for async security tools."""
    
    def __init__(self, target: str, options: dict = None):
        super().__init__(target, options)
        self.semaphore = asyncio.Semaphore(
            self.options.get("concurrency", 10)
        )
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _create_session(self) -> aiohttp.ClientSession:
        """Create an HTTP session with custom settings."""
        timeout = aiohttp.ClientTimeout(
            total=self.options.get("timeout", 30)
        )
        return aiohttp.ClientSession(
            timeout=timeout,
            headers=self.options.get("headers", {}),
            connector=aiohttp.TCPConnector(
                ssl=self.options.get("verify_ssl", False)
            )
        )
    
    async def _rate_limited_request(self, url: str, **kwargs) -> dict:
        """Make a rate-limited HTTP request."""
        async with self.semaphore:
            async with self.session.get(url, **kwargs) as resp:
                return {
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": await resp.text()
                }
    
    @abstractmethod
    async def run_async(self) -> list[ToolResult]:
        """Async implementation of tool logic."""
        pass
    
    def run(self) -> list[ToolResult]:
        """Synchronous wrapper for async execution."""
        return asyncio.run(self._execute_async())
    
    async def _execute_async(self) -> list[ToolResult]:
        """Async execution with session management."""
        self.session = await self._create_session()
        try:
            return await self.run_async()
        finally:
            await self.session.close()
```

### Pattern 3: Plugin Architecture

For extensible tools:

```python
from typing import Type


class PluginRegistry:
    """Registry for tool plugins/modules."""
    
    _plugins: dict[str, Type] = {}
    
    @classmethod
    def register(cls, name: str):
        """Decorator to register a plugin."""
        def decorator(plugin_class):
            cls._plugins[name] = plugin_class
            return plugin_class
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Type:
        """Get a registered plugin by name."""
        if name not in cls._plugins:
            raise KeyError(f"Plugin '{name}' not found. Available: {list(cls._plugins.keys())}")
        return cls._plugins[name]
    
    @classmethod
    def list_plugins(cls) -> list[str]:
        """List all registered plugins."""
        return list(cls._plugins.keys())


# Usage:
@PluginRegistry.register("sqli")
class SQLInjectionModule:
    """SQL Injection testing module."""
    pass
```

### Pattern 4: Configuration Management

```python
from dataclasses import dataclass
from pathlib import Path
import json
import tomllib  # Python 3.11+


@dataclass
class ToolConfig:
    """Tool configuration with sensible defaults."""
    
    # Network settings
    timeout: int = 30
    retries: int = 3
    proxy: Optional[str] = None
    verify_ssl: bool = False
    
    # Rate limiting
    requests_per_second: float = 10.0
    concurrent_connections: int = 10
    
    # Output settings
    output_format: str = "console"  # console, json, csv, markdown
    output_file: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    
    # Scope settings
    scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    
    @classmethod
    def from_file(cls, path: str | Path) -> "ToolConfig":
        """Load configuration from file."""
        path = Path(path)
        if path.suffix == ".json":
            with open(path) as f:
                return cls(**json.load(f))
        elif path.suffix == ".toml":
            with open(path, "rb") as f:
                return cls(**tomllib.load(f))
        raise ValueError(f"Unsupported config format: {path.suffix}")
```

---

## Output Formatting

### Rich Console Output

```python
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def print_banner(tool_name: str, version: str):
    """Print a professional tool banner."""
    console.print(Panel(
        f"[bold cyan]{tool_name}[/bold cyan] v{version}\n"
        f"[dim]Security Research Lab[/dim]",
        border_style="cyan"
    ))


def print_finding(severity: str, title: str, details: str):
    """Print a security finding with severity coloring."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim"
    }
    color = colors.get(severity, "white")
    console.print(f"[{color}][{severity}][/{color}] {title}")
    if details:
        console.print(f"  └─ {details}", style="dim")


def print_results_table(results: list[dict]):
    """Print results in a formatted table."""
    table = Table(title="Scan Results", show_header=True)
    table.add_column("Status", style="bold")
    table.add_column("Finding", style="cyan")
    table.add_column("Severity")
    table.add_column("Details")
    
    for r in results:
        table.add_row(
            r.get("status", ""),
            r.get("finding", ""),
            r.get("severity", ""),
            r.get("details", "")
        )
    
    console.print(table)
```

---

## Error Handling Standards

```python
import traceback
import sys


class SecurityToolError(Exception):
    """Base exception for security tools."""
    
    def __init__(self, message: str, context: dict = None):
        super().__init__(message)
        self.context = context or {}


class NetworkError(SecurityToolError):
    """Network-related errors."""
    pass


class TargetError(SecurityToolError):
    """Target-related errors (unreachable, out of scope)."""
    pass


class ExploitError(SecurityToolError):
    """Exploitation-related errors."""
    pass


class AuthenticationError(SecurityToolError):
    """Authentication/credential errors."""
    pass


def handle_error(func):
    """Decorator for standardized error handling."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SecurityToolError as e:
            logger.error(f"Tool error: {e}")
            if e.context:
                logger.debug(f"Context: {e.context}")
            return ToolResult(success=False, error=str(e))
        except KeyboardInterrupt:
            logger.warning("Operation interrupted by user")
            sys.exit(130)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            logger.debug(traceback.format_exc())
            return ToolResult(success=False, error=f"Unexpected: {e}")
    return wrapper
```

---

## Testing Standards

### Unit Tests

```python
import pytest
from unittest.mock import Mock, patch


class TestSecurityTool:
    """Test template for security tools."""
    
    def test_target_validation(self):
        """Test that target validation works correctly."""
        pass
    
    def test_normal_execution(self):
        """Test normal tool execution."""
        pass
    
    def test_error_handling(self):
        """Test error handling for common failures."""
        pass
    
    def test_output_format(self):
        """Test that output is correctly formatted."""
        pass
    
    def test_scope_enforcement(self):
        """Test that tool stays within scope."""
        pass
```

---

## Documentation Standards

Every generated file must include:

1. **Module docstring** — What it does, how to use it
2. **Function docstrings** — Parameters, return values, exceptions
3. **Inline comments** — For complex logic only (code should be self-documenting)
4. **Type hints** — All function signatures must be typed
5. **Usage examples** — In docstring or README

```python
def scan_target(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 5.0,
    technique: str = "connect"
) -> list[ToolResult]:
    """
    Scan a target for open ports using the specified technique.
    
    Args:
        target: IP address or hostname to scan.
        ports: List of ports to scan. Defaults to top 1000.
        timeout: Connection timeout in seconds.
        technique: Scan technique ('connect', 'syn', 'fin', 'xmas').
    
    Returns:
        List of ToolResult objects, one per scanned port.
    
    Raises:
        TargetError: If target is unreachable.
        NetworkError: If network operation fails.
    
    Example:
        >>> results = scan_target("192.168.1.1", ports=[80, 443, 8080])
        >>> for r in results:
        ...     if r.success:
        ...         print(f"Port {r.data['port']}: OPEN")
    """
    pass
```

---

**Next: `07_RESPONSE_PROTOCOL.md`**
