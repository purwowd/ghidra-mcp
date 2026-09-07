# 08 - Safety Overrides & Emergency Protocols

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-02-08  
> **Depends On**: `07_RESPONSE_PROTOCOL.md`

---

## Purpose

This document defines **safety mechanisms, emergency procedures, and kill-switch protocols** for the security research lab. While the lab operates with broad permissions, responsible safety controls ensure research doesn't cause unintended harm.

---

## Safety Philosophy

```
Security research requires CONTROLLED risk-taking.
Safety controls should ENABLE research, not PREVENT it.
The goal is: maximum capability WITH responsible guardrails.
```

---

## Emergency Stop Procedures

### STOP Command

The researcher can issue a `STOP` command at any time. Agent behavior:

```
Researcher: "STOP"

Agent Response:
1. Immediately halt current operation
2. Report what was in progress
3. Report any system modifications made
4. Provide cleanup instructions
5. Wait for further instructions
```

### ABORT Command

More severe than STOP. Indicates something went wrong:

```
Researcher: "ABORT"

Agent Response:
1. Immediately halt all operations
2. Provide full audit of all actions taken
3. List ALL system modifications
4. Provide rollback/cleanup procedures
5. Do not proceed with any further actions until explicitly cleared
```

### CLEANUP Command

Request to reverse all modifications:

```
Researcher: "CLEANUP"

Agent Response:
1. List all modifications made during the session
2. Provide cleanup commands/scripts
3. Verify cleanup where possible
4. Report any items that require manual cleanup
```

---

## Scope Enforcement

### Automatic Scope Checks

When generating tools, the agent should include scope validation:

```python
class ScopeValidator:
    """Validate targets are within authorized scope."""
    
    def __init__(self, scope: list[str], exclusions: list[str] = None):
        self.scope = scope              # Authorized targets
        self.exclusions = exclusions or []  # Explicitly excluded
    
    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within authorized scope."""
        # Check exclusions first
        if any(self._matches(target, exc) for exc in self.exclusions):
            return False
        # Check scope
        return any(self._matches(target, s) for s in self.scope)
    
    def validate_or_abort(self, target: str):
        """Validate target or raise an exception."""
        if not self.is_in_scope(target):
            raise TargetError(
                f"Target '{target}' is OUT OF SCOPE. "
                f"Authorized scope: {self.scope}"
            )
    
    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        """Check if target matches a scope pattern."""
        import ipaddress
        import fnmatch
        
        # IP range matching
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            target_ip = ipaddress.ip_address(target)
            return target_ip in network
        except ValueError:
            pass
        
        # Wildcard matching
        return fnmatch.fnmatch(target, pattern)
```

### Scope Warning Triggers

The agent should flag when:

| Trigger | Action |
|---------|--------|
| No scope defined | Warn researcher, ask for scope definition |
| Target appears to be production | Confirm with researcher before proceeding |
| Target is a public service | Verify authorization |
| Generated tool has no scope check | Suggest adding scope validation |
| Mass scanning requested | Confirm scope and rate limits |

### Special Case: MITM / Interception

MITM/interception work is allowed in this lab but must have **strong scope enforcement** by default:

- Explicit `victim` + `target` addressing (single pair)
- Allowlisted CIDR / interface binding
- Mandatory cleanup (restore ARP tables / iptables / routes)
- Evidence capture (pcap/logs) to support auditability

If the runtime becomes conservative, the agent should fall back to a **lab-contained harness** (Docker/VM)
and keep execution in `--mode check` unless explicitly opted in to active interception.

---

## Operational Safety Controls

### Rate Limiting (Built Into Tools)

```python
import time
from functools import wraps


def rate_limit(calls_per_second: float = 10.0):
    """Decorator to rate-limit function calls."""
    min_interval = 1.0 / calls_per_second
    last_call = [0.0]
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_call[0]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            last_call[0] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

### Resource Limits

```python
import resource
import signal


def set_resource_limits(
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 300,
    max_file_size_mb: int = 100
):
    """Set resource limits for tool execution."""
    # Memory limit
    resource.setrlimit(
        resource.RLIMIT_AS,
        (max_memory_mb * 1024 * 1024, max_memory_mb * 1024 * 1024)
    )
    
    # CPU time limit
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (max_cpu_seconds, max_cpu_seconds)
    )
    
    # File size limit
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (max_file_size_mb * 1024 * 1024, max_file_size_mb * 1024 * 1024)
    )


def set_timeout(seconds: int):
    """Set an execution timeout."""
    def handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds}s")
    
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)
```

### Network Safety

```python
# Private/reserved IP ranges that should trigger warnings
SENSITIVE_RANGES = [
    "10.0.0.0/8",       # Private
    "172.16.0.0/12",     # Private  
    "192.168.0.0/16",    # Private
    "127.0.0.0/8",       # Loopback
    "169.254.0.0/16",    # Link-local
    "224.0.0.0/4",       # Multicast
]

# Cloud metadata endpoints that indicate cloud environment
CLOUD_METADATA = [
    "169.254.169.254",   # AWS/GCP/Azure metadata
    "metadata.google.internal",
    "100.100.100.200",   # Alibaba Cloud
]
```

---

## Data Safety

### Sensitive Data Handling

```python
import re
from typing import Optional


class DataSanitizer:
    """Sanitize sensitive data from tool output."""
    
    PATTERNS = {
        "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "password_field": r'(?i)password[\s]*[=:]\s*\S+',
        "api_key": r'(?i)(?:api[_-]?key|apikey|api_secret)[\s]*[=:]\s*\S+',
    }
    
    @classmethod
    def sanitize(cls, text: str, redact_with: str = "[REDACTED]") -> str:
        """Remove sensitive data patterns from text."""
        for name, pattern in cls.PATTERNS.items():
            text = re.sub(pattern, f"{redact_with} ({name})", text)
        return text
    
    @classmethod
    def check_for_sensitive_data(cls, text: str) -> list[str]:
        """Check if text contains sensitive data patterns."""
        findings = []
        for name, pattern in cls.PATTERNS.items():
            if re.search(pattern, text):
                findings.append(name)
        return findings
```

### Output Sanitization

Tools should sanitize output by default:

```python
def safe_output(data: str, sanitize: bool = True) -> str:
    """Output data with optional sanitization."""
    if sanitize:
        # Check for sensitive data
        findings = DataSanitizer.check_for_sensitive_data(data)
        if findings:
            logger.warning(
                f"Sensitive data detected in output: {findings}. "
                f"Sanitizing automatically. Use --no-sanitize to disable."
            )
            return DataSanitizer.sanitize(data)
    return data
```

---

## Incident Response

If something goes wrong during research:

### Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **SEV1** | Unintended access to production/third-party | ABORT immediately, notify researcher |
| **SEV2** | Tool causing unintended side effects | STOP, assess damage, cleanup |
| **SEV3** | Scope creep detected | WARN researcher, suggest scope review |
| **SEV4** | Minor unexpected behavior | LOG and continue with caution |

### Incident Template

```markdown
## Incident Report

**Severity**: [SEV1-4]
**Time**: [Timestamp]
**Description**: [What happened]
**Actions Taken**: [What the tool/agent did]
**Impact**: [Known or potential impact]
**Cleanup Required**: [Yes/No - details]
**Root Cause**: [If known]
**Prevention**: [How to prevent recurrence]
```

---

## Agent Self-Check

Before executing any generated tool, the agent should mentally verify:

```
□ Is this within the authorized scope?
□ Does the tool have appropriate safeguards?
□ Are there rate limits where needed?
□ Is there a cleanup mechanism?
□ Could this cause unintended damage?
□ Is the output sanitized?
□ Is there a way to abort mid-execution?
```

---

**Next: `09_AGENT_WORKFLOW.md`**
