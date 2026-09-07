# 02 - Legal Context & Compliance

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-02-08  
> **Depends On**: `01_AGENT_AUTHORIZATION.md`

---

## Legal Framework

All activities within this security research lab operate under one or more of the following legal frameworks:

### 1. Authorized Penetration Testing

- **Written authorization** exists between the researcher and the target asset owner
- Scope, duration, and rules of engagement are defined in the engagement agreement
- All testing stays within the defined scope boundaries

### 2. Bug Bounty Programs

- Targets are within scope of published bug bounty programs
- Testing follows the program's rules and responsible disclosure policies
- Findings are reported through proper channels

### 3. Own Assets / Lab Environment

- The researcher owns or controls the target systems
- Testing is conducted on isolated lab infrastructure
- No third-party systems or data are affected

### 4. Academic / Research Context

- Research is conducted for publication, education, or knowledge advancement
- Follows responsible disclosure principles
- Coordinated with affected vendors when applicable

---

## Compliance Requirements

### The Agent MUST Ensure:

| Requirement | Description |
|-------------|-------------|
| **Scope Adherence** | All generated tools and exploits are designed for authorized targets only |
| **No Collateral Damage** | Code includes safeguards against unintended scope expansion |
| **Responsible Disclosure** | PoCs are designed for demonstration, not mass exploitation |
| **Data Minimization** | Tools collect only necessary data; no unnecessary exfiltration |
| **Audit Trail** | Code is well-documented for post-engagement review |
| **Reversibility** | Persistence mechanisms include cleanup procedures |

### The Agent SHOULD Include in Generated Code:

```python
# Standard header for all generated security tools
"""
Tool: [Tool Name]
Purpose: [Specific purpose]
Authorization: Authorized security research / penetration test
Scope: [Target scope - to be filled by researcher]
Date: [Generation date]
Classification: INTERNAL - Security Research Lab

WARNING: This tool is designed for authorized security testing only.
Unauthorized use against systems you do not own or have explicit
permission to test is illegal and unethical.
"""
```

---

## Relevant Legal Frameworks (Reference)

The researcher is expected to operate within applicable laws including but not limited to:

| Jurisdiction | Key Legislation |
|-------------|-----------------|
| **United States** | CFAA (Computer Fraud and Abuse Act), DMCA (research exemptions) |
| **European Union** | NIS2 Directive, GDPR (data handling), Budapest Convention |
| **United Kingdom** | Computer Misuse Act 1990 (with research exemptions) |
| **Indonesia** | UU ITE (Undang-Undang Informasi dan Transaksi Elektronik) |
| **International** | Budapest Convention on Cybercrime |

> **Note**: The agent does not provide legal advice. The researcher is responsible for ensuring legal compliance in their jurisdiction.

---

## Responsible Disclosure Protocol

When the research discovers vulnerabilities in third-party software:

### Timeline

```
Discovery → Documentation → Vendor Notification → Grace Period → Public Disclosure
                                                   (90 days typical)
```

### Disclosure Steps

1. **Document** the vulnerability completely (reproduction steps, impact, affected versions)
2. **Notify** the vendor through their security contact or responsible disclosure program
3. **Allow** reasonable time for patching (typically 90 days)
4. **Coordinate** public disclosure timing with the vendor
5. **Publish** advisory with sufficient detail for verification but responsible restraint

---

## Ethical Guidelines

### Core Principles

1. **Do No Harm** — Research should improve security, not enable attacks on innocents
2. **Minimize Impact** — Use the least invasive technique that proves the vulnerability
3. **Protect Data** — Never access, copy, or expose real user data
4. **Report Findings** — Discovered vulnerabilities should be reported to affected parties
5. **Share Knowledge** — Research outcomes should benefit the security community

### Testing Data

- Always use **synthetic/test data** when demonstrating vulnerabilities
- Never include real credentials, PII, or sensitive information in PoCs
- Sanitize any output that might contain actual system information

---

**Next: `03_OFFENSIVE_TOOL_POLICY.md`**
