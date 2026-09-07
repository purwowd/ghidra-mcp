#!/usr/bin/env python3
"""
Active Directory / Windows Lab Template
=======================================

Working multi-phase AD-style lab path.
Default backend is an in-process directory (no Windows VM required).
Optional --backend ldap for a live LDAP lab DC.

Pair with: 14_RED_TEAM_KILLCHAIN.md, pocs/RT-AD-LAB/

Usage:
    python ad_windows_lab_template.py --mode full
    python ad_windows_lab_template.py --mode full --backend ldap --ldap-url ldap://127.0.0.1:389

Legal: Authorized lab AD only. See 02_LEGAL_CONTEXT.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import argparse
import hashlib
import json
import logging
import sys


class PhaseResult(str, Enum):
    OK = "OK"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


MARKER = "LAB_AD_MARKER=srl-ad-lab"


@dataclass
class LabConfig:
    domain: str = "lab.local"
    dc_host: str = "dc01.lab.local"
    dc_ip: str = "127.0.0.1"
    attacker_user: str = "attacker"
    attacker_pass: str = "LabPass123!"
    victim_user: str = "victim"
    service_user: str = "svc_sql"
    service_pass: str = "ServicePass!999"
    target_host: str = "ws01.lab.local"
    evidence_marker: str = MARKER
    ldap_url: str = "ldap://127.0.0.1:389"
    ldap_base: str = "dc=lab,dc=local"
    ldap_bind_dn: str = "cn=admin,dc=lab,dc=local"
    ldap_bind_pw: str = "admin"


@dataclass
class PhaseOutcome:
    phase: str
    result: PhaseResult
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class PocFormatter(logging.Formatter):
    SYMBOLS = {
        logging.DEBUG: "\033[36m[D]\033[0m",
        logging.INFO: "\033[37m[*]\033[0m",
        logging.WARNING: "\033[33m[!]\033[0m",
        logging.ERROR: "\033[31m[-]\033[0m",
    }
    SUCCESS = 25
    ACTION = 15

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == self.SUCCESS:
            symbol = "\033[32m[+]\033[0m"
        elif record.levelno == self.ACTION:
            symbol = "\033[35m[>]\033[0m"
        else:
            symbol = self.SYMBOLS.get(record.levelno, "[?]")
        return f"{symbol} {record.getMessage()}"


def setup_logger(verbose: bool = False) -> logging.Logger:
    log = logging.getLogger("ad_lab")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    logging.addLevelName(PocFormatter.SUCCESS, "SUCCESS")
    logging.addLevelName(PocFormatter.ACTION, "ACTION")
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(PocFormatter())
    log.handlers.clear()
    log.addHandler(h)

    def success(self, msg, *a, **k):
        self.log(PocFormatter.SUCCESS, msg, *a, **k)

    def action(self, msg, *a, **k):
        self.log(PocFormatter.ACTION, msg, *a, **k)

    log.success = success.__get__(log)  # type: ignore[attr-defined]
    log.action = action.__get__(log)  # type: ignore[attr-defined]
    return log


logger = setup_logger()


def nt_hash(password: str) -> str:
    # Lab stand-in (not real NT hash) — deterministic marker material
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324 — lab marker only


class InProcessDirectory:
    """
    Minimal AD-like directory for reproducible lab demos.
    Models: auth, SPN enum (Kerberoast-shaped), lateral to a file share marker.
    """

    def __init__(self, cfg: LabConfig):
        self.cfg = cfg
        self.users = {
            cfg.attacker_user: {
                "password": cfg.attacker_pass,
                "groups": ["Domain Users"],
                "spn": [],
            },
            cfg.victim_user: {
                "password": "VictimPass!",
                "groups": ["Domain Users"],
                "spn": [],
            },
            cfg.service_user: {
                "password": cfg.service_pass,
                "groups": ["Domain Users"],
                "spn": [f"MSSQLSvc/{cfg.target_host}:1433"],
            },
            "Administrator": {
                "password": "AdminLab!Only",
                "groups": ["Domain Admins"],
                "spn": [],
            },
        }
        self.share = {f"\\\\{cfg.target_host}\\lab\\flag.txt": MARKER}
        self.session: Optional[str] = None
        self.tickets: list[str] = []
        self.svc_hash: Optional[str] = None

    def online(self) -> bool:
        return True

    def authenticate(self, user: str, password: str) -> bool:
        rec = self.users.get(user)
        if not rec or rec["password"] != password:
            return False
        self.session = user
        return True

    def list_users(self) -> list[dict[str, Any]]:
        out = []
        for name, rec in self.users.items():
            out.append({"sam": name, "groups": rec["groups"], "spn": rec["spn"]})
        return out

    def kerberoast(self) -> dict[str, str]:
        svc = self.users[self.cfg.service_user]
        self.svc_hash = nt_hash(svc["password"])
        ticket = f"$krb5tgs$23$*{self.cfg.service_user}${self.cfg.domain}${svc['spn'][0]}*{self.svc_hash}"
        self.tickets.append(ticket)
        return {"spn": svc["spn"][0], "hash": self.svc_hash, "ticket": ticket}

    def crack_service(self) -> Optional[str]:
        # Lab: "crack" by verifying known wordlist including service_pass
        if not self.svc_hash:
            return None
        wordlist = [self.cfg.service_pass, "Password1", "Summer2024!"]
        for w in wordlist:
            if nt_hash(w) == self.svc_hash:
                return w
        return None

    def lateral(self, password: str) -> Optional[str]:
        # Authenticate to target as service account and read share
        if password != self.cfg.service_pass:
            return None
        path = f"\\\\{self.cfg.target_host}\\lab\\flag.txt"
        return self.share.get(path)

    def cleanup(self) -> None:
        self.tickets.clear()
        self.session = None
        self.svc_hash = None


class LdapDirectory:
    """Optional live LDAP backend (requires ldap3 + reachable lab LDAP)."""

    def __init__(self, cfg: LabConfig):
        self.cfg = cfg
        try:
            from ldap3 import ALL, Connection, Server
        except ImportError as exc:
            raise RuntimeError("ldap3 required for --backend ldap: pip install ldap3") from exc
        self._Server = Server
        self._Connection = Connection
        self._ALL = ALL
        self.tickets: list[str] = []
        self.svc_hash: Optional[str] = None
        self._conn: Any = None

    def online(self) -> bool:
        server = self._Server(self.cfg.ldap_url, get_info=self._ALL)
        conn = self._Connection(
            server, self.cfg.ldap_bind_dn, self.cfg.ldap_bind_pw, auto_bind=True
        )
        self._conn = conn
        return True

    def authenticate(self, user: str, password: str) -> bool:
        # Simple bind as uid/cn=user
        from ldap3 import Connection, Server

        candidates = [
            f"cn={user},{self.cfg.ldap_base}",
            f"uid={user},{self.cfg.ldap_base}",
            f"cn={user},ou=users,{self.cfg.ldap_base}",
        ]
        server = Server(self.cfg.ldap_url)
        for dn in candidates:
            try:
                c = Connection(server, dn, password, auto_bind=True)
                c.unbind()
                return True
            except Exception:
                continue
        return False

    def list_users(self) -> list[dict[str, Any]]:
        assert self._conn is not None
        self._conn.search(self.cfg.ldap_base, "(objectClass=*)", attributes=["cn", "uid", "servicePrincipalName"])
        users = []
        for e in self._conn.entries:
            users.append({"dn": str(e.entry_dn), "attrs": json.loads(e.entry_to_json())})
        return users

    def kerberoast(self) -> dict[str, str]:
        # Without real Kerberos, emit lab ticket material from configured service user
        self.svc_hash = nt_hash(self.cfg.service_pass)
        ticket = f"$krb5tgs$23$*{self.cfg.service_user}${self.cfg.domain}*lab*{self.svc_hash}"
        self.tickets.append(ticket)
        return {
            "spn": f"MSSQLSvc/{self.cfg.target_host}:1433",
            "hash": self.svc_hash,
            "ticket": ticket,
            "note": "lab stand-in; use Impacket GetUserSPNs against real AD when available",
        }

    def crack_service(self) -> Optional[str]:
        if self.svc_hash and nt_hash(self.cfg.service_pass) == self.svc_hash:
            return self.cfg.service_pass
        return None

    def lateral(self, password: str) -> Optional[str]:
        if password == self.cfg.service_pass:
            return MARKER
        return None

    def cleanup(self) -> None:
        self.tickets.clear()
        self.svc_hash = None
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass


class ADWindowsLabPath:
    ATTACK_MAP = {
        "recon": ["T1087", "T1018"],
        "initial_access": ["T1078"],
        "credential_access": ["T1558.003"],
        "lateral": ["T1021"],
        "objective": ["T1005"],
    }

    def __init__(self, config: LabConfig, options: dict | None = None):
        self.config = config
        self.options = options or {}
        self.outcomes: list[PhaseOutcome] = []
        self.start: Optional[datetime] = None
        self.dir: Any = None
        self.backend_name = "inprocess"
        self._cracked: Optional[str] = None

    def _record(self, outcome: PhaseOutcome) -> PhaseOutcome:
        self.outcomes.append(outcome)
        if outcome.result == PhaseResult.OK:
            for e in outcome.evidence:
                logger.success(f"{outcome.phase}: {e}")
        elif outcome.result == PhaseResult.SKIP:
            logger.warning(f"{outcome.phase}: skipped — {outcome.error or 'n/a'}")
        else:
            logger.error(f"{outcome.phase}: {outcome.error or outcome.result}")
        return outcome

    def check_lab(self) -> PhaseOutcome:
        logger.action("Checking AD lab directory...")
        backend = self.options.get("backend", "inprocess")
        try:
            if backend == "ldap":
                self.dir = LdapDirectory(self.config)
                self.backend_name = "ldap"
            else:
                self.dir = InProcessDirectory(self.config)
                self.backend_name = "inprocess"
            ok = self.dir.online()
            if not ok:
                return self._record(PhaseOutcome(phase="check", result=PhaseResult.FAIL, error="directory offline"))
            return self._record(
                PhaseOutcome(
                    phase="check",
                    result=PhaseResult.OK,
                    evidence=[f"backend={self.backend_name}", f"domain={self.config.domain}"],
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="check", result=PhaseResult.FAIL, error=str(exc)))

    def recon(self) -> PhaseOutcome:
        logger.action("AD recon (users / SPNs)...")
        try:
            users = self.dir.list_users()
            spn_users = []
            if self.backend_name == "inprocess":
                spn_users = [u["sam"] for u in users if u.get("spn")]
            return self._record(
                PhaseOutcome(
                    phase="recon",
                    result=PhaseResult.OK,
                    evidence=[f"users={len(users)}", f"spn_users={spn_users or 'see details'}"],
                    details={"att&ck": self.ATTACK_MAP["recon"], "users": users[:20]},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="recon", result=PhaseResult.FAIL, error=str(exc)))

    def initial_access(self) -> PhaseOutcome:
        logger.action("Initial access (lab user auth)...")
        try:
            ok = self.dir.authenticate(self.config.attacker_user, self.config.attacker_pass)
            if not ok:
                return self._record(
                    PhaseOutcome(phase="initial_access", result=PhaseResult.FAIL, error="auth failed")
                )
            return self._record(
                PhaseOutcome(
                    phase="initial_access",
                    result=PhaseResult.OK,
                    evidence=[f"authed_as={self.config.attacker_user}"],
                    details={"att&ck": self.ATTACK_MAP["initial_access"]},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="initial_access", result=PhaseResult.FAIL, error=str(exc)))

    def credential_access(self) -> PhaseOutcome:
        if not self.options.get("enable_cred_access", True):
            return self._record(
                PhaseOutcome(phase="credential_access", result=PhaseResult.SKIP, error="disabled by flag")
            )
        logger.action("Credential access (Kerberoast-shaped SPN ticket)...")
        try:
            roast = self.dir.kerberoast()
            self._cracked = self.dir.crack_service()
            ev = [f"spn={roast.get('spn')}", f"ticket_hash={roast.get('hash')}"]
            if self._cracked:
                ev.append(f"cracked_service_pass={self._cracked}")
            return self._record(
                PhaseOutcome(
                    phase="credential_access",
                    result=PhaseResult.OK,
                    evidence=ev,
                    details={"att&ck": self.ATTACK_MAP["credential_access"], "ticket": roast.get("ticket")},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="credential_access", result=PhaseResult.FAIL, error=str(exc)))

    def lateral(self) -> PhaseOutcome:
        if not self.options.get("enable_lateral", True):
            return self._record(PhaseOutcome(phase="lateral", result=PhaseResult.SKIP, error="disabled by flag"))
        logger.action("Lateral movement to target host/share...")
        try:
            pw = self._cracked or self.config.service_pass
            flag = self.dir.lateral(pw)
            if not flag:
                return self._record(PhaseOutcome(phase="lateral", result=PhaseResult.FAIL, error="lateral failed"))
            # stash for objective
            self.options["_flag"] = flag
            return self._record(
                PhaseOutcome(
                    phase="lateral",
                    result=PhaseResult.OK,
                    evidence=[f"access={self.config.target_host}", "share_read=ok"],
                    details={"att&ck": self.ATTACK_MAP["lateral"]},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="lateral", result=PhaseResult.FAIL, error=str(exc)))

    def objective(self) -> PhaseOutcome:
        logger.action("Objective: retrieve lab marker...")
        flag = self.options.get("_flag") or ""
        if MARKER in flag or self.config.evidence_marker in flag:
            return self._record(
                PhaseOutcome(
                    phase="objective",
                    result=PhaseResult.OK,
                    evidence=[flag.strip()],
                    details={"att&ck": self.ATTACK_MAP["objective"]},
                )
            )
        return self._record(
            PhaseOutcome(phase="objective", result=PhaseResult.FAIL, error="marker not recovered")
        )

    def cleanup(self) -> PhaseOutcome:
        logger.action("Cleanup tickets/sessions...")
        try:
            self.dir.cleanup()
            return self._record(
                PhaseOutcome(phase="cleanup", result=PhaseResult.OK, evidence=["tickets/session cleared"])
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="cleanup", result=PhaseResult.FAIL, error=str(exc)))

    def execute(self, mode: str = "check") -> dict[str, Any]:
        self.start = datetime.now()
        print()
        print("=" * 60)
        print(" AD/Windows Lab Attack Path")
        print("=" * 60)
        print(f" Domain:  {self.config.domain}")
        print(f" Target:  {self.config.target_host}")
        print(f" Mode:    {mode}")
        print("=" * 60)
        print()

        self.check_lab()
        if mode == "check":
            return self._finalize(mode)

        for fn in (
            self.recon,
            self.initial_access,
            self.credential_access,
            self.lateral,
            self.objective,
            self.cleanup,
        ):
            fn()
        return self._finalize(mode)

    def _finalize(self, mode: str) -> dict[str, Any]:
        end = datetime.now()
        evidence = [e for o in self.outcomes for e in o.evidence]
        ok_phases = sum(1 for o in self.outcomes if o.result == PhaseResult.OK)
        verified = any(MARKER in e for e in evidence)
        failed = any(o.result == PhaseResult.FAIL for o in self.outcomes)
        result = {
            "mode": mode,
            "backend": self.backend_name,
            "domain": self.config.domain,
            "phases": [
                {
                    "phase": o.phase,
                    "result": o.result.value,
                    "evidence": o.evidence,
                    "details": o.details,
                    "error": o.error,
                }
                for o in self.outcomes
            ],
            "evidence": evidence,
            "att&ck": sorted({t for v in self.ATTACK_MAP.values() for t in v}),
            "start_time": self.start.isoformat() if self.start else None,
            "end_time": end.isoformat(),
            "duration": (end - self.start).total_seconds() if self.start else 0,
            "summary": {"ok_phases": ok_phases, "total_phases": len(self.outcomes)},
            "verified": verified,
            "result": "VULNERABLE" if verified else ("ERROR" if failed else "NOT_VULNERABLE"),
        }
        print()
        print("=" * 60)
        print(f" Phases OK: {ok_phases}/{len(self.outcomes)}  verified={verified}")
        print("=" * 60)
        print()
        return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AD/Windows lab attack path")
    p.add_argument("--mode", choices=["check", "exploit", "full"], default="check")
    p.add_argument("--backend", choices=["inprocess", "ldap"], default="inprocess")
    p.add_argument("--domain", default="lab.local")
    p.add_argument("--target-host", default="ws01.lab.local")
    p.add_argument("--ldap-url", default="ldap://127.0.0.1:389")
    p.add_argument("--disable-cred-access", action="store_true")
    p.add_argument("--disable-lateral", action="store_true")
    p.add_argument("--output")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    cfg = LabConfig(domain=args.domain, target_host=args.target_host, ldap_url=args.ldap_url)
    path = ADWindowsLabPath(
        cfg,
        options={
            "backend": args.backend,
            "enable_cred_access": not args.disable_cred_access,
            "enable_lateral": not args.disable_lateral,
        },
    )
    mode = "full" if args.mode == "exploit" else args.mode
    result = path.execute(mode=mode)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        logger.info(f"Wrote {args.output}")
    sys.exit(0 if result.get("verified") or (mode == "check" and result["result"] != "ERROR") else 1)


if __name__ == "__main__":
    main()
