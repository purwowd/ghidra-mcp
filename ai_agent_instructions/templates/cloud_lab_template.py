#!/usr/bin/env python3
"""
Cloud Lab Exploitation Template
===============================

Working AWS-shaped lab path (LocalStack or in-process mock).
Never point at production tenants.

Pair with: 14_RED_TEAM_KILLCHAIN.md, pocs/POC-CLOUD-IAM-LAB/

Usage:
    python cloud_lab_template.py --mode full --backend mock
    python cloud_lab_template.py --mode full --backend localstack --endpoint-url http://127.0.0.1:4566

Legal: Authorized lab cloud only. See 02_LEGAL_CONTEXT.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.request import urlopen

import argparse
import json
import logging
import sys


class PhaseResult(str, Enum):
    OK = "OK"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


MARKER = "LAB_CLOUD_TOKEN=srl-cloud-lab-7c2e"
BUCKET = "lab-secrets"
OBJECT_KEY = "flags/cloud.txt"
LOWPRIV_USER = "lowpriv"
ADMIN_POLICY_NAME = "LabAdminEscalation"


@dataclass
class CloudLabConfig:
    provider: str = "aws-localstack"
    endpoint_url: str = "http://127.0.0.1:4566"
    region: str = "us-east-1"
    access_key: str = "test"
    secret_key: str = "test"
    account_id: str = "000000000000"
    lab_metadata_token: str = MARKER


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
    log = logging.getLogger("cloud_lab")
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


class MockCloudBackend:
    """In-process AWS-shaped lab (no Docker required)."""

    def __init__(self, cfg: CloudLabConfig):
        self.cfg = cfg
        self.identity = {
            "UserId": "AIDALabLowPriv",
            "Account": cfg.account_id,
            "Arn": f"arn:aws:iam::{cfg.account_id}:user/{LOWPRIV_USER}",
        }
        self.buckets = {BUCKET: {OBJECT_KEY: MARKER}}
        self.attached_policies: list[str] = []
        self.can_read_secrets = False

    def seed(self) -> None:
        self.buckets[BUCKET][OBJECT_KEY] = MARKER
        self.attached_policies = []
        self.can_read_secrets = False

    def caller_identity(self) -> dict:
        return dict(self.identity)

    def list_buckets(self) -> list[str]:
        return list(self.buckets)

    def attach_admin(self) -> str:
        arn = f"arn:aws:iam::{self.cfg.account_id}:policy/{ADMIN_POLICY_NAME}"
        self.attached_policies.append(arn)
        self.can_read_secrets = True
        self.identity["Arn"] = f"arn:aws:iam::{self.cfg.account_id}:user/{LOWPRIV_USER}-escalated"
        return arn

    def get_secret_object(self) -> str:
        if not self.can_read_secrets:
            raise PermissionError("AccessDenied")
        return self.buckets[BUCKET][OBJECT_KEY]

    def cleanup(self) -> None:
        self.attached_policies.clear()
        self.can_read_secrets = False
        self.identity["Arn"] = f"arn:aws:iam::{self.cfg.account_id}:user/{LOWPRIV_USER}"


class LocalStackBackend:
    def __init__(self, cfg: CloudLabConfig):
        self.cfg = cfg
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 required for localstack backend: pip install boto3") from exc
        kw = {
            "region_name": cfg.region,
            "aws_access_key_id": cfg.access_key,
            "aws_secret_access_key": cfg.secret_key,
            "endpoint_url": cfg.endpoint_url,
        }
        self.sts = boto3.client("sts", **kw)
        self.s3 = boto3.client("s3", **kw)
        self.iam = boto3.client("iam", **kw)
        self._policy_arn: Optional[str] = None

    def seed(self) -> None:
        # Bucket + object
        try:
            self.s3.create_bucket(Bucket=BUCKET)
        except Exception:
            pass
        self.s3.put_object(Bucket=BUCKET, Key=OBJECT_KEY, Body=MARKER.encode())
        # Ensure lowpriv user exists
        try:
            self.iam.create_user(UserName=LOWPRIV_USER)
        except Exception:
            pass
        # Deny-by-default: detach policies if any; reading secrets requires escalation step
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket", "iam:AttachUserPolicy", "iam:CreatePolicy", "iam:GetUser"],
                    "Resource": "*",
                }
            ],
        }
        try:
            resp = self.iam.create_policy(PolicyName=ADMIN_POLICY_NAME, PolicyDocument=json.dumps(doc))
            self._policy_arn = resp["Policy"]["Arn"]
        except Exception:
            # already exists
            self._policy_arn = f"arn:aws:iam::{self.cfg.account_id}:policy/{ADMIN_POLICY_NAME}"
            try:
                paginator = self.iam.get_paginator("list_policies")
                for page in paginator.paginate(Scope="Local"):
                    for pol in page.get("Policies", []):
                        if pol["PolicyName"] == ADMIN_POLICY_NAME:
                            self._policy_arn = pol["Arn"]
            except Exception:
                pass

    def caller_identity(self) -> dict:
        return self.sts.get_caller_identity()

    def list_buckets(self) -> list[str]:
        return [b["Name"] for b in self.s3.list_buckets().get("Buckets", [])]

    def attach_admin(self) -> str:
        arn = self._policy_arn or f"arn:aws:iam::{self.cfg.account_id}:policy/{ADMIN_POLICY_NAME}"
        self.iam.attach_user_policy(UserName=LOWPRIV_USER, PolicyArn=arn)
        return arn

    def get_secret_object(self) -> str:
        obj = self.s3.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        return obj["Body"].read().decode()

    def cleanup(self) -> None:
        arn = self._policy_arn
        if arn:
            try:
                self.iam.detach_user_policy(UserName=LOWPRIV_USER, PolicyArn=arn)
            except Exception:
                pass


def endpoint_up(url: str, timeout: float = 2.0) -> bool:
    try:
        urlopen(url, timeout=timeout)
        return True
    except Exception:
        # LocalStack may reset on GET /
        try:
            urlopen(url.rstrip("/") + "/_localstack/health", timeout=timeout)
            return True
        except Exception:
            return False


def build_backend(cfg: CloudLabConfig, backend: str) -> tuple[Any, str]:
    if backend == "mock":
        b = MockCloudBackend(cfg)
        b.seed()
        return b, "mock"
    if backend == "localstack":
        b = LocalStackBackend(cfg)
        b.seed()
        return b, "localstack"
    # auto
    if endpoint_up(cfg.endpoint_url):
        try:
            b = LocalStackBackend(cfg)
            b.seed()
            return b, "localstack"
        except Exception as exc:
            logger.warning("LocalStack unreachable/unusable (%s); using mock", exc)
    b = MockCloudBackend(cfg)
    b.seed()
    return b, "mock"


class CloudLabPath:
    ATTACK_MAP = {
        "enum": ["T1580", "T1526"],
        "privesc": ["T1078.004", "T1098"],
        "data_access": ["T1530"],
    }

    def __init__(self, config: CloudLabConfig, options: dict | None = None):
        self.config = config
        self.options = options or {}
        self.outcomes: list[PhaseOutcome] = []
        self.start: Optional[datetime] = None
        self.backend_name = "mock"
        self.backend: Any = None

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

    def check(self) -> PhaseOutcome:
        logger.action("Checking cloud lab backend...")
        try:
            self.backend, self.backend_name = build_backend(
                self.config, self.options.get("backend", "auto")
            )
            return self._record(
                PhaseOutcome(
                    phase="check",
                    result=PhaseResult.OK,
                    evidence=[f"backend={self.backend_name}", f"endpoint={self.config.endpoint_url}"],
                    details={"provider": self.config.provider},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="check", result=PhaseResult.FAIL, error=str(exc)))

    def enum(self) -> PhaseOutcome:
        logger.action("Enumerating identity/resources...")
        try:
            ident = self.backend.caller_identity()
            buckets = self.backend.list_buckets()
            arn = ident.get("Arn") or ident.get("arn") or str(ident)
            return self._record(
                PhaseOutcome(
                    phase="enum",
                    result=PhaseResult.OK,
                    evidence=[f"identity={arn}", f"buckets={buckets}"],
                    details={"att&ck": self.ATTACK_MAP["enum"], "identity": ident},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="enum", result=PhaseResult.FAIL, error=str(exc)))

    def iam_privesc(self) -> PhaseOutcome:
        if not self.options.get("enable_iam_privesc", True):
            return self._record(
                PhaseOutcome(phase="iam_privesc", result=PhaseResult.SKIP, error="disabled by flag")
            )
        logger.action("IAM privilege escalation (attach lab admin policy)...")
        try:
            arn = self.backend.attach_admin()
            return self._record(
                PhaseOutcome(
                    phase="iam_privesc",
                    result=PhaseResult.OK,
                    evidence=[f"attached_policy={arn}"],
                    details={"att&ck": self.ATTACK_MAP["privesc"]},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="iam_privesc", result=PhaseResult.FAIL, error=str(exc)))

    def data_access(self) -> PhaseOutcome:
        if not self.options.get("enable_exfil_marker", True):
            return self._record(
                PhaseOutcome(phase="data_access", result=PhaseResult.SKIP, error="disabled by flag")
            )
        logger.action("Reading lab secret object...")
        try:
            body = self.backend.get_secret_object().strip()
            ok = MARKER in body
            return self._record(
                PhaseOutcome(
                    phase="data_access",
                    result=PhaseResult.OK if ok else PhaseResult.FAIL,
                    evidence=[body] if ok else [],
                    error=None if ok else f"marker missing in: {body[:80]}",
                    details={"att&ck": self.ATTACK_MAP["data_access"], "bucket": BUCKET, "key": OBJECT_KEY},
                )
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="data_access", result=PhaseResult.FAIL, error=str(exc)))

    def cleanup(self) -> PhaseOutcome:
        logger.action("Cleanup lab IAM attachments...")
        try:
            self.backend.cleanup()
            return self._record(
                PhaseOutcome(phase="cleanup", result=PhaseResult.OK, evidence=["iam attachments cleared"])
            )
        except Exception as exc:
            return self._record(PhaseOutcome(phase="cleanup", result=PhaseResult.FAIL, error=str(exc)))

    def execute(self, mode: str = "check") -> dict[str, Any]:
        self.start = datetime.now()
        print()
        print("=" * 60)
        print(" Cloud Lab Attack Path")
        print("=" * 60)
        print(f" Provider: {self.config.provider}")
        print(f" Endpoint: {self.config.endpoint_url}")
        print(f" Mode:     {mode}")
        print("=" * 60)
        print()

        self.check()
        if mode == "check":
            return self._finalize(mode)

        for fn in (self.enum, self.iam_privesc, self.data_access, self.cleanup):
            fn()
        return self._finalize(mode)

    def _finalize(self, mode: str) -> dict[str, Any]:
        end = datetime.now()
        evidence = [e for o in self.outcomes for e in o.evidence]
        ok_phases = sum(1 for o in self.outcomes if o.result == PhaseResult.OK)
        failed = any(o.result == PhaseResult.FAIL for o in self.outcomes)
        verified = MARKER in "".join(evidence)
        result = {
            "mode": mode,
            "backend": self.backend_name,
            "provider": self.config.provider,
            "endpoint_url": self.config.endpoint_url,
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
    p = argparse.ArgumentParser(description="Cloud lab attack path (LocalStack or mock)")
    p.add_argument("--mode", choices=["check", "exploit", "full"], default="check")
    p.add_argument("--backend", choices=["auto", "localstack", "mock"], default="auto")
    p.add_argument("--endpoint-url", default="http://127.0.0.1:4566")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--disable-iam-privesc", action="store_true")
    p.add_argument("--disable-exfil-marker", action="store_true")
    p.add_argument("--output")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    cfg = CloudLabConfig(endpoint_url=args.endpoint_url, region=args.region)
    path = CloudLabPath(
        cfg,
        options={
            "backend": args.backend,
            "enable_iam_privesc": not args.disable_iam_privesc,
            "enable_exfil_marker": not args.disable_exfil_marker,
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
