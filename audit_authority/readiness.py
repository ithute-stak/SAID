"""Offline, non-mutating readiness checks for the separate mock audit authority.

Policy checks are conservative and intentionally do NOT certify a live host.
A real security reviewer must inspect systemd effective properties, firewall,
ACLs, OS patching, key custody and off-host immutable backups independently.
"""
import configparser
import json
import re
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .operations import health_report

HARDENING = {
    "NoNewPrivileges": "true",
    "PrivateTmp": "true",
    "ProtectSystem": "strict",
    "ProtectHome": "true",
    "PrivateDevices": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectControlGroups": "true",
    "IPAddressDeny": "any",
    "RestrictSUIDSGID": "true",
    "LockPersonality": "true",
    "MemoryDenyWriteExecute": "true",
    "UMask": "0077",
    "Type": "oneshot",
    "User": "said-audit",
    "Group": "said-audit",
}
FORBIDDEN = ("curl", "wget", "ssh", "scp", "nc", "netcat", "bash", "sh", "sudo")


def check_unit(source: str) -> dict:
    """Static validation of *one* unit file. Does not execute it."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        text = Path(source).read_text(encoding="utf-8")
        parser.read_string(text)
    except (OSError, UnicodeError, configparser.Error) as exc:
        return {"passed": False, "issues": ["unit_unreadable_or_invalid"],
                "static_only": True, "simulated": True}
    if not parser.has_section("Service"):
        return {"passed": False, "issues": ["missing_service_section"],
                "static_only": True, "simulated": True}
    values = parser["Service"]
    issues = [
        "unexpected_" + key for key, expected in HARDENING.items()
        if values.get(key, "").strip().lower() != expected.lower()
    ]
    argv = values.get("ExecStart", "")
    try:
        tokens = shlex.split(argv)
    except ValueError:
        tokens = []
    if (len(tokens) < 5 or not tokens[0].startswith("/opt/said-audit/") or
        tokens[1:4] != ["-m", "audit_authority.cli", "drill"] or
        any(token in FORBIDDEN for token in tokens)):
        issues.append("unsafe_execstart")
    if values.get("RestrictAddressFamilies", "").strip() != "AF_UNIX":
        issues.append("address_family_not_isolated")
    if "/var/lib/said-audit/drills" not in values.get("ReadWritePaths", "").split():
        issues.append("missing_drill_write_scope")
    writable = values.get("ReadWritePaths", "").split()
    if any(p != "/var/lib/said-audit/drills" for p in writable):
        issues.append("unexpected_writable_path")
    if "/var/lib/said-audit/receipts.db" not in values.get("ReadOnlyPaths", "").split():
        issues.append("missing_readonly_source")
    if "Environment" in values or "EnvironmentFile" in values or "PassEnvironment" in values:
        issues.append("environment_secrets_not_allowed")
    for key in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload"):
        if key in values:
            issues.append("unreviewed_" + key.lower())
    return {"passed": not issues, "issues": issues, "static_only": True,
            "live_host_verified": False, "simulated": True}


class Objective(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recovery_time_objective_minutes: int = Field(ge=1, le=10080)
    recovery_point_objective_minutes: int = Field(ge=0, le=10080)
    observed_recovery_duration_seconds: int = Field(ge=0, le=2592000)
    observed_backup_age_seconds: int = Field(ge=0, le=2592000)
    recovery_test_passed: bool
    backup_integrity_passed: bool


def assess_objectives(raw: dict) -> dict:
    """Compare operator-entered measurements, never invent measured times."""
    item = Objective.model_validate(raw)
    recovery_met = item.observed_recovery_duration_seconds <= item.recovery_time_objective_minutes * 60
    point_met = item.observed_backup_age_seconds <= item.recovery_point_objective_minutes * 60
    passed = recovery_met and point_met and item.recovery_test_passed and item.backup_integrity_passed
    return {"passed": passed, "rto_met": recovery_met, "rpo_met": point_met,
            "recovery_test_passed": item.recovery_test_passed,
            "backup_integrity_passed": item.backup_integrity_passed,
            "measurements_operator_supplied": True,
            "external_backup_proven": False, "simulated": True}


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["receipt_store_corruption", "backup_missing",
                      "signing_key_suspected_compromise", "unauthorized_change"]
    evidence_preserved: bool
    signing_suspended: bool
    independent_reviewer_assigned: bool
    escalation_reference: str = Field(min_length=3, max_length=120,
                                      pattern=r"^[A-Za-z0-9_-]+$")


def assess_incident(raw: dict) -> dict:
    """Read-only exercise. Cannot suspend an actual signing process."""
    incident = Incident.model_validate(raw)
    passed = all([incident.evidence_preserved, incident.signing_suspended,
                  incident.independent_reviewer_assigned])
    return {"passed": passed, "scenario": incident.scenario,
            "required_actions": [
                "preserve_evidence", "suspend_signing_independently",
                "assign_independent_responder", "document_escalation"
            ], "escalation_reference": incident.escalation_reference,
            "actions_executed": False, "external_alert_sent": False,
            "simulated": True}


def readiness_report(unit_file: str, db_file: str, objectives: dict,
                     incident: dict) -> dict:
    """Fail closed if any criterion fails. No deploy or signing is performed."""
    unit = check_unit(unit_file)
    health = health_report(db_file)
    recovery = assess_objectives(objectives)
    exercise = assess_incident(incident)
    return {"passed": unit["passed"] and health["healthy"] and
            recovery["passed"] and exercise["passed"],
            "deployment_unit": unit, "audit_health": health,
            "recovery_objectives": recovery, "incident_exercise": exercise,
            "production_approval_granted": False, "external_audit_verified": False,
            "simulated": True}
