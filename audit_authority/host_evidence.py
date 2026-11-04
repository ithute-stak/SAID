"""Phase 25 offline evidence evaluation, not remote host attestation.

Inputs are obtained by an operator on the separately administered audit host.
Never executes shell commands or trusts self-reported evidence as certification.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .readiness import HARDENING


class HostSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema: Literal["said.mock.host-snapshot.v1"]
    hostname_reference: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    collected_at: datetime
    collected_by: str = Field(min_length=3, max_length=120)
    unit_properties: dict[str, str]
    service_account: str
    source_database_owner: str
    signing_key_owner: str
    audit_reviewer: str
    operator_account: str
    root_filesystem_readonly: bool
    independent_host_declared: bool
    immutable_offsite_backup_verified: bool
    hsm_or_kms_verified: bool


def evaluate_host_snapshot(raw: dict) -> dict:
    """Review a supplied host snapshot and strictly reject unknown input fields."""
    data = HostSnapshot.model_validate(raw)
    issues = []
    age = (datetime.now(timezone.utc) - data.collected_at).total_seconds()
    if data.collected_at.tzinfo is None or age < -300 or age > 86400:
        issues.append("snapshot_not_current")
    for key, expected in HARDENING.items():
        if data.unit_properties.get(key, "").lower() != expected.lower():
            issues.append("effective_" + key)
    if data.unit_properties.get("RestrictAddressFamilies") != "AF_UNIX":
        issues.append("unexpected_address_family")
    if data.unit_properties.get("ReadWritePaths") != "/var/lib/said-audit/drills":
        issues.append("unexpected_writable_paths")
    if data.unit_properties.get("ReadOnlyPaths") != "/var/lib/said-audit/receipts.db":
        issues.append("unexpected_readonly_paths")
    if not data.root_filesystem_readonly:
        issues.append("root_filesystem_not_readonly")
    if not data.independent_host_declared:
        issues.append("host_not_independently_declared")
    identifiers = [data.service_account, data.source_database_owner,
                   data.signing_key_owner, data.audit_reviewer,
                   data.operator_account]
    if len(set(identifiers)) != len(identifiers):
        issues.append("duties_not_separated")
    if data.service_account != "said-audit":
        issues.append("unexpected_service_account")
    if not data.immutable_offsite_backup_verified:
        issues.append("offsite_backup_unverified")
    if not data.hsm_or_kms_verified:
        issues.append("signing_key_custody_unverified")
    return {"passed": not issues, "issues": issues,
            "self_reported": True, "host_attested": False,
            "production_approval_granted": False, "simulated": True}


def evidence_digest(snapshot: dict, evaluation: dict) -> dict:
    """Stable operator-exportable evidence digest; never sign or claim notarization."""
    document = {
        "schema": "said.mock.host-evidence.v1",
        "snapshot": HostSnapshot.model_validate(snapshot).model_dump(mode="json"),
        "evaluation": evaluation,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("ascii")
    return {"evidence": document, "sha256": hashlib.sha256(canonical).hexdigest(),
            "signed": False, "externally_anchored": False,
            "operator_data_unverified": True, "simulated": True}
