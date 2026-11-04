"""Phase 30: conservative, offline security release policy.

The policy reads operator-supplied CI results; it cannot independently
attest GitHub or approve a deploy. Only a review candidate is produced.
"""
import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

REQUIRED = (
    "python_tests", "sqlite_migration", "postgres_constraints",
    "postgres_restricted_rls", "case_concurrency", "fault_rollback",
    "revision_concurrency",
)
CI_WORKFLOW_STEPS = (
    "Run python -m pytest -q",
    "Check clean migration on SQLite",
    "Verify migration on PostgreSQL with real constraints",
    "Verify PostgreSQL row-level security with restricted database role",
    "Verify concurrent PostgreSQL CEIR case writers",
    "Fault-injection rollback and competing appeals in PostgreSQL",
    "Verify concurrent sandbox status revisions and event rollback",
)


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    key: str
    status: Literal["success", "failure", "skipped", "pending"]
    evidence_reference: str = Field(min_length=6, max_length=250, pattern=r"^[A-Za-z0-9_.:/#-]+$")


class ReleaseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: Literal["said.mock.release-evidence.v1"]
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    ci_run_reference: str = Field(min_length=6, max_length=250,
                                  pattern=r"^https://github[.]com/[^ /]+/[^ /]+/actions/runs/[0-9]+$")
    checks: list[Check] = Field(min_length=1, max_length=30)
    signer_is_separate_from_application: bool
    immutable_backup_independently_verified: bool
    key_custody_independently_verified: bool
    external_authorization_granted: bool

    @model_validator(mode="after")
    def unique_checks(self):
        names = [c.key for c in self.checks]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate check evidence names")
        return self


def inspect_workflow(workflow_text: str) -> dict:
    """Conservative CI workflow structure guard; not proof CI has run."""
    missing = [s for s in CI_WORKFLOW_STEPS if s not in workflow_text]
    if "pull_request:" not in workflow_text or "contents: read" not in workflow_text:
        missing.append("expected_workflow_trigger_or_permissions")
    return {"passed": not missing, "missing": missing,
            "static_check_only": True, "run_executed": False}


def assess_release(raw: dict) -> dict:
    """Fail closed on missing/failed evidence and always require human approval."""
    evidence = ReleaseEvidence.model_validate(raw)
    by_name = {c.key: c for c in evidence.checks}
    missing = [name for name in REQUIRED if name not in by_name]
    failed = [name for name in REQUIRED if name in by_name and
              by_name[name].status != "success"]
    unknown = sorted(set(by_name) - set(REQUIRED))
    if unknown:
        raise ValueError("Unexpected release evidence check keys")
    issues = (["missing_" + x for x in missing] +
              ["not_successful_" + x for x in failed])
    for name, ok in (
        ("audit_authority_not_isolated", evidence.signer_is_separate_from_application),
        ("immutable_backup_unverified", evidence.immutable_backup_independently_verified),
        ("key_custody_unverified", evidence.key_custody_independently_verified),
        ("external_authorization_missing", evidence.external_authorization_granted),
    ):
        if not ok:
            issues.append(name)
    # Reported values can be forged: no stage or production approval is inferred.
    output = {
        "schema": "said.mock.release-gate-report.v1",
        "commit_sha": evidence.commit_sha,
        "reported_checks_complete": not (missing or failed),
        "reported_prerequisites_complete": not issues,
        "issues": issues,
        "review_candidate": not issues,
        "ci_result_cryptographically_verified": False,
        "operator_attestations_independently_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
        "simulated": True,
    }
    canonical = json.dumps(output, sort_keys=True, separators=(",", ":")).encode("utf-8")
    output["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return output


def main():
    parser = argparse.ArgumentParser(description="Offline SAID mock security release gate")
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    workflow = inspect_workflow(args.workflow.read_text(encoding="utf-8"))
    if args.evidence is None:
        print(json.dumps({"workflow_policy": workflow,
                          "live_release_evidence_checked": False}, sort_keys=True))
        raise SystemExit(0 if workflow["passed"] else 2)
    evaluated = assess_release(json.loads(args.evidence.read_text(encoding="utf-8")))
    print(json.dumps({"workflow_policy": workflow, "release_evidence": evaluated},
                     sort_keys=True))
    raise SystemExit(0 if workflow["passed"] and evaluated["review_candidate"] else 2)


if __name__ == "__main__":
    main()
