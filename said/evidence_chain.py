"""Phase 37 — Verify self-contained release report digests and their ordered chain.

This provides *integrity consistency*, not authenticity. A malicious party
can replace every report and recompute all hashes unless a trusted third
party signs or independently anchors the root hash. No deployment actions.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

ORDER = ("ci", "pr", "ruleset", "team", "staging")
DIGEST_FIELD = {"ci": "report_sha256", "pr": "report_sha256",
                "ruleset": "sha256", "team": "sha256", "staging": "sha256"}
# These are the actual schema labels emitted by the corresponding modules.
SCHEMA = {
    "ci": "said.mock.github-run-verification.v1",
    "pr": "said.mock.github-independent-review.v1",
    "ruleset": "said.mock.ruleset-bypass-assessment.v1",
    "team": "said.mock.github-team-reviewer-check.v1",
    "staging": "said.mock.staging-readiness-report.v1",
}
PASS_FIELD = {
    "ci": "checks_verified", "pr": "github_review_checks_passed",
    "ruleset": "github_ruleset_checks_passed",
    "team": "github_team_membership_checks_passed",
    "staging": "dossier_consistent",
}
ZERO = "0" * 64


def canonical(value: object) -> bytes:
    """Use exactly the JSON serialization used by existing SAID reports."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def checksum(report: dict, kind: str) -> str:
    """Verify a report's original checksum without hashing its own checksum."""
    body = dict(report)
    body.pop(DIGEST_FIELD[kind], None)
    return hashlib.sha256(canonical(body)).hexdigest()


def link_hash(kind: str, report_digest: str, parent: str) -> str:
    """Domain-separated chain node; type/order substitution is detectable."""
    return hashlib.sha256(canonical({
        "domain": "said.mock.release-chain.v1",
        "type": kind, "digest": report_digest, "parent": parent,
    })).hexdigest()


class ChainEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: str
    report: dict
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    chain_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChainEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: str = Field(pattern=r"^said[.]mock[.]release-chain[.]v1$")
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    entries: list[ChainEntry] = Field(min_length=5, max_length=5)
    root_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def strict_order(self):
        if tuple(e.kind for e in self.entries) != ORDER:
            raise ValueError("Release evidence must contain the five types in canonical order")
        return self


def build_chain(commit_sha: str, reports: dict) -> dict:
    """Construct an *untrusted* candidate envelope from existing reports."""
    if not isinstance(commit_sha, str) or len(commit_sha) != 40 or any(
        c not in "0123456789abcdef" for c in commit_sha
    ):
        raise ValueError("Expected lowercase 40-character commit SHA")
    if set(reports) != set(ORDER):
        raise ValueError("Five canonical report types required")
    entries = []
    previous = ZERO
    for kind in ORDER:
        report = reports[kind]
        if not isinstance(report, dict):
            raise ValueError("Report must be a JSON object")
        field = DIGEST_FIELD[kind]
        digest = report.get(field)
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("Report is missing its producer checksum")
        value = link_hash(kind, digest, previous)
        entries.append({"kind": kind, "report": report, "report_digest": digest,
                        "previous_digest": previous, "chain_digest": value})
        previous = value
    return {"schema": "said.mock.release-chain.v1", "commit_sha": commit_sha,
            "entries": entries, "root_digest": previous}


def verify_chain(raw: dict) -> dict:
    """Fail closed on replacement, reordering, tampering and conflicting claims."""
    envelope = ChainEnvelope.model_validate(raw)
    issues = []
    prev = ZERO
    for item in envelope.entries:
        kind = item.kind
        report = item.report
        embedded = report.get(DIGEST_FIELD[kind])
        if report.get("schema") != SCHEMA[kind]:
            issues.append(kind + "_wrong_schema")
        if report.get("commit_sha") != envelope.commit_sha:
            issues.append(kind + "_commit_mismatch")
        if report.get(PASS_FIELD[kind]) is not True:
            issues.append(kind + "_not_successful")
        if report.get("issues"):
            issues.append(kind + "_reported_issues")
        for auth in ("staging_deploy_authorized", "production_deploy_authorized",
                     "telecom_operations_enabled"):
            if auth in report and report[auth] is not False:
                issues.append(kind + "_unexpected_" + auth)
        if not isinstance(embedded, str) or not hmac.compare_digest(
            embedded, item.report_digest
        ):
            issues.append(kind + "_envelope_report_digest_mismatch")
        expected_digest = checksum(report, kind)
        if not hmac.compare_digest(expected_digest, item.report_digest):
            issues.append(kind + "_report_tampered")
        if not hmac.compare_digest(item.previous_digest, prev):
            issues.append(kind + "_previous_digest_mismatch")
        next_digest = link_hash(kind, item.report_digest, prev)
        if not hmac.compare_digest(item.chain_digest, next_digest):
            issues.append(kind + "_chain_digest_mismatch")
        prev = next_digest
    if not hmac.compare_digest(envelope.root_digest, prev):
        issues.append("root_digest_mismatch")
    # Report content in the self-contained chain is NOT an independent witness.
    return {
        "schema": "said.mock.release-chain-assessment.v1",
        "commit_sha": envelope.commit_sha,
        "integrity_consistent": not issues,
        "issues": sorted(set(issues)),
        "root_digest": envelope.root_digest,
        "external_anchor_verified": False,
        "cryptographic_signature_verified": False,
        "report_origin_independently_authenticated": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }


def main():
    parser = argparse.ArgumentParser(description="SAID offline evidence digest chain")
    parser.add_argument("--chain", required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.chain.read_text(encoding="utf-8"))
        result = verify_chain(payload)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        print(json.dumps({"integrity_consistent": False,
                          "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["integrity_consistent"] else 2)


if __name__ == "__main__":
    main()
