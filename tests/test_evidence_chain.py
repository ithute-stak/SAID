"""Phase 37: synthetic evidence-chain tests; no GitHub credentials or network."""
import copy
import hashlib

import pytest
from pydantic import ValidationError

from said.evidence_chain import (
    ORDER, SCHEMA, DIGEST_FIELD, PASS_FIELD, ZERO,
    build_chain, canonical, verify_chain, checksum, link_hash,
)

SHA = "a" * 40


def reports():
    out = {}
    for kind in ORDER:
        report = {
            "schema": SCHEMA[kind],
            "commit_sha": SHA,
            PASS_FIELD[kind]: True,
            "issues": [],
            "staging_deploy_authorized": False,
            "production_deploy_authorized": False,
            "telecom_operations_enabled": False,
        }
        report[DIGEST_FIELD[kind]] = hashlib.sha256(canonical(report)).hexdigest()
        out[kind] = report
    return out


def envelope():
    return build_chain(SHA, reports())


def test_complete_report_digest_chain_is_consistent_but_not_authorized():
    result = verify_chain(envelope())
    assert result["integrity_consistent"] is True
    assert result["issues"] == []
    assert result["root_digest"] != ZERO
    assert result["external_anchor_verified"] is False
    assert result["cryptographic_signature_verified"] is False
    assert result["report_origin_independently_authenticated"] is False
    assert result["staging_deploy_authorized"] is False
    assert result["production_deploy_authorized"] is False


def test_producer_checksum_matches_existing_report_convention():
    data = reports()
    for kind, report in data.items():
        assert checksum(report, kind) == report[DIGEST_FIELD[kind]]
    raw = envelope()
    assert raw["entries"][0]["chain_digest"] == link_hash(
        "ci", raw["entries"][0]["report_digest"], ZERO)


@pytest.mark.parametrize("kind", ORDER)
def test_any_report_field_tampering_fails_closed(kind):
    raw = envelope()
    report = next(e["report"] for e in raw["entries"] if e["kind"] == kind)
    report["unapproved_field"] = "evil"
    verdict = verify_chain(raw)
    assert not verdict["integrity_consistent"]
    assert kind + "_report_tampered" in verdict["issues"]


@pytest.mark.parametrize("kind", ORDER)
def test_wrong_commit_fails_even_with_original_checksum(kind):
    raw = envelope()
    item = next(e for e in raw["entries"] if e["kind"] == kind)
    item["report"]["commit_sha"] = "b" * 40
    assert kind + "_commit_mismatch" in verify_chain(raw)["issues"]


def test_wrong_chain_parent_fails():
    raw = envelope()
    raw["entries"][2]["previous_digest"] = "1" * 64
    assert "ruleset_previous_digest_mismatch" in verify_chain(raw)["issues"]


def test_wrong_root_fails():
    raw = envelope()
    raw["root_digest"] = "1" * 64
    assert "root_digest_mismatch" in verify_chain(raw)["issues"]


def test_order_must_be_exact():
    raw = envelope()
    raw["entries"][1], raw["entries"][2] = raw["entries"][2], raw["entries"][1]
    with pytest.raises(ValidationError):
        verify_chain(raw)


def test_missing_duplicate_or_extraneous_types_rejected():
    raw = envelope()
    raw["entries"].pop()
    with pytest.raises(ValidationError):
        verify_chain(raw)
    with pytest.raises(ValueError):
        build_chain(SHA, {"ci": reports()["ci"]})


def test_contradictory_release_claim_and_failed_check_fails():
    raw = envelope()
    raw["entries"][0]["report"]["staging_deploy_authorized"] = True
    raw["entries"][1]["report"][PASS_FIELD["pr"]] = False
    result = verify_chain(raw)
    assert not result["integrity_consistent"]
    assert "ci_unexpected_staging_deploy_authorized" in result["issues"]
    assert "pr_not_successful" in result["issues"]


def test_report_digest_substitution_fails():
    raw = envelope()
    raw["entries"][3]["report_digest"] = "f" * 64
    result = verify_chain(raw)
    assert not result["integrity_consistent"]
    assert "team_envelope_report_digest_mismatch" in result["issues"]


def test_self_consistent_forgery_cannot_be_called_authenticated():
    # Hashes do not carry a private key or trusted timestamp. A forged
    # bundle can have a valid chain; the assessor must never claim provenance.
    forged = reports()
    forged["pr"]["fictional_approval"] = True
    forged["pr"][DIGEST_FIELD["pr"]] = checksum(forged["pr"], "pr")
    result = verify_chain(build_chain(SHA, forged))
    assert result["integrity_consistent"]
    assert result["external_anchor_verified"] is False
    assert result["report_origin_independently_authenticated"] is False
    assert result["staging_deploy_authorized"] is False
