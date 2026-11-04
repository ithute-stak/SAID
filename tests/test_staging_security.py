"""Phase 38 offline staging security gate negative and boundary tests."""
import copy
import pytest
from pydantic import ValidationError

from said.staging_security import REQUIRED_CONTROLS, assess_staging_security


def valid_snapshot():
    return {
        "schema": "said.mock.staging-security-input.v1",
        "commit_sha": "a" * 40,
        "evidence_chain_root": "b" * 64,
        "evidence_chain_integrity_consistent": True,
        "staging_host_reference": "said-staging-sandbox-01",
        "controls": [
            {"name": name, "state": "verified",
             "evidence_reference": "staging/check/" + name}
            for name in REQUIRED_CONTROLS
        ],
    }


def test_all_declared_controls_only_produce_non_authorizing_candidate():
    report = assess_staging_security(valid_snapshot())
    assert report["declared_controls_complete"]
    assert not report["issues"]
    assert not report["staging_deploy_authorized"]
    assert not report["production_deploy_authorized"]
    assert not report["telecom_operations_enabled"]
    assert not report["host_configuration_remotely_measured"]
    assert not report["control_evidence_independently_authenticated"]
    assert not report["trusted_release_chain_anchor_verified"]
    assert len(report["sha256"]) == 64
    assert report == assess_staging_security(valid_snapshot())


@pytest.mark.parametrize("missing", REQUIRED_CONTROLS)
def test_each_missing_control_fails_closed(missing):
    value = valid_snapshot()
    value["controls"] = [x for x in value["controls"] if x["name"] != missing]
    result = assess_staging_security(value)
    assert not result["declared_controls_complete"]
    assert "missing_" + missing in result["issues"]


@pytest.mark.parametrize("state", ["failed", "not_checked"])
def test_non_verified_controls_fail_closed(state):
    value = valid_snapshot()
    value["controls"][0]["state"] = state
    result = assess_staging_security(value)
    assert not result["declared_controls_complete"]
    assert "not_verified_environment_isolation" in result["issues"]


def test_duplicate_or_unknown_controls_are_rejected():
    value = valid_snapshot()
    value["controls"].append(copy.deepcopy(value["controls"][0]))
    assert "duplicate_environment_isolation" in assess_staging_security(value)["issues"]
    value = valid_snapshot()
    value["controls"].append({"name": "unexpected_override", "state": "verified",
                              "evidence_reference": "staging/unauthorized-override"})
    assert "unexpected_unexpected_override" in assess_staging_security(value)["issues"]


def test_release_chain_flag_missing_or_false_fails_closed():
    value = valid_snapshot()
    value["evidence_chain_integrity_consistent"] = False
    assert "release_chain_integrity_not_confirmed" in assess_staging_security(value)["issues"]
    value = valid_snapshot()
    value.pop("evidence_chain_root")
    with pytest.raises(ValidationError):
        assess_staging_security(value)


def test_synthetic_invalid_commit_and_forged_deploy_approval_rejected():
    value = valid_snapshot()
    value["commit_sha"] = "bad"
    with pytest.raises(ValidationError):
        assess_staging_security(value)
    value = valid_snapshot()
    value["staging_deploy_authorized"] = True
    with pytest.raises(ValidationError):
        assess_staging_security(value)


def test_invalid_evidence_references_rejected():
    value = valid_snapshot()
    value["controls"][0]["evidence_reference"] = "../../rm -rf /"
    with pytest.raises(ValidationError):
        assess_staging_security(value)
