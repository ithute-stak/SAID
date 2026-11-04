"""Phase 23 offline operational monitoring is fail-closed and non-networked."""
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_authority.authority import issue, open_store
from audit_authority.operations import health_report, check_inventory, record_drill
from audit_authority.recovery import backup_store

MANIFEST = {
    "schema": "said.mock.audit-checkpoint.v1",
    "checkpoint_id": "a9999999-9999-4999-8999-999999999999",
    "investigation_id": "b8888888-8888-4888-8888-888888888888",
    "sequence": 1, "head_digest": "f" * 64,
    "checkpoint_digest": "e" * 64, "reason_reference": "phase23_monitor",
}

def setup(tmp_path):
    source = tmp_path / "authority.db"
    db = open_store(str(source))
    try:
        issue(db, MANIFEST, "ops-key-01", Ed25519PrivateKey.generate())
    finally:
        db.close()
    inventory = tmp_path / "inventory"
    inventory.mkdir(mode=0o700)
    drill = tmp_path / "drill"
    drill.mkdir(mode=0o700)
    reports = tmp_path / "reports"
    reports.mkdir(mode=0o700)
    return source, inventory, drill, reports

def test_health_and_missing_store_fail_closed(tmp_path):
    source, inventory, drill, reports = setup(tmp_path)
    good = health_report(str(source))
    assert good["healthy"] is True
    assert good["details"]["receipts_checked"] == 1
    assert good["network_alert_sent"] is False
    missing = health_report(str(tmp_path / "missing.db"))
    assert missing["healthy"] is False
    assert missing["severity"] == "critical"
    assert not (tmp_path / "missing.db").exists()
    alias = tmp_path / "alias.db"
    alias.symlink_to(source)
    assert health_report(str(alias))["healthy"] is False

def test_backup_inventory_mismatch_and_duplicate_filenames(tmp_path):
    source, inventory, drill, reports = setup(tmp_path)
    copy = inventory / "snapshot.db"
    made = backup_store(str(source), str(copy))
    catalog = {"version": "said.mock.backup-inventory.v1", "entries": [
        {"filename": "snapshot.db", "sha256": made["backup_sha256"]}]}
    good = check_inventory(str(inventory), catalog)
    assert good["healthy"] is True
    assert good["results"][0]["receipts_checked"] == 1
    assert good["catalog_authenticated"] is False
    bad = check_inventory(str(inventory), {**catalog, "entries": [
        {"filename": "snapshot.db", "sha256": "0"*64}]})
    assert bad["healthy"] is False
    assert bad["results"][0]["status"] == "invalid_or_mismatch"
    missing = check_inventory(str(inventory), {**catalog, "entries": [
        {"filename": "not-here.db", "sha256": made["backup_sha256"]}]})
    assert missing["results"][0]["status"] == "missing"
    with pytest.raises(ValueError, match="Duplicate"):
        check_inventory(str(inventory), {**catalog, "entries": catalog["entries"] * 2})
    with pytest.raises(Exception):
        check_inventory(str(inventory), {**catalog, "entries": [
            {"filename": "../escape", "sha256": made["backup_sha256"]}]})

def test_offline_drill_report_success_failure_and_sanitization(tmp_path):
    source, inventory, drill, reports = setup(tmp_path)
    report = reports / "drill-events.jsonl"
    original = source.read_bytes()
    good = record_drill(str(source), str(drill), str(report))
    assert good["outcome"] == "success"
    assert good["external_alert_sent"] is False
    assert good["report_signed"] is False
    assert source.read_bytes() == original
    assert list(drill.iterdir()) == []
    bad = record_drill(str(tmp_path / "missing.db"), str(drill), str(report))
    assert bad["outcome"] == "failure"
    assert bad["error_type"] in {"ValueError", "FileNotFoundError"}
    records = [json.loads(line) for line in report.read_text().splitlines()]
    assert [r["outcome"] for r in records] == ["success", "failure"]
    assert str(tmp_path) not in report.read_text()
    with pytest.raises(ValueError, match="unsafe"):
        record_drill(str(source), str(drill), str(source))
    symlink = reports / "report-link.jsonl"
    symlink.symlink_to(report)
    with pytest.raises(ValueError, match="unsafe"):
        record_drill(str(source), str(drill), str(symlink))
