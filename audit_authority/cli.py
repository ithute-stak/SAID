"""Offline command line interface, run by the *separate audit authority user*.

Example: python -m audit_authority.cli issue --store /srv/audit/receipts.db
  --key-file /srv/audit/signing.pem --key-id independent-2026
  --manifest /srv/audit/input.json

Passphrase is only read from AUDIT_AUTHORITY_PASSPHRASE environment, never argv.
"""
import argparse
import json
import os
from pathlib import Path

from .authority import issue, get_receipt, load_encrypted_signer, open_store, reconcile
from .recovery import backup_store, verify_backup, restore_backup, inspect_store
from .drill import recovery_drill
from .key_policy import validate_registry
from .operations import health_report, check_inventory, record_drill

def run():
    parser = argparse.ArgumentParser(description="SAID mock independent audit authority (offline only)")
    parser.add_argument("action", choices=["issue", "get", "reconcile", "inspect", "backup", "verify-backup", "restore", "drill", "validate-key-registry", "health", "inventory", "drill-report"])
    parser.add_argument("--store", required=True)
    parser.add_argument("--key-file")
    parser.add_argument("--key-id")
    parser.add_argument("--manifest")
    parser.add_argument("--checkpoint-id")
    parser.add_argument("--backup-path")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--drill-directory")
    parser.add_argument("--registry")
    parser.add_argument("--inventory")
    parser.add_argument("--inventory-directory")
    parser.add_argument("--report-path")
    args = parser.parse_args()
    if args.action == "health":
        result = health_report(args.store)
        print(json.dumps(result, sort_keys=True))
        if not result["healthy"]:
            raise SystemExit(2)
        return
    if args.action == "inventory":
        if not args.inventory or not args.inventory_directory:
            parser.error("inventory requires --inventory and --inventory-directory")
        content = json.loads(Path(args.inventory).read_text())
        result = check_inventory(args.inventory_directory, content)
        print(json.dumps(result, sort_keys=True))
        if not result["healthy"]:
            raise SystemExit(2)
        return
    if args.action == "drill-report":
        if not args.drill_directory or not args.report_path:
            parser.error("drill-report requires --drill-directory and --report-path")
        result = record_drill(args.store, args.drill_directory, args.report_path)
        print(json.dumps(result, sort_keys=True))
        if result["outcome"] != "success":
            raise SystemExit(2)
        return
    if args.action == "drill":
        if not args.drill_directory:
            parser.error("drill requires --drill-directory")
        print(json.dumps(recovery_drill(args.store, args.drill_directory), sort_keys=True))
        return
    if args.action == "validate-key-registry":
        if not args.registry:
            parser.error("validate-key-registry requires --registry")
        print(json.dumps(validate_registry(json.loads(Path(args.registry).read_text())), sort_keys=True))
        return
    if args.action in {"backup", "verify-backup", "restore"}:
        if not args.backup_path:
            parser.error("backup and restore operations require --backup-path")
        if args.action == "backup":
            result = backup_store(args.store, args.backup_path)
        elif args.action == "verify-backup":
            if not args.expected_sha256:
                parser.error("verify-backup requires --expected-sha256")
            result = verify_backup(args.backup_path, args.expected_sha256)
        else:
            if not args.expected_sha256:
                parser.error("restore requires --expected-sha256")
            result = restore_backup(args.backup_path, args.store, args.expected_sha256)
        print(json.dumps(result, sort_keys=True))
        return
    db = open_store(args.store)
    try:
        if args.action == "inspect":
            result = inspect_store(db)
        elif args.action == "issue":
            if not args.key_file or not args.key_id or not args.manifest:
                parser.error("issue requires --key-file, --key-id and --manifest")
            signer = load_encrypted_signer(args.key_file, os.getenv("AUDIT_AUTHORITY_PASSPHRASE", ""))
            input_document = json.loads(Path(args.manifest).read_text())
            manifest = input_document.get("manifest", input_document)
            result = issue(db, manifest, args.key_id, signer)
        elif args.action == "get":
            if not args.checkpoint_id:
                parser.error("get requires --checkpoint-id")
            result = get_receipt(db, args.checkpoint_id)
        else:
            if not args.manifest:
                parser.error("reconcile requires --manifest")
            documents = json.loads(Path(args.manifest).read_text())
            result = reconcile(db, documents)
        print(json.dumps(result, sort_keys=True))
    finally:
        db.close()

if __name__ == "__main__":
    run()
