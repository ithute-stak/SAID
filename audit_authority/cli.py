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

def run():
    parser = argparse.ArgumentParser(description="SAID mock independent audit authority (offline only)")
    parser.add_argument("action", choices=["issue", "get", "reconcile", "inspect", "backup", "verify-backup", "restore"])
    parser.add_argument("--store", required=True)
    parser.add_argument("--key-file")
    parser.add_argument("--key-id")
    parser.add_argument("--manifest")
    parser.add_argument("--checkpoint-id")
    parser.add_argument("--backup-path")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
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
