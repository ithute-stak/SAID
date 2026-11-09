"""Phase 44: read-only verification of an already running, approved staging stack.

Never starts containers, contacts carrier networks, or approves deployment.
The operator must use a dedicated Docker context with access only to staging.
"""
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


EXPECTED = {"api", "postgres"}
PROJECT = "said-staging-isolated"


def assess_runtime(records):
    issues = []
    if not isinstance(records, list):
        raise ValueError("Docker container inspection must be a list")
    by_service = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Malformed container inspection record")
        labels = record.get("Config", {}).get("Labels") or {}
        if labels.get("com.docker.compose.project") != PROJECT:
            issues.append("unexpected_project")
            continue
        service = labels.get("com.docker.compose.service")
        if service not in EXPECTED or service in by_service:
            issues.append("unexpected_or_duplicate_service")
            continue
        by_service[service] = record
    if set(by_service) != EXPECTED or len(records) != 2:
        issues.append("missing_or_extra_containers")

    network_names = set()
    for service, record in by_service.items():
        state = record.get("State") or {}
        host = record.get("HostConfig") or {}
        config = record.get("Config") or {}
        net = record.get("NetworkSettings") or {}
        if state.get("Running") is not True:
            issues.append(service + "_not_running")
        if (state.get("Health") or {}).get("Status") != "healthy":
            issues.append(service + "_not_healthy")
        if host.get("Privileged") or host.get("NetworkMode") in ("host", "none"):
            issues.append(service + "_unsafe_host_mode")
        if host.get("PortBindings") or net.get("Ports") and any(v for v in net["Ports"].values()):
            issues.append(service + "_published_ports")
        if host.get("CapAdd"):
            issues.append(service + "_added_capabilities")
        if "ALL" not in (host.get("CapDrop") or []):
            issues.append(service + "_capabilities_not_dropped")
        if "no-new-privileges" not in (host.get("SecurityOpt") or []):
            issues.append(service + "_new_privileges_allowed")
        if not host.get("PidsLimit") or host["PidsLimit"] > 256:
            issues.append(service + "_pid_limit_invalid")
        if not host.get("Memory") or host["Memory"] <= 0:
            issues.append(service + "_memory_limit_missing")
        if not host.get("NanoCpus") and not host.get("CpuQuota"):
            issues.append(service + "_cpu_limit_missing")
        networks = net.get("Networks") or {}
        if len(networks) != 1:
            issues.append(service + "_network_count_invalid")
        for name in networks:
            network_names.add(name)
            if not name.endswith("_isolated"):
                issues.append(service + "_unexpected_network")
        if not str(config.get("Image", "")).count("@sha256:"):
            issues.append(service + "_image_not_digest_pinned")
        if service == "api":
            if config.get("User") != "10001:10001" or host.get("ReadonlyRootfs") is not True:
                issues.append("api_not_nonroot_readonly")
        if any(m.get("Type") == "bind" for m in record.get("Mounts") or []):
            # Secret file mounts are read-only, but must not be confused with arbitrary host mounts.
            unsafe = [m for m in record.get("Mounts") or []
                      if m.get("Type") == "bind" and
                      (m.get("Destination") != "/run/secrets/pg_password" or m.get("RW") is not False)]
            if unsafe:
                issues.append(service + "_unsafe_bind_mount")
    if len(network_names) != 1:
        issues.append("network_not_shared")
    return {
        "schema": "said.staging_runtime.phase44.v1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "passed": not issues,
        "issues": sorted(set(issues)),
        "inspected_services": sorted(by_service),
        "read_only": True,
        "network_internal_verified": False,
        "tls_verified": False,
        "external_alert_delivery_verified": False,
        "backup_restoration_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }


def inspect_existing_containers(docker_context):
    if not docker_context or not docker_context.strip():
        raise ValueError("Explicit Docker context required")
    command = ["docker", "--context", docker_context, "ps", "-aq",
               "--filter", "label=com.docker.compose.project=" + PROJECT]
    ids = subprocess.run(command, capture_output=True, text=True, check=True, timeout=20).stdout.split()
    if len(ids) != 2:
        return []
    output = subprocess.run(["docker", "--context", docker_context, "inspect", *ids],
                            capture_output=True, text=True, check=True, timeout=30)
    return json.loads(output.stdout)


def main():
    parser = argparse.ArgumentParser(description="Read-only runtime inspection; no deployment")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--inspect-json", type=Path)
    source.add_argument("--docker-context")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        records = (json.loads(args.inspect_json.read_text(encoding="utf-8"))
                   if args.inspect_json else inspect_existing_containers(args.docker_context))
        result = assess_runtime(records)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        result = {"passed": False, "error_type": type(exc).__name__,
                  "staging_deploy_authorized": False, "telecom_operations_enabled": False}
    encoded = json.dumps(result, sort_keys=True)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    raise SystemExit(0 if result["passed"] else 2)


if __name__ == "__main__":
    main()
