"""Phase 42: verify a Docker Compose-normalized staging template (no deploy).

Takes 'docker compose config --format json' output, rejects exposed ports,
egress-capable networks, privileged containers and permissive services.
"""
import argparse
import json
import re
from pathlib import Path

DIGEST = re.compile(r"^[a-zA-Z0-9./_-]+@sha256:[0-9a-f]{64}$")


def verify_compose(config: dict) -> dict:
    issues = []
    if not isinstance(config, dict):
        raise ValueError("Compose configuration must be an object")
    services = config.get("services")
    networks = config.get("networks")
    if not isinstance(services, dict) or set(services) != {"api", "postgres"}:
        raise ValueError("Exactly API and PostgreSQL services required")
    if not isinstance(networks, dict) or not networks:
        issues.append("missing_networks")
        networks = {}
    for name, network in networks.items():
        if not isinstance(network, dict) or network.get("internal") is not True:
            issues.append("network_not_internal_" + name)
    for name, service in services.items():
        if not isinstance(service, dict):
            raise ValueError("Malformed service")
        if not DIGEST.fullmatch(service.get("image", "")):
            issues.append(name + "_image_not_digest_pinned")
        if service.get("ports") or service.get("expose") or service.get("network_mode") or service.get("privileged"):
            issues.append(name + "_exposes_or_bypasses_network")
        attached = service.get("networks", {})
        if not isinstance(attached, (list, dict)) or not attached:
            issues.append(name + "_network_missing")
        else:
            for network in attached:
                if network not in networks:
                    issues.append(name + "_unknown_network")
        if service.get("cap_drop") != ["ALL"]:
            issues.append(name + "_capabilities_not_dropped")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            issues.append(name + "_new_privileges_allowed")
        if service.get("restart") != "no":
            issues.append(name + "_unexpected_restart")
        if service.get("pid") == "host" or service.get("ipc") == "host":
            issues.append(name + "_host_namespace_enabled")
        if type(service.get("pids_limit")) is not int or service["pids_limit"] > 256:
            issues.append(name + "_pid_limit_missing")
        if service.get("mem_limit") is None and service.get("mem_reservation") is None:
            issues.append(name + "_memory_limit_missing")
        if not service.get("healthcheck"):
            issues.append(name + "_healthcheck_missing")
        if "pg_password" not in service.get("secrets", []):
            # The normalized representation can be a list of {source,target}
            secrets = service.get("secrets", [])
            if not isinstance(secrets, list) or not any(
                isinstance(item, dict) and item.get("source") == "pg_password"
                for item in secrets
            ):
                issues.append(name + "_secret_not_mounted")
    api = services["api"]
    if api.get("read_only") is not True or str(api.get("user")) != "10001:10001":
        issues.append("api_not_unprivileged_readonly")
    environment = api.get("environment")
    if not isinstance(environment, dict):
        issues.append("api_environment_missing")
        environment = {}
    if environment.get("SAID_ENVIRONMENT") != "staging":
        issues.append("not_staging_environment")
    if "SAID_ADMIN_API_KEY" in environment or "SAID_DATABASE_URL" in environment:
        issues.append("forbidden_inline_sensitive_configuration")
    if not all(environment.get(k) for k in (
        "SAID_OIDC_ISSUER", "SAID_OIDC_AUDIENCE", "SAID_OIDC_JWKS_URL")):
        issues.append("oidc_not_configured")
    if "said.staging_entrypoint" not in str(api.get("command", "")):
        issues.append("staging_preflight_missing")
    if services["postgres"].get("environment", {}).get("POSTGRES_PASSWORD_FILE") != "/run/secrets/pg_password":
        issues.append("postgres_secret_file_missing")
    if "pg_password" not in config.get("secrets", {}):
        issues.append("secret_definition_missing")
    return {"passed": not issues, "issues": sorted(set(issues)),
            "config_static_only": True, "containers_started": False,
            "tls_termination_verified": False, "oidc_reachability_verified": False,
            "staging_deploy_authorized": False, "production_deploy_authorized": False,
            "telecom_operations_enabled": False}


def main():
    parser = argparse.ArgumentParser(description="Validate isolated SAID staging Compose JSON")
    parser.add_argument("--config-json", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(args.config_json.read_text(encoding="utf-8"))
        report = verify_compose(value)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        print(json.dumps({"passed": False, "error_type": type(exc).__name__,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
