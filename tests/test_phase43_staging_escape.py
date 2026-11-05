"""Phase 43: fail-closed negative security regressions for the staging template."""
import copy

import pytest

from said.staging_compose_policy import verify_compose


@pytest.fixture
def baseline():
    common = {
        "image": "example.invalid/said@sha256:" + "a" * 64,
        "networks": {"isolated": None},
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "no",
        "pids_limit": 128,
        "mem_limit": 536870912,
        "cpus": 1.0,
        "healthcheck": {"test": ["CMD", "true"]},
        "secrets": [{"source": "pg_password", "target": "/run/secrets/pg_password"}],
    }
    api = {
        **common,
        "user": "10001:10001",
        "read_only": True,
        "command": ["python", "-m", "said.staging_entrypoint"],
        "environment": {
            "SAID_ENVIRONMENT": "staging",
            "SAID_OIDC_ISSUER": "https://id.example.invalid",
            "SAID_OIDC_JWKS_URL": "https://id.example.invalid/keys",
            "SAID_OIDC_AUDIENCE": "said-staging",
        },
    }
    postgres = {
        **common,
        "image": "postgres@sha256:" + "b" * 64,
        "volumes": [{"type": "volume", "source": "staging_db", "target": "/var/lib/postgresql/data"}],
        "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/pg_password"},
    }
    return {
        "name": "said-staging-isolated",
        "services": {"api": api, "postgres": postgres},
        "networks": {"isolated": {"internal": True}},
        "secrets": {"pg_password": {"file": "/tmp/test-only-secret"}},
        "volumes": {"staging_db": {}},
    }


def test_valid_isolated_config_passes(baseline):
    report = verify_compose(baseline)
    assert report["passed"], report["issues"]
    assert report["staging_deploy_authorized"] is False


@pytest.mark.parametrize("mutation,expected", [
    (lambda c: c["networks"].update({"public": {"internal": False}}), "unexpected_networks"),
    (lambda c: c["networks"]["isolated"].update({"external": True}), "externally_attachable_network_isolated"),
    (lambda c: c["services"]["api"].update({"extra_hosts": ["host.docker.internal:host-gateway"]}), "api_unsafe_host_or_network_override"),
    (lambda c: c["services"]["api"].update({"devices": ["/dev/net/tun:/dev/net/tun"]}), "api_unsafe_host_or_network_override"),
    (lambda c: c["services"]["api"].update({"cap_add": ["NET_ADMIN"]}), "api_capabilities_added"),
    (lambda c: c["services"]["api"].update({"volumes": [{"type": "bind", "source": "/", "target": "/host"}]}), "api_unexpected_volume"),
    (lambda c: c["services"]["postgres"].update({"volumes": [{"type": "bind", "source": "/", "target": "/host"}]}), "postgres_unexpected_mount"),
    (lambda c: c["services"]["api"].update({"build": "."}), "api_unapproved_image_source"),
    (lambda c: c["services"]["api"].update({"ports": [{"published": "8000", "target": 8000}]}), "api_network_exposure"),
    (lambda c: c["services"]["api"].update({"networks": {"isolated": None, "public": None}}), "api_network_scope_invalid"),
    (lambda c: c["services"]["api"].pop("cpus"), "api_cpu_limit_missing"),
    (lambda c: c.update({"name": "said-production"}), "unexpected_project_name"),
])
def test_staging_escape_rejected(baseline, mutation, expected):
    altered = copy.deepcopy(baseline)
    mutation(altered)
    report = verify_compose(altered)
    assert report["passed"] is False
    assert expected in report["issues"]
    assert report["staging_deploy_authorized"] is False
    assert report["telecom_operations_enabled"] is False
