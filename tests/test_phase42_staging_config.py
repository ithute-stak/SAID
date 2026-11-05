"""Phase 42 fail-closed staging-only configuration regression tests."""
import copy
import pytest
from said.staging_entrypoint import configuration
from said.staging_compose_policy import verify_compose


def env():
    return {
        "SAID_ENVIRONMENT": "staging",
        "SAID_OIDC_ISSUER": "https://id.example.test/realm",
        "SAID_OIDC_AUDIENCE": "said-sandbox",
        "SAID_OIDC_JWKS_URL": "https://id.example.test/keys",
        "SAID_STAGING_DB_USER": "said_staging",
        "SAID_STAGING_DB_NAME": "said_staging",
    }


def compose():
    app = {
        "image": "example/said@sha256:" + "a" * 64,
        "user": "10001:10001", "read_only": True,
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "pids_limit": 128, "mem_limit": "512m",
        "restart": "no", "networks": ["isolated"],
        "secrets": [{"source": "pg_password"}], "healthcheck": {"test": ["CMD", "true"]},
        "command": ["python", "-m", "said.staging_entrypoint"],
        "environment": env(),
    }
    db = {
        "image": "postgres@sha256:" + "b" * 64,
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "pids_limit": 128, "mem_limit": "1g",
        "restart": "no", "networks": ["isolated"],
        "secrets": [{"source": "pg_password"}],
        "healthcheck": {"test": ["CMD", "true"]},
        "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/pg_password"},
    }
    return {"services": {"api": app, "postgres": db},
            "networks": {"isolated": {"internal": True}},
            "secrets": {"pg_password": {"file": "/host/secret"}}}


def test_preflight_uses_secret_file_and_rejects_embedded_url():
    result = configuration(env(), "SecretOfAdequateLength2026%#")
    assert result["SAID_DATABASE_URL"].startswith("postgresql+psycopg://said_staging:")
    assert "%25" in result["SAID_DATABASE_URL"]
    assert "@postgres:5432/said_staging" in result["SAID_DATABASE_URL"]


@pytest.mark.parametrize("change", [
    {"SAID_ENVIRONMENT": "production"},
    {"SAID_ENVIRONMENT": "development"},
    {"SAID_ADMIN_API_KEY": "some-bypass"},
    {"SAID_DATABASE_URL": "postgresql://override"},
    {"SAID_OIDC_ISSUER": "http://example.test"},
    {"SAID_OIDC_JWKS_URL": "http://example.test/keys"},
    {"SAID_STAGING_DB_USER": "postgres;DROP TABLE"},
])
def test_preflight_rejects_unsafe_configuration(change):
    altered = env()
    altered.update(change)
    with pytest.raises(ValueError):
        configuration(altered, "ValidStagingDatabasePassword1234")


def test_preflight_rejects_weak_password():
    with pytest.raises(ValueError):
        configuration(env(), "short")


def test_isolated_compose_passes_as_non_deploying_candidate():
    result = verify_compose(compose())
    assert result["passed"], result["issues"]
    assert result["containers_started"] is False
    assert result["staging_deploy_authorized"] is False
    assert result["tls_termination_verified"] is False


@pytest.mark.parametrize("mutator,reason", [
    (lambda c: c["networks"]["isolated"].update(internal=False), "network_not_internal_isolated"),
    (lambda c: c["services"]["api"].update(ports=["0.0.0.0:8000:8000"]), "api_exposes_or_bypasses_network"),
    (lambda c: c["services"]["postgres"].update(network_mode="host"), "postgres_exposes_or_bypasses_network"),
    (lambda c: c["services"]["api"].update(privileged=True), "api_exposes_or_bypasses_network"),
    (lambda c: c["services"]["api"].update(read_only=False), "api_not_unprivileged_readonly"),
    (lambda c: c["services"]["api"].update(image="said:latest"), "api_image_not_digest_pinned"),
    (lambda c: c["services"]["postgres"].update(cap_drop=[]), "postgres_capabilities_not_dropped"),
    (lambda c: c["services"]["api"].update(secrets=[]), "api_secret_not_mounted"),
    (lambda c: c["services"]["api"]["environment"].update(SAID_ADMIN_API_KEY="oops"), "forbidden_inline_sensitive_configuration"),
    (lambda c: c["services"]["api"].update(command=["uvicorn"]), "staging_preflight_missing"),
])
def test_unsafe_compose_changes_denied(mutator, reason):
    raw = compose()
    mutator(raw)
    assert reason in verify_compose(raw)["issues"]


def test_unexpected_services_fail_closed():
    raw = compose()
    raw["services"]["telecom_connector"] = {}
    with pytest.raises(ValueError):
        verify_compose(raw)
