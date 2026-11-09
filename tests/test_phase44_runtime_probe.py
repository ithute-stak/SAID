"""Synthetic runtime inspection regression tests; never starts Docker."""
import copy

import pytest

from said.staging_runtime_probe import assess_runtime


def record(service):
    return {
        "Config": {
            "Labels": {
                "com.docker.compose.project": "said-staging-isolated",
                "com.docker.compose.service": service,
            },
            "Image": "example.invalid/image@sha256:" + "a" * 64,
            "User": "10001:10001",
        },
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "HostConfig": {
            "Privileged": False, "NetworkMode": "said-staging-isolated_isolated",
            "PortBindings": {}, "CapAdd": None, "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"], "PidsLimit": 128,
            "Memory": 536870912, "NanoCpus": 1000000000,
            "ReadonlyRootfs": True,
        },
        "NetworkSettings": {
            "Networks": {"said-staging-isolated_isolated": {}}, "Ports": {},
        },
        "Mounts": [],
    }


def fixture():
    return [record("api"), record("postgres")]


def test_healthy_existing_runtime_is_assessable_but_not_authorized():
    report = assess_runtime(fixture())
    assert report["passed"], report["issues"]
    assert report["staging_deploy_authorized"] is False
    assert report["network_internal_verified"] is False
    assert report["backup_restoration_verified"] is False


@pytest.mark.parametrize("mutate, issue", [
    (lambda d: d[0]["State"].update(Running=False), "api_not_running"),
    (lambda d: d[0]["State"]["Health"].update(Status="unhealthy"), "api_not_healthy"),
    (lambda d: d[0]["HostConfig"].update(Privileged=True), "api_unsafe_host_mode"),
    (lambda d: d[0]["HostConfig"].update(PortBindings={"8000/tcp": [{"HostPort": "8000"}]}), "api_published_ports"),
    (lambda d: d[0]["HostConfig"].update(CapAdd=["NET_ADMIN"]), "api_added_capabilities"),
    (lambda d: d[0]["HostConfig"].update(ReadonlyRootfs=False), "api_not_nonroot_readonly"),
    (lambda d: d[0]["NetworkSettings"]["Networks"].update(bridge={}), "api_network_count_invalid"),
    (lambda d: d[1]["Config"].update(Image="postgres:latest"), "postgres_image_not_digest_pinned"),
    (lambda d: d[1]["Mounts"].append({"Type": "bind", "Destination": "/host", "RW": True}), "postgres_unsafe_bind_mount"),
    (lambda d: d[1]["HostConfig"].update(Memory=0), "postgres_memory_limit_missing"),
])
def test_runtime_failure_is_rejected(mutate, issue):
    evidence = copy.deepcopy(fixture())
    mutate(evidence)
    report = assess_runtime(evidence)
    assert report["passed"] is False
    assert issue in report["issues"]
    assert report["telecom_operations_enabled"] is False


def test_missing_service_rejected():
    assert "missing_or_extra_containers" in assess_runtime([record("api")])["issues"]


def test_duplicate_service_rejected():
    assert "unexpected_or_duplicate_service" in assess_runtime(
        [record("api"), record("api")])["issues"]
