"""Simulated health-failure detection and delivery to an in-memory alert sink.

This is a working negative-path delivery exercise, not verification of an
external pager/email/Slack channel or a production monitoring service.
"""
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class HealthSignal:
    component: str
    healthy: bool
    error_rate: float


def evaluate(signal: HealthSignal):
    if signal.component not in ("said-api", "postgresql", "audit-integrity"):
        raise ValueError("Unknown protected component")
    if not 0 <= signal.error_rate <= 1:
        raise ValueError("Invalid error rate")
    return None if signal.healthy and signal.error_rate <= 0.01 else {
        "component": signal.component,
        "severity": "critical",
        "reason": "unhealthy" if not signal.healthy else "error_rate",
        "contains_identifiers": False,
    }


def deliver(signal, sink):
    event = evaluate(signal)
    if event is not None:
        sink.append(event)
    return event


def exercise():
    sink = []
    assert deliver(HealthSignal("said-api", True, 0), sink) is None
    assert deliver(HealthSignal("postgresql", False, 0), sink) is not None
    assert deliver(HealthSignal("audit-integrity", True, 0.05), sink) is not None
    assert len(sink) == 2
    assert all(x["severity"] == "critical" for x in sink)
    assert all(x["contains_identifiers"] is False for x in sink)
    print(json.dumps({
        "schema": "said.mock.inmemory-alert-drill.v1",
        "detected": 2, "delivered_to_inmemory_sink": len(sink),
        "external_alert_route_verified": False,
        "actual_production_failure_injected": False,
        "production_deploy_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    exercise()
