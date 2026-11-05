"""Phase 41: safe alert detection and non-delivery boundaries."""
import pytest
from said.alert_drill import HealthSignal, evaluate, deliver


def test_failure_routes_to_local_sink():
    sink = []
    assert deliver(HealthSignal("said-api", False, 0), sink)["severity"] == "critical"
    assert len(sink) == 1
    assert "contains_identifiers" in sink[0] and not sink[0]["contains_identifiers"]


def test_high_error_rate_triggers_local_alert():
    assert evaluate(HealthSignal("postgresql", True, 0.02))["reason"] == "error_rate"


def test_healthy_component_does_not_page():
    sink = []
    assert deliver(HealthSignal("said-api", True, 0.01), sink) is None
    assert not sink


@pytest.mark.parametrize("signal", [
    HealthSignal("unknown", False, 0),
    HealthSignal("said-api", True, -0.01),
    HealthSignal("said-api", True, 1.01),
])
def test_invalid_signal_fails_closed(signal):
    with pytest.raises(ValueError):
        evaluate(signal)
