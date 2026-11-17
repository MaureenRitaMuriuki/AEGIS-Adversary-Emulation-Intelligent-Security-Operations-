from datetime import datetime, timezone
from aegis.detections import correlate_authentication_failures, evaluate_event
from aegis.models import NormalizedEvent


def make_event(**overrides):
    data = {
        "timestamp": datetime.now(timezone.utc),
        "source": "windows",
        "event_type": "process_creation",
        "host": "lab-win01",
        "username": "analyst",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc synthetic-test",
    }
    data.update(overrides)
    return NormalizedEvent(**data)


def test_encoded_powershell_pattern_generates_high_alert():
    alerts = evaluate_event(make_event())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AEGIS-WIN-001"
    assert alerts[0].severity == "high"
    assert "T1059.001" in alerts[0].mitre_techniques


def test_normal_powershell_does_not_alert():
    alerts = evaluate_event(make_event(command_line="powershell.exe Get-Process"))
    assert alerts == []


def test_authentication_correlation_threshold():
    events = [
        make_event(event_type="authentication_failure", process_name=None, command_line=None)
        for _ in range(5)
    ]
    alerts = correlate_authentication_failures(events, threshold=5)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AEGIS-AUTH-001"
    assert len(alerts[0].event_ids) == 5


def test_authentication_below_threshold_does_not_alert():
    events = [
        make_event(event_type="authentication_failure", process_name=None, command_line=None)
        for _ in range(4)
    ]
    assert correlate_authentication_failures(events, threshold=5) == []
