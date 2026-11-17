from datetime import datetime

from aegis.models import EventIn
from aegis.normalization import normalize_event


def test_normalization_standardizes_fields_and_timezone():
    payload = EventIn(
        timestamp=datetime(2026, 11, 17, 10, 0),
        source=" Windows ",
        event_type=" Process_Creation ",
        host=" LAB-WIN01 ",
        username=" analyst ",
        process_name=" PowerShell.EXE ",
    )
    event = normalize_event(payload)
    assert event.source == "windows"
    assert event.event_type == "process_creation"
    assert event.host == "lab-win01"
    assert event.username == "analyst"
    assert event.process_name == "powershell.exe"
    assert event.timestamp.tzinfo is not None
