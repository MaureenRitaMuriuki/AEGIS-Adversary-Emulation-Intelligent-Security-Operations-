from datetime import datetime, timezone

from fastapi.testclient import TestClient

from aegis import main
from aegis.storage import EventStore


def test_health_endpoint():
    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ingest_event_persists_event_and_detection(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "store", EventStore(tmp_path / "test.db"))
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "windows",
        "event_type": "process_creation",
        "host": "LAB-WIN01",
        "username": "analyst",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand synthetic-fixture",
        "metadata": {"fixture": True},
    }

    with TestClient(main.app) as client:
        response = client.post("/api/v1/events", json=payload)
        events = client.get("/api/v1/events")
        alerts = client.get("/api/v1/alerts")

    assert response.status_code == 201
    body = response.json()
    assert body["event"]["host"] == "lab-win01"
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["rule_id"] == "AEGIS-WIN-001"
    assert events.status_code == 200
    assert events.json()["count"] == 1
    assert alerts.json()["count"] == 1


def test_ingestion_rejects_unexpected_fields():
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "linux",
        "event_type": "process_creation",
        "host": "lab-linux01",
        "unexpected": "must be rejected",
    }

    with TestClient(main.app) as client:
        response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422
