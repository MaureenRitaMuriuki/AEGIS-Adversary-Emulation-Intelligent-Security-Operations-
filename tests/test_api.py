from datetime import UTC, datetime

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
        "timestamp": datetime.now(UTC).isoformat(),
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
    assert alerts.json()["items"][0]["status"] == "new"


def test_alert_status_can_be_updated_and_persists(monkeypatch, tmp_path):
    test_store = EventStore(tmp_path / "triage.db")
    monkeypatch.setattr(main, "store", test_store)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "windows",
        "event_type": "process_creation",
        "host": "LAB-WIN01",
        "username": "analyst",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand synthetic-fixture",
    }

    with TestClient(main.app) as client:
        ingested = client.post("/api/v1/events", json=payload)
        alert_id = ingested.json()["alerts"][0]["alert_id"]
        updated = client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            json={"status": "acknowledged", "analyst_note": "Reviewing the synthetic test."},
        )
        listed = client.get("/api/v1/alerts")

    assert updated.status_code == 200
    assert updated.json()["alert"]["status"] == "acknowledged"
    assert listed.json()["items"][0]["analyst_note"] == "Reviewing the synthetic test."
    assert listed.json()["items"][0]["status"] == "acknowledged"


def test_alert_status_rejects_invalid_value(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "store", EventStore(tmp_path / "invalid-status.db"))
    with TestClient(main.app) as client:
        response = client.patch(
            "/api/v1/alerts/not-a-real-id/status",
            json={"status": "escalated"},
        )
    assert response.status_code == 422


def test_alert_status_returns_404_for_unknown_alert(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "store", EventStore(tmp_path / "missing.db"))
    with TestClient(main.app) as client:
        response = client.patch(
            "/api/v1/alerts/missing/status",
            json={"status": "resolved"},
        )
    assert response.status_code == 404


def test_ingestion_rejects_unexpected_fields():
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "linux",
        "event_type": "process_creation",
        "host": "lab-linux01",
        "unexpected": "must be rejected",
    }

    with TestClient(main.app) as client:
        response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422
