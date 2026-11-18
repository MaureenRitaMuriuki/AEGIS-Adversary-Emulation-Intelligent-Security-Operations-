"""Small SQLite persistence layer; no external database service required."""
import json
import sqlite3
from pathlib import Path

from .models import Alert, AlertStatus, NormalizedEvent


class EventStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    host TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")

    def save_event(self, event: NormalizedEvent) -> None:
        payload = event.model_dump_json()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
                (event.event_id, event.timestamp.isoformat(), event.host,
                 event.source, event.event_type, payload),
            )

    def save_alert(self, alert: Alert) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?)",
                (alert.alert_id, alert.created_at.isoformat(), alert.severity,
                 alert.rule_id, alert.model_dump_json()),
            )

    def list_events(self, limit: int = 100) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def list_alerts(self, limit: int = 100) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        items = [json.loads(row["payload"]) for row in rows]
        # Backfill defaults for alerts created before analyst triage was introduced.
        for item in items:
            item.setdefault("status", "new")
            item.setdefault("analyst_note", "")
        return items

    def update_alert_status(
        self, alert_id: str, status: AlertStatus, analyst_note: str
    ) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                return None
            payload = json.loads(row["payload"])
            payload["status"] = status
            payload["analyst_note"] = analyst_note
            conn.execute(
                "UPDATE alerts SET payload = ? WHERE alert_id = ?",
                (json.dumps(payload), alert_id),
            )
        return payload
