"""AEGIS API application."""
from fastapi import FastAPI, HTTPException, Query

from .config import APP_NAME, APP_VERSION, DB_PATH
from .detections import correlate_authentication_failures, evaluate_event
from .models import EventIn
from .normalization import normalize_event
from .storage import EventStore

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="A resource-conscious SOC telemetry ingestion and detection platform.",
)
store = EventStore(DB_PATH)


@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME, "version": APP_VERSION}


@app.post("/api/v1/events", status_code=201)
def ingest_event(payload: EventIn):
    event = normalize_event(payload)
    try:
        store.save_event(event)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Event persistence failed") from exc

    alerts = evaluate_event(event)
    for alert in alerts:
        store.save_alert(alert)
    return {"event": event.model_dump(mode="json"), "alerts": [a.model_dump(mode="json") for a in alerts]}


@app.get("/api/v1/events")
def get_events(limit: int = Query(default=100, ge=1, le=500)):
    return {"items": store.list_events(limit), "count": len(store.list_events(limit))}


@app.get("/api/v1/alerts")
def get_alerts(limit: int = Query(default=100, ge=1, le=500)):
    items = store.list_alerts(limit)
    return {"items": items, "count": len(items)}


@app.post("/api/v1/detections/correlate-auth")
def correlate_auth():
    events = store.list_events(500)
    from .models import NormalizedEvent
    parsed = [NormalizedEvent.model_validate(item) for item in events]
    alerts = correlate_authentication_failures(parsed)
    for alert in alerts:
        store.save_alert(alert)
    return {"alerts": [a.model_dump(mode="json") for a in alerts], "count": len(alerts)}
