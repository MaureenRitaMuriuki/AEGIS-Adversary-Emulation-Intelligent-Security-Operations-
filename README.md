# AEGIS
### Adversary Emulation & Intelligent Security Operations

AEGIS is a modular, resource-conscious Security Operations Centre (SOC) engineering platform. It ingests security telemetry, normalizes events, evaluates detections, correlates suspicious activity, and supports evidence-led incident investigation.

> **Project status:** Foundation / Milestone 01 in active development. Detection capabilities are experimental until validated against documented test scenarios.

## Mission
Build an end-to-end, reproducible SOC lab that demonstrates how raw endpoint and network events become investigated security incidents.

## Design principles
- **Evidence first:** every alert should retain the event evidence and rule that produced it.
- **Testable detections:** detection logic is version-controlled and covered by automated tests.
- **Resource aware:** the initial stack uses FastAPI, Python and SQLite; heavyweight services are optional integrations.
- **Safe by design:** adversary emulation is limited to isolated, authorized lab systems and benign test fixtures.
- **Honest measurement:** detection rates and false-positive metrics are published only with reproducible test data and methodology.

## Current capabilities
- API health check.
- Event ingestion with schema validation and normalization.
- SQLite persistence.
- Initial deterministic detections for suspicious PowerShell command patterns and repeated authentication failures.
- Unit tests for normalization and detection logic.

## Architecture
```text
Authorized lab / sample telemetry
            |
            v
     FastAPI ingestion API
            |
            v
 Event validation & normalization
            |
            v
        SQLite store
            |
            v
  Detection & correlation engine
            |
            v
      Alerts / investigations
            |
            v
   SOC console (planned module)
```

## Quick start
Requirements: Python 3.11+

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
uvicorn aegis.main:app --reload
```

Open the interactive API documentation at http://127.0.0.1:8000/docs.

Run tests:
```bash
pytest
```

## API quick test
```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-11-17T12:00:00Z",
    "source": "windows",
    "event_type": "process_creation",
    "host": "lab-win01",
    "username": "analyst",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgAHQAZQBzAHQ",
    "source_ip": null,
    "destination_ip": null,
    "metadata": {"event_id": 1}
  }'
```

This example is a synthetic event fixture. It does not execute the command.

## Repository map
- `src/aegis/`: application, API, data models, storage and detections.
- `tests/`: automated unit and API tests.
- `sample_telemetry/`: safe, synthetic event fixtures.
- `docs/`: architecture, roadmap, safety and investigation methodology.
- `.github/workflows/`: continuous integration.

## Roadmap
See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety and scope
AEGIS is for defensive security education and authorized testing only. Do not run adversary-emulation tests against systems you do not own or have explicit permission to assess. The initial project uses synthetic telemetry and detection logic; it is not a production SIEM or an automated containment system.

## Author
Built by Maureen Rita as a hands-on SOC and detection-engineering portfolio project.
