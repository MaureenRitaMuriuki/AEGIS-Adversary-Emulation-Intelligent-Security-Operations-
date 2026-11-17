# AEGIS Architecture

## Context
AEGIS is a learning and portfolio platform for defensive security operations. Its first deployment target is a single 8 GB RAM workstation.

## Architecture decisions
1. **Modular monolith first:** keep components independently testable without introducing distributed-system overhead.
2. **SQLite first:** local persistence with no always-on database service. A future PostgreSQL adapter can be added behind the storage interface.
3. **FastAPI:** typed API surface and generated OpenAPI documentation.
4. **Deterministic detection first:** transparent, testable rules before statistical or machine-learning approaches.
5. **Optional telemetry adapters:** ingest normalized JSON from Sysmon, Linux audit sources and Suricata EVE output without requiring all sensors to run continuously.
6. **No automatic containment in the initial release:** response actions remain analyst-approved and documented.

## Event lifecycle
1. Receive JSON event.
2. Validate schema and reject unexpected fields.
3. Normalize source, event type, host and process fields.
4. Persist the event.
5. Evaluate event-level detection rules.
6. Persist generated alerts with references to source event IDs.
7. Run explicit correlation jobs for multi-event patterns.

## Planned modules
- Ingestion adapters for Sysmon, Linux audit and Suricata.
- Rule metadata, versioning and Sigma import.
- Time-windowed correlation and alert deduplication.
- Case management, evidence timeline and analyst notes.
- IOC enrichment with provider-independent interfaces.
- ATT&CK coverage and detection test harness.
- React SOC console.

## Resource profile
The API container is capped at 512 MB and one CPU in the supplied Compose configuration. This is a starting limit, not a benchmark claim. Actual usage must be measured on the target machine. Wazuh, OpenSearch and network sensors are optional profiles/integrations, not part of the always-on baseline.
