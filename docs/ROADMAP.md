# AEGIS Roadmap

## Milestone 01 — Foundation
- [x] Repository structure and project metadata
- [x] FastAPI health endpoint
- [x] Validated event schema and normalization
- [x] SQLite event and alert persistence
- [x] Initial deterministic detections
- [x] Unit tests and CI workflow
- [ ] Verify CI on GitHub Actions
- [ ] Add API integration tests

## Milestone 02 — Telemetry engineering
- [ ] Sysmon JSON adapter
- [ ] Suricata EVE JSON adapter
- [ ] Linux authentication/audit adapter
- [ ] Event source provenance and ingestion timestamps
- [ ] Malformed-event quarantine and structured error reporting

## Milestone 03 — Detection engineering
- [ ] Versioned rule catalogue and Sigma import
- [ ] Rule metadata, confidence and severity rationale
- [ ] Detection test fixtures: positive and negative cases
- [ ] Time-windowed correlation and deduplication
- [ ] ATT&CK technique coverage report

## Milestone 04 — SOC investigations
- [ ] Alert lifecycle and analyst disposition
- [ ] Incident cases and evidence references
- [ ] Host/user pivots and event timeline
- [ ] Investigation notes and exportable incident report

## Milestone 05 — Threat intelligence
- [ ] IOC data model
- [ ] Offline/local enrichment provider
- [ ] Optional external reputation integrations
- [ ] Confidence, source and freshness tracking

## Milestone 06 — Adversary emulation
- [ ] Isolated lab guide
- [ ] Safe Atomic Red Team test selection
- [ ] Detection validation matrix
- [ ] Reproducible detection-evaluation report

## Milestone 07 — Response engineering
- [ ] Analyst-approved response playbooks
- [ ] Dry-run mode and explicit approval gates
- [ ] Audit trail for every response action

## Milestone 08 — SOC console
- [ ] Alert queue and filtering
- [ ] Incident workbench
- [ ] Event explorer
- [ ] ATT&CK coverage view
- [ ] Operational metrics with documented denominators
