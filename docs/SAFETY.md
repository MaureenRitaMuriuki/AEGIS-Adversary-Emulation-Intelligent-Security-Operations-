# Safety and Responsible Use

AEGIS is intended for defensive security learning, detection engineering and authorized lab validation.

- Run adversary emulation only on isolated systems you own or are explicitly authorized to test.
- Begin with synthetic JSON fixtures; do not execute untrusted commands from telemetry.
- Do not connect test agents to production endpoints.
- Do not enable automated blocking, account disabling or host isolation without explicit analyst approval and a documented rollback plan.
- Treat IP addresses, usernames, hostnames and logs as potentially sensitive data. Sanitize examples before publishing.
- Keep API access local by default. Do not expose the development API to the public internet.
- Detection results are hypotheses requiring investigation, not proof of compromise.
