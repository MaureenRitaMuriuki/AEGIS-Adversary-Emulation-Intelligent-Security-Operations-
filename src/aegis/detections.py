"""Initial deterministic detections. Rules are deliberately transparent and testable."""
from collections import defaultdict
from .models import Alert, NormalizedEvent

RULES = [
    {
        "id": "AEGIS-WIN-001",
        "title": "Suspicious PowerShell command pattern",
        "severity": "high",
        "techniques": ["T1059.001"],
        "description": "A process command line contains a suspicious encoded-command or hidden-window pattern.",
    },
    {
        "id": "AEGIS-AUTH-001",
        "title": "Repeated authentication failures",
        "severity": "medium",
        "techniques": ["T1110"],
        "description": "Multiple authentication failure events were observed for the same host and account.",
    },
]


def evaluate_event(event: NormalizedEvent) -> list[Alert]:
    alerts: list[Alert] = []
    command = (event.command_line or "").lower()
    suspicious_tokens = (" -enc ", " -encodedcommand ", " -windowstyle hidden")
    if event.process_name in {"powershell.exe", "pwsh.exe"} and any(
        token in f" {command} " for token in suspicious_tokens
    ):
        alerts.append(Alert(
            rule_id="AEGIS-WIN-001",
            title="Suspicious PowerShell command pattern",
            severity="high",
            description=RULES[0]["description"],
            event_ids=[event.event_id],
            mitre_techniques=["T1059.001"],
        ))
    return alerts


def correlate_authentication_failures(events: list[NormalizedEvent], threshold: int = 5) -> list[Alert]:
    """Create one alert per host/account when failures reach the threshold."""
    groups: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.event_type in {"authentication_failure", "login_failure"}:
            groups[(event.host, event.username or "unknown")].append(event)

    alerts = []
    for (host, username), matches in groups.items():
        if len(matches) >= threshold:
            alerts.append(Alert(
                rule_id="AEGIS-AUTH-001",
                title="Repeated authentication failures",
                severity="medium",
                description=(
                    f"{len(matches)} authentication failures observed on {host} "
                    f"for account {username}; investigate for possible password guessing."
                ),
                event_ids=[event.event_id for event in matches],
                mitre_techniques=["T1110"],
            ))
    return alerts
