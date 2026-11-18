"""Transparent, deterministic detection and correlation rules."""
from collections import defaultdict
from datetime import timedelta

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
        "description": "Multiple authentication failure events were observed for the same host and account within a time window.",
    },
]


def evaluate_event(event: NormalizedEvent) -> list[Alert]:
    alerts: list[Alert] = []
    command = (event.command_line or "").lower()
    suspicious_tokens = (" -enc ", " -encodedcommand ", " -windowstyle hidden")
    if event.process_name in {"powershell.exe", "pwsh.exe"} and any(
        token in f" {command} " for token in suspicious_tokens
    ):
        alerts.append(
            Alert(
                rule_id="AEGIS-WIN-001",
                title="Suspicious PowerShell command pattern",
                severity="high",
                description=RULES[0]["description"],
                event_ids=[event.event_id],
                mitre_techniques=["T1059.001"],
            )
        )
    return alerts


def correlate_authentication_failures(
    events: list[NormalizedEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    """Alert when a host/account has threshold failures in a rolling time window."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    groups: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.event_type in {"authentication_failure", "login_failure"}:
            groups[(event.host, event.username or "unknown")].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for (host, username), matches in groups.items():
        ordered = sorted(matches, key=lambda event: event.timestamp)
        if not ordered:
            continue
        window_end = ordered[-1].timestamp
        window_start = window_end - window
        recent = [
            event for event in ordered
            if window_start <= event.timestamp <= window_end
        ]
        if len(recent) >= threshold:
            alerts.append(
                Alert(
                    rule_id="AEGIS-AUTH-001",
                    title="Repeated authentication failures",
                    severity="medium",
                    description=(
                        f"{len(recent)} authentication failures observed on {host} "
                        f"for account {username} within {window_minutes} minutes; "
                        "investigate for possible password guessing."
                    ),
                    event_ids=[event.event_id for event in recent],
                    mitre_techniques=["T1110"],
                )
            )
    return alerts
