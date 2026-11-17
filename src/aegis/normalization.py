"""Convert validated input into the canonical event representation."""
from .models import EventIn, NormalizedEvent


def normalize_event(event: EventIn) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=event.timestamp,
        source=event.source.strip().lower(),
        event_type=event.event_type.strip().lower(),
        host=event.host.strip().lower(),
        username=event.username.strip() if event.username else None,
        process_name=event.process_name.strip().lower() if event.process_name else None,
        command_line=event.command_line.strip() if event.command_line else None,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        metadata=event.metadata,
    )
