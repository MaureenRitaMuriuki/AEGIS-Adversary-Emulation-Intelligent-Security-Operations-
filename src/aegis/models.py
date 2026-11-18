"""Validated API and domain models."""
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    source: str = Field(min_length=1, max_length=40)
    event_type: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    process_name: str | None = Field(default=None, max_length=255)
    command_line: str | None = Field(default=None, max_length=4000)
    source_ip: str | None = None
    destination_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    source: str
    event_type: str
    host: str
    username: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


AlertStatus = Literal["new", "acknowledged", "resolved"]


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    title: str
    severity: str
    description: str
    event_ids: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: AlertStatus = "new"
    analyst_note: str = Field(default="", max_length=2000)


class AlertStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus
    analyst_note: str = Field(default="", max_length=2000)
