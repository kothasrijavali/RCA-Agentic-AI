"""Canonical models used throughout the Conventional Engine."""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


# ============================================================
# ENUMS
# ============================================================

class Severity(str, Enum):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class EventType(str, Enum):
    LOG = "LOG"
    METRIC = "METRIC"
    TRACE = "TRACE"
    HTTP = "HTTP"
    EXCEPTION = "EXCEPTION"
    DEPLOYMENT = "DEPLOYMENT"
    REPOSITORY = "REPOSITORY"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    DETECTED = "DETECTED"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    UNRESOLVED = "UNRESOLVED"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    UNKNOWN = "UNKNOWN"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: Any) -> datetime | None:
    """Convert datetime or ISO-8601 string to timezone-aware datetime."""

    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        result = value

    elif isinstance(value, str):
        value = value.strip()

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        try:
            result = datetime.fromisoformat(value)

        except ValueError as exc:
            raise ValueError(
                f"Invalid ISO 8601 timestamp: {value!r}"
            ) from exc

    else:
        raise TypeError(
            "Timestamp must be a datetime, ISO 8601 string, or None"
        )

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)

    return result


def enum_value(enum_type, value, default):
    if isinstance(value, enum_type):
        return value

    if value is None:
        return default

    try:
        return enum_type(str(value).strip().upper())

    except ValueError:
        return default


def serialize_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.isoformat()


# ============================================================
# CANONICAL EVENT
# ============================================================

@dataclass
class CanonicalEvent:
    """Normalized representation of a log, metric, trace, or event."""

    event_id: str = dc_field(default_factory=lambda: str(uuid4()))

    timestamp: datetime | None = None

    event_type: EventType = EventType.UNKNOWN
    severity: Severity = Severity.UNKNOWN

    source: str | None = None
    service: str | None = None
    component: str | None = None
    environment: str | None = None

    message: str | None = None

    exception_type: str | None = None
    stack_trace: str | None = None

    trace_id: str | None = None
    span_id: str | None = None
    request_id: str | None = None

    attributes: dict[str, Any] = dc_field(default_factory=dict)
    tags: list[str] = dc_field(default_factory=list)

    raw: Any = None

    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid4())

        self.event_id = str(self.event_id)

        self.timestamp = parse_datetime(self.timestamp)

        self.event_type = enum_value(
            EventType,
            self.event_type,
            EventType.UNKNOWN,
        )

        self.severity = enum_value(
            Severity,
            self.severity,
            Severity.UNKNOWN,
        )

        if self.attributes is None:
            self.attributes = {}

        if not isinstance(self.attributes, dict):
            raise TypeError("attributes must be a dictionary")

        if self.tags is None:
            self.tags = []

        self.tags = [str(tag) for tag in self.tags]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CanonicalEvent":
        if not isinstance(data, dict):
            raise TypeError("CanonicalEvent input must be a dictionary")

        known_fields = {
            "event_id",
            "timestamp",
            "event_type",
            "severity",
            "source",
            "service",
            "component",
            "environment",
            "message",
            "exception_type",
            "stack_trace",
            "trace_id",
            "span_id",
            "request_id",
            "attributes",
            "tags",
            "raw",
        }

        attributes = dict(data.get("attributes") or {})

        # Preserve fields that are not part of the canonical schema.
        for key, value in data.items():
            if key not in known_fields:
                attributes.setdefault(key, value)

        return cls(
            event_id=data.get("event_id") or str(uuid4()),
            timestamp=data.get("timestamp") or data.get("time"),
            event_type=data.get(
                "event_type",
                data.get("type", "UNKNOWN"),
            ),
            severity=data.get(
                "severity",
                data.get("level", "UNKNOWN"),
            ),
            source=data.get("source", data.get("logger")),
            service=data.get("service", data.get("service_name")),
            component=data.get("component"),
            environment=data.get("environment", data.get("env")),
            message=data.get("message", data.get("msg")),
            exception_type=data.get("exception_type"),
            stack_trace=data.get("stack_trace", data.get("stacktrace")),
            trace_id=data.get("trace_id"),
            span_id=data.get("span_id"),
            request_id=data.get("request_id"),
            attributes=attributes,
            tags=data.get("tags") or [],
            raw=data.get("raw", data),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": serialize_datetime(self.timestamp),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "source": self.source,
            "service": self.service,
            "component": self.component,
            "environment": self.environment,
            "message": self.message,
            "exception_type": self.exception_type,
            "stack_trace": self.stack_trace,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "request_id": self.request_id,
            "attributes": self.attributes,
            "tags": self.tags,
            "raw": self.raw,
        }


# ============================================================
# EVIDENCE
# ============================================================

@dataclass
class Evidence:
    """Specific information supporting a finding."""

    evidence_id: str = dc_field(default_factory=lambda: str(uuid4()))

    event_id: str | None = None
    source: str | None = None
    field: str | None = None

    observed_value: Any = None
    expected_value: Any = None

    description: str = ""

    line_number: int | None = None
    file_path: str | None = None

    metadata: dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = str(uuid4())

        self.evidence_id = str(self.evidence_id)

        if self.line_number is not None:
            if not isinstance(self.line_number, int):
                raise TypeError("line_number must be an integer")

            if self.line_number < 1:
                raise ValueError("line_number must be >= 1")

        if self.metadata is None:
            self.metadata = {}

        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dictionary")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        if not isinstance(data, dict):
            raise TypeError("Evidence input must be a dictionary")

        return cls(
            evidence_id=data.get("evidence_id") or str(uuid4()),
            event_id=data.get("event_id"),
            source=data.get("source"),
            field=data.get("field", data.get("field_name")),
            observed_value=data.get("observed_value"),
            expected_value=data.get("expected_value"),
            description=str(data.get("description", "")),
            line_number=data.get("line_number"),
            file_path=data.get("file_path"),
            metadata=data.get("metadata") or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "event_id": self.event_id,
            "source": self.source,
            "field": self.field,
            "observed_value": self.observed_value,
            "expected_value": self.expected_value,
            "description": self.description,
            "line_number": self.line_number,
            "file_path": self.file_path,
            "metadata": self.metadata,
        }


# ============================================================
# FINDING
# ============================================================

@dataclass
class Finding:
    """Structured detection result produced by a rule."""

    finding_id: str = dc_field(default_factory=lambda: str(uuid4()))

    rule_id: str = ""
    rule_version: str = "1.0"

    title: str = ""
    description: str = ""

    category: str = "UNKNOWN"
    severity: Severity = Severity.WARNING

    confidence: float = 0.5
    status: FindingStatus = FindingStatus.DETECTED

    evidence: list[Evidence] = dc_field(default_factory=list)

    affected_event_ids: list[str] = dc_field(default_factory=list)
    affected_components: list[str] = dc_field(default_factory=list)

    probable_causes: list[str] = dc_field(default_factory=list)
    remediation: list[str] = dc_field(default_factory=list)

    created_at: datetime = dc_field(default_factory=utc_now)

    metadata: dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = str(uuid4())

        self.finding_id = str(self.finding_id)

        self.severity = enum_value(
            Severity,
            self.severity,
            Severity.WARNING,
        )

        self.status = enum_value(
            FindingStatus,
            self.status,
            FindingStatus.DETECTED,
        )

        if not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be numeric")

        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

        self.confidence = float(self.confidence)

        self.created_at = parse_datetime(self.created_at) or utc_now()

        self.evidence = [
            item if isinstance(item, Evidence) else Evidence.from_dict(item)
            for item in (self.evidence or [])
        ]

        self.affected_event_ids = [
            str(item) for item in (self.affected_event_ids or [])
        ]

        self.affected_components = [
            str(item) for item in (self.affected_components or [])
        ]

        self.probable_causes = [
            str(item) for item in (self.probable_causes or [])
        ]

        self.remediation = [
            str(item) for item in (self.remediation or [])
        ]

        if self.metadata is None:
            self.metadata = {}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        if not isinstance(data, dict):
            raise TypeError("Finding input must be a dictionary")

        return cls(
            finding_id=data.get("finding_id") or str(uuid4()),
            rule_id=str(data.get("rule_id", "")),
            rule_version=str(data.get("rule_version", "1.0")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            category=str(data.get("category", "UNKNOWN")),
            severity=data.get("severity", "WARNING"),
            confidence=data.get("confidence", 0.5),
            status=data.get("status", "DETECTED"),
            evidence=data.get("evidence") or [],
            affected_event_ids=data.get("affected_event_ids") or [],
            affected_components=data.get("affected_components") or [],
            probable_causes=data.get("probable_causes") or [],
            remediation=data.get("remediation") or [],
            created_at=data.get("created_at") or utc_now(),
            metadata=data.get("metadata") or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "status": self.status.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "affected_event_ids": self.affected_event_ids,
            "affected_components": self.affected_components,
            "probable_causes": self.probable_causes,
            "remediation": self.remediation,
            "created_at": serialize_datetime(self.created_at),
            "metadata": self.metadata,
        }


# ============================================================
# INCIDENT / CORRELATION GROUP
# ============================================================

@dataclass
class Incident:
    """A group of related events and findings."""

    incident_id: str = dc_field(default_factory=lambda: str(uuid4()))

    title: str = ""
    description: str = ""

    status: IncidentStatus = IncidentStatus.OPEN

    event_ids: list[str] = dc_field(default_factory=list)
    finding_ids: list[str] = dc_field(default_factory=list)

    trace_ids: list[str] = dc_field(default_factory=list)
    request_ids: list[str] = dc_field(default_factory=list)

    services: list[str] = dc_field(default_factory=list)

    start_time: datetime | None = None
    end_time: datetime | None = None

    metadata: dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self):
        if not self.incident_id:
            self.incident_id = str(uuid4())

        self.incident_id = str(self.incident_id)

        self.status = enum_value(
            IncidentStatus,
            self.status,
            IncidentStatus.UNKNOWN,
        )

        self.start_time = parse_datetime(self.start_time)
        self.end_time = parse_datetime(self.end_time)

        self.event_ids = [str(x) for x in (self.event_ids or [])]
        self.finding_ids = [str(x) for x in (self.finding_ids or [])]
        self.trace_ids = [str(x) for x in (self.trace_ids or [])]
        self.request_ids = [str(x) for x in (self.request_ids or [])]
        self.services = [str(x) for x in (self.services or [])]

        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "event_ids": self.event_ids,
            "finding_ids": self.finding_ids,
            "trace_ids": self.trace_ids,
            "request_ids": self.request_ids,
            "services": self.services,
            "start_time": serialize_datetime(self.start_time),
            "end_time": serialize_datetime(self.end_time),
            "metadata": self.metadata,
        }