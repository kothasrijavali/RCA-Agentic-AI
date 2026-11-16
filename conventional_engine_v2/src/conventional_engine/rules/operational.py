"""Deterministic rules for common operational failures."""

from __future__ import annotations

from typing import Any

from conventional_engine.models import CanonicalEvent, Finding
from conventional_engine.rules.base import DetectionRule


def _get_value(event: CanonicalEvent, *keys: str) -> Any:
    """Read a value from event attributes or raw data."""

    attributes = getattr(event, "attributes", {}) or {}
    raw = getattr(event, "raw", {}) or {}

    if not isinstance(attributes, dict):
        attributes = {}

    if not isinstance(raw, dict):
        raw = {}

    containers = [
        attributes,
        raw,
        getattr(event, "metadata", {}) or {},
    ]

    for container in containers:
        if not isinstance(container, dict):
            continue

        for key in keys:
            if key in container and container[key] is not None:
                return container[key]

            # Support case-insensitive field lookup.
            for existing_key, value in container.items():
                if (
                    str(existing_key).lower() == key.lower()
                    and value is not None
                ):
                    return value

    return None


def _event_text(event: CanonicalEvent) -> str:
    """Build searchable text from an event."""

    parts = [
        str(getattr(event, "message", "") or ""),
        str(getattr(event, "event_type", "") or ""),
        str(getattr(event, "severity", "") or ""),
    ]

    raw = getattr(event, "raw", {}) or {}

    if isinstance(raw, dict):
        parts.extend(str(value) for value in raw.values())

    attributes = getattr(event, "attributes", {}) or {}

    if isinstance(attributes, dict):
        parts.extend(str(value) for value in attributes.values())

    return " ".join(parts).lower()


def _status_code(event: CanonicalEvent) -> int | None:
    """Extract an HTTP status code from an event."""

    value = _get_value(
        event,
        "status_code",
        "http_status",
        "http_status_code",
        "response_code",
        "status",
    )

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class HTTPErrorRule(DetectionRule):
    rule_id = "HTTP_ERROR"
    rule_version = "1.0"
    title = "HTTP Error Response"
    category = "HTTP"

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        status_code = _status_code(event)

        if status_code is None:
            return None

        if not 400 <= status_code <= 599:
            return None

        severity = "WARNING"
        if status_code >= 500:
            severity = "ERROR"

        return self.create_finding(
            event=event,
            description=f"HTTP request returned status code {status_code}.",
            severity=severity,
            confidence=0.95,
            field="status_code",
            observed_value=status_code,
            expected_value="HTTP status below 400",
            probable_causes=[
                "The request was invalid or unauthorized.",
                "The server or an upstream dependency failed.",
            ],
            remediation=[
                "Inspect the request and response details.",
                "Check application logs around the request timestamp.",
                "For 5xx responses, inspect server and dependency health.",
            ],
            metadata={"http_status_code": status_code},
        )


class HTTPServerErrorRule(DetectionRule):
    rule_id = "HTTP_SERVER_ERROR"
    rule_version = "1.0"
    title = "HTTP Server Error"
    category = "HTTP"

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        status_code = _status_code(event)

        if status_code is None or not 500 <= status_code <= 599:
            return None

        return self.create_finding(
            event=event,
            description=f"HTTP {status_code} indicates a server-side failure.",
            severity="ERROR",
            confidence=0.98,
            field="status_code",
            observed_value=status_code,
            expected_value="HTTP status below 500",
            probable_causes=[
                "An application exception occurred.",
                "A downstream service or dependency failed.",
                "The server is overloaded or misconfigured.",
            ],
            remediation=[
                "Inspect the server-side stack trace.",
                "Check downstream dependency health.",
                "Review recent deployments and configuration changes.",
            ],
            metadata={"http_status_code": status_code},
        )


class ExceptionRule(DetectionRule):
    rule_id = "APPLICATION_EXCEPTION"
    rule_version = "1.0"
    title = "Application Exception"
    category = "APPLICATION"

    exception_terms = (
        "exception",
        "traceback",
        "stack trace",
        "uncaught error",
        "unhandled exception",
        "fatal error",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.exception_terms):
            return None

        return self.create_finding(
            event=event,
            description="The event contains an application exception or error trace.",
            severity="ERROR",
            confidence=0.85,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "An unhandled application error occurred.",
                "Invalid input or unexpected application state.",
                "A dependency raised an exception.",
            ],
            remediation=[
                "Inspect the exception message and stack trace.",
                "Identify the first application frame in the trace.",
                "Check recent code and configuration changes.",
            ],
        )


class DatabaseFailureRule(DetectionRule):
    rule_id = "DATABASE_FAILURE"
    rule_version = "1.0"
    title = "Database Failure"
    category = "DATABASE"

    database_terms = (
        "database connection failed",
        "database unavailable",
        "connection refused",
        "too many connections",
        "deadlock detected",
        "sql error",
        "database timeout",
        "db connection error",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.database_terms):
            return None

        return self.create_finding(
            event=event,
            description="The event indicates a possible database failure.",
            severity="ERROR",
            confidence=0.85,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "The database is unavailable.",
                "Connection pool exhaustion.",
                "A query or transaction failed.",
                "Database resource contention.",
            ],
            remediation=[
                "Check database availability and connectivity.",
                "Inspect connection pool usage.",
                "Review slow queries and database locks.",
            ],
        )


class TimeoutRule(DetectionRule):
    rule_id = "OPERATION_TIMEOUT"
    rule_version = "1.0"
    title = "Operation Timeout"
    category = "PERFORMANCE"

    timeout_terms = (
        "timeout",
        "timed out",
        "deadline exceeded",
        "read timeout",
        "connect timeout",
        "request timeout",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.timeout_terms):
            return None

        return self.create_finding(
            event=event,
            description="The event indicates that an operation timed out.",
            severity="WARNING",
            confidence=0.85,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "The operation exceeded its configured timeout.",
                "A downstream dependency responded slowly.",
                "The system is experiencing resource contention.",
            ],
            remediation=[
                "Measure operation and dependency latency.",
                "Check CPU, memory, and network utilization.",
                "Review timeout settings and retry behavior.",
            ],
        )


class ResourceExhaustionRule(DetectionRule):
    rule_id = "RESOURCE_EXHAUSTION"
    rule_version = "1.0"
    title = "Resource Exhaustion"
    category = "RESOURCE"

    resource_terms = (
        "out of memory",
        "oom",
        "memory exhausted",
        "disk full",
        "no space left on device",
        "too many open files",
        "file descriptor limit",
        "resource exhausted",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.resource_terms):
            return None

        return self.create_finding(
            event=event,
            description="The event indicates possible resource exhaustion.",
            severity="CRITICAL",
            confidence=0.9,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "Memory, disk, or file descriptor capacity was exhausted.",
                "A workload exceeded available resources.",
                "A resource leak may be present.",
            ],
            remediation=[
                "Inspect memory, disk, and file descriptor utilization.",
                "Identify processes consuming excessive resources.",
                "Check for resource leaks and capacity limits.",
            ],
        )


def get_operational_rules() -> list[DetectionRule]:
    """Return the default operational rule collection."""

    return [
        HTTPErrorRule(),
        HTTPServerErrorRule(),
        ExceptionRule(),
        DatabaseFailureRule(),
        TimeoutRule(),
        ResourceExhaustionRule(),
    ]