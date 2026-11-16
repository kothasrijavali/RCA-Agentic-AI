"""Normalize raw input records into CanonicalEvent objects."""

from __future__ import annotations

import json
import re
import csv
import io
import xml.etree.ElementTree as ET

from typing import Any

from conventional_engine.models import (
    CanonicalEvent,
    EventType,
    Severity,
)


# ============================================================
# ALIASES
# ============================================================

FIELD_ALIASES = {
    "timestamp": [
        "timestamp",
        "time",
        "datetime",
        "date",
        "@timestamp",
        "ts",
    ],
    "severity": [
        "severity",
        "level",
        "log_level",
        "loglevel",
        "status",
    ],
    "message": [
        "message",
        "msg",
        "error_message",
        "description",
        "event",
    ],
    "service": [
        "service",
        "service_name",
        "application",
        "app",
    ],
    "component": [
        "component",
        "module",
        "logger",
    ],
    "environment": [
        "environment",
        "env",
        "deployment_environment",
    ],
    "trace_id": [
        "trace_id",
        "traceid",
        "traceId",
    ],
    "span_id": [
        "span_id",
        "spanid",
        "spanId",
    ],
    "request_id": [
        "request_id",
        "requestid",
        "requestId",
        "correlation_id",
    ],
    "exception_type": [
        "exception_type",
        "exception",
        "error_type",
        "error_class",
    ],
    "stack_trace": [
        "stack_trace",
        "stacktrace",
        "stack",
        "traceback",
    ],
}


# ============================================================
# HELPERS
# ============================================================

def _normalized_key(key: Any) -> str:
    """Normalize keys for case-insensitive matching."""
    return str(key).strip().lower().replace("-", "_")


def _find_alias(
    record: dict[str, Any],
    canonical_name: str,
) -> Any:
    """Find the first matching alias for a canonical field."""

    aliases = FIELD_ALIASES.get(canonical_name, [])

    normalized_record = {
        _normalized_key(key): value
        for key, value in record.items()
    }

    for alias in aliases:
        normalized_alias = _normalized_key(alias)

        if normalized_alias in normalized_record:
            return normalized_record[normalized_alias]

    return None


def _normalize_severity(value: Any) -> Severity:
    if value is None:
        return Severity.UNKNOWN

    normalized = str(value).strip().upper()

    mapping = {
        "WARN": Severity.WARNING,
        "WARNING": Severity.WARNING,
        "ERR": Severity.ERROR,
        "ERROR": Severity.ERROR,
        "FATAL": Severity.CRITICAL,
        "CRITICAL": Severity.CRITICAL,
        "DEBUG": Severity.DEBUG,
        "TRACE": Severity.TRACE,
        "INFO": Severity.INFO,
        "INFORMATION": Severity.INFO,
    }

    return mapping.get(normalized, Severity.UNKNOWN)


def _infer_event_type(
    record: dict[str, Any],
    input_format: str,
) -> EventType:
    fmt = input_format.upper()

    if fmt == "METRICS":
        return EventType.METRIC

    if fmt == "LOGS":
        return EventType.LOG

    if any(
        key in record
        for key in ("exception_type", "exception", "stack_trace", "traceback")
    ):
        return EventType.EXCEPTION

    if any(
        key in record
        for key in ("status_code", "http_status", "response_status")
    ):
        return EventType.HTTP

    if "trace_id" in record or "traceId" in record:
        return EventType.TRACE

    return EventType.UNKNOWN


def _flatten_xml_element(element: ET.Element) -> dict[str, Any]:
    """Convert a basic XML element into a dictionary."""

    result = {}

    for child in element:
        if len(child):
            value = _flatten_xml_element(child)

        else:
            value = (child.text or "").strip()

        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]

            result[child.tag].append(value)

        else:
            result[child.tag] = value

    return result


# ============================================================
# INPUT PARSERS
# ============================================================

def parse_json(payload: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(payload)

    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if isinstance(parsed, dict):
        return [parsed]

    if isinstance(parsed, list):
        if not all(isinstance(item, dict) for item in parsed):
            raise ValueError(
                "JSON arrays must contain objects"
            )

        return parsed

    raise ValueError(
        "JSON input must be an object or an array of objects"
    )


def parse_csv(payload: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(payload))

    if not reader.fieldnames:
        raise ValueError("CSV header is required")

    return [
        dict(record)
        for record in reader
    ]


def parse_xml(payload: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(payload)

    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    if not list(root):
        return [{root.tag: (root.text or "").strip()}]

    records = []

    for child in root:
        if list(child):
            records.append(_flatten_xml_element(child))

        else:
            records.append({
                child.tag: (child.text or "").strip()
            })

    return records


def parse_logs(payload: str) -> list[dict[str, Any]]:
    """Parse common timestamped log lines.

    Supported format:
    2026-11-04 10:20:30 ERROR service-name: message

    This parser intentionally rejects unsupported formats instead of
    silently producing incorrect records.
    """

    pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"
        r"\s+(?P<severity>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)"
        r"\s+(?:(?P<service>[\w.-]+):\s*)?"
        r"(?P<message>.+)$",
        re.IGNORECASE,
    )

    records = []

    for line_number, line in enumerate(payload.splitlines(), start=1):
        if not line.strip():
            continue

        match = pattern.match(line.strip())

        if not match:
            raise ValueError(
                f"Unsupported log format at line {line_number}"
            )

        records.append(match.groupdict())

    if not records:
        raise ValueError("No log records found")

    return records


def parse_metrics(payload: str) -> list[dict[str, Any]]:
    """Parse JSON metrics or basic Prometheus samples."""

    stripped = payload.strip()

    if stripped.startswith(("{", "[")):
        return parse_json(payload)

    pattern = re.compile(
        r'^([a-zA-Z_:][a-zA-Z0-9_:]*)'
        r'(?:\{([^}]*)\})?\s+'
        r'(-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$'
    )

    records = []

    for line_number, line in enumerate(payload.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        match = pattern.match(line)

        if not match:
            raise ValueError(
                f"Unsupported metric format at line {line_number}"
            )

        metric_name = match.group(1)
        label_text = match.group(2)
        value = float(match.group(3))

        labels = {}

        if label_text:
            for key, label_value in re.findall(
                r'(\w+)="([^"]*)"',
                label_text,
            ):
                labels[key] = label_value

        records.append({
            "metric_name": metric_name,
            "labels": labels,
            "value": value,
        })

    if not records:
        raise ValueError("No metric records found")

    return records


# ============================================================
# RECORD NORMALIZATION
# ============================================================

def normalize_record(
    record: dict[str, Any],
    input_format: str = "JSON",
) -> CanonicalEvent:
    """Convert one raw record into a CanonicalEvent."""

    if not isinstance(record, dict):
        raise TypeError("Record must be a dictionary")

    canonical = {}

    for field_name in FIELD_ALIASES:
        canonical[field_name] = _find_alias(
            record,
            field_name,
        )

    severity = _normalize_severity(
        canonical.get("severity")
    )

    event_type = _infer_event_type(
        record,
        input_format,
    )

    known_aliases = set()

    for aliases in FIELD_ALIASES.values():
        known_aliases.update(
            _normalized_key(alias)
            for alias in aliases
        )

    known_aliases.update({
        "event_id",
        "event_type",
        "type",
        "raw",
        "tags",
    })

    attributes = {}

    for key, value in record.items():
        if _normalized_key(key) not in known_aliases:
            attributes[key] = value

    # Preserve original fields for future rules.
    attributes.setdefault("input_format", input_format.upper())

    return CanonicalEvent(
        event_id=record.get("event_id"),
        timestamp=canonical.get("timestamp"),
        event_type=record.get("event_type", event_type),
        severity=severity,
        source=record.get("source"),
        service=canonical.get("service"),
        component=canonical.get("component"),
        environment=canonical.get("environment"),
        message=canonical.get("message"),
        exception_type=canonical.get("exception_type"),
        stack_trace=canonical.get("stack_trace"),
        trace_id=canonical.get("trace_id"),
        span_id=canonical.get("span_id"),
        request_id=canonical.get("request_id"),
        attributes=attributes,
        tags=record.get("tags") or [],
        raw=record,
    )


# ============================================================
# PUBLIC NORMALIZATION API
# ============================================================

def normalize_input(
    input_format: str,
    payload: str,
) -> list[CanonicalEvent]:
    """Parse and normalize an entire input payload."""

    fmt = str(input_format).strip().upper()

    if not isinstance(payload, str):
        raise TypeError("Payload must be a string")

    if not payload.strip():
        raise ValueError("Empty input")

    if fmt == "JSON":
        records = parse_json(payload)

    elif fmt == "CSV":
        records = parse_csv(payload)

    elif fmt == "XML":
        records = parse_xml(payload)

    elif fmt == "LOGS":
        records = parse_logs(payload)

    elif fmt == "METRICS":
        records = parse_metrics(payload)

    else:
        raise NotImplementedError(
            f"Unsupported input format: {fmt}"
        )

    return [
        normalize_record(record, fmt)
        for record in records
    ]