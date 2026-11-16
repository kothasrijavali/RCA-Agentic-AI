import json
from datetime import datetime, timezone

import pytest

from conventional_engine import (
    CanonicalEvent,
    EventType,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)


# ---------------------------------------------------------------------------
# CanonicalEvent tests
# ---------------------------------------------------------------------------

def test_canonical_event_creation():
    event = CanonicalEvent(
        event_type=EventType.LOG,
        severity=Severity.ERROR,
        service="payment-service",
        message="Payment request failed",
    )

    assert event.event_type == EventType.LOG
    assert event.severity == Severity.ERROR
    assert event.service == "payment-service"
    assert event.message == "Payment request failed"
    assert event.event_id


def test_canonical_event_from_dict_with_common_aliases():
    event = CanonicalEvent.from_dict({
        "time": "2026-11-04T10:30:00Z",
        "level": "error",
        "service_name": "checkout",
        "msg": "Request timed out",
        "request_id": "req-123",
    })

    assert event.severity == Severity.ERROR
    assert event.service == "checkout"
    assert event.message == "Request timed out"
    assert event.request_id == "req-123"
    assert event.timestamp is not None
    assert event.timestamp.tzinfo is not None


def test_canonical_event_preserves_unknown_fields():
    event = CanonicalEvent.from_dict({
        "message": "Database error",
        "custom_field": "custom_value",
        "region": "us-east-1",
    })

    assert event.attributes["custom_field"] == "custom_value"
    assert event.attributes["region"] == "us-east-1"


def test_canonical_event_serialization():
    event = CanonicalEvent(
        timestamp="2026-11-04T10:30:00Z",
        event_type="LOG",
        severity="ERROR",
        message="Something failed",
    )

    result = event.to_dict()

    assert result["event_type"] == "LOG"
    assert result["severity"] == "ERROR"
    assert result["message"] == "Something failed"
    assert result["timestamp"].endswith("+00:00")

    # Ensure the output can be JSON serialized.
    json.dumps(result)


def test_unknown_severity_falls_back_to_unknown():
    event = CanonicalEvent.from_dict({
        "severity": "SOMETHING_NEW",
        "message": "Unknown severity",
    })

    assert event.severity == Severity.UNKNOWN


def test_invalid_timestamp_raises_error():
    with pytest.raises(ValueError):
        CanonicalEvent(timestamp="not-a-valid-timestamp")


def test_attributes_must_be_dictionary():
    with pytest.raises(TypeError):
        CanonicalEvent(attributes=["not", "a", "dictionary"])


# ---------------------------------------------------------------------------
# Evidence tests
# ---------------------------------------------------------------------------

def test_evidence_creation():
    evidence = Evidence(
        event_id="event-1",
        source="application.log",
        field="message",
        observed_value="Connection refused",
        description="Connection failure observed",
    )

    assert evidence.event_id == "event-1"
    assert evidence.field == "message"
    assert evidence.evidence_id


def test_evidence_serialization():
    evidence = Evidence(
        event_id="event-1",
        file_path="src/database.py",
        line_number=42,
        description="Database connection error",
    )

    result = evidence.to_dict()

    assert result["event_id"] == "event-1"
    assert result["file_path"] == "src/database.py"
    assert result["line_number"] == 42

    json.dumps(result)


def test_evidence_line_number_must_be_positive():
    with pytest.raises(ValueError):
        Evidence(line_number=0)


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------

def test_finding_creation():
    finding = Finding(
        rule_id="DB_CONNECTION_TIMEOUT",
        title="Database connection timeout",
        description="A database connection timed out.",
        category="DATABASE",
        severity=Severity.ERROR,
        confidence=0.9,
    )

    assert finding.rule_id == "DB_CONNECTION_TIMEOUT"
    assert finding.severity == Severity.ERROR
    assert finding.confidence == 0.9
    assert finding.status == FindingStatus.DETECTED
    assert finding.finding_id


def test_finding_confidence_must_be_between_zero_and_one():
    with pytest.raises(ValueError):
        Finding(confidence=1.5)

    with pytest.raises(ValueError):
        Finding(confidence=-0.1)


def test_finding_accepts_evidence_objects():
    evidence = Evidence(
        event_id="event-123",
        description="Observed database timeout",
    )

    finding = Finding(
        rule_id="DATABASE_TIMEOUT",
        evidence=[evidence],
    )

    assert len(finding.evidence) == 1
    assert finding.evidence[0].event_id == "event-123"


def test_finding_accepts_evidence_dictionaries():
    finding = Finding(
        rule_id="DATABASE_TIMEOUT",
        evidence=[
            {
                "event_id": "event-456",
                "description": "Timeout in application log",
            }
        ],
    )

    assert len(finding.evidence) == 1
    assert isinstance(finding.evidence[0], Evidence)
    assert finding.evidence[0].event_id == "event-456"


def test_finding_serialization():
    finding = Finding(
        rule_id="HTTP_SERVER_ERROR",
        title="HTTP server error",
        category="HTTP",
        severity="ERROR",
        confidence=0.95,
        status="CONFIRMED",
        affected_event_ids=["event-1", "event-2"],
        affected_components=["api"],
        probable_causes=["Backend exception"],
        remediation=["Inspect backend logs"],
        created_at=datetime(2026, 11, 4, 10, 30, tzinfo=timezone.utc),
    )

    result = finding.to_dict()

    assert result["rule_id"] == "HTTP_SERVER_ERROR"
    assert result["severity"] == "ERROR"
    assert result["status"] == "CONFIRMED"
    assert result["confidence"] == 0.95
    assert result["affected_event_ids"] == ["event-1", "event-2"]

    json.dumps(result)


def test_finding_round_trip():
    original = Finding(
        rule_id="NETWORK_CONNECTION_RESET",
        title="Connection reset",
        severity=Severity.ERROR,
        confidence=0.8,
        evidence=[
            Evidence(
                event_id="event-1",
                description="Connection reset by peer",
            )
        ],
    )

    serialized = original.to_dict()
    restored = Finding.from_dict(serialized)

    assert restored.rule_id == original.rule_id
    assert restored.severity == original.severity
    assert restored.confidence == original.confidence
    assert len(restored.evidence) == 1
    assert restored.evidence[0].event_id == "event-1"