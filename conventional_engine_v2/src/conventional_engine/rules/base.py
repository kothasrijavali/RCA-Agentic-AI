"""Base interface for deterministic detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from conventional_engine.models import (
    CanonicalEvent,
    Finding,
)


class DetectionRule(ABC):
    """Abstract base class for all deterministic rules.

    Every rule should:
    - Have a unique rule_id
    - Have a version
    - Evaluate one canonical event
    - Return a Finding when it detects an issue
    - Return None when no issue is detected
    """

    rule_id: str = "BASE_RULE"
    rule_version: str = "1.0"

    title: str = "Base Detection Rule"
    category: str = "UNKNOWN"

    enabled: bool = True

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        """Evaluate an event and return a finding if applicable."""
        raise NotImplementedError

    def create_finding(
        self,
        event: CanonicalEvent,
        description: str,
        severity: str = "WARNING",
        confidence: float = 0.8,
        field: str | None = None,
        observed_value: Any = None,
        expected_value: Any = None,
        probable_causes: list[str] | None = None,
        remediation: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Create a standard evidence-backed finding."""

        from conventional_engine.models import Evidence

        evidence = Evidence(
            event_id=event.event_id,
            source=event.source,
            field=field,
            observed_value=observed_value,
            expected_value=expected_value,
            description=description,
            metadata={
                "rule_id": self.rule_id,
            },
        )

        component = event.component or event.service

        return Finding(
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            title=self.title,
            description=description,
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=[evidence],
            affected_event_ids=[event.event_id],
            affected_components=[component] if component else [],
            probable_causes=probable_causes or [],
            remediation=remediation or [],
            metadata=metadata or {},
        )