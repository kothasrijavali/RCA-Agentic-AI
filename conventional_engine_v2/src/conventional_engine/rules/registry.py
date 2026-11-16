"""Registry for managing and executing detection rules."""

from __future__ import annotations

from typing import Any, Iterable

from conventional_engine.models import CanonicalEvent, Finding
from conventional_engine.rules.base import DetectionRule


class RuleRegistry:
    """Stores and executes detection rules."""

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        """Register a detection rule.

        Raises:
            ValueError: If a rule with the same ID already exists.
        """

        if not isinstance(rule, DetectionRule):
            raise TypeError(
                "Registered rule must inherit from DetectionRule."
            )

        if not rule.rule_id:
            raise ValueError("Rule must have a non-empty rule_id.")

        if rule.rule_id in self._rules:
            raise ValueError(
                f"Rule '{rule.rule_id}' is already registered."
            )

        self._rules[rule.rule_id] = rule

    def register_many(
        self,
        rules: Iterable[DetectionRule],
    ) -> None:
        """Register multiple rules."""

        for rule in rules:
            self.register(rule)

    def get(self, rule_id: str) -> DetectionRule | None:
        """Get a rule by its ID."""

        return self._rules.get(rule_id)

    def unregister(self, rule_id: str) -> bool:
        """Remove a rule.

        Returns True if the rule existed and was removed.
        """

        return self._rules.pop(rule_id, None) is not None

    def enable(self, rule_id: str) -> bool:
        """Enable a registered rule."""

        rule = self.get(rule_id)

        if rule is None:
            return False

        rule.enabled = True
        return True

    def disable(self, rule_id: str) -> bool:
        """Disable a registered rule."""

        rule = self.get(rule_id)

        if rule is None:
            return False

        rule.enabled = False
        return True

    def list_rules(self) -> list[str]:
        """Return registered rule IDs."""

        return list(self._rules.keys())

    def execute(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Run all enabled rules against one canonical event."""

        findings: list[Finding] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                result = rule.evaluate(event, context)

            except Exception as exc:
                # A single failing rule should not stop other rules.
                # In production, this should also be logged.
                continue

            if result is None:
                continue

            if isinstance(result, Finding):
                findings.append(result)

            elif isinstance(result, list):
                findings.extend(
                    finding
                    for finding in result
                    if isinstance(finding, Finding)
                )

        return findings

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules