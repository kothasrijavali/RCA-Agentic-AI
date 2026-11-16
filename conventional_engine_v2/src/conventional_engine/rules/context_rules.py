"""Detection rules that use repository and runtime context."""

from __future__ import annotations

from typing import Any

from conventional_engine.models import CanonicalEvent, Finding
from conventional_engine.rules.base import DetectionRule


def _context_value(
    context: dict[str, Any] | None,
    *keys: str,
) -> Any:
    """Retrieve a value from context using case-insensitive keys."""

    if not isinstance(context, dict):
        return None

    for key in keys:
        if key in context and context[key] is not None:
            return context[key]

        for existing_key, value in context.items():
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
        str(getattr(event, "component", "") or ""),
        str(getattr(event, "service", "") or ""),
    ]

    raw = getattr(event, "raw", {}) or {}
    attributes = getattr(event, "attributes", {}) or {}

    if isinstance(raw, dict):
        parts.extend(str(value) for value in raw.values())

    if isinstance(attributes, dict):
        parts.extend(str(value) for value in attributes.values())

    return " ".join(parts).lower()


class MissingConfigurationRule(DetectionRule):
    rule_id = "MISSING_CONFIGURATION"
    rule_version = "1.0"
    title = "Missing Configuration"
    category = "CONFIGURATION"

    configuration_terms = (
        "missing configuration",
        "configuration not found",
        "config not found",
        "missing environment variable",
        "environment variable is not set",
        "undefined configuration",
        "required setting",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.configuration_terms):
            return None

        repository_context = _context_value(
            context,
            "repository_context",
            "repo_context",
        )

        config_files = []

        if isinstance(repository_context, dict):
            config_files = repository_context.get(
                "configuration_files",
                [],
            )

        return self.create_finding(
            event=event,
            description=(
                "The event suggests that required application "
                "configuration is missing or unavailable."
            ),
            severity="ERROR",
            confidence=0.85,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "A required environment variable is missing.",
                "Configuration was not loaded during startup.",
                "The deployment environment differs from expectations.",
            ],
            remediation=[
                "Identify the missing configuration key.",
                "Verify environment variables and configuration files.",
                "Compare configuration between working and failing environments.",
            ],
            metadata={
                "configuration_files": config_files,
            },
        )


class DependencyMismatchRule(DetectionRule):
    rule_id = "DEPENDENCY_MISMATCH"
    rule_version = "1.0"
    title = "Dependency Version or Compatibility Issue"
    category = "DEPENDENCY"

    dependency_terms = (
        "version conflict",
        "incompatible version",
        "dependency conflict",
        "module not found",
        "package not found",
        "cannot import",
        "no module named",
        "unsupported version",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.dependency_terms):
            return None

        repository_context = _context_value(
            context,
            "repository_context",
            "repo_context",
        )

        dependency_files = []

        if isinstance(repository_context, dict):
            dependency_files = repository_context.get(
                "dependency_files",
                [],
            )

        return self.create_finding(
            event=event,
            description=(
                "The event indicates a possible missing, incompatible, "
                "or conflicting software dependency."
            ),
            severity="ERROR",
            confidence=0.85,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "A required package is not installed.",
                "Installed dependency versions are incompatible.",
                "The runtime environment differs from the development environment.",
            ],
            remediation=[
                "Inspect the dependency manifest and lock file.",
                "Verify installed package versions.",
                "Rebuild the environment using the project's documented dependencies.",
            ],
            metadata={
                "dependency_files": dependency_files,
            },
        )


class DeploymentChangeRule(DetectionRule):
    rule_id = "RECENT_DEPLOYMENT_CHANGE"
    rule_version = "1.0"
    title = "Possible Recent Deployment Regression"
    category = "DEPLOYMENT"

    deployment_terms = (
        "deployment",
        "deployed",
        "release",
        "rollout",
        "new version",
        "version updated",
    )

    failure_terms = (
        "error",
        "failed",
        "failure",
        "exception",
        "unavailable",
        "crash",
    )

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        text = _event_text(event)

        if not any(term in text for term in self.failure_terms):
            return None

        deployment_context = _context_value(
            context,
            "deployment_context",
            "deployment",
        )

        deployment_detected = (
            isinstance(deployment_context, dict)
            and bool(
                _context_value(
                    deployment_context,
                    "recent_deployment",
                    "deployment_id",
                    "version",
                )
            )
        )

        event_mentions_deployment = any(
            term in text for term in self.deployment_terms
        )

        if not deployment_detected and not event_mentions_deployment:
            return None

        return self.create_finding(
            event=event,
            description=(
                "A failure occurred in a context that mentions or "
                "contains deployment information. A deployment regression "
                "is possible but not confirmed."
            ),
            severity="WARNING",
            confidence=0.65,
            field="message",
            observed_value=getattr(event, "message", None),
            probable_causes=[
                "A recent deployment introduced a regression.",
                "A configuration change affected runtime behavior.",
                "The new version is incompatible with a dependency.",
            ],
            remediation=[
                "Compare the current release with the previous known-good version.",
                "Review deployment and configuration changes.",
                "Check whether failures began after rollout.",
            ],
            metadata={
                "deployment_context_available": deployment_detected,
            },
        )


class RepositoryFileHintRule(DetectionRule):
    rule_id = "REPOSITORY_FILE_HINT"
    rule_version = "1.0"
    title = "Potentially Relevant Repository File"
    category = "REPOSITORY"

    def evaluate(
        self,
        event: CanonicalEvent,
        context: dict[str, Any] | None = None,
    ) -> Finding | None:
        repository_context = _context_value(
            context,
            "repository_context",
            "repo_context",
        )

        if not isinstance(repository_context, dict):
            return None

        files = repository_context.get("relevant_files", [])

        if not files:
            return None

        if not isinstance(files, list):
            return None

        # This rule does not claim that a file caused the issue.
        # It only records repository files that may help investigation.
        return self.create_finding(
            event=event,
            description=(
                "Repository context contains files that may be relevant "
                "to investigating this event."
            ),
            severity="INFO",
            confidence=0.5,
            field="repository_context",
            observed_value=files,
            probable_causes=[],
            remediation=[
                "Review the listed repository files for related implementation "
                "or configuration."
            ],
            metadata={
                "relevant_files": files,
                "is_investigation_hint": True,
            },
        )


def get_context_rules() -> list[DetectionRule]:
    """Return the default context-aware rule collection."""

    return [
        MissingConfigurationRule(),
        DependencyMismatchRule(),
        DeploymentChangeRule(),
        RepositoryFileHintRule(),
    ]