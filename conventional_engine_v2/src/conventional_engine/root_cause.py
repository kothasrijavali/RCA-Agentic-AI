"""Rank root-cause candidates from deterministic findings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from conventional_engine.models import Finding


SEVERITY_WEIGHTS = {
    "CRITICAL": 5.0,
    "ERROR": 4.0,
    "WARNING": 2.0,
    "INFO": 1.0,
    "DEBUG": 0.5,
    "TRACE": 0.25,
    "UNKNOWN": 1.0,
}

CAUSE_KEYWORDS = {
    "database": [
        "database",
        "db",
        "sql",
        "connection pool",
        "deadlock",
    ],
    "network": [
        "network",
        "connection",
        "socket",
        "dns",
        "connectivity",
    ],
    "resource": [
        "memory",
        "oom",
        "disk",
        "resource",
        "file descriptor",
        "cpu",
    ],
    "configuration": [
        "configuration",
        "config",
        "environment variable",
        "setting",
    ],
    "dependency": [
        "dependency",
        "package",
        "module",
        "version",
        "import",
    ],
    "deployment": [
        "deployment",
        "release",
        "rollout",
        "version change",
    ],
    "timeout": [
        "timeout",
        "timed out",
        "deadline exceeded",
        "latency",
    ],
}


def _severity_weight(severity: Any) -> float:
    """Convert severity to a numeric weight."""

    if hasattr(severity, "value"):
        severity = severity.value

    return SEVERITY_WEIGHTS.get(
        str(severity).upper(),
        1.0,
    )


def _finding_text(finding: Finding) -> str:
    """Build searchable text from a finding."""

    parts = [
        str(getattr(finding, "rule_id", "") or ""),
        str(getattr(finding, "title", "") or ""),
        str(getattr(finding, "description", "") or ""),
        str(getattr(finding, "category", "") or ""),
    ]

    parts.extend(
        str(cause)
        for cause in getattr(finding, "probable_causes", [])
    )

    return " ".join(parts).lower()


def _cause_category(text: str) -> str:
    """Infer a broad cause category from finding text."""

    for category, keywords in CAUSE_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return category

    return "general"


def _is_symptom(finding: Finding) -> bool:
    """Identify findings that usually represent symptoms."""

    rule_id = str(
        getattr(finding, "rule_id", "")
    ).upper()

    symptom_rules = {
        "HTTP_ERROR",
        "HTTP_SERVER_ERROR",
        "APPLICATION_EXCEPTION",
        "OPERATION_TIMEOUT",
    }

    return rule_id in symptom_rules


def rank_root_causes(
    findings: list[Finding],
    correlations: dict[str, Any] | None = None,
    repository_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rank possible root causes using deterministic heuristics.

    This is a heuristic ranking, not proof of causality.
    """

    if not findings:
        return {
            "root_cause_candidates": [],
            "symptoms": [],
            "summary": "No findings were available for root-cause analysis.",
        }

    category_scores: dict[str, float] = defaultdict(float)
    category_findings: dict[str, list[Finding]] = defaultdict(list)

    symptoms: list[dict[str, Any]] = []

    for finding in findings:
        text = _finding_text(finding)
        category = _cause_category(text)

        severity_weight = _severity_weight(
            getattr(finding, "severity", "UNKNOWN")
        )

        confidence = float(
            getattr(finding, "confidence", 0.5) or 0.5
        )

        confidence = max(0.0, min(confidence, 1.0))

        score = severity_weight * confidence

        category_scores[category] += score
        category_findings[category].append(finding)

        if _is_symptom(finding):
            symptoms.append(
                {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": str(finding.severity),
                }
            )

    candidates: list[dict[str, Any]] = []

    for category, score in category_scores.items():
        related_findings = category_findings[category]

        evidence_event_ids = sorted(
            {
                event_id
                for finding in related_findings
                for event_id in finding.affected_event_ids
            }
        )

        causes = sorted(
            {
                cause
                for finding in related_findings
                for cause in finding.probable_causes
            }
        )

        candidates.append(
            {
                "category": category,
                "score": round(score, 4),
                "finding_count": len(related_findings),
                "finding_ids": [
                    finding.finding_id
                    for finding in related_findings
                ],
                "evidence_event_ids": evidence_event_ids,
                "possible_causes": causes,
                "confidence": round(
                    min(
                        0.95,
                        score / (score + 5.0),
                    ),
                    4,
                ),
            }
        )

    candidates.sort(
        key=lambda item: (
            -item["score"],
            item["category"],
        )
    )

    if candidates:
        summary = (
            f"Highest-ranked category: {candidates[0]['category']}. "
            "This is a heuristic candidate and requires verification."
        )
    else:
        summary = "No root-cause candidates could be ranked."

    if correlations:
        summary += (
            f" Correlation data contains "
            f"{correlations.get('total_correlations', 0)} correlation groups."
        )

    if repository_context:
        summary += (
            " Repository context was available for investigation."
        )

    return {
        "root_cause_candidates": candidates,
        "symptoms": symptoms,
        "summary": summary,
        "analysis_type": "deterministic_heuristic",
        "causality_confirmed": False,
    }