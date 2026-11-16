"""High-level Conventional Engine analysis pipeline.

This module wraps the legacy deterministic `process()` API and emits canonical
events/findings. Repository context extraction is intentionally lightweight and
safe: it reads common manifests/config files without executing project code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .engine import process
from .models import CanonicalEvent, EventType, Evidence, Finding, Severity


def _infer_event_type(fmt: str) -> EventType:
    return {
        "LOGS": EventType.LOG,
        "METRICS": EventType.METRIC,
        "JSON": EventType.UNKNOWN,
        "CSV": EventType.UNKNOWN,
        "XML": EventType.UNKNOWN,
    }.get(fmt.upper(), EventType.UNKNOWN)


def scan_repository(
    repo_path: str | Path,
    max_files: int = 5000,
) -> dict[str, Any]:
    """Extract basic repository context from filenames and common manifests.

    Does not execute code, install dependencies, or access the network.
    """
    root = Path(repo_path).resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")

    ignored = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
    }

    files: list[str] = []
    services: set[str] = set()
    dependencies: set[str] = set()
    config_files: list[str] = []

    manifests = {
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "pom.xml",
        "go.mod",
        "Cargo.toml",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }

    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue

        if not path.is_file():
            continue

        rel = str(path.relative_to(root))
        files.append(rel)

        if len(files) >= max_files:
            break

        if path.name in manifests or path.suffix.lower() in {".yaml", ".yml"}:
            config_files.append(rel)

            try:
                text = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )[:500_000]
            except OSError:
                continue

            # Extract service names from Compose-like YAML.
            for match in re.finditer(
                r"(?m)^\s{0,2}([A-Za-z0-9_.-]+):\s*$",
                text,
            ):
                candidate = match.group(1)

                if candidate.lower() not in {
                    "services",
                    "version",
                    "networks",
                    "volumes",
                }:
                    services.add(candidate)

            if path.name == "package.json":
                try:
                    data = json.loads(text)

                    dependencies.update(
                        (data.get("dependencies") or {}).keys()
                    )

                    dependencies.update(
                        (data.get("devDependencies") or {}).keys()
                    )

                except json.JSONDecodeError:
                    pass

            elif path.name == "requirements.txt":
                for line in text.splitlines():
                    line = line.strip()

                    if line and not line.startswith(("#", "-")):
                        dependency = re.split(
                            r"[<>=!~;]",
                            line,
                        )[0].strip()

                        if dependency:
                            dependencies.add(dependency)

    return {
        "repository_path": str(root),
        "file_count": len(files),
        "files": files,
        "services": sorted(services),
        "dependencies": sorted(dependencies),
        "config_files": sorted(config_files),
        "truncated": len(files) >= max_files,
    }


def analyze(
    input_format: str,
    payload: str,
    context: dict[str, Any] | None = None,
    repository_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run deterministic checks and return canonical events and findings."""
    combined_context = dict(context or {})
    repo_context = None

    if repository_path is not None:
        repo_context = scan_repository(repository_path)

        combined_context.setdefault(
            "repository",
            repo_context,
        )

    result = process(
        input_format,
        payload,
        combined_context,
    )

    fmt = str(input_format).upper()

    events: list[CanonicalEvent] = []
    findings: list[Finding] = []

    for idx, record in enumerate(result.get("records", [])):
        event_data = dict(record)

        event_data.setdefault(
            "event_type",
            _infer_event_type(fmt).value,
        )

        event_data.setdefault(
            "source",
            record.get("source") or record.get("service"),
        )

        event_data.setdefault(
            "message",
            record.get("message") or record.get("msg"),
        )

        event_data.setdefault(
            "severity",
            record.get("severity", "UNKNOWN"),
        )

        event_data.setdefault(
            "attributes",
            {
                k: v
                for k, v in record.items()
                if k not in {
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
                    "tags",
                    "raw",
                }
            },
        )

        event_data.setdefault("raw", record)

        try:
            events.append(
                CanonicalEvent.from_dict(event_data)
            )

        except (TypeError, ValueError):
            # Preserve legacy records if canonical conversion fails.
            events.append(
                CanonicalEvent(
                    event_type=_infer_event_type(fmt),
                    source=str(record.get("source", "")) or None,
                    message=str(record.get("message", record)),
                    raw=record,
                    attributes={"record_index": idx},
                )
            )

    issue_map = {
        "ERROR": Severity.ERROR,
        "CRITICAL": Severity.CRITICAL,
        "WARNING": Severity.WARNING,
        "INFO": Severity.INFO,
    }

    for issue in result.get("issues", []):
        record_index = issue.get("record_index")
        event_id = None

        if (
            isinstance(record_index, int)
            and 0 <= record_index < len(events)
        ):
            event_id = events[record_index].event_id

        observed_value = None

        if (
            isinstance(record_index, int)
            and 0 <= record_index < len(result.get("records", []))
            and issue.get("field")
        ):
            observed_value = result["records"][record_index].get(
                issue.get("field")
            )

        evidence = Evidence(
            event_id=event_id,
            source=issue.get("field"),
            field=issue.get("field"),
            observed_value=observed_value,
            description=issue.get("message", ""),
            metadata={
                "record_index": record_index,
                "legacy_issue": issue,
            },
        )

        findings.append(
            Finding(
                rule_id=str(
                    issue.get("code", "LEGACY_DETECTION")
                ),
                title=str(
                    issue.get("code", "Detected issue")
                ).replace("_", " ").title(),
                description=str(issue.get("message", "")),
                category=str(
                    issue.get("category", "UNKNOWN")
                ).upper(),
                severity=issue_map.get(
                    str(issue.get("severity", "WARNING")).upper(),
                    Severity.WARNING,
                ),
                confidence=0.8,
                evidence=[evidence],
                affected_event_ids=[event_id] if event_id else [],
                metadata={"legacy_issue": issue},
            )
        )

    return {
        "status": result.get("status", "UNKNOWN"),
        "input_format": fmt,
        "records": result.get("records", []),
        "issues": result.get("issues", []),
        "events": [
            event.to_dict()
            for event in events
        ],
        "findings": [
            finding.to_dict()
            for finding in findings
        ],
        "repository_context": repo_context,
        "reason": result.get("reason"),
    }


# Alias for callers preferring a pipeline-oriented API.
run_pipeline = analyze