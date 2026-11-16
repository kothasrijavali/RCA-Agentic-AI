"""Correlate related canonical events."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from conventional_engine.models import CanonicalEvent


CORRELATION_FIELDS = (
    "trace_id",
    "request_id",
    "correlation_id",
    "transaction_id",
    "session_id",
)


def _get_value(event: CanonicalEvent, key: str) -> Any:
    """Read a correlation value from event data."""

    containers = [
        getattr(event, "attributes", {}) or {},
        getattr(event, "raw", {}) or {},
        getattr(event, "metadata", {}) or {},
    ]

    for container in containers:
        if not isinstance(container, dict):
            continue

        if key in container and container[key] is not None:
            return container[key]

        for existing_key, value in container.items():
            if (
                str(existing_key).lower() == key.lower()
                and value is not None
            ):
                return value

    return None


def _event_timestamp(event: CanonicalEvent):
    """Return event timestamp if available."""

    return getattr(event, "timestamp", None)


def _event_service(event: CanonicalEvent) -> str | None:
    """Return service or component name."""

    service = (
        getattr(event, "service", None)
        or getattr(event, "component", None)
    )

    return str(service) if service else None


def correlate_by_identifier(
    events: list[CanonicalEvent],
) -> list[dict[str, Any]]:
    """Group events that share trace/request/correlation identifiers."""

    groups: dict[tuple[str, str], list[CanonicalEvent]] = defaultdict(list)

    for event in events:
        for field in CORRELATION_FIELDS:
            value = _get_value(event, field)

            if value is None:
                continue

            groups[(field, str(value))].append(event)

    correlations: list[dict[str, Any]] = []

    for (field, identifier), grouped_events in groups.items():
        unique_events = {
            event.event_id: event
            for event in grouped_events
        }

        if len(unique_events) < 2:
            continue

        correlations.append(
            {
                "correlation_type": field,
                "correlation_id": identifier,
                "event_ids": list(unique_events.keys()),
                "event_count": len(unique_events),
                "services": sorted(
                    {
                        service
                        for event in unique_events.values()
                        if (service := _event_service(event))
                    }
                ),
            }
        )

    return correlations


def correlate_by_time(
    events: list[CanonicalEvent],
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """Group events that occur within a time window.

    This is temporal correlation only; it does not prove causality.
    """

    timestamped_events = [
        event
        for event in events
        if _event_timestamp(event) is not None
    ]

    timestamped_events.sort(
        key=lambda event: _event_timestamp(event)
    )

    groups: list[list[CanonicalEvent]] = []
    current_group: list[CanonicalEvent] = []

    for event in timestamped_events:
        timestamp = _event_timestamp(event)

        if not current_group:
            current_group = [event]
            continue

        previous_timestamp = _event_timestamp(current_group[-1])

        if timestamp - previous_timestamp <= timedelta(
            seconds=window_seconds
        ):
            current_group.append(event)
        else:
            if len(current_group) >= 2:
                groups.append(current_group)

            current_group = [event]

    if len(current_group) >= 2:
        groups.append(current_group)

    return [
        {
            "correlation_type": "time_window",
            "event_ids": [
                event.event_id
                for event in group
            ],
            "event_count": len(group),
            "start_time": _event_timestamp(group[0]).isoformat(),
            "end_time": _event_timestamp(group[-1]).isoformat(),
            "services": sorted(
                {
                    service
                    for event in group
                    if (service := _event_service(event))
                }
            ),
        }
        for group in groups
    ]


def correlate_events(
    events: list[CanonicalEvent],
    time_window_seconds: int = 60,
) -> dict[str, Any]:
    """Run all supported correlation strategies."""

    identifier_correlations = correlate_by_identifier(events)

    time_correlations = correlate_by_time(
        events,
        window_seconds=time_window_seconds,
    )

    return {
        "identifier_correlations": identifier_correlations,
        "time_correlations": time_correlations,
        "total_correlations": (
            len(identifier_correlations)
            + len(time_correlations)
        ),
    }