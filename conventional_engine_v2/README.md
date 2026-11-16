# Conventional Data Transformation Engine — Starter v0.1

This is the deterministic (non-agentic) part of a hybrid data transformation system.
It does **not** perform full root-cause diagnosis. It parses supported inputs,
normalizes records, applies configured checks, and returns an explicit status.

## Supported input formats in v0.1

- `JSON`: JSON object or array of objects
- `CSV`: CSV text with a header row
- `XML`: repeated child elements under a root element
- `LOGS`: one log event per line, using the documented timestamp/severity format
- `METRICS`: JSON metric records or a basic Prometheus exposition format

## Setup

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate

pip install -e ".[dev]"
pytest
```

## Quick use

```python
from conventional_engine import process

result = process(
    input_format="JSON",
    payload='[{"service":"checkout","status_code":503}]',
    context={"api": {"status_code_field": "status_code"}}
)

print(result)
```

## Result statuses

- `SUCCESS`: supported input parsed and checks completed; inspect `issues` for warnings/errors.
- `UNSUPPORTED`: format or pattern is not supported by this conventional implementation.
- `INVALID`: malformed input or invalid structure.
- `ERROR`: unexpected internal engine failure.

`SUCCESS` does not mean that the underlying system is healthy. It means the engine processed the input. A detected issue is represented in `issues`.

## Configuration examples

```python
context = {
    "data_platform": {
        "required_fields": ["event_id", "service"],
        "field_types": {"event_id": "string", "latency_ms": "number"}
    },
    "etl": {
        "unique_keys": ["event_id"],
        "non_null_fields": ["event_id"]
    },
    "sre": {
        "metric_thresholds": {"cpu_usage_percent": {"max": 90}},
    },
    "enterprise": {
        "allowed_values": {"region": ["ap-south-1", "us-east-1"]}
    }
}
```

The checks are configuration-driven. Do not assume a field is required, a metric is unhealthy,
or a value is invalid unless a contract or threshold says so.

## v0.1 limitations

- Log parsing supports a deliberately narrow, documented format. Real repositories use many
  formats; add parsers based on observed examples rather than guessing.
- Prometheus parsing supports basic `name{labels} value` samples; comments and metadata lines
  are ignored.
- XML parsing treats each direct child of the root as one record.
- No AI/LLM call is made. The `UNSUPPORTED` status is the handoff signal for a separate router.
- This is a transformation/validation layer, not a full RCA engine.

## Planned increments

1. Core result contract, parsers, normalizer, configurable checks and tests (this starter).
2. Expand parser coverage using real examples from selected systems.
3. Add richer API/ETL/data-contract/lineage/enterprise consistency rules.
4. Add metrics and trace correlation, plus controlled fault-injection experiments.
5. Add benchmark datasets, accuracy/coverage/latency evaluation and integration adapter.


## Version 2: 67-scenario evaluation dataset

Run `python -m pytest -v`. The `test_data/v2_scenarios.json` file contains 67 deterministic cases across API/backend, ETL, SRE/DevOps, data platform, and enterprise consistency. Each case records input, configuration, expected status and expected issue code. Passing tests verifies these scenarios only; it does not establish broad real-world accuracy. No AI agent or LLM is invoked.
