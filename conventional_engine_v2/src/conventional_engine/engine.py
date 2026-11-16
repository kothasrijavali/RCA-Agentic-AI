import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from datetime import datetime


def _records(value):
    if isinstance(value, dict):
        return [value]

    if isinstance(value, list) and all(isinstance(x, dict) for x in value):
        return value

    raise ValueError("JSON must be an object or array of objects")


def _parse(fmt, payload):
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("Empty input")

    if fmt == "JSON":
        try:
            return _records(json.loads(payload))

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e

    if fmt == "CSV":
        reader = csv.DictReader(io.StringIO(payload))

        if not reader.fieldnames:
            raise ValueError("CSV header required")

        return [dict(r) for r in reader]

    if fmt == "XML":
        try:
            root = ET.fromstring(payload)

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML: {e}") from e

        if not list(root):
            raise ValueError("XML root must contain record elements")

        def val(el):
            if not list(el):
                return (el.text or "").strip()

            out = {}

            for c in el:
                v = val(c)

                if c.tag in out:
                    if not isinstance(out[c.tag], list):
                        out[c.tag] = [out[c.tag]]

                    out[c.tag].append(v)

                else:
                    out[c.tag] = v

            return out

        return [
            val(c) if list(c) else {c.tag: val(c)}
            for c in root
        ]

    if fmt == "LOGS":
        out = []

        pat = re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"
            r"\s+(?P<sev>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)"
            r"\s+(?:(?P<svc>[\w.-]+):\s*)?(?P<msg>.+)$",
            re.I,
        )

        for n, line in enumerate(payload.splitlines(), 1):
            if not line.strip():
                continue

            m = pat.match(line.strip())

            if not m:
                raise NotImplementedError(
                    f"Unsupported log format at line {n}"
                )

            d = m.groupdict()
            ts = d["ts"].replace(" ", "T")

            try:
                datetime.fromisoformat(ts)

            except ValueError:
                raise ValueError(f"Invalid timestamp at line {n}")

            sev = d["sev"].upper()

            out.append({
                "timestamp": ts,
                "severity": "WARN" if sev == "WARNING" else sev,
                "service": d["svc"] or "UNKNOWN",
                "message": d["msg"].strip(),
            })

        if not out:
            raise ValueError("No log records")

        return out

    if fmt == "METRICS":
        if payload.lstrip().startswith(("{", "[")):
            return _records(json.loads(payload))

        out = []

        pat = re.compile(
            r'^([a-zA-Z_:][a-zA-Z0-9_:]*)'
            r'(?:\{([^}]*)\})?\s+'
            r'(-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$'
        )

        for line in payload.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            m = pat.match(line)

            if not m:
                raise NotImplementedError(
                    "Unsupported Prometheus metric sample"
                )

            labels = {}

            if m.group(2):
                for k, v in re.findall(
                    r'(\w+)="([^"]*)"',
                    m.group(2),
                ):
                    labels[k] = v

            out.append({
                "metric_name": m.group(1),
                "labels": labels,
                "value": float(m.group(3)),
            })

        if not out:
            raise ValueError("No metric samples")

        return out

    raise NotImplementedError(f"Unsupported input format: {fmt}")


def process(input_format, payload, context=None):
    fmt = str(input_format).upper()
    context = context or {}

    try:
        records = _parse(fmt, payload)

    except NotImplementedError as e:
        return {
            "status": "UNSUPPORTED",
            "input_format": fmt,
            "records": [],
            "issues": [],
            "reason": str(e),
        }

    except Exception as e:
        return {
            "status": "INVALID",
            "input_format": fmt,
            "records": [],
            "issues": [],
            "reason": str(e),
        }

    out = [dict(r) for r in records]
    issues = []

    def issue(cat, code, msg, sev="WARNING", i=None, field=None):
        issues.append({
            "category": cat,
            "code": code,
            "message": msg,
            "severity": sev,
            "record_index": i,
            "field": field,
        })

    # ------------------------------------------------------------------
    # API/backend checks
    # ------------------------------------------------------------------

    status_field = (
        context.get("api", {}).get(
            "status_code_field",
            "status_code",
        )
    )

    for i, r in enumerate(out):
        if status_field in r:
            try:
                code = int(r[status_field])

                if code >= 500:
                    issue(
                        "api",
                        "HTTP_SERVER_ERROR",
                        f"HTTP status {code} indicates server error",
                        "ERROR",
                        i,
                        status_field,
                    )

                elif code >= 400:
                    issue(
                        "api",
                        "HTTP_CLIENT_ERROR",
                        f"HTTP status {code} indicates client error",
                        "WARNING",
                        i,
                        status_field,
                    )

            except (TypeError, ValueError):
                issue(
                    "api",
                    "INVALID_HTTP_STATUS",
                    "HTTP status must be an integer",
                    "ERROR",
                    i,
                    status_field,
                )

    # ------------------------------------------------------------------
    # ETL checks
    # ------------------------------------------------------------------

    ec = context.get("etl", {})

    for i, r in enumerate(out):
        for f in ec.get("non_null_fields", []):
            if r.get(f) in (None, ""):
                issue(
                    "etl",
                    "NULL_REQUIRED_VALUE",
                    f"Required value '{f}' is null or empty",
                    "ERROR",
                    i,
                    f,
                )

    for key in ec.get("unique_keys", []):
        seen = set()

        for i, r in enumerate(out):
            v = r.get(key)

            if v is not None:
                try:
                    duplicate = v in seen
                    seen.add(v)

                except TypeError:
                    duplicate = False

                if duplicate:
                    issue(
                        "etl",
                        "DUPLICATE_KEY",
                        f"Duplicate value for '{key}'",
                        "WARNING",
                        i,
                        key,
                    )

    # ------------------------------------------------------------------
    # SRE known log patterns and metric thresholds
    # ------------------------------------------------------------------

    rules = [
        (
            "DATABASE_TIMEOUT",
            r"(database|db).*(timeout|timed out)",
        ),
        (
            "DATABASE_CONNECTION_REFUSED",
            r"(database|db).*(connection refused|connect refused)",
        ),
        (
            "NETWORK_CONNECTION_RESET",
            r"connection reset by peer",
        ),
        (
            "DNS_RESOLUTION_FAILURE",
            r"(dns|name) resolution failed|temporary failure in name resolution",
        ),
        (
            "NETWORK_UNREACHABLE",
            r"network is unreachable",
        ),
        (
            "SERVICE_UNAVAILABLE",
            r"service unavailable",
        ),
        (
            "REQUEST_TIMEOUT",
            r"request timed out|request timeout",
        ),
        (
            "OUT_OF_MEMORY",
            r"out of memory|memory exhausted",
        ),
        (
            "DISK_FULL",
            r"no space left on device|disk full",
        ),
        (
            "NULL_POINTER_EXCEPTION",
            r"nullpointerexception|null pointer exception",
        ),
        (
            "INTERNAL_SERVER_ERROR",
            r"internal server error",
        ),
    ]

    for i, r in enumerate(out):
        msg = str(r.get("message", ""))

        for name, pat in rules:
            if fmt == "LOGS" and re.search(pat, msg, re.I):
                r["detected_error"] = name

                issue(
                    "sre",
                    name,
                    f"Matched known operational pattern: {name}",
                    "ERROR",
                    i,
                    "message",
                )

                break

    for i, r in enumerate(out):
        name = r.get("metric_name")

        rule = (
            context.get("sre", {})
            .get("metric_thresholds", {})
            .get(name)
        )

        if rule:
            try:
                val = float(r["value"])

            except (KeyError, TypeError, ValueError):
                issue(
                    "sre",
                    "INVALID_METRIC_VALUE",
                    f"{name} has a non-numeric value",
                    "ERROR",
                    i,
                    "value",
                )

                continue

            if "max" in rule and val > float(rule["max"]):
                issue(
                    "sre",
                    "METRIC_ABOVE_THRESHOLD",
                    f"{name} exceeds configured maximum",
                    "ERROR",
                    i,
                    "value",
                )

            if "min" in rule and val < float(rule["min"]):
                issue(
                    "sre",
                    "METRIC_BELOW_THRESHOLD",
                    f"{name} is below configured minimum",
                    "WARNING",
                    i,
                    "value",
                )

    # ------------------------------------------------------------------
    # Data platform contracts
    # ------------------------------------------------------------------

    dp = context.get("data_platform", {})

    type_check = {
        "string": lambda x: isinstance(x, str),
        "number": lambda x: isinstance(x, (int, float))
        and not isinstance(x, bool),
        "integer": lambda x: isinstance(x, int)
        and not isinstance(x, bool),
        "boolean": lambda x: isinstance(x, bool),
        "object": lambda x: isinstance(x, dict),
        "array": lambda x: isinstance(x, list),
    }

    for i, r in enumerate(out):
        for f in dp.get("required_fields", []):
            if f not in r:
                issue(
                    "data_platform",
                    "MISSING_REQUIRED_FIELD",
                    f"Required field '{f}' missing",
                    "ERROR",
                    i,
                    f,
                )

        for f, t in dp.get("field_types", {}).items():
            if (
                f in r
                and t in type_check
                and not type_check[t](r[f])
            ):
                issue(
                    "data_platform",
                    "FIELD_TYPE_MISMATCH",
                    f"Field '{f}' does not match {t}",
                    "ERROR",
                    i,
                    f,
                )

    # ------------------------------------------------------------------
    # Enterprise reference validation
    # ------------------------------------------------------------------

    allowed = (
        context.get("enterprise", {})
        .get("allowed_values", {})
    )

    for i, r in enumerate(out):
        for f, values in allowed.items():
            if f in r and r[f] not in values:
                issue(
                    "enterprise",
                    "VALUE_NOT_IN_REFERENCE_SET",
                    f"Field '{f}' is outside configured reference values",
                    "ERROR",
                    i,
                    f,
                )

    return {
        "status": "SUCCESS",
        "input_format": fmt,
        "records": out,
        "issues": issues,
        "reason": None,
    }