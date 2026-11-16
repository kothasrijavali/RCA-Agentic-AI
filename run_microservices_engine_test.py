"""
Conventional Engine - Online Boutique Kubernetes log smoke test.

Run from the folder containing:
  conventional_engine_v2/src/
  microservices-demo/

1) Collect logs using collect_microservices_logs.ps1.
2) Run:
   $env:PYTHONPATH="conventional_engine_v2\src"
   python run_microservices_engine_test.py microservices-demo\microservices_logs_raw.txt

This is a smoke/integration test, not a full reliability or performance benchmark.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter


# Import existing Conventional Engine.
# No changes are made to the engine itself.
try:
    from conventional_engine import process
except ImportError as exc:
    print("Cannot import Conventional Engine.")
    print('Run from the project root and set:')
    print('$env:PYTHONPATH="conventional_engine_v2\\src"')
    raise exc


# Kubernetes log collector pod marker.
POD_MARKER = re.compile(
    r"^###\s*POD:\s*(.+?)\s*$",
    re.I
)


# Kubernetes timestamp prefix.
K8S_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<rest>.*)$"
)


# Conventional Engine supported log format.
ENGINE_LOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"
    r"\s+(?P<sev>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)"
    r"\s+(?:(?P<svc>[\w.-]+):\s*)?(?P<msg>.+)$",
    re.I,
)


def clean_timestamp(value):
    """Convert timestamps into YYYY-MM-DD HH:MM:SS format."""

    if not value:
        return None

    value = str(value).strip().replace("Z", "")
    value = value.split(".")[0]

    try:
        return datetime.fromisoformat(value).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None


def service_from_pod(pod_name):
    """Convert Kubernetes pod names into readable service names."""

    if not pod_name:
        return "UnknownService"

    # Remove Kubernetes deployment/hash suffixes.
    name = re.sub(
        r"-[a-z0-9]{5,10}-[a-z0-9]{5,10}$",
        "",
        pod_name,
        flags=re.I
    )

    name = re.sub(
        r"-[a-z0-9]{8,}$",
        "",
        name,
        flags=re.I
    )

    mapping = {
        "adservice": "AdService",
        "cartservice": "CartService",
        "checkoutservice": "CheckoutService",
        "currencyservice": "CurrencyService",
        "emailservice": "EmailService",
        "frontend": "Frontend",
        "loadgenerator": "LoadGenerator",
        "paymentservice": "PaymentService",
        "productcatalogservice": "ProductCatalogService",
        "recommendationservice": "RecommendationService",
        "redis-cart": "RedisCart",
        "shippingservice": "ShippingService",
    }

    return mapping.get(
        name.lower(),
        name.replace("-", " ").title().replace(" ", "")
    )


def parse_log(raw_line, current_pod):
    """Parse JSON, plain-text, or Kubernetes logs."""

    line = raw_line.strip()

    if not line:
        return None

    outer_timestamp = None

    # Extract Kubernetes timestamp prefix.
    match = K8S_PREFIX.match(line)

    if match:
        outer_timestamp = match.group("ts")
        line = match.group("rest")

    # ---------------------------------------------------------
    # Parse structured JSON logs.
    # ---------------------------------------------------------

    if line.startswith("{"):

        try:
            obj = json.loads(line)

        except json.JSONDecodeError:
            obj = None

        if isinstance(obj, dict):

            timestamp = (
                clean_timestamp(obj.get("time"))
                or clean_timestamp(outer_timestamp)
            )

            severity = str(
                obj.get(
                    "level",
                    obj.get("severity", "INFO")
                )
            ).upper()

            message = str(
                obj.get(
                    "message",
                    obj.get("msg", line)
                )
            ).replace("\n", " ")

            logger = str(
                obj.get(
                    "loggerName",
                    obj.get("logger", "")
                )
            )

            if logger:
                service = logger.split(".")[-1]
            else:
                service = service_from_pod(current_pod)

            allowed_levels = {
                "TRACE",
                "DEBUG",
                "INFO",
                "WARN",
                "WARNING",
                "ERROR",
                "FATAL",
                "CRITICAL",
            }

            if severity not in allowed_levels:
                severity = "INFO"

            if timestamp:

                normalized = (
                    f"{timestamp} {severity} "
                    f"{service}: {message}"
                )

                return {
                    "normalized": normalized,
                    "timestamp": timestamp,
                    "service": service,
                    "severity": (
                        "WARN"
                        if severity == "WARNING"
                        else severity
                    ),
                    "message": message,
                    "raw": raw_line,
                }

    # ---------------------------------------------------------
    # Parse already formatted plain-text logs.
    # ---------------------------------------------------------

    match = ENGINE_LOG.match(line)

    if match:

        timestamp = clean_timestamp(
            match.group("ts")
        )

        severity = match.group("sev").upper()

        service = (
            match.group("svc")
            or service_from_pod(current_pod)
        )

        message = match.group("msg").strip()

        if timestamp:

            normalized = (
                f"{timestamp} {severity} "
                f"{service}: {message}"
            )

            return {
                "normalized": normalized,
                "timestamp": timestamp,
                "service": service,
                "severity": (
                    "WARN"
                    if severity == "WARNING"
                    else severity
                ),
                "message": message,
                "raw": raw_line,
            }

    # ---------------------------------------------------------
    # Handle unstructured text with Kubernetes timestamp.
    # ---------------------------------------------------------

    timestamp = clean_timestamp(
        outer_timestamp
    )

    if timestamp:

        service = service_from_pod(
            current_pod
        )

        severity_match = re.search(
            r"\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b",
            line,
            re.I
        )

        severity = (
            severity_match.group(1).upper()
            if severity_match
            else "INFO"
        )

        message = line

        normalized = (
            f"{timestamp} {severity} "
            f"{service}: {message}"
        )

        return {
            "normalized": normalized,
            "timestamp": timestamp,
            "service": service,
            "severity": (
                "WARN"
                if severity == "WARNING"
                else severity
            ),
            "message": message,
            "raw": raw_line,
        }

    return None


def style_sheet(sheet):
    """Apply readable Excel formatting."""

    sheet.freeze_panes = "A2"

    if sheet.max_row:

        for cell in sheet[1]:

            cell.font = Font(
                bold=True,
                color="FFFFFF"
            )

            cell.fill = PatternFill(
                "solid",
                fgColor="1F4E78"
            )

    for column in sheet.columns:

        column_letter = get_column_letter(
            column[0].column
        )

        max_length = 0

        for cell in column:

            value = (
                ""
                if cell.value is None
                else str(cell.value)
            )

            max_length = max(
                max_length,
                min(len(value), 65)
            )

            cell.alignment = Alignment(
                wrap_text=True,
                vertical="top"
            )

        sheet.column_dimensions[
            column_letter
        ].width = max(
            14,
            min(max_length + 2, 67)
        )


def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python run_microservices_engine_test.py "
            "<raw-log-file>"
        )

        sys.exit(2)

    source_path = Path(
        sys.argv[1]
    )

    if not source_path.exists():

        print(
            f"Input log file not found: {source_path}"
        )

        print(
            "Collect logs first using "
            "collect_microservices_logs.ps1."
        )

        sys.exit(2)

    # ---------------------------------------------------------
    # Read raw logs.
    # ---------------------------------------------------------

    raw_lines = source_path.read_text(
        encoding="utf-8-sig",
        errors="replace"
    ).splitlines()

    normalized_records = []

    skipped = []

    current_pod = None

    # ---------------------------------------------------------
    # Normalize each line.
    # ---------------------------------------------------------

    for line_number, raw in enumerate(
        raw_lines,
        start=1
    ):

        marker = POD_MARKER.match(
            raw.strip()
        )

        if marker:

            current_pod = marker.group(1).strip()

            continue

        parsed = parse_log(
            raw,
            current_pod
        )

        if parsed:

            parsed["raw_line_number"] = (
                line_number
            )

            parsed["pod"] = (
                current_pod
                or "Pod name unavailable"
            )

            normalized_records.append(
                parsed
            )

        elif raw.strip():

            skipped.append([
                line_number,
                raw[:500]
            ])

    if not normalized_records:

        print(
            "No logs could be normalized. "
            "Check the raw log file and collector."
        )

        sys.exit(1)

    # ---------------------------------------------------------
    # Run existing Conventional Engine.
    # ---------------------------------------------------------

    normalized_text = "\n".join(
        record["normalized"]
        for record in normalized_records
    )

    result = process(
        "LOGS",
        normalized_text
    )

    # ---------------------------------------------------------
    # Extract engine result information.
    # ---------------------------------------------------------

    engine_records = (
        result.get("records", [])
        if isinstance(result, dict)
        else []
    )

    engine_issues = (
        result.get("issues", [])
        if isinstance(result, dict)
        else []
    )

    service_counts = Counter(
        record["service"]
        for record in normalized_records
    )

    severity_counts = Counter(
        record["severity"]
        for record in normalized_records
    )

    service_severity = Counter(
        (
            record["service"],
            record["severity"]
        )
        for record in normalized_records
    )

    error_logs = [
        record
        for record in normalized_records
        if record["severity"] in {
            "ERROR",
            "FATAL",
            "CRITICAL"
        }
    ]

    # ---------------------------------------------------------
    # Create Excel report.
    # ---------------------------------------------------------

    output_path = Path(
        "conventional_engine_microservices_report.xlsx"
    )

    wb = Workbook()

    # ---------------------------------------------------------
    # Summary sheet.
    # ---------------------------------------------------------

    summary = wb.active

    summary.title = "Summary"

    summary.append([
        "Conventional Engine - Online Boutique Kubernetes Log Smoke Test"
    ])

    summary.append([
        "Input file",
        str(source_path.resolve())
    ])

    summary.append([
        "Engine status",
        result.get("status", "UNKNOWN")
    ])

    summary.append([
        "Raw input lines",
        len(raw_lines)
    ])

    summary.append([
        "Normalized logs",
        len(normalized_records)
    ])

    summary.append([
        "Skipped/unparsed lines",
        len(skipped)
    ])

    summary.append([
        "Engine parsed records",
        len(engine_records)
    ])

    summary.append([
        "Engine rule detections",
        len(engine_issues)
    ])

    summary.append([
        "ERROR/FATAL/CRITICAL log messages",
        len(error_logs)
    ])

    summary.append([
        "Test scope",
        "Integration/smoke test of log ingestion "
        "and known-pattern checks."
    ])

    summary.append([
        "Limitations",
        "Not a service health check or performance benchmark. "
        "Detection only covers implemented rules."
    ])

    summary.append([
        "Engine status meaning",
        "SUCCESS means input parsing/check execution succeeded; "
        "it does not mean services are error-free."
    ])

    # ---------------------------------------------------------
    # Per-service summary.
    # ---------------------------------------------------------

    service_sheet = wb.create_sheet(
        "Service Summary"
    )

    service_sheet.append([
        "Service",
        "Total logs",
        "INFO",
        "DEBUG",
        "WARN",
        "ERROR",
        "FATAL",
        "CRITICAL"
    ])

    for service in sorted(
        service_counts
    ):

        service_sheet.append([
            service,
            service_counts[service],
            service_severity[(service, "INFO")],
            service_severity[(service, "DEBUG")],
            service_severity[(service, "WARN")],
            service_severity[(service, "ERROR")],
            service_severity[(service, "FATAL")],
            service_severity[(service, "CRITICAL")],
        ])

    # ---------------------------------------------------------
    # Engine detections sheet.
    # ---------------------------------------------------------

    detections = wb.create_sheet(
        "Engine Detections"
    )

    detections.append([
        "Issue #",
        "Category",
        "Rule Code",
        "Severity",
        "Message",
        "Record Index",
        "Field"
    ])

    if engine_issues:

        for index, issue in enumerate(
            engine_issues,
            start=1
        ):

            detections.append([
                index,
                issue.get("category"),
                issue.get("code"),
                issue.get("severity"),
                issue.get("message"),
                issue.get("record_index"),
                issue.get("field"),
            ])

    else:

        detections.append([
            "",
            "",
            "",
            "",
            "No implemented engine rules matched the collected logs.",
            "",
            ""
        ])

    # ---------------------------------------------------------
    # Error logs sheet.
    # ---------------------------------------------------------

    errors_sheet = wb.create_sheet(
        "Error Logs"
    )

    errors_sheet.append([
        "Raw line #",
        "Pod",
        "Service",
        "Timestamp",
        "Severity",
        "Message"
    ])

    for record in error_logs:

        errors_sheet.append([
            record["raw_line_number"],
            record["pod"],
            record["service"],
            record["timestamp"],
            record["severity"],
            record["message"]
        ])

    if not error_logs:

        errors_sheet.append([
            "",
            "",
            "",
            "",
            "",
            "No ERROR/FATAL/CRITICAL severity logs found."
        ])

    # ---------------------------------------------------------
    # Normalized logs sheet.
    # ---------------------------------------------------------

    all_logs = wb.create_sheet(
        "Normalized Logs"
    )

    all_logs.append([
        "Raw line #",
        "Pod",
        "Service",
        "Timestamp",
        "Severity",
        "Message",
        "Normalized log"
    ])

    for record in normalized_records:

        all_logs.append([
            record["raw_line_number"],
            record["pod"],
            record["service"],
            record["timestamp"],
            record["severity"],
            record["message"],
            record["normalized"]
        ])

    # ---------------------------------------------------------
    # Read Me sheet.
    # ---------------------------------------------------------

    readme = wb.create_sheet(
        "Read Me"
    )

    readme_data = [
        ["About this report"],

        [
            "Logs were collected from Online Boutique Kubernetes "
            "pods and normalized for Conventional Engine."
        ],

        [
            "Pod markers allow service attribution for plain-text "
            "logs that do not contain logger/service metadata."
        ],

        [
            "Engine Detections lists only issues returned by "
            "the engine's built-in known-pattern rules."
        ],

        [
            "Error Logs lists ERROR/FATAL/CRITICAL messages from "
            "log severity; these are not automatically engine rule detections."
        ],

        [
            "SUCCESS means processing completed, not that all "
            "services are healthy."
        ],

        [
            "This is a smoke/integration test. It does not inject "
            "faults, validate every failure mode, or benchmark latency/throughput."
        ],
    ]

    for row in readme_data:

        readme.append(
            row
        )

    # ---------------------------------------------------------
    # Skipped lines sheet.
    # ---------------------------------------------------------

    if skipped:

        skip_sheet = wb.create_sheet(
            "Skipped Lines"
        )

        skip_sheet.append([
            "Raw line #",
            "Raw text"
        ])

        for row in skipped:

            skip_sheet.append(
                row
            )

    # ---------------------------------------------------------
    # Format all Excel sheets.
    # ---------------------------------------------------------

    for sheet in wb.worksheets:

        style_sheet(
            sheet
        )

    # ---------------------------------------------------------
    # Save Excel report.
    # ---------------------------------------------------------

    wb.save(
        output_path
    )

    print(
        f"Engine status: {result.get('status')}"
    )

    print(
        f"Raw lines: {len(raw_lines)}"
    )

    print(
        f"Normalized logs: {len(normalized_records)}"
    )

    print(
        f"Skipped lines: {len(skipped)}"
    )

    print(
        f"Services identified: {len(service_counts)}"
    )

    print(
        f"Engine rule detections: {len(engine_issues)}"
    )

    print(
        f"ERROR/FATAL/CRITICAL logs: {len(error_logs)}"
    )

    print(
        f"Excel report saved: {output_path.resolve()}"
    )


if __name__ == "__main__":

    main()