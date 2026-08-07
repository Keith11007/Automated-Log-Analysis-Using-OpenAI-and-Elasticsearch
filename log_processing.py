"""Parse raw log files and normalize every entry into one dashboard shape."""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from settings import CLASSIFICATION_SCORES, VALID_CLASSIFICATIONS


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIME_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b")


def now_iso() -> str:
    """Return the current UTC time in the same text format used by log rows."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> str:
    """Accept common timestamp shapes and fall back to the current time."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(value, tz=timezone.utc)
            return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return now_iso()
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return now_iso()


def extract_message(source: dict[str, Any]) -> str:
    """Look through common log fields to find the best human-readable message."""
    nested_event = source.get("event") if isinstance(source.get("event"), dict) else {}
    nested_log = source.get("log") if isinstance(source.get("log"), dict) else {}
    for value in (
        source.get("message"),
        nested_log.get("message"),
        source.get("summary"),
        nested_event.get("original"),
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return json.dumps(source, default=str)


def extract_ip(source: dict[str, Any], message: str) -> str:
    """Prefer structured IP fields, then fall back to finding an IP in text."""
    candidates = [
        source.get("ip"),
        source.get("src_ip"),
        source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else None,
        source.get("client", {}).get("ip") if isinstance(source.get("client"), dict) else None,
        source.get("host", {}).get("ip") if isinstance(source.get("host"), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    match = IP_PATTERN.search(message)
    return match.group(0) if match else "unknown"


def extract_source_name(source: dict[str, Any]) -> str:
    """Pull a useful source label from common ECS-style and custom fields."""
    candidates = [
        source.get("source"),
        source.get("component"),
        source.get("app"),
        source.get("event", {}).get("dataset") if isinstance(source.get("event"), dict) else None,
        source.get("service", {}).get("name") if isinstance(source.get("service"), dict) else None,
        source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def normalize_log(entry: dict[str, Any], index: int) -> dict[str, Any]:
    """Convert a raw event into the consistent structure used everywhere else."""
    message = extract_message(entry)
    nested_log = entry.get("log") if isinstance(entry.get("log"), dict) else {}
    event = entry.get("event") if isinstance(entry.get("event"), dict) else {}
    raw_level = str(entry.get("level") or nested_log.get("level") or "info").lower()
    return {
        "id": str(entry.get("id") or entry.get("_id") or f"log-{index}"),
        "timestamp": normalize_timestamp(entry.get("@timestamp") or entry.get("timestamp") or event.get("created")),
        "source": extract_source_name(entry),
        "ip": extract_ip(entry, message),
        "message": message,
        "level": raw_level,
        "classification": "info",
        "score": 0,
        "reasons": [],
        "classified_by": "openai",
    }


def parse_text_lines(text: str, source_name: str) -> list[dict[str, Any]]:
    """Treat each non-empty line as one log entry."""
    logs = []
    for index, line in enumerate((line.strip() for line in text.splitlines() if line.strip()), 1):
        timestamp = TIME_PATTERN.search(line)
        payload = {
            "id": f"text-{index}",
            "timestamp": timestamp.group(0) if timestamp else now_iso(),
            "source": source_name,
            "message": line,
        }
        logs.append(normalize_log(payload, index))
    return logs


def parse_json_text(text: str, source_name: str) -> list[dict[str, Any]]:
    """Parse JSON files that are either one object, a list, or `{logs: [...]}`."""
    parsed = json.loads(text)
    if isinstance(parsed, dict):
        items = parsed.get("logs") if isinstance(parsed.get("logs"), list) else [parsed]
    elif isinstance(parsed, list):
        items = parsed
    else:
        items = [parsed]
    return [
        normalize_log(item if isinstance(item, dict) else {"message": str(item), "source": source_name}, index)
        for index, item in enumerate(items, 1)
    ]


def parse_jsonl_text(text: str, source_name: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON, with a plain-text fallback per bad line."""
    logs: list[dict[str, Any]] = []
    for index, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
            entry = parsed if isinstance(parsed, dict) else {"message": str(parsed), "source": source_name}
            logs.append(normalize_log(entry, index))
        except json.JSONDecodeError:
            logs.extend(parse_text_lines(stripped, source_name))
    return logs


def parse_csv_text(text: str, source_name: str) -> list[dict[str, Any]]:
    """Convert each CSV row into the same normalized log structure."""
    reader = csv.DictReader(io.StringIO(text))
    logs = []
    for index, row in enumerate(reader, 1):
        payload = {key: value for key, value in row.items() if value not in ("", None)}
        payload.setdefault("source", source_name)
        logs.append(normalize_log(payload, index))
    return logs


def parse_uploaded_content(filename: str, text: str) -> list[dict[str, Any]]:
    """Choose the best parser based on file type, then fall back to plain text."""
    suffix = Path(filename).suffix.lower()
    source_name = Path(filename).stem or "uploaded"
    if suffix == ".csv":
        return parse_csv_text(text, source_name)
    if suffix == ".json":
        return parse_json_text(text, source_name)
    if suffix in {".jsonl", ".ndjson"}:
        return parse_jsonl_text(text, source_name)
    try:
        # Some `.log` or `.txt` exports are actually JSON; try that before
        # falling back to one-log-per-line parsing.
        return parse_json_text(text, source_name)
    except json.JSONDecodeError:
        return parse_text_lines(text, source_name)


def filter_logs(logs: list[dict[str, Any]], query_text: str, limit: int | None, severity: str = "") -> list[dict[str, Any]]:
    """Apply the dashboard's severity and free-text filters."""
    category = severity.strip().lower()
    if category in VALID_CLASSIFICATIONS - {"info"}:
        logs = [log for log in logs if log["classification"] == category]
    query = query_text.strip().lower()
    if query:
        logs = [log for log in logs if query in json.dumps(log, default=str).lower()]
    # Newest logs should appear first in the dashboard regardless of source.
    logs = sorted(logs, key=lambda item: item["timestamp"], reverse=True)
    if limit is None:
        return logs
    return logs[:max(limit, 1)]


def build_stats(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the summary numbers shown in the dashboard and sent to OpenAI."""
    by_class = Counter(log["classification"] for log in logs)
    by_ip = Counter(log["ip"] for log in logs if log["ip"] != "unknown")
    top_sources = Counter(log["source"] for log in logs if log["source"] != "unknown")
    # Alerts are the highest-risk rows the sidebar should draw attention to.
    alerts = sorted(
        [log for log in logs if log["classification"] in {"critical", "high", "warning"}],
        key=lambda item: (CLASSIFICATION_SCORES.get(item["classification"], 0), item["timestamp"]),
        reverse=True,
    )[:6]
    return {
        "total_logs": len(logs),
        "critical_count": by_class.get("critical", 0),
        "high_count": by_class.get("high", 0),
        "warning_count": by_class.get("warning", 0),
        "alerts_count": len(alerts),
        "alerts": alerts,
        "top_ips": dict(by_ip.most_common(5)),
        "top_sources": dict(top_sources.most_common(5)),
    }
