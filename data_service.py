"""Coordinates whichever log source is currently active for the dashboard."""

from __future__ import annotations

from typing import Any

from elastic_service import fetch_es_logs, format_es_error
from log_processing import filter_logs, parse_uploaded_content
from openai_service import CategorizationError, classify_logs_with_openai
from settings import DEFAULT_LIMIT, STATE


def source_snapshot() -> tuple[int, str, str | None, str]:
    """summary of whats going on"""
    if STATE["source"] == "upload":
       
        return len(STATE["uploaded_logs"]), "upload", None, STATE["uploaded_label"]
    if STATE["source"] == "elasticsearch":
        
        error = None if STATE["es"]["connected"] else STATE["es"]["error"] or "Elasticsearch is not connected."
        return 0, "elasticsearch", error, STATE["es"]["index"]
    return 0, "none", "Connect to Elasticsearch or upload logs to begin.", "No data source selected"


def current_logs(limit: int | None = DEFAULT_LIMIT, query_text: str = "", severity: str = "") -> tuple[list[dict[str, Any]], str, str | None, str]:
    """Loads logs from the active source and apply dashboard filters."""
    if STATE["source"] == "upload" and STATE["uploaded_logs"]:
     
        return filter_logs(STATE["uploaded_logs"], query_text, limit, severity), "upload", None, STATE["uploaded_label"]

    if STATE["source"] != "elasticsearch":
        return [], "none", "Connect to Elasticsearch or upload logs to begin.", "No data source selected"

    if not STATE["es"]["connected"]:
        return [], "elasticsearch", STATE["es"]["error"] or "Elasticsearch is not connected.", STATE["es"]["index"]

    try:
        
        logs = fetch_es_logs(None if limit is None else limit, query_text)
        if severity.strip():
            logs = filter_logs(logs, "", limit, severity)
        return logs, "elasticsearch", None, STATE["es"]["index"]
    except CategorizationError as exc:
        return [], "elasticsearch", str(exc), STATE["es"]["index"]
    except Exception as exc:
        message = format_es_error(exc, STATE["es"]["index"], STATE["es"]["username"])
        STATE["es"]["connected"] = False
        STATE["es"]["error"] = message
        return [], "elasticsearch", message, STATE["es"]["index"]


def ingest_uploaded_logs(filename: str, content: bytes) -> dict[str, Any]:
    """do the same on uploaded logs"""
    logs = parse_uploaded_content(filename, content.decode("utf-8", errors="ignore"))
    if not logs:
        return {"ok": False, "message": "No log entries could be extracted from that file.", "status": 400}

    logs = classify_logs_with_openai(logs)
    STATE["uploaded_logs"] = logs
    STATE["uploaded_label"] = f"Uploaded file: {filename}"
    STATE["source"] = "upload"
    ai_count = sum(1 for log in logs if log.get("classified_by") == "openai")
    return {
        "ok": True,
        "message": f"Loaded {len(logs)} log entries from {filename}. OpenAI categorized {ai_count} entries.",
        "count": len(logs),
        "ai_categorized": ai_count,
    }
