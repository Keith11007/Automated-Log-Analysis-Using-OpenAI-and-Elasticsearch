"""crrreating the Flask app and keep route handlers 

"""

from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, request, send_from_directory

from abuseipdb_service import lookup_abuseipdb
from data_service import current_logs, ingest_uploaded_logs, source_snapshot
from elastic_service import connect_to_elasticsearch
from log_processing import build_stats
from openai_service import CategorizationError, build_openai_analysis, summarize_openai_error
from settings import BASE_DIR, DEFAULT_LIMIT, INDEX_FILE, STATE


def create_app() -> Flask:
    """Build the Flask app """
    app = Flask(__name__)

    @app.get("/")
    def home() -> Any:
        # The my homeeeee
        return send_from_directory(BASE_DIR, INDEX_FILE.name)

    @app.get("/health")
    def health() -> Any:
        # A health status 
        count, source, error, label = source_snapshot()
        return jsonify(
            {
                "status": "ok",
                "source": source,
                "source_label": label,
                "log_count": count,
                "error": error,
                "elasticsearch_connected": STATE["es"]["connected"],
                "uploaded_loaded": bool(STATE["uploaded_logs"]),
            }
        )

    @app.post("/connect-elasticsearch")
    def connect_elasticsearch() -> Any:
    
        payload = request.get_json(silent=True) or {}
        result = connect_to_elasticsearch(
            raw_url=str(payload.get("url", "")).strip(),
            username=str(payload.get("username", "")).strip(),
            password=str(payload.get("password", "")),
            index_pattern=str(payload.get("index", "logs-*")).strip() or "logs-*",
        )
        return jsonify(result)

    @app.post("/upload-logs")
    def upload_logs() -> Any:
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return jsonify({"ok": False, "message": "Choose a log file first."}), 400

        try:
            
            result = ingest_uploaded_logs(uploaded.filename, uploaded.read())
        except CategorizationError as exc:
            return jsonify({"ok": False, "message": str(exc), "ai_error": str(exc)}), 502

    
        status = result.pop("status", 200)
        return jsonify(result), status

    @app.post("/abuseipdb-check")
    def abuseipdb_check() -> Any:
        payload = request.get_json(silent=True) or {}
        result = lookup_abuseipdb(str(payload.get("ip", "")).strip())
        status = int(result.pop("status", 200))
        return jsonify(result), status

    @app.get("/get-logs")
    def api_get_logs() -> Any:
        # get looooogs
        limit = request.args.get("limit", default=DEFAULT_LIMIT, type=int)
        query_text = request.args.get("q", default="", type=str)
        severity = request.args.get("severity", default="", type=str)
        logs, source, error, label = current_logs(limit=limit, query_text=query_text, severity=severity)
        return jsonify({"logs": logs, "source": source, "source_label": label, "error": error})

    @app.get("/stats")
    def api_stats() -> Any:
        # Stats
        logs, source, error, label = current_logs(limit=None)
        stats = build_stats(logs)
        stats["source"] = source
        stats["source_label"] = label
        stats["error"] = error
        return jsonify(stats)

    @app.post("/chat")
    def api_chat() -> Any:
        payload = request.get_json(silent=True) or {}
        # Re-apply the current UI filters before asking OpenAI, so the answer
        # matches what the user is looking at.
        search_filter = str(payload.get("search", "")).strip()
        severity_filter = str(payload.get("severity", "")).strip()
        logs, source, error, label = current_logs(limit=None, query_text=search_filter, severity=severity_filter)

        try:
            result = build_openai_analysis(
                query=str(payload.get("query", "")).strip(),
                logs=logs,
                selected_log=payload.get("log") if isinstance(payload.get("log"), dict) else None,
                source_label=label,
            )
            return jsonify(
                {
                    "response": result["text"],
                    "source": source,
                    "source_label": label,
                    "error": error,
                    "ai_used": True,
                    "ai_error": None,
                    "model": result["model"],
                }
            )
        except Exception as exc:
            return jsonify(
                {
                    "response": "",
                    "source": source,
                    "source_label": label,
                    "error": error,
                    "ai_used": False,
                    "ai_error": summarize_openai_error(exc),
                    "model": None,
                }
            )

    return app
