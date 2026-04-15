from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from elasticsearch import (
    AuthenticationException,
    AuthorizationException,
    BadRequestError,
    ConnectionError,
    Elasticsearch,
    NotFoundError,
    SSLError,
)
from flask import Flask, jsonify, request, send_from_directory
from openai import OpenAI


BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "index.html"
DEFAULT_LIMIT = 300
MAX_LIMIT = 1000
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIME_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b")

KEYWORDS = {
    "critical": ("ransomware", "malware", "sql injection", "reverse shell", "credential dumping"),
    "high": ("unauthorized", "brute force", "powershell", "port scan", "xss", "lateral movement"),
    "warning": ("failed", "error", "timeout", "warning", "blocked", "anomaly"),
}

STATE: dict[str, Any] = {
    "source": "none",
    "es": {
        "url": "",
        "username": "",
        "password": "",
        "index": "logs-*",
        "connected": False,
        "error": "",
    },
    "uploaded_logs": [],
    "uploaded_label": "Uploaded logs",
}


def load_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_env_file()
app = Flask(__name__)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> str:
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


def normalize_es_url(url: str) -> str:
    cleaned = url.strip()
    if cleaned and "://" not in cleaned:
        return f"http://{cleaned}"
    return cleaned


def candidate_es_urls(url: str) -> list[str]:
    cleaned = url.strip()
    if not cleaned:
        return [""]
    if "://" in cleaned:
        return [cleaned]
    return [f"https://{cleaned}", f"http://{cleaned}"]


def current_source_label() -> str:
    if STATE["source"] == "elasticsearch":
        return STATE["es"]["index"]
    if STATE["source"] == "upload":
        return STATE["uploaded_label"]
    return "No data source selected"


def summarize_openai_error(exc: Exception) -> str:
    lowered = str(exc).lower()
    if "insufficient_quota" in lowered or "429" in lowered:
        return "OpenAI quota is unavailable right now."
    if "invalid_api_key" in lowered or "incorrect_api_key" in lowered or "api key" in lowered:
        return "OpenAI API key is invalid or missing."
    if "rate limit" in lowered:
        return "OpenAI is rate-limiting requests right now. Try again shortly."
    if "timeout" in lowered:
        return "OpenAI timed out."
    return "OpenAI is unavailable right now."


def format_es_error(exc: Exception, index_pattern: str, username: str = "") -> str:
    lowered = str(exc).lower()
    if index_pattern.startswith(".security"):
        return (
            f"The index pattern {index_pattern} points to Elasticsearch's internal security index. "
            "Use your real log index instead."
        )
    if isinstance(exc, SSLError) or any(token in lowered for token in ("ssl", "tls", "handshake", "certificate_unknown")):
        return "Elasticsearch SSL/TLS handshake failed. Use the correct https:// URL and certificate settings."
    if isinstance(exc, AuthenticationException):
        user_text = f" for user {username}" if username else ""
        return f"Elasticsearch authentication failed{user_text}. Check the username and password."
    if isinstance(exc, AuthorizationException):
        return "Elasticsearch rejected this account for the requested action."
    if isinstance(exc, NotFoundError) or "no such index" in lowered:
        return f"Elasticsearch index pattern {index_pattern} does not exist."
    if isinstance(exc, BadRequestError):
        return f"Elasticsearch rejected the index pattern {index_pattern}. Check the name or wildcard."
    if isinstance(exc, ConnectionError):
        return "Could not reach Elasticsearch. Check the URL, port, and whether the cluster is running."
    return f"Elasticsearch connection failed: {exc}"


def es_client(config: dict[str, Any] | None = None) -> Elasticsearch:
    cfg = config or STATE["es"]
    options: dict[str, Any] = {
        "hosts": [cfg["url"]],
        "request_timeout": 20,
        "verify_certs": False,
        "ssl_show_warn": False,
    }
    if cfg.get("username"):
        options["basic_auth"] = (cfg["username"], cfg.get("password", ""))
    return Elasticsearch(**options)


def validate_es(config: dict[str, Any]) -> dict[str, Any]:
    client = es_client(config)
    client.info()
    response = client.search(index=config["index"], size=1, query={"match_all": {}})
    hits = response.get("hits", {}) if isinstance(response, dict) else {}
    total = hits.get("total", 0)
    if isinstance(total, dict):
        document_count = int(total.get("value", 0))
    elif isinstance(total, int):
        document_count = total
    else:
        document_count = len(hits.get("hits", []) or [])
    return {"targets": [config["index"]], "document_count": document_count}


def extract_message(source: dict[str, Any]) -> str:
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


def classify_log(message: str, level: str) -> tuple[str, list[str], int]:
    lowered = message.lower()
    reasons: list[str] = []
    score = 0

    if level in {"critical", "error"}:
        score += 2
    elif level == "warning":
        score += 1

    for severity, words in KEYWORDS.items():
        for word in words:
            if word in lowered:
                reasons.append(word)
                score += {"critical": 4, "high": 3, "warning": 2}[severity]

    if score >= 6:
        classification = "critical"
    elif score >= 4:
        classification = "high"
    elif score >= 2:
        classification = "warning"
    else:
        classification = "info"
    return classification, sorted(set(reasons)), score


def normalize_log(entry: dict[str, Any], index: int) -> dict[str, Any]:
    message = extract_message(entry)
    nested_log = entry.get("log") if isinstance(entry.get("log"), dict) else {}
    event = entry.get("event") if isinstance(entry.get("event"), dict) else {}
    raw_level = str(entry.get("level") or nested_log.get("level") or "info").lower()
    classification, reasons, score = classify_log(message, raw_level)
    return {
        "id": str(entry.get("id") or entry.get("_id") or f"log-{index}"),
        "timestamp": normalize_timestamp(entry.get("@timestamp") or entry.get("timestamp") or event.get("created")),
        "source": extract_source_name(entry),
        "ip": extract_ip(entry, message),
        "message": message,
        "level": raw_level,
        "classification": classification,
        "score": score,
        "reasons": reasons,
    }


def parse_text_lines(text: str, source_name: str) -> list[dict[str, Any]]:
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
    reader = csv.DictReader(io.StringIO(text))
    logs = []
    for index, row in enumerate(reader, 1):
        payload = {key: value for key, value in row.items() if value not in ("", None)}
        payload.setdefault("source", source_name)
        logs.append(normalize_log(payload, index))
    return logs


def parse_uploaded_content(filename: str, text: str) -> list[dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    source_name = Path(filename).stem or "uploaded"
    if suffix == ".csv":
        return parse_csv_text(text, source_name)
    if suffix == ".json":
        return parse_json_text(text, source_name)
    if suffix in {".jsonl", ".ndjson"}:
        return parse_jsonl_text(text, source_name)
    try:
        return parse_json_text(text, source_name)
    except json.JSONDecodeError:
        return parse_text_lines(text, source_name)


def filter_logs(logs: list[dict[str, Any]], query_text: str, limit: int) -> list[dict[str, Any]]:
    query = query_text.strip().lower()
    if query:
        logs = [log for log in logs if query in json.dumps(log, default=str).lower()]
    logs = sorted(logs, key=lambda item: item["timestamp"], reverse=True)
    return logs[: min(max(limit, 1), MAX_LIMIT)]


def fetch_es_logs(limit: int, query_text: str) -> list[dict[str, Any]]:
    query: dict[str, Any]
    if query_text.strip():
        query = {
            "simple_query_string": {
                "query": query_text,
                "fields": ["message^3", "event.original^2", "host.name", "service.name", "source", "*"],
                "lenient": True,
            }
        }
    else:
        query = {"match_all": {}}

    response = es_client().search(
        index=STATE["es"]["index"],
        size=min(max(limit, 1), MAX_LIMIT),
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        query=query,
    )
    hits = response.get("hits", {}).get("hits", [])
    logs = []
    for index, hit in enumerate(hits, 1):
        source = hit.get("_source", {})
        source["_id"] = hit.get("_id")
        logs.append(normalize_log(source, index))
    return logs


def current_logs(limit: int = DEFAULT_LIMIT, query_text: str = "") -> tuple[list[dict[str, Any]], str, str | None, str]:
    if STATE["source"] == "upload" and STATE["uploaded_logs"]:
        return filter_logs(STATE["uploaded_logs"], query_text, limit), "upload", None, STATE["uploaded_label"]

    if STATE["source"] == "elasticsearch":
        if not STATE["es"]["connected"]:
            return [], "elasticsearch", STATE["es"]["error"] or "Elasticsearch is not connected.", STATE["es"]["index"]
        try:
            return fetch_es_logs(limit, query_text), "elasticsearch", None, STATE["es"]["index"]
        except Exception as exc:
            message = format_es_error(exc, STATE["es"]["index"], STATE["es"]["username"])
            STATE["es"]["connected"] = False
            STATE["es"]["error"] = message
            return [], "elasticsearch", message, STATE["es"]["index"]

    return [], "none", "Connect to Elasticsearch or upload logs to begin.", "No data source selected"


def build_stats(logs: list[dict[str, Any]]) -> dict[str, Any]:
    by_class = Counter(log["classification"] for log in logs)
    by_ip = Counter(log["ip"] for log in logs if log["ip"] != "unknown")
    top_sources = Counter(log["source"] for log in logs if log["source"] != "unknown")
    alerts = sorted(
        [log for log in logs if log["classification"] in {"critical", "high", "warning"}],
        key=lambda item: (item["score"], item["timestamp"]),
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


def build_openai_analysis(query: str, logs: list[dict[str, Any]], selected_log: dict[str, Any] | None, source_label: str) -> dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY.")
    payload = {
        "source": source_label,
        "query": query or "Summarize the current dataset.",
        "selected_log": selected_log,
        "stats": build_stats(logs),
        "logs": [
            {
                "timestamp": log["timestamp"],
                "source": log["source"],
                "ip": log["ip"],
                "classification": log["classification"],
                "message": log["message"],
            }
            for log in logs[:20]
        ],
    }
    client = OpenAI(api_key=api_key, timeout=60.0)
    response = client.responses.create(
        model=OPENAI_MODEL,
        input=[
            {
                "role": "system",
                "content": (
                    "You are a professional SOC analyst. Answer directly, summarize risk clearly, "
                    "and give practical next steps based only on the provided log data. "
                    "Format the answer as clean Markdown with short section headings, concise numbered or bulleted lists, "
                    "and no tables or code fences."
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=True)},
        ],
        temperature=0.2,
    )
    text = getattr(response, "output_text", "").strip()
    if not text:
        raise RuntimeError("OpenAI returned an empty response.")
    return {"text": text, "model": OPENAI_MODEL}


@app.get("/")
def home() -> Any:
    return send_from_directory(BASE_DIR, INDEX_FILE.name)


@app.get("/health")
def health() -> Any:
    logs, source, error, label = current_logs(limit=20)
    return jsonify(
        {
            "status": "ok",
            "source": source,
            "source_label": label,
            "log_count": len(logs),
            "error": error,
            "elasticsearch_connected": STATE["es"]["connected"],
            "uploaded_loaded": bool(STATE["uploaded_logs"]),
        }
    )


@app.post("/connect-elasticsearch")
def connect_elasticsearch() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get("url", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    index_pattern = str(payload.get("index", "logs-*")).strip() or "logs-*"

    if not raw_url:
        STATE["es"] = {
            "url": "",
            "username": username,
            "password": password,
            "index": index_pattern,
            "connected": False,
            "error": "Elasticsearch URL cleared.",
        }
        STATE["source"] = "upload" if STATE["uploaded_logs"] else "none"
        return jsonify({"connected": False, "message": "Elasticsearch URL cleared."})

    best_error = "Elasticsearch connection failed."
    best_details = ""
    attempted_config = None

    for candidate_url in candidate_es_urls(raw_url):
        config = {
            "url": normalize_es_url(candidate_url),
            "username": username,
            "password": password,
            "index": index_pattern,
            "connected": False,
            "error": "",
        }
        attempted_config = config
        try:
            validation = validate_es(config)
            config["connected"] = True
            STATE["es"] = config
            STATE["source"] = "elasticsearch"
            target_count = len(validation["targets"])
            target_label = "target" if target_count == 1 else "targets"
            return jsonify(
                {
                    "connected": True,
                    "message": (
                        f"Connected to Elasticsearch. Index pattern {index_pattern} matched "
                        f"{target_count} {target_label} and {validation['document_count']} documents."
                    ),
                    "config": {"url": config["url"], "index": index_pattern, "username": username},
                    "targets": validation["targets"],
                    "document_count": validation["document_count"],
                }
            )
        except Exception as exc:
            best_error = format_es_error(exc, index_pattern, username)
            best_details = str(exc)
            if isinstance(exc, (AuthenticationException, AuthorizationException, NotFoundError, BadRequestError, SSLError)):
                break

    STATE["es"] = attempted_config or {
        "url": normalize_es_url(raw_url),
        "username": username,
        "password": password,
        "index": index_pattern,
        "connected": False,
        "error": best_error,
    }
    STATE["es"]["connected"] = False
    STATE["es"]["error"] = best_error
    STATE["source"] = "upload" if STATE["uploaded_logs"] else "none"
    return jsonify(
        {
            "connected": False,
            "message": best_error,
            "details": best_details,
            "config": {"url": STATE["es"]["url"], "index": index_pattern, "username": username},
        }
    )


@app.post("/upload-logs")
def upload_logs() -> Any:
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"ok": False, "message": "Choose a log file first."}), 400

    text = uploaded.read().decode("utf-8", errors="ignore")
    logs = parse_uploaded_content(uploaded.filename, text)
    if not logs:
        return jsonify({"ok": False, "message": "No log entries could be extracted from that file."}), 400

    STATE["uploaded_logs"] = logs
    STATE["uploaded_label"] = f"Uploaded file: {uploaded.filename}"
    STATE["source"] = "upload"
    return jsonify({"ok": True, "message": f"Loaded {len(logs)} log entries from {uploaded.filename}.", "count": len(logs)})


@app.get("/get-logs")
def api_get_logs() -> Any:
    limit = request.args.get("limit", default=DEFAULT_LIMIT, type=int)
    query_text = request.args.get("q", default="", type=str)
    logs, source, error, label = current_logs(limit=limit, query_text=query_text)
    return jsonify({"logs": logs, "source": source, "source_label": label, "error": error})


@app.get("/stats")
def api_stats() -> Any:
    logs, source, error, label = current_logs(limit=MAX_LIMIT)
    stats = build_stats(logs)
    stats["source"] = source
    stats["source_label"] = label
    stats["error"] = error
    return jsonify(stats)


@app.post("/chat")
def api_chat() -> Any:
    payload = request.get_json(silent=True) or {}
    query = str(payload.get("query", "")).strip()
    selected_log = payload.get("log") if isinstance(payload.get("log"), dict) else None
    logs, source, error, label = current_logs(limit=MAX_LIMIT)

    if not logs:
        return jsonify(
            {
                "response": "",
                "source": source,
                "source_label": label,
                "error": error,
                "ai_used": False,
                "ai_error": "No logs are available to analyze.",
                "model": None,
            }
        )

    try:
        result = build_openai_analysis(query=query, logs=logs, selected_log=selected_log, source_label=label)
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


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "8000"))
    app.run(debug=True, host=host, port=port)
