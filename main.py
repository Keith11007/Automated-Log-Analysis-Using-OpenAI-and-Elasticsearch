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

from elasticsearch import Elasticsearch
from flask import Flask, jsonify, request, send_from_directory
from openai import OpenAI


BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "index.html"
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_TIMESTAMP_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b")

APP_STATE: dict[str, Any] = {
    "es_config": {
        "url": "",
        "username": "",
        "password": "",
        "index": "logs-*",
    },
    "active_source": "sample",
    "custom_logs": [],
    "custom_label": "Built-in sample logs",
}

KEYWORD_RULES = {
    "critical": [
        "ransomware",
        "malware",
        "data exfiltration",
        "sql injection",
        "privilege escalation",
        "remote code execution",
        "reverse shell",
        "credential dumping",
    ],
    "high": [
        "unauthorized",
        "forbidden",
        "brute force",
        "multiple failed login",
        "account locked",
        "suspicious",
        "powershell",
        "port scan",
        "xss",
        "denied",
        "persistence",
        "lateral movement",
    ],
    "medium": [
        "error",
        "timeout",
        "failed",
        "exception",
        "retry",
        "unusual",
        "warning",
        "spike",
        "blocked",
        "anomaly",
    ],
}

SAMPLE_LOGS = [
    {
        "id": "sample-1",
        "ip": "185.220.101.14",
        "message": "Multiple failed login attempts detected for admin account from remote host.",
        "timestamp": "2026-04-05T07:15:00Z",
        "source": "vpn-gateway",
        "level": "warning",
    },
    {
        "id": "sample-2",
        "ip": "10.0.14.22",
        "message": "User payroll-service generated repeated database timeout errors during report export.",
        "timestamp": "2026-04-05T07:18:00Z",
        "source": "finance-api",
        "level": "error",
    },
    {
        "id": "sample-3",
        "ip": "172.16.0.8",
        "message": "PowerShell encoded command execution blocked by endpoint policy.",
        "timestamp": "2026-04-05T07:22:00Z",
        "source": "edr-agent",
        "level": "critical",
    },
    {
        "id": "sample-4",
        "ip": "41.89.64.10",
        "message": "Firewall detected port scan against exposed SSH service.",
        "timestamp": "2026-04-05T07:25:00Z",
        "source": "firewall",
        "level": "warning",
    },
    {
        "id": "sample-5",
        "ip": "10.0.14.22",
        "message": "Application health check recovered after temporary upstream timeout.",
        "timestamp": "2026-04-05T07:31:00Z",
        "source": "finance-api",
        "level": "info",
    },
    {
        "id": "sample-6",
        "ip": "196.201.214.55",
        "message": "WAF flagged possible SQL injection payload on /login endpoint.",
        "timestamp": "2026-04-05T07:34:00Z",
        "source": "waf",
        "level": "critical",
    },
]


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
    if not value:
        return now_iso()

    if isinstance(value, str):
        return value

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return now_iso()

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    return str(value)


def extract_message(source: dict[str, Any]) -> str:
    nested_event = source.get("event") if isinstance(source.get("event"), dict) else {}
    for key in ("message", "log", "summary"):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    event_original = nested_event.get("original")
    if isinstance(event_original, str) and event_original.strip():
        return event_original.strip()

    return json.dumps(source, default=str)


def extract_ip(source: dict[str, Any], message: str = "") -> str:
    ip_paths = [
        source.get("ip"),
        source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else None,
        source.get("client", {}).get("ip") if isinstance(source.get("client"), dict) else None,
        source.get("host", {}).get("ip") if isinstance(source.get("host"), dict) else None,
        source.get("src_ip"),
    ]
    for value in ip_paths:
        if isinstance(value, str) and value.strip():
            return value.strip()

    match = IP_PATTERN.search(message)
    return match.group(0) if match else "unknown"


def extract_source_name(source: dict[str, Any]) -> str:
    candidates = [
        source.get("service", {}).get("name") if isinstance(source.get("service"), dict) else None,
        source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else None,
        source.get("agent", {}).get("name") if isinstance(source.get("agent"), dict) else None,
        source.get("source"),
        source.get("component"),
        source.get("app"),
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def severity_rank(level: str) -> int:
    order = {"critical": 4, "high": 3, "warning": 2, "medium": 2, "info": 1, "low": 1}
    return order.get(level.lower(), 0)


def classify_message(message: str, level: str = "") -> tuple[str, list[str], int]:
    lowered = message.lower()
    reasons: list[str] = []
    score = 0
    classification = "info"

    if level:
        if level.lower() in {"critical", "error"}:
            score += 2
        elif level.lower() == "warning":
            score += 1

    for severity, keywords in KEYWORD_RULES.items():
        for keyword in keywords:
            if keyword in lowered:
                reasons.append(keyword)
                score += {"critical": 4, "high": 3, "medium": 2}[severity]

    if "failed login" in lowered and ("multiple" in lowered or "repeated" in lowered):
        reasons.append("repeated failed authentication")
        score += 3

    if "blocked" in lowered and "powershell" in lowered:
        reasons.append("script execution attempt")
        score += 2

    if score >= 6:
        classification = "critical"
    elif score >= 4:
        classification = "high"
    elif score >= 2:
        classification = "warning"

    return classification, sorted(set(reasons)), score


def normalize_log(entry: dict[str, Any], index: int = 0) -> dict[str, Any]:
    message = extract_message(entry)
    event_data = entry.get("event") if isinstance(entry.get("event"), dict) else {}
    nested_log = entry.get("log") if isinstance(entry.get("log"), dict) else {}
    raw_level = str(entry.get("level") or nested_log.get("level") or "info").lower()
    classification, reasons, score = classify_message(message, raw_level)
    timestamp = normalize_timestamp(entry.get("timestamp") or entry.get("@timestamp") or event_data.get("created"))
    ip = extract_ip(entry, message)
    source_name = extract_source_name(entry)
    level = raw_level if raw_level and raw_level != "info" else classification

    return {
        "id": str(entry.get("id") or entry.get("_id") or f"log-{index}"),
        "ip": ip,
        "message": message,
        "timestamp": timestamp,
        "source": source_name,
        "level": level,
        "classification": classification,
        "score": score,
        "reasons": reasons,
        "raw": entry,
    }


def get_es_client() -> Elasticsearch | None:
    cfg = APP_STATE["es_config"]
    if not cfg.get("url"):
        return None

    options: dict[str, Any] = {"hosts": [cfg["url"]], "request_timeout": 15}
    if cfg.get("username"):
        options["basic_auth"] = (cfg["username"], cfg.get("password", ""))
    return Elasticsearch(**options)


def make_text_log(line: str, index: int, source_name: str) -> dict[str, Any]:
    timestamp_match = ISO_TIMESTAMP_PATTERN.search(line)
    ip_match = IP_PATTERN.search(line)
    payload = {
        "id": f"text-{index}",
        "timestamp": timestamp_match.group(0) if timestamp_match else now_iso(),
        "ip": ip_match.group(0) if ip_match else "unknown",
        "message": line.strip(),
        "source": source_name,
        "level": "info",
    }
    return normalize_log(payload, index)


def parse_text_blob(text: str, source_name: str = "manual-input") -> list[dict[str, Any]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return [make_text_log(line, index, source_name) for index, line in enumerate(lines, 1)]


def parse_json_payload(text: str, source_name: str) -> list[dict[str, Any]]:
    parsed = json.loads(text)
    if isinstance(parsed, dict):
        if isinstance(parsed.get("logs"), list):
            items = parsed["logs"]
        else:
            items = [parsed]
    elif isinstance(parsed, list):
        items = parsed
    else:
        return []
    return [normalize_log(item if isinstance(item, dict) else {"message": str(item), "source": source_name}, idx) for idx, item in enumerate(items, 1)]


def parse_jsonl_payload(text: str, source_name: str) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = []
    for index, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            logs.append(make_text_log(stripped, index, source_name))
            continue
        entry = parsed if isinstance(parsed, dict) else {"message": str(parsed), "source": source_name}
        logs.append(normalize_log(entry, index))
    return logs


def parse_csv_payload(text: str, source_name: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    logs: list[dict[str, Any]] = []
    for index, row in enumerate(reader, 1):
        payload = {key: value for key, value in row.items() if value not in (None, "")}
        if "source" not in payload:
            payload["source"] = source_name
        logs.append(normalize_log(payload, index))
    return logs


def parse_uploaded_content(filename: str, content: str) -> list[dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    source_name = Path(filename).stem or "uploaded-file"

    if suffix == ".csv":
        logs = parse_csv_payload(content, source_name)
    elif suffix in {".json"}:
        logs = parse_json_payload(content, source_name)
    elif suffix in {".jsonl", ".ndjson"}:
        logs = parse_jsonl_payload(content, source_name)
    else:
        try:
            logs = parse_json_payload(content, source_name)
        except json.JSONDecodeError:
            logs = parse_text_blob(content, source_name)

    return logs


def set_custom_logs(logs: list[dict[str, Any]], label: str) -> None:
    APP_STATE["custom_logs"] = logs
    APP_STATE["custom_label"] = label
    APP_STATE["active_source"] = "custom" if logs else "sample"


def fetch_logs_from_elasticsearch(limit: int = 50, query_text: str = "") -> list[dict[str, Any]]:
    client = get_es_client()
    if client is None:
        return []

    cfg = APP_STATE["es_config"]
    if query_text:
        es_query: dict[str, Any] = {
            "bool": {
                "should": [
                    {"query_string": {"query": query_text}},
                    {"match": {"message": query_text}},
                ],
                "minimum_should_match": 1,
            }
        }
    else:
        es_query = {"match_all": {}}

    response = client.search(
        index=cfg.get("index") or "logs-*",
        size=min(max(limit, 1), 200),
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        query=es_query,
    )
    hits = response.get("hits", {}).get("hits", [])
    logs = []
    for index, hit in enumerate(hits, 1):
        source = hit.get("_source", {})
        source["_id"] = hit.get("_id")
        logs.append(normalize_log(source, index))
    return logs


def apply_query(logs: list[dict[str, Any]], query_text: str, limit: int) -> list[dict[str, Any]]:
    query = query_text.strip().lower()
    if query:
        logs = [
            log for log in logs
            if query in json.dumps(log, default=str).lower()
        ]
    logs = sorted(logs, key=lambda item: item["timestamp"], reverse=True)
    return logs[: min(max(limit, 1), 200)]


def get_logs(limit: int = 50, query_text: str = "") -> tuple[list[dict[str, Any]], str, str | None, str]:
    active_source = APP_STATE.get("active_source", "sample")

    if active_source == "custom" and APP_STATE["custom_logs"]:
        logs = apply_query(APP_STATE["custom_logs"], query_text, limit)
        return logs, "custom", None, APP_STATE["custom_label"]

    if active_source == "elasticsearch":
        try:
            logs = fetch_logs_from_elasticsearch(limit=limit, query_text=query_text)
            return logs, "elasticsearch", None, APP_STATE["es_config"].get("index", "logs-*")
        except Exception as exc:
            fallback = [normalize_log(log, idx) for idx, log in enumerate(SAMPLE_LOGS, 1)]
            return fallback[:limit], "sample", str(exc), "Built-in sample logs"

    logs = apply_query([normalize_log(log, idx) for idx, log in enumerate(SAMPLE_LOGS, 1)], query_text, limit)
    return logs, "sample", None, "Built-in sample logs"


def extract_keywords(logs: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for log in logs:
        for reason in log["reasons"]:
            counts[reason] += 1
    return dict(counts.most_common(8))


def build_timeline(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: Counter[str] = Counter()
    for log in logs:
        stamp = log["timestamp"]
        bucket = stamp[:13] + ":00Z" if "T" in stamp and len(stamp) >= 13 else stamp
        buckets[bucket] += 1
    return [{"time": key, "count": value} for key, value in sorted(buckets.items())]


def build_recommendations(logs: list[dict[str, Any]], stats: dict[str, Any]) -> list[str]:
    recommendations: list[str] = []
    top_keywords = list(stats["keyword_count"].keys())

    if stats["critical_count"]:
        recommendations.append("Prioritize the critical alerts first and pivot on the affected IPs and hosts.")
    if "sql injection" in top_keywords:
        recommendations.append("Review the targeted web endpoints and inspect WAF, reverse proxy, and application traces together.")
    if "repeated failed authentication" in top_keywords or "multiple failed login" in top_keywords:
        recommendations.append("Check for brute-force activity, correlate usernames, and confirm whether MFA or account lockout was triggered.")
    if any(log["source"] == "unknown" for log in logs):
        recommendations.append("Normalize missing source fields so future searches and dashboards remain reliable.")
    if not recommendations:
        recommendations.append("Use the search bar and assistant prompt to pivot on the most active IPs, sources, and warning patterns.")

    return recommendations[:4]


def build_stats(logs: list[dict[str, Any]]) -> dict[str, Any]:
    by_ip = Counter(log["ip"] for log in logs)
    by_level = Counter(log["classification"] for log in logs)
    by_source = Counter(log["source"] for log in logs)
    alerts = sorted(
        (log for log in logs if severity_rank(log["classification"]) >= severity_rank("warning")),
        key=lambda item: (item["score"], item["timestamp"]),
        reverse=True,
    )[:8]
    keyword_count = extract_keywords(logs)
    stats = {
        "total_logs": len(logs),
        "alerts_count": len(alerts),
        "critical_count": by_level.get("critical", 0),
        "high_count": by_level.get("high", 0),
        "warning_count": by_level.get("warning", 0),
        "ip_count": dict(by_ip.most_common(8)),
        "source_count": dict(by_source.most_common(6)),
        "level_count": dict(by_level),
        "keyword_count": keyword_count,
        "timeline": build_timeline(logs),
        "alerts": alerts,
        "recommendations": [],
    }
    stats["recommendations"] = build_recommendations(logs, stats)
    return stats


def build_local_analysis(query: str, selected_log: dict[str, Any] | None, stats: dict[str, Any], active_label: str) -> str:
    if selected_log:
        reasons = ", ".join(selected_log["reasons"]) if selected_log["reasons"] else "no strong threat indicators were matched"
        return (
            f"Data source: {active_label}. Selected event risk is {selected_log['classification']} from "
            f"{selected_log['source']} at {selected_log['timestamp']}. Indicators: {reasons}. "
            f"Top IPs in the current view are {', '.join(list(stats['ip_count'].keys())[:3]) or 'not available'}. "
            f"Prompt: {query or 'general analysis request'}. "
            f"Immediate actions: {stats['recommendations'][0]}"
        )

    return (
        f"Data source: {active_label}. Current log set contains {stats['total_logs']} events with "
        f"{stats['alerts_count']} notable alerts, {stats['critical_count']} critical findings, and "
        f"{stats['high_count']} high-risk findings. Prompt: {query or 'general summary request'}. "
        f"Most common indicators are {', '.join(list(stats['keyword_count'].keys())[:4]) or 'not enough data yet'}. "
        f"Immediate actions: {stats['recommendations'][0]}"
    )


def build_openai_analysis(query: str, selected_log: dict[str, Any] | None, stats: dict[str, Any], active_label: str) -> str:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return ""

    client = OpenAI(api_key=api_key)
    prompt = {
        "data_source": active_label,
        "user_question": query,
        "selected_log": selected_log,
        "stats": {
            "total_logs": stats["total_logs"],
            "alerts_count": stats["alerts_count"],
            "critical_count": stats["critical_count"],
            "high_count": stats["high_count"],
            "top_ips": stats["ip_count"],
            "top_sources": stats["source_count"],
            "top_keywords": stats["keyword_count"],
            "recommendations": stats["recommendations"],
        },
    }

    response = client.responses.create(
        model="gpt-4o-mini",
        input=[
            {
                "role": "system",
                "content": (
                    "You are a SOC analyst. Explain logs clearly, mention risk level, likely meaning, "
                    "and 3 practical next steps. Keep it concise."
                ),
            },
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=True)},
        ],
        temperature=0.2,
    )
    return getattr(response, "output_text", "").strip()


@app.get("/")
def home() -> Any:
    return send_from_directory(BASE_DIR, INDEX_FILE.name)


@app.get("/health")
def health() -> Any:
    logs, source, error, label = get_logs(limit=20)
    return jsonify(
        {
            "status": "ok",
            "data_source": source,
            "source_label": label,
            "elasticsearch_configured": bool(APP_STATE["es_config"].get("url")),
            "custom_logs_loaded": bool(APP_STATE["custom_logs"]),
            "log_count": len(logs),
            "error": error,
            "platform_hint": "Runs on Linux and Kali Linux with Python 3 and pip-installed dependencies.",
        }
    )


@app.post("/connect-elasticsearch")
def connect_elasticsearch() -> Any:
    payload = request.get_json(silent=True) or {}
    config = {
        "url": str(payload.get("url", "")).strip(),
        "username": str(payload.get("username", "")).strip(),
        "password": str(payload.get("password", "")).strip(),
        "index": str(payload.get("index", "logs-*")).strip() or "logs-*",
    }
    APP_STATE["es_config"] = config

    if not config["url"]:
        APP_STATE["active_source"] = "sample"
        return jsonify({"connected": False, "message": "Elasticsearch URL cleared. Using built-in sample logs."})

    try:
        client = get_es_client()
        assert client is not None
        client.info()
        APP_STATE["active_source"] = "elasticsearch"
        return jsonify({"connected": True, "message": f"Connected to Elasticsearch index pattern {config['index']}."})
    except Exception as exc:
        APP_STATE["active_source"] = "sample"
        return jsonify({"connected": False, "message": f"Elasticsearch connection failed. Falling back to sample logs. Details: {exc}"})


@app.post("/set-source")
def set_source() -> Any:
    payload = request.get_json(silent=True) or {}
    requested = str(payload.get("source", "sample")).strip().lower()

    if requested == "custom" and APP_STATE["custom_logs"]:
        APP_STATE["active_source"] = "custom"
        return jsonify({"ok": True, "message": f"Switched to {APP_STATE['custom_label']}."})

    if requested == "elasticsearch" and APP_STATE["es_config"].get("url"):
        APP_STATE["active_source"] = "elasticsearch"
        return jsonify({"ok": True, "message": "Switched to Elasticsearch data."})

    APP_STATE["active_source"] = "sample"
    return jsonify({"ok": True, "message": "Switched to built-in sample logs."})


@app.post("/upload-logs")
def upload_logs() -> Any:
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"ok": False, "message": "Choose a log file first."}), 400

    content = uploaded.read().decode("utf-8", errors="ignore")
    logs = parse_uploaded_content(uploaded.filename, content)
    if not logs:
        return jsonify({"ok": False, "message": "No log entries could be extracted from that file."}), 400

    set_custom_logs(logs, f"Uploaded file: {uploaded.filename}")
    return jsonify({"ok": True, "message": f"Loaded {len(logs)} log entries from {uploaded.filename}.", "count": len(logs)})


@app.post("/ingest-text")
def ingest_text() -> Any:
    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", "")).strip()
    source_name = str(payload.get("source_name", "manual-input")).strip() or "manual-input"
    if not text:
        return jsonify({"ok": False, "message": "Paste log text or other content first."}), 400

    try:
        logs = parse_json_payload(text, source_name)
    except json.JSONDecodeError:
        logs = parse_text_blob(text, source_name)

    if not logs:
        return jsonify({"ok": False, "message": "No logs could be parsed from the supplied text."}), 400

    set_custom_logs(logs, f"Manual input: {source_name}")
    return jsonify({"ok": True, "message": f"Loaded {len(logs)} entries from pasted text.", "count": len(logs)})


@app.get("/get-logs")
def api_get_logs() -> Any:
    limit = request.args.get("limit", default=50, type=int)
    query_text = request.args.get("q", default="", type=str)
    logs, source, error, label = get_logs(limit=limit, query_text=query_text)
    return jsonify({"logs": logs, "source": source, "source_label": label, "error": error})


@app.get("/stats")
def api_stats() -> Any:
    logs, source, error, label = get_logs(limit=200)
    stats = build_stats(logs)
    stats["source"] = source
    stats["source_label"] = label
    stats["error"] = error
    return jsonify(stats)


@app.post("/chat")
def api_chat() -> Any:
    payload = request.get_json(silent=True)
    if payload is None:
        payload = request.form.to_dict()

    query = str(payload.get("query", "")).strip()
    selected_log_payload = payload.get("log")
    selected_log: dict[str, Any] | None = None
    if isinstance(selected_log_payload, str) and selected_log_payload.strip():
        try:
            selected_log = json.loads(selected_log_payload)
        except json.JSONDecodeError:
            selected_log = {
                "message": selected_log_payload,
                "source": "unknown",
                "timestamp": now_iso(),
                "classification": "info",
                "reasons": [],
            }
    elif isinstance(selected_log_payload, dict):
        selected_log = selected_log_payload

    logs, source, error, label = get_logs(limit=200)
    stats = build_stats(logs)
    try:
        response_text = build_openai_analysis(query=query, selected_log=selected_log, stats=stats, active_label=label)
    except Exception:
        response_text = ""

    if not response_text:
        response_text = build_local_analysis(query=query, selected_log=selected_log, stats=stats, active_label=label)

    return jsonify({"response": response_text, "source": source, "source_label": label, "error": error})


@app.get("/report")
def report() -> Any:
    logs, source, error, label = get_logs(limit=200)
    stats = build_stats(logs)
    summary = build_local_analysis(query="Generate a concise incident report.", selected_log=None, stats=stats, active_label=label)
    return jsonify(
        {
            "source": source,
            "source_label": label,
            "summary": summary,
            "recommendations": stats["recommendations"],
            "top_indicators": stats["keyword_count"],
            "error": error,
        }
    )


@app.get("/architecture")
def architecture() -> Any:
    return jsonify(
        {
            "title": "Automated Log Analysis Using OpenAI and Elasticsearch",
            "components": [
                "Linux-ready Flask backend",
                "Responsive browser dashboard frontend",
                "Elasticsearch log retrieval",
                "File upload ingestion for txt, json, jsonl, ndjson, and csv",
                "Pasted text ingestion",
                "Heuristic anomaly detection and summary reporting",
                "OpenAI-assisted analyst explanations",
            ],
            "flow": [
                "User selects Elasticsearch, uploaded file, pasted text, or sample logs",
                "Backend normalizes logs into a common structure",
                "System scores suspicious events and aggregates operational metrics",
                "Dashboard shows alerts, trends, indicators, and recommended actions",
                "Analyst enters a prompt to ask about the whole dataset or a selected log",
            ],
        }
    )


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "8000"))
    app.run(debug=True, host=host, port=port)
