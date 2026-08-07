"""Elasticsearch connection setup, validation, and log retrieval."""


from __future__ import annotations


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
from elasticsearch.helpers import scan

from log_processing import normalize_log
from openai_service import classify_logs_with_openai
from settings import STATE


NON_RETRYABLE_ES_ERRORS = (AuthenticationException, AuthorizationException, NotFoundError, BadRequestError, SSLError)


def normalize_es_url(url: str) -> str:
    """Add an HTTP scheme when the user types only host:port."""
    cleaned = url.strip()
    if cleaned and "://" not in cleaned:
        return f"http://{cleaned}"
    return cleaned


def candidate_es_urls(url: str) -> list[str]:
    """Try both secure and plain HTTP when the user omits a scheme."""
    cleaned = url.strip()
    if not cleaned:
        return [""]
    if "://" in cleaned:
        return [cleaned]
    return [f"https://{cleaned}", f"http://{cleaned}"]


def is_non_retryable_es_error(exc: Exception) -> bool:
    """avoids retrying URL variants when credentials or index names are wrong."""
    return isinstance(exc, NON_RETRYABLE_ES_ERRORS)


def format_es_error(exc: Exception, index_pattern: str, username: str = "") -> str:
    """making them errors easy to  understand"""
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
    """Build a client from either"""
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
    """chck the cluster is reachable and the target index can be searched."""
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


def connect_to_elasticsearch(raw_url: str, username: str, password: str, index_pattern: str) -> dict[str, Any]:
    """Validate Elasticsearch settings"""
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
        return {"connected": False, "message": "Elasticsearch URL cleared."}

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
            return {
                "connected": True,
                "message": (
                    f"Connected to Elasticsearch. Index pattern {index_pattern} matched "
                    f"{target_count} {target_label} and {validation['document_count']} documents."
                ),
                "config": {"url": config["url"], "index": index_pattern, "username": username},
                "targets": validation["targets"],
                "document_count": validation["document_count"],
            }
        except Exception as exc:
            best_error = format_es_error(exc, index_pattern, username)
            best_details = str(exc)
            if is_non_retryable_es_error(exc):
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
    return {
        "connected": False,
        "message": best_error,
        "details": best_details,
        "config": {"url": STATE["es"]["url"], "index": index_pattern, "username": username},
    }


def fetch_es_logs(limit: int | None, query_text: str) -> list[dict[str, Any]]:
    """Fetch logs from Elasticsearch and normalize them for the dashboard."""
    if query_text.strip():

        query: dict[str, Any] = {
            "simple_query_string": {
                "query": query_text,
                "fields": ["message^3", "event.original^2", "host.name", "service.name", "source", "*"],
                "lenient": True,
            }
        }
    else:
        query = {"match_all": {}}

    client = es_client()
    logs = []
    if limit is None:
        
        hits = scan(client, index=STATE["es"]["index"], query={"query": query}, size=500, request_timeout=60)
        for index, hit in enumerate(hits, 1):
            source = hit.get("_source", {})
            source["_id"] = hit.get("_id")
            logs.append(normalize_log(source, index))
    else:
      
        response = client.search(
            index=STATE["es"]["index"],
            size=max(limit, 1),
            sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            query=query,
        )
        for index, hit in enumerate(response.get("hits", {}).get("hits", []), 1):
            source = hit.get("_source", {})
            source["_id"] = hit.get("_id")
            logs.append(normalize_log(source, index))
    return classify_logs_with_openai(logs)
