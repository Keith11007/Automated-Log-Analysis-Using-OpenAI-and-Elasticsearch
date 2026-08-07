""" OpenAI calls """

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from openai import OpenAI

from log_processing import build_stats
from settings import (
    CLASSIFICATION_SCORES,
    OPENAI_CLASSIFY_BATCH_SIZE,
    OPENAI_CLASSIFY_MODEL,
    OPENAI_MODEL,
    VALID_CLASSIFICATIONS,
)


# Cache repeated classification so its always updated
CLASSIFICATION_CACHE: dict[str, dict[str, Any]] = {}


class CategorizationError(RuntimeError):
    """Raised when log classification cannot complete successfully."""
    pass


def summarize_openai_error(exc: Exception) -> str:
    """openai errors"""
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


def classification_cache_key(log: dict[str, Any]) -> str:
    """classification formattt"""
    cache_payload = {
        "message": log.get("message", ""),
        "level": log.get("level", ""),
        "source": log.get("source", ""),
        "ip": log.get("ip", ""),
    }
    raw = json.dumps(cache_payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compact_log_for_openai(log: dict[str, Any], item_id: int) -> dict[str, Any]:
    """Sending only the fields OpenAI needs"""
    return {
        "id": str(item_id),
        "timestamp": log.get("timestamp", ""),
        "source": log.get("source", "unknown"),
        "ip": log.get("ip", "unknown"),
        "level": log.get("level", "info"),
        "message": str(log.get("message", ""))[:800],
    }


def clean_openai_reasons(value: Any) -> list[str]:
    """making openAI's reason into a good formtt"""
    if isinstance(value, list):
        reasons = [str(item).strip() for item in value if str(item).strip()]
    elif isinstance(value, str) and value.strip():
        reasons = [value.strip()]
    else:
        reasons = []
    return reasons[:5]


def parse_openai_classifications(text: str) -> dict[str, dict[str, Any]]:
    """Extract JSON classification response from OpenAI."""
    cleaned = text.strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if not match:
            raise
        parsed = json.loads(match.group(0))

    items = parsed.get("classifications") if isinstance(parsed, dict) else parsed
    if not isinstance(items, list):
        raise ValueError("OpenAI classification response did not include a classifications list.")

    results: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id", "")).strip()
        category = str(item.get("category", "")).strip().lower()
        if item_id and category in VALID_CLASSIFICATIONS:
            results[item_id] = {"category": category, "reasons": clean_openai_reasons(item.get("reasons"))}
    return results


def apply_openai_classification(log: dict[str, Any], result: dict[str, Any]) -> None:
    """ normalize log with its category, score, and explanations."""
    category = str(result.get("category", "")).strip().lower()
    if category not in VALID_CLASSIFICATIONS:
        return
    log["classification"] = category
    log["score"] = CLASSIFICATION_SCORES[category]
    log["reasons"] = clean_openai_reasons(result.get("reasons")) or [f"OpenAI categorized this log as {category}."]
    log["classified_by"] = "openai"


def classify_logs_with_openai(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """classify logs once and cache repeated results by message fingerprint."""
    if not logs:
        return logs

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise CategorizationError("OpenAI categorization failed: missing OPENAI_API_KEY.")

    client = OpenAI(api_key=api_key, timeout=90.0)
    uncached: list[dict[str, Any]] = []

    for log in logs:
        key = classification_cache_key(log)
        cached = CLASSIFICATION_CACHE.get(key)
        if cached:
            # Reusing cached categories avoids paying to classify the same log on
            # every dashboard refresh.
            apply_openai_classification(log, cached)
        else:
            # Store this temporary key on the log so we can save the response
            # back into the cache after the batch completes.
            log["_classification_cache_key"] = key
            uncached.append(log)

    for start in range(0, len(uncached), OPENAI_CLASSIFY_BATCH_SIZE):
        batch = uncached[start:start + OPENAI_CLASSIFY_BATCH_SIZE]
        # IDs are simple 1-based strings so the model can map each answer back
        # to the exact item in this batch.
        payload = [compact_log_for_openai(log, start + index + 1) for index, log in enumerate(batch)]
        try:
            response = client.responses.create(
                model=OPENAI_CLASSIFY_MODEL,
                input=[
                    {
                        "role": "system",
                        "content": (
                            "Classify each security log into exactly one category: critical, high, warning, or info. "
                            "Use critical for active compromise, malware, exploitation, data loss, or urgent containment. "
                            "Use high for credible threats requiring prompt investigation. "
                            "Use warning for suspicious, failed, blocked, error, or anomalous activity. "
                            "Use info for normal or low-risk operational events. "
                            "Return only JSON: {\"classifications\":[{\"id\":\"...\",\"category\":\"critical|high|warning|info\",\"reasons\":[\"short reason\"]}]}."
                        ),
                    },
                    {"role": "user", "content": json.dumps({"logs": payload}, ensure_ascii=True)},
                ],
                temperature=0,
            )
            results = parse_openai_classifications(getattr(response, "output_text", ""))
            for index, log in enumerate(batch, 1):
                result = results.get(str(start + index))
                if not result:
                    raise CategorizationError("OpenAI categorization returned an incomplete response.")
                apply_openai_classification(log, result)
                cache_key = str(log.pop("_classification_cache_key", ""))
                if cache_key:
                    CLASSIFICATION_CACHE[cache_key] = result
        except Exception as exc:
            # Clean temporary helper fields before bubbling the error to Flask.
            for log in batch:
                log.pop("_classification_cache_key", None)
            if isinstance(exc, CategorizationError):
                raise
            raise CategorizationError(f"OpenAI categorization failed: {summarize_openai_error(exc)}") from exc

    for log in logs:
        log.pop("_classification_cache_key", None)
    return logs


def build_openai_analysis(query: str, logs: list[dict[str, Any]], selected_log: dict[str, Any] | None, source_label: str) -> dict[str, Any]:
    """Ask OpenAI for the questions."""
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
                "classified_by": log.get("classified_by", "openai"),
                "message": log["message"],
            }
            for log in logs
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
                    "and give practical next steps based on the provided log data when it exists. "
                    "If no log data is provided, answer the user's prompt generally and say that no current log was included. "
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
