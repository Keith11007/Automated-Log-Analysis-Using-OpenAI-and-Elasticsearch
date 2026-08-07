"""Query AbuseIPDB and reshape the result for the dashboard card."""

from __future__ import annotations

import ipaddress
import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from settings import ABUSEIPDB_MAX_AGE_DAYS


ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def country_flag(code: str) -> str:
    """Convert a two-letter country code into a flag for display."""
    normalized = code.strip().upper()
    if len(normalized) != 2 or not normalized.isalpha():
        return ""
    return "".join(chr(127397 + ord(char)) for char in normalized)


def parse_abuseipdb_error(body: bytes, fallback: str) -> str:
    """Pull AbuseIPDB's first validation message out of an error response."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return fallback

    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            detail = errors[0].get("detail") if isinstance(errors[0], dict) else ""
            if detail:
                return str(detail)
    return fallback


def normalize_asn(value: Any) -> str:
    """Display AS numbers consistently, even when the API returns only digits."""
    text = str(value or "").strip()
    if not text:
        return "Unknown"
    return text if text.upper().startswith("AS") else f"AS{text}"


def lookup_abuseipdb(ip_text: str) -> dict[str, Any]:
    """Validate an IP, call AbuseIPDB, and return only fields used by the UI."""
    ip_address = ip_text.strip()
    if not ip_address:
        return {"ok": False, "message": "Enter an IP address first.", "status": 400}

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return {"ok": False, "message": "Enter a valid IPv4 or IPv6 address.", "status": 400}

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {
            "ok": False,
            "message": "Missing ABUSEIPDB_API_KEY. Add it to your .env file first.",
            "status": 400,
        }

    params = urlencode(
        {
            "ipAddress": ip_address,
            "maxAgeInDays": str(ABUSEIPDB_MAX_AGE_DAYS),
            "verbose": "true",
        }
    )
    # `urllib` keeps this dependency-free; the only secret required is the API
    # key passed in the header.
    request = Request(
        url=f"{ABUSEIPDB_CHECK_URL}?{params}",
        headers={"Accept": "application/json", "Key": api_key},
        method="GET",
    )

    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        message = parse_abuseipdb_error(exc.read(), "AbuseIPDB rejected the request.")
        return {"ok": False, "message": message, "status": exc.code}
    except (URLError, TimeoutError):
        return {"ok": False, "message": "Unable to reach AbuseIPDB right now.", "status": 502}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "message": "AbuseIPDB returned an invalid response.", "status": 502}

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return {"ok": False, "message": "AbuseIPDB returned an unexpected response.", "status": 502}

    # Normalize optional API fields so the frontend can render a complete card
    # without checking every field for missing values.
    total_reports = int(data.get("totalReports") or 0)
    score = int(data.get("abuseConfidenceScore") or 0)
    country_code = str(data.get("countryCode") or "").strip().upper()
    last_reported = str(data.get("lastReportedAt") or "").strip()

    return {
        "ok": True,
        "ip": str(data.get("ipAddress") or ip_address),
        "is_found": total_reports > 0 or score > 0 or bool(last_reported),
        "abuse_confidence_score": score,
        "total_reports": total_reports,
        "isp": str(data.get("isp") or "Unknown"),
        "usage_type": str(data.get("usageType") or "Unknown"),
        "asn": normalize_asn(data.get("asn")),
        "domain": str(data.get("domain") or "Unknown"),
        "country_name": str(data.get("countryName") or "Unknown"),
        "country_flag": country_flag(country_code),
        "city": str(data.get("city") or "Unknown"),
    }
