"""CTTO — GeoIP Lookup Module.

Resolves attacker IP addresses to country/city.

Resolution order:
    1. MaxMind GeoLite2 offline database (fastest, no network)
       Setup: pip install geoip2 && place GeoLite2-City.mmdb in data/
    2. Free ip-api.com HTTP API (no key required, 45 req/min)
    3. Graceful fallback → {"country": "Unknown", "city": "Unknown"}

Results are cached in-memory so each IP is resolved only once.
"""

import os
import urllib.request
import json

_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "GeoLite2-City.mmdb",
)

_reader = None
_cache: dict[str, dict] = {}

_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "0.", "::1", "fe80:")

_UNKNOWN = {"country": "Unknown", "city": "Unknown"}


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _get_reader():
    global _reader
    if _reader is not None:
        return _reader
    if not os.path.exists(_DB_PATH):
        return None
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(_DB_PATH)
        return _reader
    except ImportError:
        return None


def _lookup_maxmind(ip: str) -> dict | None:
    reader = _get_reader()
    if reader is None:
        return None
    try:
        resp = reader.city(ip)
        return {
            "country": resp.country.name or "Unknown",
            "city": resp.city.name or "Unknown",
        }
    except Exception:
        return None


def _lookup_api(ip: str) -> dict | None:
    """Query the free ip-api.com service (no key needed, 45 rpm)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
        req = urllib.request.Request(url, headers={"User-Agent": "CTTO/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
            }
    except Exception:
        pass
    return None


def lookup(ip: str) -> dict:
    """Return ``{"country": ..., "city": ...}`` for the given IP."""
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip):
        result = {"country": "Localhost", "city": "Local"}
        _cache[ip] = result
        return result

    result = _lookup_maxmind(ip) or _lookup_api(ip) or dict(_UNKNOWN)
    _cache[ip] = result
    return result
