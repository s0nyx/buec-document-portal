from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest


def client_ip(request: HttpRequest) -> str:
    if settings.TRUST_X_REAL_IP:
        forwarded = (request.META.get("HTTP_X_REAL_IP") or "").strip()
        if forwarded:
            return forwarded[:80]
    return (request.META.get("REMOTE_ADDR") or "unknown")[:80]


def hash_sensitive_value(value: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        value.encode("utf-8", errors="ignore"),
        hashlib.sha256,
    ).hexdigest()


def client_ip_hash(request: HttpRequest) -> str:
    return hash_sensitive_value(client_ip(request))


def _rate_key(scope: str, parts: Iterable[str]) -> str:
    joined = "|".join(parts)
    digest = hash_sensitive_value(joined)
    return f"rate:{scope}:{digest}"


def consume_rate_limit(
    scope: str,
    parts: Iterable[str],
    *,
    limit: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """Increment a rate-limit bucket and return (limited, current_count)."""
    key = _rate_key(scope, parts)
    if cache.add(key, 1, timeout=window_seconds):
        return False, 1

    try:
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=window_seconds)
        count = 1
    return count > limit, count


def clear_rate_limit(scope: str, parts: Iterable[str]) -> None:
    cache.delete(_rate_key(scope, parts))
