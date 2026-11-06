"""Never echo secret-looking values from a spec or an example. Names are fine; values are not."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SECRET_KEY = re.compile(
    r"(pass(word|wd|phrase)?|secret|token|api[-_ ]?key|authorization|bearer|credential|private[-_ ]?key|session|cookie)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(sk-[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*|AIza[0-9A-Za-z_\-]{30,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|[A-Fa-f0-9]{40,}|[A-Za-z0-9+/_\-]{48,}={0,2})"
)
REDACTED = "<redacted>"


def key_is_secret(name: str) -> bool:
    return bool(_SECRET_KEY.search(name))


def value_is_secret(v: Any) -> bool:
    if isinstance(v, str):
        return bool(_SECRET_VALUE.search(v[:100_000]))
    if isinstance(v, (dict, list)):
        try:
            return bool(_SECRET_VALUE.search(json.dumps(v, default=str)[:100_000]))
        except (TypeError, ValueError):
            return False
    return False


def shown(v: Any, limit: int = 60, name: str = "") -> str:
    """repr-like text of a value for messages, or <redacted>."""
    if (name and key_is_secret(name) and v not in (None, True, False)) or value_is_secret(v):
        return REDACTED
    text = json.dumps(v, ensure_ascii=False, default=str) if not isinstance(v, str) else repr(v)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def redact_url(url: str) -> str:
    """Strip credentials (user:pass@) and secret-looking query values from a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc
    if "@" in netloc:
        netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]
    query = parts.query
    if query:
        pieces = []
        for kv in query.split("&"):
            k, eq, v = kv.partition("=")
            pieces.append(f"{k}={REDACTED}" if eq and (key_is_secret(k) or value_is_secret(v)) else kv)
        query = "&".join(pieces)
    if netloc == parts.netloc and query == parts.query:
        return url
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
