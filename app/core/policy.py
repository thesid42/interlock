"""Small deterministic fixture rules and canonical action fingerprints."""

import hashlib
import json
import re


EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ROUTING_PATTERN = re.compile(
    r"\b(?:must be sent to|always forward to)\b[^\n]{0,200}"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)


def explicit_routing(content: str) -> bool:
    return bool(ROUTING_PATTERN.search(content))


def valid_recipient(recipient: str) -> bool:
    return bool(EMAIL_PATTERN.fullmatch(recipient)) and len(recipient) <= 254


def fingerprint(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
