"""ULID generation and prefixed canonical identifier validation."""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from vault_next.errors import ErrorCode, Issue, ValidationError

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_PATTERN = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
PREFIXES = frozenset(
    {
        "action",
        "approval",
        "artifact",
        "artifact_version",
        "bundle",
        "case",
        "committee_challenge",
        "committee_comparison",
        "committee_dissent",
        "committee_finding",
        "committee_run",
        "committee_synthesis",
        "checkpoint",
        "decision",
        "experience_candidate",
        "evaluation_run",
        "event",
        "feedback",
        "operation",
        "owner_input",
        "knowledge_candidate",
        "public_item",
        "recommendation",
        "research_scope",
        "receipt",
        "request",
        "review",
        "review_result",
        "session",
        "source",
        "source_capture",
        "source_extraction",
        "source_index_build",
        "source_version",
        "triage",
        "waiver",
        "work_item",
        "work_batch",
        "work_transaction",
    }
)


def encode_ulid(timestamp_ms: int, random_bytes: bytes) -> str:
    """Encode a 48-bit millisecond timestamp and 80 random bits as a ULID."""

    if not 0 <= timestamp_ms < 2**48:
        raise ValueError("timestamp_ms must fit in 48 bits")
    if len(random_bytes) != 10:
        raise ValueError("random_bytes must contain exactly 10 bytes")
    value = (timestamp_ms << 80) | int.from_bytes(random_bytes, "big")
    chars = ["0"] * 26
    for index in range(25, -1, -1):
        chars[index] = CROCKFORD[value & 31]
        value >>= 5
    return "".join(chars)


@dataclass
class ULIDFactory:
    """Thread-safe, process-local monotonic ULID factory."""

    now_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000
    random_source: Callable[[int], bytes] = os.urandom
    _last_ms: int = field(default=-1, init=False)
    _last_random: int = field(default=-1, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def new_body(self) -> str:
        """Create one monotonic ULID body."""

        with self._lock:
            timestamp_ms = self.now_ms()
            if timestamp_ms < self._last_ms:
                raise RuntimeError("system clock moved backwards during ULID generation")
            if timestamp_ms == self._last_ms:
                if self._last_random >= 2**80 - 1:
                    raise RuntimeError("ULID random component exhausted for one millisecond")
                random_value = self._last_random + 1
            else:
                random_value = int.from_bytes(self.random_source(10), "big")
            self._last_ms = timestamp_ms
            self._last_random = random_value
            return encode_ulid(timestamp_ms, random_value.to_bytes(10, "big"))

    def new(self, prefix: str) -> str:
        """Create a canonical prefixed identifier."""

        if prefix not in PREFIXES:
            raise ValueError(f"unknown canonical identifier prefix: {prefix}")
        return f"{prefix}_{self.new_body()}"


def validate_id(value: str, expected_prefix: str | None = None) -> None:
    """Raise a stable validation error unless *value* is a canonical ID."""

    prefix, separator, body = value.partition("_")
    valid_prefix = prefix in PREFIXES and (expected_prefix is None or prefix == expected_prefix)
    if separator != "_" or not valid_prefix or not ULID_PATTERN.fullmatch(body):
        raise ValidationError(
            [Issue(ErrorCode.ID_INVALID, "$", f"invalid {expected_prefix or 'canonical'} ID")]
        )


DEFAULT_FACTORY = ULIDFactory()
