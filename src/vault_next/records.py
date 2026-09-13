"""Versioned Phase 1 record builders and schema registry."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from vault_next.canonical import canonical_sha256
from vault_next import __version__
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.schema import load_schema, require_valid
from vault_next.schema import validate as validate_schema

SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0", "2.0", "3.0"})
RUNTIME_ACTOR = {"type": "runtime", "id": f"vault-next-runtime/{__version__}"}
AUDIT_ACTOR = {"id": "vault-next-runtime", "version": __version__}


class SchemaRegistry:
    """Load and execute the checked-in Phase 1 schemas."""

    def __init__(self, schema_root: Path):
        self.schema_root = schema_root
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    def get(self, name: str, *, schema_version: str = SCHEMA_VERSION) -> dict[str, Any]:
        key = (schema_version, name)
        if key not in self._cache:
            root = self._root_for_version(schema_version)
            if root is None:
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.SCHEMA_VERSION_UNSUPPORTED,
                            "$/schema_version",
                            f"unsupported schema version: {schema_version}",
                        )
                    ]
                )
            self._cache[key] = load_schema(root / f"{name}.schema.json")
        return self._cache[key]

    def require(
        self, name: str, record: dict[str, Any], *, schema_version: str = SCHEMA_VERSION
    ) -> None:
        require_valid(record, self.get(name, schema_version=schema_version))

    def issues(
        self, name: str, record: dict[str, Any], *, schema_version: str = SCHEMA_VERSION
    ) -> tuple[Any, ...]:
        """Return stable structural issues for one named record contract."""

        return validate_schema(record, self.get(name, schema_version=schema_version))

    def require_for_record(self, name: str, record: dict[str, Any]) -> None:
        """Validate an envelope using its declared schema version without future fallback."""

        version = record.get("schema_version")
        if not isinstance(version, str) or self._root_for_version(version) is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.SCHEMA_VERSION_UNSUPPORTED,
                        "$/schema_version",
                        f"unsupported schema version: {version!r}",
                    )
                ]
            )
        self.require(name, record, schema_version=version)

    def issues_for_record(self, name: str, record: dict[str, Any]) -> tuple[Any, ...]:
        """Return version-selection or structural issues for one versioned envelope."""

        version = record.get("schema_version")
        if not isinstance(version, str) or self._root_for_version(version) is None:
            return (
                Issue(
                    ErrorCode.SCHEMA_VERSION_UNSUPPORTED,
                    "$/schema_version",
                    f"unsupported schema version: {version!r}",
                ),
            )
        return self.issues(name, record, schema_version=version)

    def _root_for_version(self, schema_version: str) -> Path | None:
        if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            return None
        major = schema_version.split(".", maxsplit=1)[0]
        root = self.schema_root.parent / f"v{major}"
        return root if root.is_dir() else None


def aware_utc_now() -> datetime:
    """Return the current aware UTC time."""

    return datetime.now(UTC)


def timestamp(value: datetime) -> str:
    """Render one aware timestamp in a stable UTC form."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_event(
    *,
    event_type: str,
    case_id: str | None,
    session_id: str | None,
    payload: dict[str, Any],
    actor: dict[str, str] | None = None,
    subject_refs: list[str] | None = None,
    provenance: list[dict[str, str]] | None = None,
    correlation_id: str,
    causation_event_id: str | None = None,
    sensitivity: str = "none",
    approval_ref: str | None = None,
    schema_version: str = SCHEMA_VERSION,
    occurred_at: datetime | None = None,
    recorded_at: datetime | None = None,
    id_factory: ULIDFactory = DEFAULT_FACTORY,
) -> dict[str, Any]:
    """Build an unhashed semantic-event candidate."""

    occurred = occurred_at or aware_utc_now()
    recorded = recorded_at or aware_utc_now()
    return {
        "schema_version": schema_version,
        "event_id": id_factory.new("event"),
        "event_type": event_type,
        "occurred_at": timestamp(occurred),
        "recorded_at": timestamp(recorded),
        "actor": actor or dict(RUNTIME_ACTOR),
        "case_id": case_id,
        "session_id": session_id,
        "subject_refs": subject_refs or [],
        "correlation_id": correlation_id,
        "causation_event_id": causation_event_id,
        "provenance": provenance or [],
        "sensitivity": sensitivity,
        "approval_ref": approval_ref,
        "payload": payload,
        "integrity": {
            "payload_sha256": canonical_sha256(payload),
            "previous_event_sha256": "GENESIS",
            "event_sha256": "0" * 64,
        },
    }


def build_audit_record(
    *,
    operation_class: str,
    target_summary: str,
    input_digest: str,
    policy: dict[str, Any],
    attempt_status: str,
    result: str,
    case_id: str | None = None,
    session_id: str | None = None,
    action_id: str | None = None,
    semantic_event_refs: list[str] | None = None,
    output_refs: list[str] | None = None,
    error_code: str | None = None,
    public_research_attempt: dict[str, Any] | None = None,
    attempted_at: datetime | None = None,
    id_factory: ULIDFactory = DEFAULT_FACTORY,
) -> dict[str, Any]:
    """Build an unhashed operational-audit candidate without raw input content."""

    return {
        "schema_version": SCHEMA_VERSION,
        "operation_id": id_factory.new("operation"),
        "attempted_at": timestamp(attempted_at or aware_utc_now()),
        "actor": dict(AUDIT_ACTOR),
        "case_id": case_id,
        "session_id": session_id,
        "action_id": action_id,
        "semantic_event_refs": semantic_event_refs or [],
        "operation_class": operation_class,
        "target_summary": target_summary,
        "input_digest": input_digest,
        "policy": policy,
        "public_research_attempt": public_research_attempt,
        "attempt_status": attempt_status,
        "result": result,
        "output_refs": output_refs or [],
        "error_code": error_code,
        "integrity": {"previous_record_sha256": "GENESIS", "record_sha256": "0" * 64},
    }


Clock = Callable[[], datetime]
