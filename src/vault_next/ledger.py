"""Crash-aware, hash-chained semantic and operational JSONL ledgers."""

from __future__ import annotations

import copy
import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next import __version__
from vault_next.contracts import (
    OwnerReceipt,
    require_work_change_proposal,
    require_work_transaction_manifest,
    work_transaction_targets,
)
from vault_next.errors import ErrorCode, Issue, LedgerCorruptionError, ValidationError
from vault_next.lifecycle import fold_case_states, fold_decisions, fold_session_states, manifest_issues
from vault_next.paths import RuntimePaths
from vault_next.policy import Approval, PolicyEngine, Proposal
from vault_next.records import RUNTIME_ACTOR, SchemaRegistry
from vault_next.state import fold_artifact_state, fold_interaction_state, fold_work_items
from vault_next.work_transaction_policy import policy_proposal_for_transaction


@dataclass(frozen=True)
class ScanResult:
    """Validated prefix and any first-tail corruption finding."""

    records: tuple[dict[str, Any], ...]
    valid_byte_count: int
    total_byte_count: int
    last_hash: str
    issues: tuple[Issue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.issues and self.valid_byte_count == self.total_byte_count


@dataclass(frozen=True)
class RecoveryResult:
    """Result of quarantining and removing an invalid ledger suffix."""

    recovered: bool
    valid_byte_count: int
    quarantined_byte_count: int
    quarantine_path: Path | None
    issues: tuple[Issue, ...]


class HashChainedLedger:
    """Shared locked JSONL mechanics for one canonical record class."""

    def __init__(
        self,
        *,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        root: Path,
        schema_name: str,
        timestamp_field: str,
        id_field: str,
        previous_hash_field: str,
        record_hash_field: str,
        staging_kind: str,
    ):
        self.paths = paths
        self.schemas = schemas
        self.root = root
        self.schema_name = schema_name
        self.timestamp_field = timestamp_field
        self.id_field = id_field
        self.previous_hash_field = previous_hash_field
        self.record_hash_field = record_hash_field
        self.staging_kind = staging_kind

    def partition_path(self, timestamp_value: str) -> Path:
        parsed = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
        partition = f"{parsed.astimezone(UTC).strftime('%Y-%m')}.jsonl"
        return self.paths.ensure_runtime_write_target(self.root / partition)

    def append(self, candidate: dict[str, Any]) -> dict[str, Any]:
        """Validate, finalize, append, fsync, and verify one record."""

        return self.append_with_locked_revalidation(candidate, lambda _previous: None)

    def append_with_locked_revalidation(
        self,
        candidate: dict[str, Any],
        revalidate: Callable[[list[dict[str, Any]]], dict[str, Any] | None],
    ) -> dict[str, Any]:
        """Append one record after a caller rechecks exact state under this ledger's lock.

        The callback may return an already committed exact record for an idempotent retry.  It
        runs after every partition has been read and validated, immediately before the candidate
        is finalized, so transaction callers cannot rely on an unlocked preflight observation.
        """

        preliminary = self.schemas.issues_for_record(self.schema_name, candidate)
        essential_paths = {
            f"$/{self.id_field}",
            f"$/{self.timestamp_field}",
            "$/schema_version",
            "$/integrity",
        }
        if any(
            issue.path in essential_paths
            or issue.path.startswith(f"$/{self.timestamp_field}/")
            or issue.path.startswith("$/integrity/")
            for issue in preliminary
        ):
            raise ValidationError(preliminary)
        path = self.partition_path(candidate[self.timestamp_field])
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.paths.ensure_runtime_write_target(self.root / ".writer.lock")
        stage_path = self._stage_candidate(candidate)
        finished = False
        try:
            with _exclusive_lock(lock_path):
                scan = self.scan(path)
                if not scan.is_valid:
                    raise LedgerCorruptionError(scan.issues)
                previous_records = self.read_all()
                existing = revalidate(previous_records)
                if existing is not None:
                    finished = True
                    return existing
                final = self._finalize(candidate, scan.last_hash)
                candidate_issues = list(self.schemas.issues_for_record(self.schema_name, final))
                try:
                    candidate_issues.extend(self.domain_issues(final, previous_records))
                except (KeyError, TypeError):
                    # Structural findings already identify unavailable domain inputs.
                    pass
                if candidate_issues:
                    raise ValidationError(candidate_issues)
                line = canonical_bytes(final) + b"\n"
                descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
                try:
                    written = os.write(descriptor, line)
                    if written != len(line):
                        raise OSError(f"short ledger write: {written}/{len(line)}")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _fsync_directory(path.parent)
                verify = self.scan(path)
                if not verify.is_valid or verify.records[-1] != final:
                    raise LedgerCorruptionError(
                        [
                            Issue(
                                ErrorCode.LEDGER_POST_WRITE_VERIFY_FAILED,
                                str(path),
                                "appended record did not pass post-write verification",
                            )
                        ]
                    )
                finished = True
                return final
        finally:
            if finished and stage_path.exists():
                stage_path.unlink()

    def scan(self, path: Path) -> ScanResult:
        """Validate one partition and identify its longest valid byte prefix."""

        if not path.exists():
            return ScanResult((), 0, 0, "GENESIS")
        data = path.read_bytes()
        records: list[dict[str, Any]] = []
        offset = 0
        previous = "GENESIS"
        for line_number, framed in enumerate(data.splitlines(keepends=True), start=1):
            start = offset
            offset += len(framed)
            if not framed.endswith(b"\n"):
                issue = Issue(
                    ErrorCode.LEDGER_CORRUPT_TAIL,
                    f"{path}:{line_number}",
                    "partial final record has no newline",
                )
                return ScanResult(tuple(records), start, len(data), previous, (issue,))
            raw = framed[:-1]
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                issue = Issue(
                    ErrorCode.LEDGER_CORRUPT_TAIL,
                    f"{path}:{line_number}",
                    "record is not valid UTF-8 JSON",
                )
                return ScanResult(tuple(records), start, len(data), previous, (issue,))
            issues: list[Issue] = []
            try:
                is_canonical = isinstance(record, dict) and canonical_bytes(record) == raw
            except ValidationError as exc:
                is_canonical = False
                issues.extend(exc.issues)
            if not is_canonical:
                issues.append(
                    Issue(
                        ErrorCode.CANONICAL_RECORD_MISMATCH,
                        f"{path}:{line_number}",
                        "record bytes are not canonical JSON",
                    )
                )
            else:
                try:
                    self.schemas.require_for_record(self.schema_name, record)
                except ValidationError as exc:
                    issues.extend(exc.issues)
                issues.extend(self.integrity_issues(record, previous))
            if issues:
                return ScanResult(tuple(records), start, len(data), previous, tuple(sorted(issues)))
            records.append(record)
            previous = record["integrity"][self.record_hash_field]
        return ScanResult(tuple(records), len(data), len(data), previous)

    def read_all(self, *, exclude: Path | None = None) -> list[dict[str, Any]]:
        """Read every fully valid partition in stable order."""

        records: list[dict[str, Any]] = []
        if not self.root.exists():
            return records
        for path in sorted(self.root.glob("*.jsonl")):
            if exclude is not None and path == exclude:
                continue
            scan = self.scan(path)
            if not scan.is_valid:
                raise LedgerCorruptionError(scan.issues)
            records.extend(scan.records)
        return records

    def validate_all(self) -> tuple[Issue, ...]:
        """Validate chains and cross-record semantics for all partitions."""

        records: list[dict[str, Any]] = []
        issues: list[Issue] = []
        if self.root.exists():
            for path in sorted(self.root.glob("*.jsonl")):
                scan = self.scan(path)
                issues.extend(scan.issues)
                records.extend(scan.records)
        if issues:
            return tuple(sorted(issues))
        previous: list[dict[str, Any]] = []
        for record in records:
            issues.extend(self.domain_issues(record, previous))
            previous.append(record)
        return tuple(sorted(issues))

    def recovery_proposal(self, path: Path, *, approval_ref: str | None = None) -> Proposal:
        """Describe the exact current invalid suffix as a protected recovery proposal."""

        path = self.paths.ensure_runtime_write_target(path)
        scan = self.scan(path)
        data = path.read_bytes() if path.exists() else b""
        suffix = data[scan.valid_byte_count :]
        return Proposal(
            operation_class="write",
            targets=(str(path),),
            consequence_class="canonical_recovery",
            actor_id=f"vault-next-runtime/{__version__}",
            source_refs=(
                f"invalid_tail_sha256:{sha256_hex(suffix)}",
                f"valid_byte_count:{scan.valid_byte_count}",
            ),
            approval_ref=approval_ref,
        ).finalized()

    def recover(
        self,
        path: Path,
        *,
        proposal: Proposal,
        policy: PolicyEngine,
        approvals: dict[str, Approval],
        receipts: dict[str, OwnerReceipt] | None = None,
        now: datetime,
    ) -> RecoveryResult:
        """Quarantine an exactly approved invalid suffix while preserving the valid prefix."""

        path = self.paths.ensure_runtime_write_target(path)
        lock_path = self.paths.ensure_runtime_write_target(self.root / ".writer.lock")
        with _exclusive_lock(lock_path):
            fresh = self.recovery_proposal(path, approval_ref=proposal.approval_ref)
            if fresh.proposal_digest != proposal.proposal_digest:
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.APPROVAL_DIGEST_MISMATCH,
                            "$proposal_digest",
                            "ledger tail changed after the recovery proposal was approved",
                        )
                    ]
                )
            decision = policy.evaluate(fresh, approvals=approvals, receipts=receipts, now=now)
            if decision.result != "allow" or decision.approval_ref is None:
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.ACTOR_AUTHORITY_INVALID,
                            "$approval_ref",
                            f"canonical recovery not authorized: {decision.reason_code}",
                        )
                    ]
                )
            scan = self.scan(path)
            if scan.is_valid:
                return RecoveryResult(False, scan.valid_byte_count, 0, None, ())
            original = path.read_bytes()
            prefix = original[: scan.valid_byte_count]
            suffix = original[scan.valid_byte_count :]
            digest = sha256_hex(suffix)
            quarantine_dir = self.paths.ensure_runtime_write_target(
                self.paths.quarantine_root / self.staging_kind
            )
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            quarantine_path = self.paths.ensure_runtime_write_target(
                quarantine_dir / f"{path.stem}-{digest}.tail"
            )
            _durable_create_if_absent(quarantine_path, suffix)
            descriptor = os.open(path, os.O_WRONLY)
            try:
                os.ftruncate(descriptor, scan.valid_byte_count)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if path.read_bytes() != prefix:
                raise LedgerCorruptionError(
                    [
                        Issue(
                            ErrorCode.LEDGER_POST_WRITE_VERIFY_FAILED,
                            str(path),
                            "valid prefix changed during recovery",
                        )
                    ]
                )
            return RecoveryResult(
                True,
                scan.valid_byte_count,
                len(suffix),
                quarantine_path,
                scan.issues,
            )

    def integrity_issues(self, record: dict[str, Any], previous: str) -> list[Issue]:
        integrity = record.get("integrity", {})
        issues: list[Issue] = []
        if integrity.get(self.previous_hash_field) != previous:
            issues.append(
                Issue(ErrorCode.HASH_CHAIN_INVALID, "$integrity", "previous hash does not match")
            )
        expected = self._record_hash(record)
        if integrity.get(self.record_hash_field) != expected:
            issues.append(Issue(ErrorCode.HASH_CHAIN_INVALID, "$integrity", "record hash mismatch"))
        return issues

    def domain_issues(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        return []

    def _finalize(self, candidate: dict[str, Any], previous_hash: str) -> dict[str, Any]:
        record = copy.deepcopy(candidate)
        record["integrity"][self.previous_hash_field] = previous_hash
        record["integrity"][self.record_hash_field] = "0" * 64
        record["integrity"][self.record_hash_field] = self._record_hash(record)
        return record

    def _record_hash(self, record: dict[str, Any]) -> str:
        material = copy.deepcopy(record)
        material["integrity"].pop(self.record_hash_field, None)
        return canonical_sha256(material)

    def _stage_candidate(self, candidate: dict[str, Any]) -> Path:
        stage_dir = self.paths.ensure_runtime_write_target(
            self.paths.staging_root / self.staging_kind
        )
        stage_dir.mkdir(parents=True, exist_ok=True)
        record_id = candidate[self.id_field]
        stage_path = self.paths.ensure_runtime_write_target(stage_dir / f"{record_id}.candidate.json")
        _durable_create(stage_path, canonical_bytes(candidate) + b"\n")
        return stage_path


class SemanticLedger(HashChainedLedger):
    """Canonical semantic event ledger with Phase 1 actor/reference rules."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry):
        super().__init__(
            paths=paths,
            schemas=schemas,
            root=paths.semantic_root,
            schema_name="event",
            timestamp_field="recorded_at",
            id_field="event_id",
            previous_hash_field="previous_event_sha256",
            record_hash_field="event_sha256",
            staging_kind="semantic",
        )

    def integrity_issues(self, record: dict[str, Any], previous: str) -> list[Issue]:
        issues = super().integrity_issues(record, previous)
        expected_payload = canonical_sha256(record.get("payload"))
        if record.get("integrity", {}).get("payload_sha256") != expected_payload:
            issues.append(Issue(ErrorCode.HASH_CHAIN_INVALID, "$payload", "payload hash mismatch"))
        return issues

    def domain_issues(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        event_ids = {item["event_id"] for item in previous_records}
        case_ids = {
            item["case_id"] for item in previous_records if item["event_type"] == "case.created"
        }
        session_ids = {
            item["session_id"]
            for item in previous_records
            if item["event_type"] in {"session.started", "session.created"}
        }
        event_type = record["event_type"]
        event_id = record["event_id"]
        is_global_transaction = event_type == "work_transaction.committed"
        payload_name = event_type.replace(".", "-").replace("_", "-")
        payload_schema = f"events/{payload_name}"
        expected_event_types = {
            "2.0": {"work_batch.committed"},
            "3.0": {"work_transaction.committed"},
        }
        if event_type in expected_event_types.get(record["schema_version"], {event_type}):
            for issue in self.schemas.issues(
                payload_schema, record["payload"], schema_version=record["schema_version"]
            ):
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(Issue(issue.code, f"$payload{suffix}", issue.message))
        if event_id in event_ids:
            issues.append(Issue(ErrorCode.DUPLICATE_ID, "$event_id", "event ID already exists"))
        if event_type == "case.created" and record["case_id"] in case_ids:
            issues.append(Issue(ErrorCode.DUPLICATE_ID, "$case_id", "case ID already exists"))
        if event_type == "case.created" and record["session_id"] is not None:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$session_id",
                    "case creation is not session-scoped",
                )
            )
        if (
            event_type != "case.created"
            and event_type.startswith("case.")
            and record["session_id"] is not None
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$session_id",
                    "case lifecycle events cannot be session-scoped",
                )
            )
        if (
            event_type != "case.created"
            and not is_global_transaction
            and record["case_id"] not in case_ids
        ):
            issues.append(
                Issue(ErrorCode.EVENT_REFERENCE_MISSING, "$case_id", "case has not been created")
            )
        session_id = record["session_id"]
        session_creation_types = {"session.started", "session.created"}
        if event_type in session_creation_types and session_id is None:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$session_id",
                    "session start requires a session ID",
                )
            )
        if event_type in session_creation_types and session_id in session_ids:
            issues.append(Issue(ErrorCode.DUPLICATE_ID, "$session_id", "session ID already exists"))
        if session_id is not None and event_type not in session_creation_types and session_id not in session_ids:
            issues.append(
                Issue(
                    ErrorCode.SESSION_REFERENCE_MISSING,
                    "$session_id",
                    "session has not been started",
                )
            )
        if session_id is not None and session_id in session_ids:
            prior_session_states, _ = fold_session_states(previous_records)
            prior_session = prior_session_states.get(session_id)
            if prior_session is not None and prior_session.frozen:
                issues.append(
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$session_id",
                        "terminal session is frozen; use a new linked session",
                    )
                )
        causation = record["causation_event_id"]
        if causation is not None and causation not in event_ids:
            issues.append(
                Issue(
                    ErrorCode.EVENT_REFERENCE_MISSING,
                    "$causation_event_id",
                    "causation event does not exist",
                )
            )
        for index, provenance in enumerate(record["provenance"]):
            ref = provenance["ref"]
            if ref.startswith("event_") and ref not in event_ids:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        f"$provenance/{index}/ref",
                        "provenance event does not exist",
                    )
                )
        issues.extend(self._manifest_semantics(record, previous_records))
        issues.extend(self._source_semantics(record, previous_records))
        issues.extend(self._public_research_semantics(record, previous_records))
        issues.extend(self._case_session_relationship_issues(record, previous_records))
        issues.extend(self._reasoning_reference_semantics(record, previous_records))
        issues.extend(self._interaction_and_work_semantics(record, previous_records))
        if event_type == "work_transaction.committed":
            issues.extend(self._work_transaction_issues(record, previous_records))
        if event_type in {
            "work_item.recorded",
            "work_item.status_changed",
            "work_batch.committed",
        } and any(
            item["event_type"] == "work_transaction.committed"
            for item in previous_records
        ):
            issues.append(
                Issue(
                    ErrorCode.WORK_BATCH_CONFLICT,
                    "$event_type",
                    "legacy per-case work writers are fenced after a v3 global transaction",
                )
            )
        all_records = [*previous_records, record]
        issues.extend(fold_case_states(all_records)[1])
        issues.extend(fold_session_states(all_records)[1])
        issues.extend(fold_decisions(all_records)[1])
        issues.extend(self._actor_and_event_semantics(record, previous_records, event_ids))
        return issues

    def _public_research_semantics(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        """Keep citation-only records separate from source intake and retained evidence."""

        if record["event_type"] != "public_research.citation_captured":
            return []
        issues: list[Issue] = []
        payload = record["payload"]
        citation = payload.get("citation")
        if not isinstance(citation, dict):
            return issues
        issues.extend(
            self._nested_schema_issues("public-research-citation", citation, "$payload/citation")
        )
        if payload.get("citation_sha256") != canonical_sha256(citation):
            issues.append(
                Issue(ErrorCode.HASH_CHAIN_INVALID, "$payload/citation_sha256", "citation digest mismatch")
            )
        states, _ = fold_session_states(previous_records)
        session = states.get(record["session_id"])
        if session is None or session.case_id != record["case_id"] or session.status != "active":
            issues.append(
                Issue(ErrorCode.SESSION_REFERENCE_MISSING, "$session_id", "citation requires an active exact session")
            )
        if record["actor"] != RUNTIME_ACTOR:
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "citation must be materialized by the governed runtime",
                )
            )
        if citation.get("case_id") != record["case_id"] or citation.get("session_id") != record["session_id"]:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$payload/citation",
                    "citation case/session must equal its event",
                )
            )
        if citation.get("redirect_chain") != [] or citation.get("object_ref") is not None:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$payload/citation",
                    "citation cannot retain redirects or an object reference",
                )
            )
        if record["subject_refs"] != [citation.get("scope_receipt_id"), citation.get("item_receipt_id")]:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$subject_refs",
                    "citation subjects must be scope then item receipt",
                )
            )
        for prior in previous_records:
            if prior["event_type"] != "public_research.citation_captured":
                continue
            prior_citation = prior["payload"].get("citation", {})
            if (
                prior_citation.get("item_id") == citation.get("item_id")
                or prior_citation.get("request_id") == citation.get("request_id")
            ):
                issues.append(
                    Issue(ErrorCode.DUPLICATE_ID, "$payload/citation", "public citation item/request already exists")
                )
                break
        return issues

    def _source_semantics(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        """Validate additive S3-B source receipts without altering legacy evidence semantics."""

        issues: list[Issue] = []
        event_type = record["event_type"]
        payload = record["payload"]
        if event_type not in {"source.version_registered", "source.extraction_recorded"}:
            return issues
        if record["actor"]["type"] != "runtime":
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "synthetic source receipts are materialized by the governed runtime",
                )
            )
        states, _ = fold_session_states(previous_records)
        session = states.get(record["session_id"])
        if session is None or session.case_id != record["case_id"] or session.status != "active":
            issues.append(
                Issue(
                    ErrorCode.SESSION_REFERENCE_MISSING,
                    "$session_id",
                    "source capture requires an active session in the exact case",
                )
            )
        registrations = [
            item
            for item in previous_records
            if item["event_type"] == "source.version_registered"
        ]
        versions = {
            item["payload"]["version"]["source_version_id"]: item
            for item in registrations
            if isinstance(item["payload"].get("version"), dict)
        }
        if event_type == "source.version_registered":
            version = payload.get("version")
            if not isinstance(version, dict):
                return issues
            issues.extend(self._nested_schema_issues("source-version", version, "$payload/version"))
            if payload.get("version_sha256") != canonical_sha256(version):
                issues.append(
                    Issue(
                        ErrorCode.HASH_CHAIN_INVALID,
                        "$payload/version_sha256",
                        "source version digest mismatch",
                    )
                )
            version_id = version.get("source_version_id")
            family_id = version.get("source_family_id")
            content_sha256 = version.get("content_sha256")
            if version_id in versions:
                issues.append(
                    Issue(ErrorCode.DUPLICATE_ID, "$payload/version/source_version_id", "source version exists")
                )
            parent_id = version.get("prior_source_version_id")
            parent_sha = version.get("prior_content_sha256")
            same_family = [
                item
                for item in registrations
                if item["payload"]["version"].get("source_family_id") == family_id
            ]
            if (parent_id is None) != (parent_sha is None):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/version/prior_source_version_id",
                        "source parent ID and digest must be both present or both null",
                    )
                )
            if parent_id is None and same_family:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/version/source_family_id",
                        "source family already requires an exact parent binding",
                    )
                )
            if (
                not isinstance(content_sha256, str)
                or version.get("object_ref")
                != f"sha256/{content_sha256[:2]}/{content_sha256}"
                or version.get("byte_count", -1) < 0
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$/payload/version",
                        "source object reference and byte count must exactly describe the source digest",
                    )
                )
            capture_method = version.get("capture_method")
            capture_receipt_id = version.get("capture_receipt_id")
            capture_manifest_sha256 = version.get("capture_manifest_sha256")
            if capture_method == "synthetic_fixture" and (
                capture_receipt_id is not None or capture_manifest_sha256 is not None
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$/payload/version",
                        "synthetic fixture source cannot claim a capture receipt",
                    )
                )
            if capture_method == "native_local_synthetic_attachment_handoff" and (
                not isinstance(capture_receipt_id, str)
                or not isinstance(capture_manifest_sha256, str)
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$/payload/version",
                        "native local handoff source requires receipt and manifest bindings",
                    )
                )
            if parent_id is not None:
                parent = versions.get(parent_id)
                if (
                    parent is None
                    or parent["case_id"] != record["case_id"]
                    or parent["payload"]["version"].get("source_family_id") != family_id
                    or parent["payload"]["version"].get("content_sha256") != parent_sha
                ):
                    issues.append(
                        Issue(
                            ErrorCode.EVENT_REFERENCE_MISSING,
                            "$payload/version/prior_source_version_id",
                            "source revision requires an exact same-case parent version",
                        )
                    )
                elif any(
                    item["payload"]["version"].get("prior_source_version_id") == parent_id
                    for item in same_family
                ):
                    issues.append(
                        Issue(
                            ErrorCode.WORK_BATCH_CONFLICT,
                            "$payload/version/prior_source_version_id",
                            "source family cannot create divergent children in S3-B",
                        )
                    )
            if record["subject_refs"] != [family_id, version_id]:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$subject_refs",
                        "source registration subjects must be exactly family then version",
                    )
                )
            return issues

        extraction = payload.get("extraction")
        if not isinstance(extraction, dict):
            return issues
        issues.extend(
            self._nested_schema_issues("source-extraction", extraction, "$payload/extraction")
        )
        if payload.get("extraction_sha256") != canonical_sha256(extraction):
            issues.append(
                Issue(
                    ErrorCode.HASH_CHAIN_INVALID,
                    "$payload/extraction_sha256",
                    "source extraction digest mismatch",
                )
            )
        source = versions.get(extraction.get("source_version_id"))
        if (
            source is None
            or source["event_id"] != extraction.get("registration_event_id")
            or source["case_id"] != record["case_id"]
            or source["payload"]["version"].get("content_sha256")
            != extraction.get("source_object_sha256")
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_REFERENCE_MISSING,
                    "$payload/extraction/source_version_id",
                    "extraction requires its exact same-case source registration",
                )
            )
        extraction_ids = {
            item["payload"]["extraction"].get("extraction_id")
            for item in previous_records
            if item["event_type"] == "source.extraction_recorded"
            and isinstance(item["payload"].get("extraction"), dict)
        }
        if extraction.get("extraction_id") in extraction_ids:
            issues.append(
                Issue(ErrorCode.DUPLICATE_ID, "$payload/extraction/extraction_id", "extraction exists")
            )
        if any(
            item["payload"]["extraction"].get("source_version_id")
            == extraction.get("source_version_id")
            and item["payload"]["extraction"].get("extractor_version")
            == extraction.get("extractor_version")
            for item in previous_records
            if item["event_type"] == "source.extraction_recorded"
            and isinstance(item["payload"].get("extraction"), dict)
        ):
            issues.append(
                Issue(
                    ErrorCode.DUPLICATE_ID,
                    "$payload/extraction/source_version_id",
                    "source version already has this extractor result",
                )
            )
        chunks = extraction.get("chunks", [])
        anchors = [item.get("anchor") for item in chunks if isinstance(item, dict)]
        if len(anchors) != len(set(anchors)) or any(
            item.get("byte_start", 0) < 0
            or item.get("byte_end", -1) <= item.get("byte_start", 0)
            or item.get("line_start", 0) < 1
            or item.get("line_end", 0) < item.get("line_start", 0)
            for item in chunks
            if isinstance(item, dict)
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$payload/extraction/chunks",
                    "source chunks require unique positive ordered anchors and ranges",
                )
            )
        if record["subject_refs"] != [extraction.get("source_version_id"), extraction.get("extraction_id")]:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$subject_refs",
                    "source extraction subjects must be exactly version then extraction",
                )
            )
        return issues

    def _interaction_and_work_semantics(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        event_type = record["event_type"]
        payload = record["payload"]
        session_id = record["session_id"]
        session_events = [
            item for item in previous_records if item.get("session_id") == session_id
        ]
        interaction = (
            fold_interaction_state(previous_records, session_id)
            if session_id is not None
            else None
        )

        if event_type == "interaction.started":
            issues.extend(self._nested_schema_issues("interaction-contract", payload["contract"], "$payload/contract"))
            if payload.get("contract_sha256") != canonical_sha256(payload.get("contract")):
                issues.append(
                    Issue(
                        ErrorCode.HASH_CHAIN_INVALID,
                        "$payload/contract_sha256",
                        "interaction contract digest mismatch",
                    )
                )
            if interaction is not None and interaction["contract"] is not None:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$event_type",
                        "session already has an interaction contract",
                    )
                )
            if record["actor"]["type"] != "runtime":
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "interaction start must be materialized by the governed runtime",
                    )
                )
            plan = next(
                (
                    item["payload"].get("plan")
                    for item in reversed(session_events)
                    if item["event_type"] == "routing.proposed"
                    and item["payload"].get("plan_sha256") == payload.get("plan_sha256")
                ),
                None,
            )
            if (
                plan is None
                or plan.get("plan_id") != payload.get("plan_id")
                or plan.get("interaction") != payload.get("contract")
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload/plan_id",
                        "interaction start must reference the routed plan and exact contract",
                    )
                )

        if event_type == "interaction.mode_changed":
            for field in ("previous_contract", "new_contract"):
                issues.extend(
                    self._nested_schema_issues(
                        "interaction-contract", payload[field], f"$payload/{field}"
                    )
                )
                if payload.get(f"{field}_sha256") != canonical_sha256(payload.get(field)):
                    issues.append(
                        Issue(
                            ErrorCode.HASH_CHAIN_INVALID,
                            f"$payload/{field}_sha256",
                            "interaction contract digest mismatch",
                        )
                    )
            if (
                record["actor"]["type"] != "owner"
                or payload.get("explicit_confirmation") is not True
            ):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "interaction mode change requires explicit owner confirmation",
                    )
                )
            if interaction is None or interaction["contract"] != payload.get("previous_contract"):
                issues.append(
                    Issue(
                        ErrorCode.MANIFEST_HASH_MISMATCH,
                        "$payload/previous_contract",
                        "mode change does not start from the current interaction contract",
                    )
                )
            elif payload["new_contract"]["mode"] not in interaction["contract"][
                "allowed_mode_transitions"
            ]:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/new_contract/mode",
                        "interaction transition is not allowed by the prior contract",
                    )
                )
            revised = payload.get("revised_plan", {})
            issues.extend(
                self._nested_schema_issues(
                    "triage-plan", revised, "$payload/revised_plan"
                )
            )
            expected_plan_hash = canonical_sha256({**revised, "plan_sha256": "0" * 64})
            if (
                revised.get("plan_id") != payload.get("new_plan_id")
                or revised.get("plan_sha256") != payload.get("new_plan_sha256")
                or expected_plan_hash != payload.get("new_plan_sha256")
                or revised.get("interaction") != payload.get("new_contract")
            ):
                issues.append(
                    Issue(
                        ErrorCode.HASH_CHAIN_INVALID,
                        "$payload/revised_plan",
                        "revised plan identity, digest, or interaction contract does not match",
                    )
                )
            prior_state = fold_session_states(previous_records)[0].get(session_id)
            if (
                prior_state is None
                or prior_state.manifest is None
                or prior_state.manifest["triage"].get("plan_sha256")
                != payload.get("previous_plan_sha256")
            ):
                issues.append(
                    Issue(
                        ErrorCode.MANIFEST_HASH_MISMATCH,
                        "$payload/previous_plan_sha256",
                        "mode change does not start from the current manifest plan",
                    )
                )
            old_ids = _skill_ids_for_plan_hash(
                previous_records, payload.get("previous_plan_sha256")
            )
            new_ids = {
                item["package_id"]
                for item in revised.get("selected_packages", [])
                if item.get("package_type") == "skill"
            }
            if (
                payload.get("added_skill_ids") != sorted(new_ids - old_ids)
                or payload.get("removed_skill_ids") != sorted(old_ids - new_ids)
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/added_skill_ids",
                        "mode-change package diff does not match the revised plan",
                    )
                )

        if event_type == "checkpoint.recorded":
            if interaction is None or interaction["contract_sha256"] != payload.get(
                "contract_sha256"
            ):
                issues.append(
                    Issue(
                        ErrorCode.MANIFEST_HASH_MISMATCH,
                        "$payload/contract_sha256",
                        "checkpoint does not bind the current interaction contract",
                    )
                )
            issues.extend(_source_watermark_issues(payload, session_events, "$payload"))
            forbidden = _forbidden_checkpoint_keys(payload.get("state"))
            if forbidden:
                issues.append(
                    Issue(
                        ErrorCode.CHECKPOINT_CONTENT_FORBIDDEN,
                        "$payload/state",
                        f"checkpoint contains forbidden fields: {', '.join(sorted(forbidden))}",
                    )
                )
            checkpoint_ids = {
                item["payload"].get("checkpoint_id")
                for item in previous_records
                if item["event_type"] == "checkpoint.recorded"
            }
            if payload.get("checkpoint_id") in checkpoint_ids:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/checkpoint_id",
                        "checkpoint ID already exists",
                    )
                )

        if event_type == "owner_input.recorded" and (
            record["actor"]["type"] != "owner"
            or payload.get("explicit_confirmation") is not True
        ):
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "owner input requires explicit owner attribution",
                )
            )
        if event_type == "owner_input.recorded":
            input_ids = {
                item["payload"].get("input_id")
                for item in previous_records
                if item["event_type"] == "owner_input.recorded"
            }
            if payload.get("input_id") in input_ids:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/input_id",
                        "owner-input ID already exists",
                    )
                )

        if event_type == "artifact.version_created":
            version = payload["version"]
            issues.extend(
                self._nested_schema_issues("artifact-version", version, "$payload/version")
            )
            if payload.get("version_sha256") != canonical_sha256(version):
                issues.append(
                    Issue(
                        ErrorCode.HASH_CHAIN_INVALID,
                        "$payload/version_sha256",
                        "artifact-version digest mismatch",
                    )
                )
            if record["actor"] != version.get("producer"):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "artifact event actor must match the declared producer",
                    )
                )
            issues.extend(_source_watermark_issues(version, session_events, "$payload/version"))
            artifacts = fold_artifact_state(previous_records, case_id=record["case_id"])
            if interaction is None or interaction["contract"]["artifact_policy"] == "none":
                issues.append(
                    Issue(
                        ErrorCode.ARTIFACT_REFERENCE_INVALID,
                        "$payload/version",
                        "current interaction contract does not allow artifact creation",
                    )
                )
            artifact = artifacts.get(version["artifact_id"])
            all_version_ids = {
                version_id
                for item in artifacts.values()
                for version_id in item["versions"]
            }
            if version["version_id"] in all_version_ids:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/version/version_id",
                        "artifact version ID already exists",
                    )
                )
            if artifact is None:
                if version["version_number"] != 1 or version["prior_version_id"] is not None:
                    issues.append(
                        Issue(
                            ErrorCode.ARTIFACT_REFERENCE_INVALID,
                            "$payload/version/prior_version_id",
                            "new artifact must begin at version 1 without a prior version",
                        )
                    )
            else:
                prior_id = version["prior_version_id"]
                prior_version = artifact["versions"].get(prior_id)
                if (
                    prior_id != artifact["current_version_id"]
                    or prior_version is None
                    or version["version_number"] != prior_version["version_number"] + 1
                ):
                    issues.append(
                        Issue(
                            ErrorCode.ARTIFACT_REFERENCE_INVALID,
                            "$payload/version/prior_version_id",
                            "artifact revision must increment from the current version",
                        )
                    )
                missing = set(version["addressed_feedback_ids"]) - set(artifact["feedback"])
                if missing:
                    issues.append(
                        Issue(
                            ErrorCode.ARTIFACT_REFERENCE_INVALID,
                            "$payload/version/addressed_feedback_ids",
                            "artifact revision references unknown feedback",
                        )
                    )

        if event_type in {
            "artifact.feedback_recorded",
            "artifact.accepted",
            "artifact.withdrawn",
        }:
            artifacts = fold_artifact_state(previous_records, case_id=record["case_id"])
            artifact = artifacts.get(payload.get("artifact_id"))
            version = (
                artifact["versions"].get(payload.get("version_id"))
                if artifact is not None
                else None
            )
            if version is None or version["content_sha256"] != payload.get("content_sha256"):
                issues.append(
                    Issue(
                        ErrorCode.ARTIFACT_REFERENCE_INVALID,
                        "$payload/version_id",
                        "artifact event must reference an existing exact content hash",
                    )
                )
            elif event_type == "artifact.accepted" and version["status"] in {
                "accepted",
                "withdrawn",
            }:
                issues.append(
                    Issue(
                        ErrorCode.ARTIFACT_REFERENCE_INVALID,
                        "$payload/version_id",
                        "artifact version is already accepted or withdrawn",
                    )
                )
            elif event_type == "artifact.withdrawn" and version["status"] == "withdrawn":
                issues.append(
                    Issue(
                        ErrorCode.ARTIFACT_REFERENCE_INVALID,
                        "$payload/version_id",
                        "artifact version is already withdrawn",
                    )
                )
            if (
                record["actor"]["type"] != "owner"
                or payload.get("explicit_confirmation") is not True
            ):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "artifact feedback or disposition requires explicit owner attribution",
                    )
                )
            if event_type == "artifact.feedback_recorded":
                known_feedback = {
                    feedback_id
                    for item in artifacts.values()
                    for feedback_id in item["feedback"]
                }
                if payload.get("feedback_id") in known_feedback:
                    issues.append(
                        Issue(
                            ErrorCode.DUPLICATE_ID,
                            "$payload/feedback_id",
                            "artifact feedback ID already exists",
                        )
                    )

        if event_type == "work_item.recorded":
            issues.extend(_work_item_date_issues(payload, "$payload"))
            existing = fold_work_items(previous_records)
            if payload["work_item_id"] in existing:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/work_item_id",
                        "work-item ID already exists",
                    )
                )
            actor_type = record["actor"]["type"]
            is_system_proposal = (
                actor_type == "runtime"
                and payload["status"] == "proposed"
                and payload["source_kind"] == "system_suggestion"
                and payload["explicit_confirmation"] is False
            )
            is_owner_commitment = (
                actor_type == "owner"
                and payload["status"] == "open"
                and payload["source_kind"] == "owner_instruction"
                and payload["explicit_confirmation"] is True
            )
            if not (is_system_proposal or is_owner_commitment):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "work item must be a system proposal or explicit owner commitment",
                    )
                )

        if event_type == "work_item.status_changed":
            issues.extend(_work_item_date_issues(payload, "$payload"))
            items = fold_work_items(previous_records, case_id=record["case_id"])
            current = items.get(payload["work_item_id"])
            transitions = {
                "proposed": {"open", "cancelled"},
                "open": {"in_progress", "waiting", "done", "cancelled"},
                "in_progress": {"open", "waiting", "done", "cancelled"},
                "waiting": {"open", "in_progress", "done", "cancelled"},
                "done": set(),
                "cancelled": set(),
            }
            if (
                current is None
                or payload["from_status"] != current["status"]
                or payload["to_status"] not in transitions[current["status"]]
            ):
                issues.append(
                    Issue(
                        ErrorCode.WORK_ITEM_TRANSITION_INVALID,
                        "$payload/to_status",
                        "work-item transition does not match current canonical state",
                    )
                )
            if (
                record["actor"]["type"] != "owner"
                or payload.get("explicit_confirmation") is not True
            ):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "work-item status change requires explicit owner confirmation",
                    )
                )
        if event_type == "work_batch.committed":
            issues.extend(self._work_batch_issues(record, previous_records))
        return issues

    def _work_transaction_issues(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        """Validate the one global v3 visibility event against all affected cases at once."""

        issues: list[Issue] = []
        payload = record["payload"]
        manifest = payload.get("transaction_manifest")
        if not isinstance(manifest, dict):
            return issues
        try:
            require_work_transaction_manifest(manifest, self.schemas)
        except ValidationError as exc:
            for issue in exc.issues:
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(
                    Issue(issue.code, f"$payload/transaction_manifest{suffix}", issue.message)
                )
            return issues

        receipt = payload.get("owner_receipt")
        if not isinstance(receipt, dict):
            return issues
        try:
            self.schemas.require("owner-receipt", receipt)
        except ValidationError as exc:
            for issue in exc.issues:
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(Issue(issue.code, f"$payload/owner_receipt{suffix}", issue.message))
            return issues

        expected_targets = work_transaction_targets(manifest)
        policy_proposal = policy_proposal_for_transaction(
            manifest, approval_ref=receipt["approval_id"]
        )
        if any(
            (
                record["case_id"] is not None,
                record["session_id"] is not None,
                payload.get("transaction_id") != manifest["transaction_id"],
                payload.get("transaction_manifest_digest") != manifest["manifest_digest"],
                payload.get("transaction_manifest") != manifest,
                payload.get("affected_case_ids") != manifest["affected_case_ids"],
                payload.get("request_id") != manifest["request_id"],
                payload.get("idempotency_key") != manifest["idempotency_key"],
                payload.get("compatibility") != manifest["compatibility"],
                record["approval_ref"] != receipt["approval_id"],
                tuple(receipt["targets"]) != expected_targets,
                receipt["consequence_class"] != "owner_decision",
                receipt["proposal_digest"] != policy_proposal.proposal_digest,
                manifest["compatibility"].get("minimum_semantic_schema_version") != "3.0",
                not _reader_version_supported(
                    manifest["compatibility"].get("minimum_reader_version")
                ),
            )
        ):
            issues.append(
                Issue(
                    ErrorCode.WORK_BATCH_CONFLICT,
                    "$payload",
                    "global transaction, receipt, compatibility, and affected cases must bind one exact manifest",
                )
            )
        if sorted(record["subject_refs"]) != list(expected_targets):
            issues.append(
                Issue(
                    ErrorCode.WORK_BATCH_CONFLICT,
                    "$subject_refs",
                    "global transaction subjects must be exactly the proposed work-item IDs",
                )
            )

        for prior in previous_records:
            if prior["event_type"] not in {
                "work_batch.committed",
                "work_transaction.committed",
            }:
                continue
            prior_payload = prior["payload"]
            if prior_payload.get("idempotency_key") == manifest["idempotency_key"]:
                issues.append(
                    Issue(
                        ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT,
                        "$payload/idempotency_key",
                        "idempotency key has already been consumed by a committed work update",
                    )
                )
            if prior_payload.get("request_id") == manifest["request_id"]:
                issues.append(
                    Issue(
                        ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT,
                        "$payload/request_id",
                        "request ID has already been consumed by a committed work update",
                    )
                )
            if (
                prior["event_type"] == "work_transaction.committed"
                and prior_payload.get("transaction_id") == manifest["transaction_id"]
            ):
                issues.append(
                    Issue(
                        ErrorCode.WORK_BATCH_CONFLICT,
                        "$payload/transaction_id",
                        "transaction ID has already been committed",
                    )
                )
            if prior_payload.get("transaction_receipt_id") == payload.get(
                "transaction_receipt_id"
            ):
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/transaction_receipt_id",
                        "transaction receipt ID already exists",
                    )
                )
            prior_receipt = prior_payload.get("owner_receipt")
            if isinstance(prior_receipt, dict) and prior_receipt.get("receipt_id") == receipt["receipt_id"]:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/owner_receipt/receipt_id",
                        "owner receipt already supports a committed work update",
                    )
                )

        case_states, _ = fold_case_states(previous_records)
        session_states, _ = fold_session_states(previous_records)
        current_items = fold_work_items(previous_records)
        transitions = {
            "proposed": {"open", "cancelled"},
            "open": {"in_progress", "waiting", "done", "cancelled"},
            "in_progress": {"open", "waiting", "done", "cancelled"},
            "waiting": {"open", "in_progress", "done", "cancelled"},
            "done": set(),
            "cancelled": set(),
        }
        for index, operation in enumerate(manifest["operations"]):
            path = f"$payload/transaction_manifest/operations/{index}"
            case_id = operation["case_id"]
            session_id = operation["session_id"]
            current = current_items.get(operation["work_item_id"])
            issues.extend(_work_item_date_issues(operation["next_state"], f"{path}/next_state"))
            if case_id not in case_states or case_states[case_id].status not in {
                "open",
                "reopened",
            }:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        f"{path}/case_id",
                        "transaction operation requires an open existing case",
                    )
                )
            session = session_states.get(session_id)
            if (
                session is None
                or session.case_id != case_id
                or session.frozen
                or session.status != "active"
            ):
                issues.append(
                    Issue(
                        ErrorCode.SESSION_REFERENCE_MISSING,
                        f"{path}/session_id",
                        "transaction operation requires an active session in its exact case",
                    )
                )
            if operation["operation"] == "record":
                if current is not None or operation["expected_revision"] != 0:
                    issues.append(
                        Issue(
                            ErrorCode.WORK_BATCH_CONFLICT,
                            path,
                            "record operation requires an absent work item at revision zero",
                        )
                    )
                if (
                    operation["next_state"]["status"] != "open"
                    or operation["next_state"]["source_kind"] != "owner_instruction"
                ):
                    issues.append(
                        Issue(
                            ErrorCode.WORK_ITEM_TRANSITION_INVALID,
                            f"{path}/next_state",
                            "owner-authorized transaction records must create open owner instructions",
                        )
                    )
                continue
            if (
                current is None
                or current.get("case_id") != case_id
                or operation["expected_revision"] != current.get("revision", 1)
                or operation["next_state"]["statement"] != current["statement"]
                or operation["next_state"]["source_kind"] != current["source_kind"]
                or operation["next_state"]["status"]
                not in transitions.get(current["status"], set())
            ):
                issues.append(
                    Issue(
                        ErrorCode.WORK_ITEM_TRANSITION_INVALID,
                        path,
                        "status change must start at the exact scoped revision and make one permitted transition",
                    )
                )
        return issues

    def _work_batch_issues(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        """Validate an all-or-nothing v2 work batch against the current v1/v2 view.

        The embedded proposal remains a v1 public contract.  This reader performs its
        versioned upcast only in memory: legacy one-event work mutations have implicit
        revisions, while a v2 batch supplies the expected revision explicitly.
        """

        issues: list[Issue] = []
        payload = record["payload"]
        proposal = payload.get("proposal")
        if not isinstance(proposal, dict):
            return issues
        try:
            require_work_change_proposal(proposal, self.schemas)
        except ValidationError as exc:
            for issue in exc.issues:
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(Issue(issue.code, f"$payload/proposal{suffix}", issue.message))
            return issues

        receipt = payload.get("owner_receipt")
        if not isinstance(receipt, dict):
            return issues
        try:
            self.schemas.require("owner-receipt", receipt)
        except ValidationError as exc:
            for issue in exc.issues:
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(Issue(issue.code, f"$payload/owner_receipt{suffix}", issue.message))
            return issues

        operation_ids = [operation["work_item_id"] for operation in proposal["operations"]]
        expected_targets = tuple(sorted(operation_ids))
        policy_proposal = Proposal(
            operation_class="commit",
            targets=expected_targets,
            consequence_class="owner_decision",
            actor_id=record["actor"]["id"],
            source_refs=(f"work_batch:{proposal['proposal_digest']}",),
            approval_ref=receipt["approval_id"],
        ).finalized()
        if any(
            (
                payload.get("request_id") != proposal["request_id"],
                payload.get("idempotency_key") != proposal["idempotency_key"],
                record["case_id"] != proposal["case_id"],
                record["approval_ref"] != receipt["approval_id"],
                tuple(receipt["targets"]) != expected_targets,
                receipt["consequence_class"] != "owner_decision",
                receipt["proposal_digest"] != policy_proposal.proposal_digest,
                payload.get("compatibility", {}).get("minimum_semantic_schema_version") != "2.0",
                not _reader_version_supported(
                    payload.get("compatibility", {}).get("minimum_reader_version")
                ),
            )
        ):
            issues.append(
                Issue(
                    ErrorCode.WORK_BATCH_CONFLICT,
                    "$payload",
                    "batch fields, owner receipt, and reader capability must bind one exact proposal",
                )
            )
        if sorted(record["subject_refs"]) != list(expected_targets):
            issues.append(
                Issue(
                    ErrorCode.WORK_BATCH_CONFLICT,
                    "$subject_refs",
                    "batch subjects must be exactly the proposed work-item IDs",
                )
            )

        prior_batches = [
            item
            for item in previous_records
            if item["event_type"] == "work_batch.committed"
        ]
        for prior in prior_batches:
            prior_payload = prior["payload"]
            prior_proposal = prior_payload["proposal"]
            if prior_proposal["batch_id"] == proposal["batch_id"]:
                issues.append(
                    Issue(
                        ErrorCode.WORK_BATCH_CONFLICT,
                        "$payload/proposal/batch_id",
                        "work batch ID has already been committed",
                    )
                )
            if prior_payload["idempotency_key"] == proposal["idempotency_key"]:
                issues.append(
                    Issue(
                        ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT,
                        "$payload/idempotency_key",
                        "idempotency key has already been consumed by a committed batch",
                    )
                )
            if prior_payload["work_receipt_id"] == payload.get("work_receipt_id"):
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/work_receipt_id",
                        "work receipt ID already exists",
                    )
                )
            if prior_payload["owner_receipt"]["receipt_id"] == receipt["receipt_id"]:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/owner_receipt/receipt_id",
                        "owner receipt ID already supports a committed batch",
                    )
                )

        current_items = fold_work_items(previous_records, case_id=record["case_id"])
        transitions = {
            "proposed": {"open", "cancelled"},
            "open": {"in_progress", "waiting", "done", "cancelled"},
            "in_progress": {"open", "waiting", "done", "cancelled"},
            "waiting": {"open", "in_progress", "done", "cancelled"},
            "done": set(),
            "cancelled": set(),
        }
        for index, operation in enumerate(proposal["operations"]):
            path = f"$payload/proposal/operations/{index}"
            work_item_id = operation["work_item_id"]
            next_state = operation["next_state"]
            issues.extend(_work_item_date_issues(next_state, f"{path}/next_state"))
            current = current_items.get(work_item_id)
            if operation["operation"] == "record":
                if current is not None or operation["expected_revision"] != 0:
                    issues.append(
                        Issue(
                            ErrorCode.WORK_BATCH_CONFLICT,
                            path,
                            "record operation requires an absent work item at revision zero",
                        )
                    )
                if (
                    next_state["status"] != "open"
                    or next_state["source_kind"] != "owner_instruction"
                ):
                    issues.append(
                        Issue(
                            ErrorCode.WORK_ITEM_TRANSITION_INVALID,
                            f"{path}/next_state",
                            "owner-authorized batch records must create open owner instructions",
                        )
                    )
                continue
            if (
                current is None
                or operation["expected_revision"] != current.get("revision", 1)
                or next_state["statement"] != current["statement"]
                or next_state["source_kind"] != current["source_kind"]
                or next_state["status"] not in transitions.get(current["status"], set())
            ):
                issues.append(
                    Issue(
                        ErrorCode.WORK_ITEM_TRANSITION_INVALID,
                        path,
                        "status change must start at the exact revision and make one permitted transition",
                    )
                )
        return issues

    def _nested_schema_issues(
        self, schema_name: str, value: dict[str, Any], path: str
    ) -> list[Issue]:
        issues: list[Issue] = []
        for issue in self.schemas.issues(schema_name, value):
            suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
            issues.append(Issue(issue.code, f"{path}{suffix}", issue.message))
        return issues

    @staticmethod
    def _case_session_relationship_issues(
        record: dict[str, Any], previous_records: list[dict[str, Any]]
    ) -> list[Issue]:
        issues: list[Issue] = []
        event_type = record["event_type"]
        payload = record["payload"]
        case_states, _ = fold_case_states(previous_records)
        session_states, _ = fold_session_states(previous_records)
        if event_type == "session.created":
            case_state = case_states.get(record["case_id"])
            if case_state is None or case_state.status not in {"open", "reopened"}:
                issues.append(
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$case_id",
                        "new session requires an open or reopened case",
                    )
                )
        if event_type == "case.status_changed" and payload.get("to_status") == "closed":
            active_sessions = [
                state
                for state in session_states.values()
                if state.case_id == record["case_id"] and not state.frozen
            ]
            if active_sessions:
                issues.append(
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$payload/to_status",
                        "case cannot close while a session is nonterminal",
                    )
                )
        if event_type == "case.linked":
            related_case_id = payload.get("related_case_id")
            if related_case_id not in case_states or related_case_id == record["case_id"]:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload/related_case_id",
                        "related case must be a different existing case",
                    )
                )
        return issues

    @staticmethod
    def _reasoning_reference_semantics(
        record: dict[str, Any], previous_records: list[dict[str, Any]]
    ) -> list[Issue]:
        issues: list[Issue] = []
        event_type = record["event_type"]
        payload = record["payload"]
        prior_decisions, _ = fold_decisions(previous_records)
        if event_type == "owner_decision.recorded":
            decision_id = payload.get("decision_id") or next(
                (ref for ref in record["subject_refs"] if ref.startswith("decision_")),
                None,
            )
            if decision_id in prior_decisions:
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        "$payload/decision_id",
                        "decision ID already exists",
                    )
                )
        elif event_type == "owner_decision.revised":
            prior = prior_decisions.get(payload.get("decision_id"))
            if prior is None or prior.case_id != record["case_id"]:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload/decision_id",
                        "decision to revise does not exist",
                    )
                )
        elif event_type == "owner_decision.superseded":
            source = payload.get("decision_id")
            replacement = payload.get("superseded_by_decision_id")
            source_state = prior_decisions.get(source)
            replacement_state = prior_decisions.get(replacement)
            if (
                source_state is None
                or replacement_state is None
                or source_state.case_id != record["case_id"]
                or replacement_state.case_id != record["case_id"]
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload",
                        "both decisions must exist before supersession",
                    )
                )
            if source == replacement:
                issues.append(
                    Issue(
                        ErrorCode.DECISION_SUPERSESSION_CYCLE,
                        "$payload/superseded_by_decision_id",
                        "decision cannot supersede itself",
                    )
                )

        object_specs = {
            "assumption": ("assumption.recorded", "assumption.revised", "assumption_id"),
            "alternative": ("alternative.recorded", "alternative.disposition_changed", "alternative_id"),
            "disagreement": ("disagreement.recorded", "disagreement.resolved", "disagreement_id"),
            "recommendation": ("recommendation.issued", "recommendation.revised", "recommendation_id"),
        }
        for label, (created_type, changed_type, id_field) in object_specs.items():
            identifiers = {
                item["payload"].get(id_field)
                for item in previous_records
                if item["event_type"] == created_type
            }
            identifier = payload.get(id_field)
            if (
                event_type == created_type
                and identifier is not None
                and identifier in identifiers
            ):
                issues.append(
                    Issue(
                        ErrorCode.DUPLICATE_ID,
                        f"$payload/{id_field}",
                        f"{label} ID already exists",
                    )
                )
            if event_type == changed_type and identifier not in identifiers:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        f"$payload/{id_field}",
                        f"{label} does not exist",
                    )
                )
        if event_type == "recommendation.withdrawn":
            identifiers = {
                item["payload"].get("recommendation_id")
                for item in previous_records
                if item["event_type"] == "recommendation.issued"
            }
            if payload.get("recommendation_id") not in identifiers:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload/recommendation_id",
                        "recommendation does not exist",
                    )
                )
        if event_type == "recommendation.revised":
            prior_revisions = [
                item["payload"].get("revision", 1)
                for item in previous_records
                if item["event_type"] in {"recommendation.issued", "recommendation.revised"}
                and (
                    item["payload"].get("recommendation_id")
                    or next(
                        (
                            ref
                            for ref in item["subject_refs"]
                            if ref.startswith("recommendation_")
                        ),
                        None,
                    )
                )
                == payload.get("recommendation_id")
            ]
            if prior_revisions and payload.get("revision") != prior_revisions[-1] + 1:
                issues.append(
                    Issue(
                        ErrorCode.MANIFEST_VERSION_INVALID,
                        "$payload/revision",
                        "recommendation revision must increment exactly once",
                    )
                )
        return issues

    def _manifest_semantics(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        payload = record["payload"]
        event_type = record["event_type"]
        if event_type == "case.created" and "manifest" in payload:
            manifest = payload["manifest"]
            issues.extend(self.schemas.issues("case-manifest", manifest))
            issues.extend(
                manifest_issues(
                    manifest,
                    payload.get("manifest_sha256"),
                    path="$payload/manifest_sha256",
                )
            )
            if manifest.get("case_id") != record["case_id"]:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/manifest/case_id",
                        "case manifest identity mismatch",
                    )
                )
        manifest = payload.get("manifest") or payload.get("frozen_manifest")
        if event_type.startswith("session.") and isinstance(manifest, dict):
            for issue in self.schemas.issues("session-manifest", manifest):
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(Issue(issue.code, f"$payload/manifest{suffix}", issue.message))
            if manifest.get("interaction") is not None:
                issues.extend(
                    self._nested_schema_issues(
                        "interaction-contract",
                        manifest["interaction"],
                        "$payload/manifest/interaction",
                    )
                )
            digest = payload.get("manifest_sha256") or payload.get("frozen_manifest_sha256")
            issues.extend(manifest_issues(manifest, digest, path="$payload/manifest_sha256"))
            if (
                manifest.get("case_id") != record["case_id"]
                or manifest.get("session_id") != record["session_id"]
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/manifest",
                        "session manifest identity mismatch",
                    )
                )
            issues.extend(
                self._session_manifest_policy_issues(
                    manifest,
                    record,
                    previous_records,
                )
            )
            prior_states, _ = fold_session_states(previous_records)
            prior = prior_states.get(record["session_id"])
            if prior is None:
                if (
                    manifest.get("manifest_version") != 1
                    or payload.get("previous_manifest_sha256") is not None
                ):
                    issues.append(
                        Issue(
                            ErrorCode.MANIFEST_VERSION_INVALID,
                            "$payload/manifest/manifest_version",
                            "new session requires manifest version 1 and no prior digest",
                        )
                    )
            else:
                expected_version = (prior.manifest or {}).get("manifest_version", 0) + 1
                if manifest.get("manifest_version") != expected_version:
                    issues.append(
                        Issue(
                            ErrorCode.MANIFEST_VERSION_INVALID,
                            "$payload/manifest/manifest_version",
                            "manifest version must increment exactly once",
                        )
                    )
                if payload.get("previous_manifest_sha256") != prior.manifest_sha256:
                    issues.append(
                        Issue(
                            ErrorCode.MANIFEST_HASH_MISMATCH,
                            "$payload/previous_manifest_sha256",
                            "previous manifest digest mismatch",
                        )
                    )
                prior_interaction = (prior.manifest or {}).get("interaction")
                next_interaction = manifest.get("interaction")
                if next_interaction != prior_interaction:
                    changed_fields = set(payload.get("changed_fields", []))
                    latest_interaction_event = next(
                        (
                            item
                            for item in reversed(previous_records)
                            if item.get("session_id") == record["session_id"]
                            and item["event_type"]
                            in {"interaction.started", "interaction.mode_changed"}
                        ),
                        None,
                    )
                    expected_contract = None
                    if latest_interaction_event is not None:
                        expected_contract = latest_interaction_event["payload"].get(
                            "contract"
                        ) or latest_interaction_event["payload"].get("new_contract")
                    if (
                        event_type != "session.scope_changed"
                        or "interaction" not in changed_fields
                        or next_interaction != expected_contract
                    ):
                        issues.append(
                            Issue(
                                ErrorCode.ACTOR_AUTHORITY_INVALID,
                                "$payload/manifest/interaction",
                                "interaction change requires the matching canonical interaction event",
                            )
                        )
        if event_type == "evidence.registered":
            metadata = payload.get("metadata", {})
            for issue in self.schemas.issues("evidence-metadata", metadata):
                suffix = issue.path[1:] if issue.path.startswith("$") else f"/{issue.path}"
                issues.append(Issue(issue.code, f"$payload/metadata{suffix}", issue.message))
            if payload.get("metadata_sha256") != canonical_sha256(metadata):
                issues.append(
                    Issue(
                        ErrorCode.EVIDENCE_OBJECT_INVALID,
                        "$payload/metadata_sha256",
                        "evidence metadata digest mismatch",
                    )
                )
        return issues

    @staticmethod
    def _session_manifest_policy_issues(
        manifest: dict[str, Any],
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        manifest_labels = set(manifest.get("sensitivity_labels", []))
        authorized_labels = {
            label
            for authorization in manifest.get("authorized_context", [])
            for label in authorization.get("sensitivity_labels", [])
        }
        if not authorized_labels.issubset(manifest_labels):
            issues.append(
                Issue(
                    ErrorCode.CONTEXT_SENSITIVITY_EXCEEDED,
                    "$payload/manifest/sensitivity_labels",
                    "session sensitivity must cover every authorized context label",
                )
            )
        requested = set(manifest.get("requested_permissions", []))
        granted = set(manifest.get("granted_permissions", []))
        if not granted.issubset(requested):
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$payload/manifest/granted_permissions",
                    "granted permissions must be a subset of requested permissions",
                )
            )
        status = manifest.get("status")
        terminal = status in {"closed", "abandoned"}
        has_closure = (
            manifest.get("closure_disposition") is not None
            and manifest.get("closure_reason") is not None
        )
        if terminal != has_closure:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$payload/manifest/closure_disposition",
                    "closure fields must be present exactly for terminal sessions",
                )
            )

        event_index = {event["event_id"]: event for event in previous_records}
        evidence_index = {
            event["payload"]["metadata"]["evidence_id"]: event
            for event in previous_records
            if event["event_type"] == "evidence.registered"
        }
        for index, event_ref in enumerate(manifest.get("event_refs", [])):
            source = event_index.get(event_ref)
            if (
                source is None
                or source.get("case_id") != record["case_id"]
                or source.get("session_id") != record["session_id"]
            ):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        f"$payload/manifest/event_refs/{index}",
                        "manifest event reference must be a prior event in this session",
                    )
                )
        for index, authorization in enumerate(manifest.get("authorized_context", [])):
            ref = authorization.get("ref", "")
            if ref.startswith("event_"):
                source = event_index.get(ref)
            elif ref.startswith("evidence_sha256_"):
                source = evidence_index.get(ref)
            else:
                source = None
            if source is None or source.get("case_id") != record["case_id"]:
                issues.append(
                    Issue(
                        ErrorCode.CONTEXT_AUTHORIZATION_DENIED,
                        f"$payload/manifest/authorized_context/{index}/ref",
                        "authorized context must already exist in the same case",
                    )
                )
                continue
            if ref.startswith("event_"):
                source_labels = {source["sensitivity"]}
            else:
                source_labels = set(source["payload"]["metadata"]["sensitivity_labels"])
            authorization_labels = set(authorization.get("sensitivity_labels", []))
            if not source_labels.issubset(authorization_labels):
                issues.append(
                    Issue(
                        ErrorCode.CONTEXT_SENSITIVITY_EXCEEDED,
                        f"$payload/manifest/authorized_context/{index}/sensitivity_labels",
                        "reference authorization must cover source sensitivity",
                    )
                )
        for index, evidence_ref in enumerate(manifest.get("evidence_refs", [])):
            source = evidence_index.get(evidence_ref)
            if source is None or source.get("case_id") != record["case_id"]:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        f"$payload/manifest/evidence_refs/{index}",
                        "manifest evidence reference must already exist in this case",
                    )
                )

        continues = manifest.get("continues_session_id")
        if continues is not None:
            prior_states, _ = fold_session_states(previous_records)
            prior = prior_states.get(continues)
            if (
                prior is None
                or not prior.frozen
                or prior.case_id != record["case_id"]
                or continues == record["session_id"]
            ):
                issues.append(
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$payload/manifest/continues_session_id",
                        "continued session must be a different terminal session in this case",
                    )
                )
        return issues

    @staticmethod
    def _actor_and_event_semantics(
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
        event_ids: set[str],
    ) -> list[Issue]:
        issues: list[Issue] = []
        event_type = record["event_type"]
        actor_type = record["actor"]["type"]
        payload = record["payload"]
        if event_type in {"owner_decision.recorded", "session.closed"}:
            issues.extend(_semantic_review_gate_issues(record, previous_records))
        if event_type in {"work_batch.committed", "work_transaction.committed"} and actor_type != "runtime":
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "work commitment is materialized by the governed runtime",
                )
            )
        if event_type == "review.requested":
            target = _review_target_from_events(
                previous_records,
                record["session_id"],
                payload.get("target_type"),
                payload.get("target_ref"),
            )
            if actor_type != "runtime":
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "semantic review request is coordinator-attributed, not reviewer-attributed",
                    )
                )
            if target is None or target != payload.get("target_sha256"):
                issues.append(
                    Issue(
                        ErrorCode.REVIEW_TARGET_STALE,
                        "$payload/target_sha256",
                        "review request must bind an existing exact session target",
                    )
                )
        if event_type == "review.completed":
            request = next(
                (
                    item
                    for item in reversed(previous_records)
                    if item["event_type"] == "review.requested"
                    and item["session_id"] == record["session_id"]
                    and item["payload"].get("review_id") == payload.get("review_id")
                ),
                None,
            )
            if actor_type != "runtime":
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "semantic review completion is coordinator-attributed, not reviewer-attributed",
                    )
                )
            if request is None or any(
                request["payload"].get(key) != payload.get(key)
                for key in ("packet_sha256", "target_sha256")
            ):
                issues.append(
                    Issue(
                        ErrorCode.REVIEW_RESULT_INVALID,
                        "$payload",
                        "review completion must bind the prior exact request",
                    )
                )
        if event_type == "review.waived":
            completion = next(
                (
                    item
                    for item in reversed(previous_records)
                    if item["event_type"] == "review.completed"
                    and item["session_id"] == record["session_id"]
                    and item["payload"].get("review_id") == payload.get("review_id")
                    and item["payload"].get("target_sha256") == payload.get("target_sha256")
                    and item["payload"].get("result_sha256") == payload.get("result_sha256")
                ),
                None,
            )
            if (
                actor_type != "owner"
                or payload.get("explicit_confirmation") is not True
                or completion is None
                or completion["payload"].get("status") != "findings"
            ):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$payload",
                        "review waiver requires explicit owner confirmation of an exact finding result",
                    )
                )
        if event_type in {
            "owner_decision.recorded",
            "owner_decision.revised",
            "owner_decision.superseded",
        }:
            if actor_type != "owner" or payload.get("explicit_confirmation") is not True:
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "owner decision requires owner actor and explicit confirmation",
                    )
                )
            if not any(ref.startswith("decision_") for ref in record["subject_refs"]):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$subject_refs",
                        "owner decision requires a decision subject reference",
                    )
                )
        if event_type == "recommendation.issued" and actor_type == "owner":
            if payload.get("owner_authored") is not True:
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "owner-attributed recommendation must be explicitly owner-authored",
                    )
                )
        if event_type == "approval.granted" and actor_type != "owner":
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "approval grant requires owner actor",
                )
            )
        if event_type == "routing.overridden" and (
            actor_type != "owner" or payload.get("explicit_confirmation") is not True
        ):
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "route override requires owner actor and explicit confirmation",
                )
            )
        if event_type == "contribution.recorded" and (
            actor_type != "skill" or record["actor"]["id"] != payload.get("skill_id")
        ):
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "contribution must be attributed to its selected skill actor",
                )
            )
        if event_type == "contribution.recorded" and not any(
            item["event_type"] == "skill.selected"
            and item["session_id"] == record["session_id"]
            and item["payload"].get("package", {}).get("package_id")
            == payload.get("skill_id")
            for item in previous_records
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_REFERENCE_MISSING,
                    "$payload/skill_id",
                    "contributing skill was not selected earlier in this session",
                )
            )
        if event_type == "framework.stage_recorded" and not any(
            item["event_type"] == "framework.selected"
            and item["session_id"] == record["session_id"]
            and item["payload"].get("package", {}).get("package_id")
            == payload.get("framework_id")
            for item in previous_records
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_REFERENCE_MISSING,
                    "$payload/framework_id",
                    "framework was not selected earlier in this session",
                )
            )
        if event_type == "review.finding_recorded" and actor_type != "reviewer":
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    "review finding requires a reviewer actor",
                )
            )
        if event_type == "review.finding_recorded" and not any(
            item["session_id"] == record["session_id"]
            and item["event_type"]
            in {"recommendation.issued", "recommendation.revised"}
            and payload.get("recommendation_id") in item["subject_refs"]
            for item in previous_records
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_REFERENCE_MISSING,
                    "$payload/recommendation_id",
                    "review target recommendation does not exist in this session",
                )
            )
        if event_type == "recommendation.upheld" and not any(
            item["session_id"] == record["session_id"]
            and item["event_type"] == "review.finding_recorded"
            and item["payload"].get("finding_id") == payload.get("finding_id")
            for item in previous_records
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_REFERENCE_MISSING,
                    "$payload/finding_id",
                    "upheld recommendation must respond to a prior review finding",
                )
            )
        if event_type == "event.correction_recorded":
            corrected = payload.get("corrects_event_id")
            has_relation = any(
                item["ref"] == corrected and item["relation"] == "corrects"
                for item in record["provenance"]
            )
            if corrected not in event_ids or not has_relation:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/corrects_event_id",
                        "correction must reference a prior event with corrects provenance",
                    )
                )
        if event_type == "outcome.assessed":
            decision_id = payload.get("decision_id")
            decision_events = [
                item
                for item in previous_records
                if item["event_type"] == "owner_decision.recorded"
                and decision_id in item["subject_refs"]
            ]
            evidence_ids = {
                item["payload"]["metadata"]["evidence_id"]
                for item in previous_records
                if item["event_type"] == "evidence.registered"
            }
            if actor_type != "owner":
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$actor",
                        "outcome assessment requires explicit owner attribution",
                    )
                )
            if not any(item["case_id"] == record["case_id"] for item in decision_events):
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload/decision_id",
                        "outcome assessment must reference a prior decision in the same case",
                    )
                )
            missing_evidence = sorted(set(payload.get("evidence_refs", [])) - evidence_ids)
            if missing_evidence:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$payload/evidence_refs",
                        "outcome assessment references unregistered evidence",
                    )
                )
        if event_type == "session.closed":
            disposition = payload.get("disposition")
            allowed = {"completed", "decided", "no_decision", "deferred", "abandoned", "blocked"}
            if disposition not in allowed:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$payload/disposition",
                        "session closure requires an explicit disposition",
                    )
                )
            has_owner_decision = any(
                item["event_type"] == "owner_decision.recorded"
                and item["session_id"] == record["session_id"]
                for item in previous_records
            )
            if disposition == "decided" and not has_owner_decision:
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$payload/disposition",
                        "decided closure requires a prior explicit owner decision",
                    )
                )
        return issues


def _skill_ids_for_plan_hash(
    events: list[dict[str, Any]], plan_sha256: str | None
) -> set[str]:
    for event in reversed(events):
        plan: dict[str, Any] | None = None
        if event["event_type"] == "routing.proposed":
            plan = event["payload"].get("plan")
        elif event["event_type"] == "routing.overridden":
            plan = event["payload"].get("revised_plan")
        elif event["event_type"] == "interaction.mode_changed":
            plan = event["payload"].get("revised_plan")
        if plan is not None and plan.get("plan_sha256") == plan_sha256:
            return {
                item["package_id"]
                for item in plan.get("selected_packages", [])
                if item.get("package_type") == "skill"
            }
    return set()


def _source_watermark_issues(
    payload: dict[str, Any], session_events: list[dict[str, Any]], path: str
) -> list[Issue]:
    issues: list[Issue] = []
    expected_ids = [event["event_id"] for event in session_events]
    if payload.get("source_event_ids") != expected_ids:
        issues.append(
            Issue(
                ErrorCode.EVENT_REFERENCE_MISSING,
                f"{path}/source_event_ids",
                "source events must be the complete prior session watermark",
            )
        )
    expected_watermark = (
        session_events[-1]["integrity"]["event_sha256"] if session_events else None
    )
    if payload.get("source_watermark") != expected_watermark:
        issues.append(
            Issue(
                ErrorCode.HASH_CHAIN_INVALID,
                f"{path}/source_watermark",
                "source watermark does not match the latest prior session event",
            )
        )
    return issues


def _review_target_from_events(
    events: list[dict[str, Any]], session_id: str | None, target_type: str | None, target_ref: str | None
) -> str | None:
    """Return the exact target digest that a review request is permitted to bind."""

    for event in reversed(events):
        if event.get("session_id") != session_id:
            continue
        payload = event["payload"]
        if (
            target_type == "recommendation"
            and event["event_type"] in {"recommendation.issued", "recommendation.revised"}
            and payload.get("recommendation_id") == target_ref
        ):
            return event["integrity"]["event_sha256"]
        if (
            target_type == "checkpoint"
            and event["event_type"] == "checkpoint.recorded"
            and payload.get("checkpoint_id") == target_ref
        ):
            return event["integrity"]["event_sha256"]
        if (
            target_type == "artifact_version"
            and event["event_type"] == "artifact.version_created"
            and payload.get("version", {}).get("version_id") == target_ref
        ):
            return payload["version"].get("content_sha256")
    return None


def _semantic_review_gate_issues(
    record: dict[str, Any], previous_records: list[dict[str, Any]]
) -> list[Issue]:
    """Block consequential finalization while an exact requested review remains unresolved."""

    session_id = record.get("session_id")
    requests = [
        item
        for item in previous_records
        if item.get("session_id") == session_id and item["event_type"] == "review.requested"
    ]
    unresolved: list[str] = []
    for request in requests:
        payload = request["payload"]
        review_id = payload["review_id"]
        target_sha256 = payload["target_sha256"]
        completions = [
            item
            for item in previous_records
            if item.get("session_id") == session_id
            and item["event_type"] == "review.completed"
            and item["payload"].get("review_id") == review_id
            and item["payload"].get("target_sha256") == target_sha256
        ]
        waivers = [
            item
            for item in previous_records
            if item.get("session_id") == session_id
            and item["event_type"] == "review.waived"
            and item["payload"].get("review_id") == review_id
            and item["payload"].get("target_sha256") == target_sha256
        ]
        if (completions and completions[-1]["payload"].get("status") == "pass") or waivers:
            continue
        unresolved.append(review_id)
    if not unresolved:
        return []
    return [
        Issue(
            ErrorCode.REVIEW_REQUIRED_UNRESOLVED,
            "$review",
            "required semantic review is not passed or explicitly waived: " + ", ".join(unresolved),
        )
    ]


def _forbidden_checkpoint_keys(value: Any) -> set[str]:
    forbidden = {"chain_of_thought", "hidden_reasoning", "messages", "raw_transcript", "transcript"}
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in forbidden:
                found.add(key)
            found.update(_forbidden_checkpoint_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_forbidden_checkpoint_keys(item))
    return found


def _work_item_date_issues(payload: dict[str, Any], path: str) -> list[Issue]:
    issues: list[Issue] = []
    for field in ("due_on", "next_review_on"):
        value = payload.get(field)
        if value is None:
            continue
        try:
            date.fromisoformat(value)
        except ValueError:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    f"{path}/{field}",
                    "work-item date must be a real ISO calendar date",
                )
            )
    return issues


def _reader_version_supported(required: Any) -> bool:
    """Return whether this reader meets a declared three-component minimum version."""

    if not isinstance(required, str):
        return False
    try:
        required_parts = tuple(int(part) for part in required.split("."))
        current_parts = tuple(int(part) for part in __version__.split("."))
    except ValueError:
        return False
    return len(required_parts) == 3 and len(current_parts) == 3 and current_parts >= required_parts


class OperationalLedger(HashChainedLedger):
    """Separate operational audit ledger."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry):
        super().__init__(
            paths=paths,
            schemas=schemas,
            root=paths.audit_root,
            schema_name="operational-audit",
            timestamp_field="attempted_at",
            id_field="operation_id",
            previous_hash_field="previous_record_sha256",
            record_hash_field="record_sha256",
            staging_kind="operational",
        )

    def domain_issues(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        operation_ids = {item["operation_id"] for item in previous_records}
        if record["operation_id"] in operation_ids:
            issues.append(Issue(ErrorCode.DUPLICATE_ID, "$operation_id", "operation ID exists"))
        if record["policy"]["result"] == "deny":
            if record["attempt_status"] != "not_attempted" or record["result"] != "denied":
                issues.append(
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$attempt_status",
                        "denied policy must produce a non-attempted denied operation",
                    )
                )
        return issues


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _durable_create(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        written = os.write(descriptor, data)
        if written != len(data):
            raise OSError(f"short durable write: {written}/{len(data)}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _durable_create_if_absent(path: Path, data: bytes) -> None:
    try:
        _durable_create(path, data)
    except FileExistsError:
        if path.read_bytes() != data:
            raise LedgerCorruptionError(
                [Issue(ErrorCode.HASH_CHAIN_INVALID, str(path), "quarantine hash collision")]
            )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
