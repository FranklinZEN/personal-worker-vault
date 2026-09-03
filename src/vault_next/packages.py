"""Immutable Phase 3 package registry and governed lifecycle."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from vault_next.canonical import canonical_bytes, canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.ledger import HashChainedLedger
from vault_next.paths import RuntimePaths
from vault_next.records import SCHEMA_VERSION, SchemaRegistry, aware_utc_now, timestamp

PACKAGE_TYPES = frozenset({"profile", "skill", "framework"})


@dataclass(frozen=True)
class PackagePointer:
    package_type: str
    package_id: str
    version: str
    digest: str
    status: str = "candidate"
    approval_ref: str | None = None
    activated_at: datetime | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "package_type": self.package_type,
            "package_id": self.package_id,
            "version": self.version,
            "digest": self.digest,
            "status": self.status,
            "approval_ref": self.approval_ref,
            "activated_at": timestamp(self.activated_at) if self.activated_at else None,
        }


def validate_package_pointer(pointer: PackagePointer, schemas: SchemaRegistry) -> None:
    """Require coherent candidate/active lifecycle metadata."""

    issues = list(schemas.issues("package-pointer", pointer.to_record()))
    if pointer.status == "active" and (
        pointer.approval_ref is None or pointer.activated_at is None
    ):
        issues.append(
            Issue(
                ErrorCode.ACTOR_AUTHORITY_INVALID,
                "$status",
                "active package pointer requires approval and activation time",
            )
        )
    if pointer.status == "candidate" and (
        pointer.approval_ref is not None or pointer.activated_at is not None
    ):
        issues.append(
            Issue(
                ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                "$status",
                "candidate package pointer cannot claim active approval metadata",
            )
        )
    if issues:
        raise ValidationError(issues)


def validate_pointer_transition(previous: PackagePointer, proposed: PackagePointer) -> None:
    """Prevent an active version from being behaviorally mutated in place."""

    issues: list[Issue] = []
    same_identity = (
        previous.package_type == proposed.package_type
        and previous.package_id == proposed.package_id
        and previous.version == proposed.version
    )
    if same_identity and previous.digest != proposed.digest:
        issues.append(
            Issue(
                ErrorCode.PACKAGE_VERSION_IMMUTABLE,
                "$digest",
                "a package version digest is immutable; create a new version",
            )
        )
    if previous.status == "active" and proposed.status == "candidate" and same_identity:
        issues.append(
            Issue(
                ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                "$status",
                "an active pointer cannot be rewritten back to candidate",
            )
        )
    if issues:
        raise ValidationError(issues)


class PackageLifecycleLedger(HashChainedLedger):
    """Independent canonical history for package governance events."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry):
        super().__init__(
            paths=paths,
            schemas=schemas,
            root=paths.package_root / "lifecycle",
            schema_name="package-lifecycle-event",
            timestamp_field="recorded_at",
            id_field="event_id",
            previous_hash_field="previous_event_sha256",
            record_hash_field="event_sha256",
            staging_kind="package-lifecycle",
        )

    def domain_issues(
        self,
        record: dict[str, Any],
        previous_records: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        if record["event_id"] in {item["event_id"] for item in previous_records}:
            issues.append(Issue(ErrorCode.DUPLICATE_ID, "$event_id", "event ID already exists"))
        event_type = record["event_type"]
        actor_type = record["actor"]["type"]
        allowed_actors = {
            "package.proposed": {"runtime", "owner"},
            "package.design_reviewed": {"reviewer"},
            "package.candidate_created": {"runtime", "owner"},
            "package.evaluated": {"reviewer"},
            "package.reviewed": {"reviewer"},
            "package.owner_approved": {"owner"},
            "package.activated": {"runtime"},
            "package.suspended": {"owner", "policy"},
            "package.deprecated": {"owner", "policy"},
        }
        if actor_type not in allowed_actors[event_type]:
            issues.append(
                Issue(
                    ErrorCode.ACTOR_AUTHORITY_INVALID,
                    "$actor",
                    f"{event_type} cannot be recorded by {actor_type}",
                )
            )
        identity = (
            record["package_type"],
            record["package_id"],
            record["version"],
            record["package_digest"],
        )
        history = [
            item
            for item in previous_records
            if (
                item["package_type"],
                item["package_id"],
                item["version"],
                item["package_digest"],
            )
            == identity
        ]
        required_prior = {
            "package.design_reviewed": "package.proposed",
            "package.candidate_created": "package.design_reviewed",
            "package.evaluated": "package.candidate_created",
            "package.reviewed": "package.candidate_created",
            "package.owner_approved": "package.reviewed",
            "package.activated": "package.owner_approved",
            "package.suspended": "package.activated",
            "package.deprecated": "package.activated",
        }
        prerequisite = required_prior.get(event_type)
        if prerequisite and not any(
            item["event_type"] == prerequisite for item in history
        ):
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$event_type",
                    f"{event_type} requires prior {prerequisite} for the exact package digest",
                )
            )
        if event_type == "package.owner_approved":
            latest_evaluation = next(
                (
                    item
                    for item in reversed(history)
                    if item["event_type"] == "package.evaluated"
                ),
                None,
            )
            latest_review = next(
                (
                    item
                    for item in reversed(history)
                    if item["event_type"] == "package.reviewed"
                ),
                None,
            )
            if (
                latest_evaluation is None
                or latest_evaluation["payload"].get("adjudication") != "pass"
                or latest_review is None
                or latest_review["payload"].get("outcome") != "pass"
                or record["payload"].get("explicit_confirmation") is not True
            ):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$payload",
                        "owner approval requires explicit confirmation and passing evaluation/review",
                    )
                )
        if event_type == "package.activated":
            approval = next(
                (
                    item
                    for item in reversed(history)
                    if item["event_type"] == "package.owner_approved"
                ),
                None,
            )
            if approval is not None and record["payload"].get(
                "approval_ref"
            ) != approval["payload"].get("approval_ref"):
                issues.append(
                    Issue(
                        ErrorCode.ACTOR_AUTHORITY_INVALID,
                        "$payload/approval_ref",
                        "activation must use the exact prior owner approval",
                    )
                )
        return issues


class PackageRegistry:
    """Create immutable candidates and expose only exactly approved active versions."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
    ) -> None:
        self.paths = paths
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock
        self.lifecycle = PackageLifecycleLedger(paths, schemas)

    def create_candidate(
        self,
        package: dict[str, Any],
        *,
        proposal_rationale: str,
        actor: dict[str, str] | None = None,
    ) -> str:
        actor = actor or {"type": "runtime", "id": "vault-next-runtime"}
        if actor["type"] not in {"runtime", "owner"}:
            raise self._authority_error("candidate packages cannot create or alter themselves")
        package_type = package.get("package_type", "")
        if package_type not in PACKAGE_TYPES:
            raise ValidationError(
                [Issue(ErrorCode.SCHEMA_ENUM, "$package_type", "unknown package type")]
            )
        self.schemas.require(f"{package_type}-package", package)
        self._validate_change_classification(package)
        digest = canonical_sha256(package)
        path = self._version_path(
            package_type,
            package["package_id"],
            package["version"],
        )
        _durable_create_if_absent(path, canonical_bytes(package) + b"\n")
        identity = self._identity(package_type, package["package_id"], package["version"])
        existing = [
            event
            for event in self.lifecycle.read_all()
            if self._event_identity(event) == identity
        ]
        if existing:
            if any(event["package_digest"] != digest for event in existing):
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.PACKAGE_VERSION_IMMUTABLE,
                            str(path),
                            "package version already exists with a different digest",
                        )
                    ]
                )
            return digest
        self._append_event(
            "package.proposed",
            package,
            digest,
            actor,
            {"rationale": proposal_rationale},
        )
        review = package["design_review"]
        self._append_event(
            "package.design_reviewed",
            package,
            digest,
            {"type": "reviewer", "id": review["reviewer_id"]},
            {"outcome": review["outcome"], "rationale": review["rationale"]},
        )
        self._append_event(
            "package.candidate_created",
            package,
            digest,
            actor,
            {
                "change_class": package["change_class"],
                "fixture_refs": package["evaluation_fixture_refs"],
            },
        )
        return digest

    def record_evaluation(
        self,
        package_type: str,
        package_id: str,
        version: str,
        *,
        fixture_results: list[dict[str, Any]],
        adjudicator_id: str,
        suite_version: str = "1.0.0",
    ) -> dict[str, Any]:
        package, digest = self.resolve_version(package_type, package_id, version)
        all_passed = all(result["passed"] for result in fixture_results)
        evaluation = {
            "schema_version": SCHEMA_VERSION,
            "evaluation_id": f"evaluation_{canonical_sha256(fixture_results)[:24]}",
            "package_digest": digest,
            "suite_version": suite_version,
            "evaluated_at": timestamp(self.clock()),
            "fixture_results": fixture_results,
            "adjudication": "pass" if all_passed else "fail",
            "adjudicator_id": adjudicator_id,
        }
        self.schemas.require("package-evaluation", evaluation)
        path = self.paths.ensure_runtime_write_target(
            self.paths.evaluation_root
            / package_type
            / package_id
            / version
            / f"{evaluation['evaluation_id']}.json"
        )
        _durable_create_if_absent(path, canonical_bytes(evaluation) + b"\n")
        return self._append_event(
            "package.evaluated",
            package,
            digest,
            {"type": "reviewer", "id": adjudicator_id},
            {
                "adjudication": evaluation["adjudication"],
                "evaluation_id": evaluation["evaluation_id"],
                "evaluation_sha256": canonical_sha256(evaluation),
            },
        )

    def record_independent_review(
        self,
        package_type: str,
        package_id: str,
        version: str,
        *,
        reviewer_id: str,
        outcome: str,
        findings: list[str],
        rollback_plan: str,
    ) -> dict[str, Any]:
        if outcome not in {"pass", "fail"}:
            raise ValueError("review outcome must be pass or fail")
        package, digest = self.resolve_version(package_type, package_id, version)
        return self._append_event(
            "package.reviewed",
            package,
            digest,
            {"type": "reviewer", "id": reviewer_id},
            {
                "outcome": outcome,
                "findings": findings,
                "rollback_plan": rollback_plan,
            },
        )

    def approve(
        self,
        package_type: str,
        package_id: str,
        version: str,
        *,
        owner_id: str,
        accepted_limitations: list[str],
    ) -> dict[str, Any]:
        package, digest = self.resolve_version(package_type, package_id, version)
        history = self._history(package_type, package_id, version, digest)
        evaluation = self._latest(history, "package.evaluated")
        review = self._latest(history, "package.reviewed")
        if evaluation is None or evaluation["payload"].get("adjudication") != "pass":
            raise self._lifecycle_error("passing evaluation is required before approval")
        if review is None or review["payload"].get("outcome") != "pass":
            raise self._lifecycle_error("passing independent review is required before approval")
        approval_ref = self.ids.new("approval")
        permission_profile = {
            "requested": package["requested_permissions"],
            "prohibited": package["prohibited_actions"],
        }
        return self._append_event(
            "package.owner_approved",
            package,
            digest,
            {"type": "owner", "id": owner_id},
            {
                "approval_ref": approval_ref,
                "candidate_digest": digest,
                "evaluation_event_id": evaluation["event_id"],
                "review_event_id": review["event_id"],
                "permission_profile_sha256": canonical_sha256(permission_profile),
                "accepted_limitations": accepted_limitations,
                "explicit_confirmation": True,
            },
        )

    def activate(
        self,
        package_type: str,
        package_id: str,
        version: str,
    ) -> PackagePointer:
        package, digest = self.resolve_version(package_type, package_id, version)
        history = self._history(package_type, package_id, version, digest)
        approval = self._latest(history, "package.owner_approved")
        if approval is None or approval["payload"].get("candidate_digest") != digest:
            raise self._lifecycle_error("exact owner approval is required before activation")
        when = self.clock()
        pointer = PackagePointer(
            package_type,
            package_id,
            version,
            digest,
            "active",
            approval["payload"]["approval_ref"],
            when,
        )
        validate_package_pointer(pointer, self.schemas)
        previous = self.read_pointer(package_type, package_id)
        if previous is not None:
            if (
                previous.version == version
                and previous.digest == digest
                and previous.status == "active"
            ):
                return previous
            if previous.version == version and previous.status in {
                "suspended",
                "deprecated",
            }:
                raise self._lifecycle_error(
                    "a suspended or deprecated version cannot be reactivated; create a new version"
                )
            validate_pointer_transition(previous, pointer)
        self._append_event(
            "package.activated",
            package,
            digest,
            {"type": "runtime", "id": "vault-next-runtime"},
            {
                "approval_ref": pointer.approval_ref,
                "pointer_sha256": canonical_sha256(pointer.to_record()),
            },
            when=when,
        )
        _atomic_write(self._pointer_path(package_type, package_id), pointer.to_record())
        return pointer

    def change_availability(
        self,
        package_type: str,
        package_id: str,
        *,
        status: str,
        reason: str,
        actor: dict[str, str],
    ) -> PackagePointer:
        if status not in {"suspended", "deprecated"}:
            raise ValueError("availability change must suspend or deprecate")
        if actor["type"] not in {"owner", "policy"}:
            raise self._authority_error("only owner or policy may change availability")
        previous = self.read_pointer(package_type, package_id)
        if previous is None:
            raise self._lifecycle_error("package has no active pointer")
        allowed = {
            "active": {"suspended", "deprecated"},
            "suspended": {"deprecated"},
            "deprecated": set(),
        }
        if status not in allowed.get(previous.status, set()):
            raise self._lifecycle_error(
                f"invalid package availability transition: {previous.status} -> {status}"
            )
        package, digest = self.resolve_version(
            package_type,
            package_id,
            previous.version,
            expected_digest=previous.digest,
        )
        proposed = PackagePointer(
            package_type,
            package_id,
            previous.version,
            digest,
            status,
            previous.approval_ref,
            previous.activated_at,
        )
        validate_package_pointer(proposed, self.schemas)
        self._append_event(
            f"package.{status}",
            package,
            digest,
            actor,
            {"reason": reason, "prior_status": previous.status},
        )
        _atomic_write(self._pointer_path(package_type, package_id), proposed.to_record())
        return proposed

    def resolve_version(
        self,
        package_type: str,
        package_id: str,
        version: str,
        *,
        expected_digest: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        path = self._version_path(package_type, package_id, version)
        try:
            raw = path.read_bytes()
            package = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(
                [Issue(ErrorCode.EVENT_REFERENCE_MISSING, str(path), "package version unavailable")]
            ) from exc
        if canonical_bytes(package) + b"\n" != raw:
            raise ValidationError(
                [Issue(ErrorCode.CANONICAL_RECORD_MISMATCH, str(path), "package is not canonical")]
            )
        self.schemas.require(f"{package_type}-package", package)
        digest = canonical_sha256(package)
        if expected_digest is not None and digest != expected_digest:
            raise ValidationError(
                [Issue(ErrorCode.PACKAGE_VERSION_IMMUTABLE, str(path), "package digest mismatch")]
            )
        return package, digest

    def require_selectable(self, package_type: str, package_id: str) -> dict[str, Any]:
        pointer = self.read_pointer(package_type, package_id)
        if pointer is None or pointer.status != "active":
            raise self._lifecycle_error("package is not active and selectable")
        package, _ = self.resolve_version(
            package_type,
            package_id,
            pointer.version,
            expected_digest=pointer.digest,
        )
        return package

    def read_pointer(self, package_type: str, package_id: str) -> PackagePointer | None:
        path = self._pointer_path(package_type, package_id)
        if not path.exists():
            return None
        record = json.loads(path.read_text(encoding="utf-8"))
        pointer = PackagePointer(
            record["package_type"],
            record["package_id"],
            record["version"],
            record["digest"],
            record["status"],
            record["approval_ref"],
            datetime.fromisoformat(record["activated_at"].replace("Z", "+00:00"))
            if record["activated_at"]
            else None,
        )
        validate_package_pointer(pointer, self.schemas)
        return pointer

    def active_packages(
        self, package_type: str
    ) -> list[tuple[dict[str, Any], PackagePointer]]:
        results: list[tuple[dict[str, Any], PackagePointer]] = []
        base = self.paths.package_root / package_type
        if not base.exists():
            return results
        for path in sorted(base.glob("*/active-pointer.json")):
            pointer = self.read_pointer(package_type, path.parent.name)
            if pointer is None or pointer.status != "active":
                continue
            package = self.require_selectable(package_type, pointer.package_id)
            results.append((package, pointer))
        return results

    def generate_catalog_index(self) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        for package_type in sorted(PACKAGE_TYPES):
            for package, pointer in self.active_packages(package_type):
                entries.append(
                    {
                        "package_type": package_type,
                        "package_id": pointer.package_id,
                        "version": pointer.version,
                        "digest": pointer.digest,
                        "display_name": package["display_name"],
                    }
                )
        lifecycle_events = self.lifecycle.read_all()
        index = {
            "schema_version": SCHEMA_VERSION,
            "entries": entries,
            "source_lifecycle_hash": lifecycle_events[-1]["integrity"]["event_sha256"]
            if lifecycle_events
            else "GENESIS",
            "catalog_sha256": "0" * 64,
        }
        index["catalog_sha256"] = canonical_sha256(
            {**index, "catalog_sha256": "0" * 64}
        )
        index_path = self.paths.ensure_runtime_write_target(
            self.paths.projection_root / "catalog-index.json"
        )
        _atomic_write(index_path, index)
        return index

    def validate(self) -> tuple[Issue, ...]:
        issues = list(self.lifecycle.validate_all())
        for package_type in PACKAGE_TYPES:
            base = self.paths.package_root / package_type
            if not base.exists():
                continue
            for pointer_path in sorted(base.glob("*/active-pointer.json")):
                try:
                    pointer = self.read_pointer(package_type, pointer_path.parent.name)
                    if pointer is None:
                        continue
                    self.resolve_version(
                        package_type,
                        pointer.package_id,
                        pointer.version,
                        expected_digest=pointer.digest,
                    )
                    if pointer.status == "active":
                        history = self._history(
                            package_type,
                            pointer.package_id,
                            pointer.version,
                            pointer.digest,
                        )
                        if self._latest(history, "package.activated") is None:
                            raise self._lifecycle_error("active pointer lacks activation event")
                except (KeyError, ValueError, ValidationError) as exc:
                    issues.append(
                        Issue(
                            ErrorCode.PACKAGE_VERSION_IMMUTABLE,
                            str(pointer_path),
                            f"package pointer validation failed: {type(exc).__name__}",
                        )
                    )
        index_path = self.paths.projection_root / "catalog-index.json"
        if index_path.exists():
            try:
                raw = index_path.read_bytes()
                index = json.loads(raw)
                if raw != canonical_bytes(index) + b"\n":
                    raise ValueError("catalog index is not canonical")
                expected_hash = canonical_sha256(
                    {**index, "catalog_sha256": "0" * 64}
                )
                if index.get("catalog_sha256") != expected_hash:
                    raise ValueError("catalog digest mismatch")
                active = {
                    (package_type, pointer.package_id, pointer.version, pointer.digest)
                    for package_type in PACKAGE_TYPES
                    for _, pointer in self.active_packages(package_type)
                }
                indexed = {
                    (
                        entry["package_type"],
                        entry["package_id"],
                        entry["version"],
                        entry["digest"],
                    )
                    for entry in index["entries"]
                }
                if indexed != active:
                    raise ValueError("catalog entries differ from active pointers")
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                issues.append(
                    Issue(
                        ErrorCode.PROJECTION_TAMPERED,
                        str(index_path),
                        f"catalog index validation failed: {type(exc).__name__}",
                    )
                )
        return tuple(sorted(issues))

    def _append_event(
        self,
        event_type: str,
        package: dict[str, Any],
        digest: str,
        actor: dict[str, str],
        payload: dict[str, Any],
        *,
        when: datetime | None = None,
    ) -> dict[str, Any]:
        instant = when or self.clock()
        candidate = {
            "schema_version": SCHEMA_VERSION,
            "event_id": self.ids.new("event"),
            "event_type": event_type,
            "recorded_at": timestamp(instant),
            "actor": actor,
            "package_type": package["package_type"],
            "package_id": package["package_id"],
            "version": package["version"],
            "package_digest": digest,
            "payload": payload,
            "integrity": {
                "previous_event_sha256": "GENESIS",
                "event_sha256": "0" * 64,
            },
        }
        return self.lifecycle.append(candidate)

    def _history(
        self,
        package_type: str,
        package_id: str,
        version: str,
        digest: str,
    ) -> list[dict[str, Any]]:
        return [
            event
            for event in self.lifecycle.read_all()
            if self._event_identity(event)
            == self._identity(package_type, package_id, version)
            and event["package_digest"] == digest
        ]

    @staticmethod
    def _latest(
        history: list[dict[str, Any]], event_type: str
    ) -> dict[str, Any] | None:
        return next(
            (event for event in reversed(history) if event["event_type"] == event_type),
            None,
        )

    def _version_path(self, package_type: str, package_id: str, version: str) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.package_root
            / package_type
            / package_id
            / "versions"
            / f"{version}.json"
        )

    def _pointer_path(self, package_type: str, package_id: str) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.package_root / package_type / package_id / "active-pointer.json"
        )

    @staticmethod
    def _identity(package_type: str, package_id: str, version: str) -> tuple[str, str, str]:
        return package_type, package_id, version

    @staticmethod
    def _event_identity(event: dict[str, Any]) -> tuple[str, str, str]:
        return event["package_type"], event["package_id"], event["version"]

    @staticmethod
    def _authority_error(message: str) -> ValidationError:
        return ValidationError([Issue(ErrorCode.ACTOR_AUTHORITY_INVALID, "$actor", message)])

    @staticmethod
    def _lifecycle_error(message: str) -> ValidationError:
        return ValidationError(
            [Issue(ErrorCode.EVENT_TYPE_SEMANTICS_INVALID, "$package", message)]
        )

    @staticmethod
    def _validate_change_classification(package: dict[str, Any]) -> None:
        change_class = package["change_class"]
        fields = {field.casefold() for field in package["change_summary"]["behavioral_fields"]}
        behavioral_terms = {
            "config",
            "trigger",
            "phrase",
            "shortcut",
            "method",
            "output",
            "context",
            "permission",
            "schema",
            "baseline",
            "work_units",
            "framework",
        }
        claims_nonbehavioral = change_class in {"documentation", "presentation"}
        if claims_nonbehavioral and any(
            any(term in field for term in behavioral_terms) for field in fields
        ):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$change_class",
                        "documentation/presentation classification cannot contain behavioral fields",
                    )
                ]
            )
        if change_class == "initial" and package["supersedes_version"] is not None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$supersedes_version",
                        "initial package cannot supersede a version",
                    )
                ]
            )
        if change_class != "initial" and package["supersedes_version"] is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$supersedes_version",
                        "changed package must name the version it supersedes",
                    )
                ]
            )


def _durable_create_if_absent(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.PACKAGE_VERSION_IMMUTABLE,
                        str(path),
                        "immutable package artifact already exists with different bytes",
                    )
                ]
            )
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short immutable package write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(record) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short package pointer write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
