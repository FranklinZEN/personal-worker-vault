"""Synthetic-only migration discovery and deterministic staging dry runs.

This is a hostile-fixture laboratory. It admits only an in-memory capability created by the
fixture workspace, never a marker or caller-selected source path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.migration_io import (
    SYNTHETIC_MARKER,
    StagingArea,
    SyntheticFixtureWorkspace,
    SyntheticSourceAdmission,
    canonical_json_bytes,
    open_admitted_source,
    parse_canonical_json,
    run_staging_path,
)
from vault_next.paths import RuntimePaths
from vault_next.policy import Proposal
from vault_next.records import SchemaRegistry


RULESET_VERSION = "phase6-synthetic-v1"
CONTRACT_VERSION = "1.0"


@dataclass(frozen=True)
class MigrationSnapshot:
    """A deterministic inventory with no source writes and no symlink traversal."""

    source_label: str
    items: tuple[dict[str, Any], ...]
    repositories: tuple[str, ...]
    snapshot_sha256: str

    def to_record(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "items": list(self.items),
            "repositories": list(self.repositories),
            "ruleset_version": RULESET_VERSION,
            "snapshot_sha256": self.snapshot_sha256,
            "source_label": self.source_label,
        }


@dataclass(frozen=True)
class MigrationDryRun:
    """Staging-only candidates, provenance, reconciliation, and fidelity output."""

    run_id: str
    run_sha256: str
    snapshot_sha256: str
    candidates: tuple[dict[str, Any], ...]
    provenance: tuple[dict[str, Any], ...]
    exceptions: tuple[dict[str, Any], ...]
    reconciliation: tuple[dict[str, Any], ...]
    fidelity: tuple[dict[str, Any], ...]
    staging_path: Path

    def to_record(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "candidates": list(self.candidates),
            "exceptions": list(self.exceptions),
            "fidelity": list(self.fidelity),
            "provenance": list(self.provenance),
            "reconciliation": list(self.reconciliation),
            "run_id": self.run_id,
            "run_sha256": self.run_sha256,
            "snapshot_sha256": self.snapshot_sha256,
        }


class SyntheticMigrationLab:
    """Admitted fixture discovery with staging output only below a pinned runtime root."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        source_open_observer: Callable[[str], None] | None = None,
        publication_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.paths = paths
        self.schemas = schemas
        self._source_open_observer = source_open_observer
        self._publication_hook = publication_hook
        self._staging = StagingArea(paths)

    def discover(
        self,
        admission: SyntheticSourceAdmission | object,
        *,
        source_label: str = "synthetic-legacy",
    ) -> MigrationSnapshot:
        """Inventory one admitted fixture without following links or modifying its source."""

        if not isinstance(source_label, str) or not source_label:
            _raise(ErrorCode.MIGRATION_RECORD_INVALID, "$source_label", "source label is required")
        with open_admitted_source(admission, self.paths.root, self._source_open_observer) as source:
            snapshot = self._discover_open_source(source, source_label)
        return self._validated_snapshot(snapshot)

    def dry_run(
        self,
        admission: SyntheticSourceAdmission | object,
        snapshot: MigrationSnapshot,
    ) -> MigrationDryRun:
        """Validate then stage a current admitted fixture without canonical writes."""

        supplied = self._validated_snapshot(snapshot)
        with open_admitted_source(admission, self.paths.root, self._source_open_observer) as source:
            current = self._validated_snapshot(self._discover_open_source(source, supplied.source_label))
            if current.snapshot_sha256 != supplied.snapshot_sha256:
                _raise(
                    ErrorCode.MIGRATION_SOURCE_CHANGED,
                    "$snapshot",
                    "source no longer matches the supplied read-only snapshot",
                )
            plan = _plan_for_snapshot(supplied)
            run_sha256 = canonical_sha256(_run_material(plan, supplied.snapshot_sha256))
            run_id = f"migration_run_sha256_{run_sha256}"
            staging_path = run_staging_path(self.paths, run_id)
            with self._staging.open_run(run_id, create=True) as staging:
                if staging.exists("dry-run.json") and not staging.exists("snapshot.json"):
                    _raise(
                        ErrorCode.MIGRATION_RUN_INCOMPLETE,
                        "$staging",
                        "unbound pre-S1-A staging output must be recreated from an admitted fixture",
                    )
                snapshot_record = supplied.to_record()
                staging.write_immutable("snapshot.json", canonical_json_bytes(snapshot_record))
                self._publish("after-snapshot")
                fidelity = self._stage_exact_copies(source, staging, plan["candidates"])
                dry_run = MigrationDryRun(
                    run_id=run_id,
                    run_sha256=run_sha256,
                    snapshot_sha256=supplied.snapshot_sha256,
                    candidates=tuple(plan["candidates"]),
                    provenance=tuple(plan["provenance"]),
                    exceptions=tuple(plan["exceptions"]),
                    reconciliation=tuple(plan["reconciliation"]),
                    fidelity=tuple(fidelity),
                    staging_path=staging_path,
                )
                self._validate_run_instance(dry_run, supplied)
                dry_record = dry_run.to_record()
                fidelity_record = {
                    "contract_version": CONTRACT_VERSION,
                    "fidelity": list(fidelity),
                    "run_id": run_id,
                }
                staging.write_immutable("dry-run.json", canonical_json_bytes(dry_record))
                staging.write_immutable("fidelity-report.json", canonical_json_bytes(fidelity_record))
                self._publish("after-fidelity-report")
            self._validate_staged_run(dry_run, require_complete=False)
            with self._staging.open_run(run_id, create=False) as staging:
                completion = _completion_record(snapshot_record, dry_record, fidelity_record)
                staging.write_immutable("COMPLETE.json", canonical_json_bytes(completion))
                self._publish("after-completion")
            self._validate_staged_run(dry_run, require_complete=True)
            return dry_run

    def deactivate(self, run: MigrationDryRun, *, reason: str) -> Path:
        """Append an idempotent logical deactivation marker to one verified completed run."""

        if not isinstance(reason, str) or not reason:
            _raise(ErrorCode.MIGRATION_RECORD_INVALID, "$reason", "deactivation reason is required")
        self._validate_staged_run(run, require_complete=True)
        with self._staging.open_run(run.run_id, create=False) as staging:
            staging.write_immutable(
                "DEACTIVATED.json",
                canonical_json_bytes(
                    {"reason": reason, "run_id": run.run_id, "run_sha256": run.run_sha256}
                ),
            )
        return run_staging_path(self.paths, run.run_id) / "DEACTIVATED.json"

    def pilot_commit_proposal(
        self, run: MigrationDryRun, *, candidate_ids: list[str]
    ) -> Proposal:
        """Describe—not execute—a policy-bound pilot operation for one exact eligible selection."""

        self._validate_staged_run(run, require_complete=True)
        with self._staging.open_run(run.run_id, create=False) as staging:
            if staging.exists("DEACTIVATED.json"):
                _raise(
                    ErrorCode.MIGRATION_RUN_DEACTIVATED,
                    "$run_id",
                    "deactivated staging runs cannot be proposed",
                )
        if not isinstance(candidate_ids, list) or not candidate_ids or not all(
            isinstance(candidate_id, str) for candidate_id in candidate_ids
        ):
            _raise(ErrorCode.MIGRATION_PROPOSAL_INVALID, "$candidate_ids", "selection is required")
        if len(candidate_ids) != len(set(candidate_ids)):
            _raise(ErrorCode.MIGRATION_PROPOSAL_INVALID, "$candidate_ids", "selection contains duplicates")
        candidates = {candidate["candidate_id"]: candidate for candidate in run.candidates}
        if not set(candidate_ids).issubset(candidates):
            _raise(ErrorCode.MIGRATION_PROPOSAL_INVALID, "$candidate_ids", "selected candidates are absent")
        collision_paths = {
            exception["relative_path"]
            for exception in run.exceptions
            if exception["code"] == "TARGET_COLLISION"
        }
        if any(candidates[candidate_id]["source_relative_path"] in collision_paths for candidate_id in candidate_ids):
            _raise(
                ErrorCode.MIGRATION_PROPOSAL_INVALID,
                "$candidate_ids",
                "colliding candidates have no approved winner",
            )
        selected = tuple(sorted(candidate_ids))
        return Proposal(
            operation_class="promote",
            targets=(str(run_staging_path(self.paths, run.run_id)),),
            consequence_class="canonical_recovery",
            actor_id="vault-next-migration-pilot-interface",
            source_refs=(run.run_id, *selected),
        ).finalized()

    def _discover_open_source(self, source: Any, source_label: str) -> MigrationSnapshot:
        items, repositories = source.walk()
        material = {
            "items": sorted(items, key=lambda item: str(item["relative_path"])),
            "repositories": sorted(set(repositories)),
            "ruleset_version": RULESET_VERSION,
            "source_label": source_label,
        }
        return MigrationSnapshot(
            source_label=source_label,
            items=tuple(material["items"]),
            repositories=tuple(material["repositories"]),
            snapshot_sha256=canonical_sha256(material),
        )

    def _stage_exact_copies(
        self,
        source: Any,
        staging: Any,
        candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        fidelity: list[dict[str, Any]] = []
        for candidate in candidates:
            if candidate["disposition"] != "exact-copy":
                continue
            content = source.read_regular(candidate["source_relative_path"])
            if sha256_hex(content) != candidate["source_content_sha256"]:
                _raise(ErrorCode.MIGRATION_SOURCE_CHANGED, "$source", "exact-copy source hash changed")
            copy_name = f"{candidate['candidate_id']}.bin"
            staging.write_copy_immutable(copy_name, content)
            copied = staging.read_copy(copy_name)
            target_sha256 = sha256_hex(copied)
            if target_sha256 != candidate["source_content_sha256"]:
                _raise(
                    ErrorCode.MIGRATION_STAGING_TAMPERED,
                    "$staging/copies",
                    "published copy does not match source digest",
                )
            fidelity.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "source_content_sha256": candidate["source_content_sha256"],
                    "status": "exact-match",
                    "target_content_sha256": target_sha256,
                }
            )
        return fidelity

    def _validated_snapshot(self, snapshot: MigrationSnapshot) -> MigrationSnapshot:
        if not isinstance(snapshot, MigrationSnapshot):
            _raise(ErrorCode.MIGRATION_RECORD_INVALID, "$snapshot", "snapshot type is invalid")
        record = snapshot.to_record()
        self.schemas.require("migration-snapshot", record)
        _validate_snapshot_record(record)
        return MigrationSnapshot(
            source_label=record["source_label"],
            items=tuple(dict(item) for item in record["items"]),
            repositories=tuple(record["repositories"]),
            snapshot_sha256=record["snapshot_sha256"],
        )

    def _validate_run_instance(self, run: MigrationDryRun, snapshot: MigrationSnapshot) -> None:
        if not isinstance(run, MigrationDryRun):
            _raise(ErrorCode.MIGRATION_RUN_INVALID, "$run", "run type is invalid")
        expected_path = run_staging_path(self.paths, run.run_id)
        if not run.staging_path.is_absolute() or run.staging_path != expected_path:
            _raise(ErrorCode.MIGRATION_RUN_INVALID, "$staging_path", "run path is not derived")
        record = run.to_record()
        self.schemas.require("migration-dry-run", record)
        _validate_run_record(record, snapshot)

    def _validate_staged_run(self, run: MigrationDryRun, *, require_complete: bool) -> MigrationSnapshot:
        if not isinstance(run, MigrationDryRun):
            _raise(ErrorCode.MIGRATION_RUN_INVALID, "$run", "run type is invalid")
        expected_path = run_staging_path(self.paths, run.run_id)
        if not run.staging_path.is_absolute() or run.staging_path != expected_path:
            _raise(ErrorCode.MIGRATION_RUN_INVALID, "$staging_path", "run path is not derived")
        run_record = run.to_record()
        self.schemas.require("migration-dry-run", run_record)
        if run.run_id != f"migration_run_sha256_{run.run_sha256}":
            _raise(ErrorCode.MIGRATION_RUN_INVALID, "$run_id", "run id does not bind caller digest")
        with self._staging.open_run(run.run_id, create=False) as staging:
            snapshot_record = parse_canonical_json(
                staging.read("snapshot.json", missing_code=ErrorCode.MIGRATION_RUN_INCOMPLETE),
                path="$staging/snapshot.json",
                code=ErrorCode.MIGRATION_STAGING_TAMPERED,
            )
            self.schemas.require("migration-snapshot", snapshot_record)
            _validate_snapshot_record(snapshot_record)
            snapshot = MigrationSnapshot(
                source_label=snapshot_record["source_label"],
                items=tuple(dict(item) for item in snapshot_record["items"]),
                repositories=tuple(snapshot_record["repositories"]),
                snapshot_sha256=snapshot_record["snapshot_sha256"],
            )
            _validate_run_record(run_record, snapshot)
            stored_record = parse_canonical_json(
                staging.read("dry-run.json", missing_code=ErrorCode.MIGRATION_RUN_INCOMPLETE),
                path="$staging/dry-run.json",
                code=ErrorCode.MIGRATION_STAGING_TAMPERED,
            )
            self.schemas.require("migration-dry-run", stored_record)
            _validate_run_record(stored_record, snapshot)
            if stored_record != run.to_record():
                _raise(
                    ErrorCode.MIGRATION_STAGING_TAMPERED,
                    "$staging/dry-run.json",
                    "stored run does not match caller record",
                )
            fidelity_record = parse_canonical_json(
                staging.read("fidelity-report.json", missing_code=ErrorCode.MIGRATION_RUN_INCOMPLETE),
                path="$staging/fidelity-report.json",
                code=ErrorCode.MIGRATION_STAGING_TAMPERED,
            )
            expected_fidelity = {
                "contract_version": CONTRACT_VERSION,
                "fidelity": stored_record["fidelity"],
                "run_id": stored_record["run_id"],
            }
            if fidelity_record != expected_fidelity:
                _raise(
                    ErrorCode.MIGRATION_STAGING_TAMPERED,
                    "$staging/fidelity-report.json",
                    "fidelity report binding is invalid",
                )
            for row in stored_record["fidelity"]:
                copy_name = f"{row['candidate_id']}.bin"
                if sha256_hex(staging.read_copy(copy_name)) != row["target_content_sha256"]:
                    _raise(
                        ErrorCode.MIGRATION_STAGING_TAMPERED,
                        "$staging/copies",
                        "staged copy fidelity binding is invalid",
                    )
            if require_complete:
                completion = parse_canonical_json(
                    staging.read("COMPLETE.json", missing_code=ErrorCode.MIGRATION_RUN_INCOMPLETE),
                    path="$staging/COMPLETE.json",
                    code=ErrorCode.MIGRATION_STAGING_TAMPERED,
                )
                if completion != _completion_record(snapshot_record, stored_record, fidelity_record):
                    _raise(
                        ErrorCode.MIGRATION_STAGING_TAMPERED,
                        "$staging/COMPLETE.json",
                        "completion marker binding is invalid",
                    )
        return snapshot

    def _publish(self, stage: str) -> None:
        if self._publication_hook is not None:
            self._publication_hook(stage)


def _validate_snapshot_record(record: dict[str, Any]) -> None:
    issues: list[Issue] = []
    if record["ruleset_version"] != RULESET_VERSION:
        issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, "$snapshot/ruleset_version", "ruleset is unsupported"))
    paths: set[str] = set()
    previous_path = ""
    for index, item in enumerate(record["items"]):
        path = item["relative_path"]
        item_path = f"$snapshot/items/{index}"
        if path in paths:
            issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, f"{item_path}/relative_path", "path is duplicated"))
        paths.add(path)
        if previous_path and path <= previous_path:
            issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, item_path, "items are not sorted"))
        previous_path = path
        _validate_snapshot_item(item, item_path, issues)
    repositories = record["repositories"]
    if repositories != sorted(repositories):
        issues.append(
            Issue(
                ErrorCode.MIGRATION_RECORD_INVALID,
                "$snapshot/repositories",
                "repositories are not sorted",
            )
        )
    for index, repository in enumerate(repositories):
        if repository != "." and not _is_source_relative_path(repository):
            issues.append(
                Issue(
                    ErrorCode.MIGRATION_PATH_INVALID,
                    f"$snapshot/repositories/{index}",
                    "repository path is invalid",
                )
            )
    expected_digest = canonical_sha256(
        {
            "items": record["items"],
            "repositories": repositories,
            "ruleset_version": record["ruleset_version"],
            "source_label": record["source_label"],
        }
    )
    if record["snapshot_sha256"] != expected_digest:
        issues.append(
            Issue(
                ErrorCode.MIGRATION_DIGEST_MISMATCH,
                "$snapshot/snapshot_sha256",
                "snapshot digest does not bind its fields",
            )
        )
    if issues:
        raise ValidationError(issues)


def _validate_snapshot_item(item: dict[str, Any], path: str, issues: list[Issue]) -> None:
    kind = item["kind"]
    relative_path = item["relative_path"]
    expected_keys = {
        "file": {"kind", "relative_path", "byte_count", "content_sha256", "is_binary"},
        "directory": {"kind", "relative_path", "byte_count", "content_sha256"},
        "symlink": {"kind", "relative_path", "byte_count", "content_sha256", "symlink_inside_source"},
        "inaccessible": {"kind", "relative_path", "byte_count", "content_sha256", "error"},
    }[kind]
    if set(item) != expected_keys:
        issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, path, "row fields do not match item kind"))
    if not _is_source_relative_path(relative_path):
        if not (kind == "inaccessible" and item.get("error") == "UNSUPPORTED_PATH"):
            issues.append(Issue(ErrorCode.MIGRATION_PATH_INVALID, f"{path}/relative_path", "source path is invalid"))
    count = item["byte_count"]
    digest = item["content_sha256"]
    if count < 0:
        issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, f"{path}/byte_count", "byte count is negative"))
    if kind in {"file", "symlink"} and not isinstance(digest, str):
        issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, f"{path}/content_sha256", "item requires digest"))
    if kind in {"directory", "inaccessible"} and (count != 0 or digest is not None):
        issues.append(Issue(ErrorCode.MIGRATION_RECORD_INVALID, path, "metadata-only item has file content fields"))


def _plan_for_snapshot(snapshot: MigrationSnapshot) -> dict[str, list[dict[str, Any]]]:
    dispositions = [_disposition(item) for item in snapshot.items]
    candidates = [
        _candidate(item, disposition)
        for item, disposition in zip(snapshot.items, dispositions, strict=True)
        if disposition["disposition"] in {"exact-copy", "transform", "quarantine"} and item["kind"] == "file"
    ]
    candidates.sort(key=lambda candidate: candidate["candidate_id"])
    collisions = _collision_exceptions(candidates)
    provenance = [
        {
            "candidate_id": candidate["candidate_id"],
            "mapping_rule": candidate["mapping_rule"],
            "source_content_sha256": candidate["source_content_sha256"],
            "source_relative_path": candidate["source_relative_path"],
        }
        for candidate in candidates
    ]
    exceptions = [
        {
            "code": disposition["code"],
            "relative_path": item["relative_path"],
            "reason": disposition["reason"],
        }
        for item, disposition in zip(snapshot.items, dispositions, strict=True)
        if disposition["code"] is not None
    ] + collisions
    exceptions.sort(key=lambda exception: (exception["relative_path"], exception["code"], exception["reason"]))
    reconciliation = [
        {
            "disposition": disposition["disposition"],
            "relative_path": item["relative_path"],
            "status": "exception" if disposition["code"] else "mapped",
        }
        for item, disposition in zip(snapshot.items, dispositions, strict=True)
    ]
    return {
        "candidates": candidates,
        "exceptions": exceptions,
        "provenance": provenance,
        "reconciliation": reconciliation,
    }


def _validate_run_record(record: dict[str, Any], snapshot: MigrationSnapshot) -> None:
    issues: list[Issue] = []
    if record["snapshot_sha256"] != snapshot.snapshot_sha256:
        issues.append(
            Issue(
                ErrorCode.MIGRATION_RUN_INVALID,
                "$run/snapshot_sha256",
                "run snapshot differs from staged inventory",
            )
        )
    plan = _plan_for_snapshot(snapshot)
    for field in ("candidates", "provenance", "exceptions", "reconciliation"):
        if record[field] != plan[field]:
            issues.append(
                Issue(
                    ErrorCode.MIGRATION_RECORD_INVALID,
                    f"$run/{field}",
                    "row bindings differ from snapshot plan",
                )
            )
    expected_sha256 = canonical_sha256(_run_material(plan, snapshot.snapshot_sha256))
    if record["run_sha256"] != expected_sha256:
        issues.append(
            Issue(
                ErrorCode.MIGRATION_RUN_INVALID,
                "$run/run_sha256",
                "run digest does not bind plan fields",
            )
        )
    if record["run_id"] != f"migration_run_sha256_{record['run_sha256']}":
        issues.append(
            Issue(
                ErrorCode.MIGRATION_RUN_INVALID,
                "$run/run_id",
                "run id does not bind run digest",
            )
        )
    exact_candidates = [
        candidate for candidate in plan["candidates"] if candidate["disposition"] == "exact-copy"
    ]
    expected_ids = [candidate["candidate_id"] for candidate in exact_candidates]
    fidelity_ids = [row["candidate_id"] for row in record["fidelity"]]
    if fidelity_ids != expected_ids:
        issues.append(
            Issue(
                ErrorCode.MIGRATION_RECORD_INVALID,
                "$run/fidelity",
                "fidelity does not cover exact-copy candidates",
            )
        )
    candidate_by_id = {candidate["candidate_id"]: candidate for candidate in exact_candidates}
    for index, row in enumerate(record["fidelity"]):
        candidate = candidate_by_id.get(row["candidate_id"])
        if (
            candidate is None
            or row["source_content_sha256"] != candidate["source_content_sha256"]
            or row["target_content_sha256"] != candidate["source_content_sha256"]
            or row["status"] != "exact-match"
        ):
            issues.append(
                Issue(
                    ErrorCode.MIGRATION_RECORD_INVALID,
                    f"$run/fidelity/{index}",
                    "fidelity row is inconsistent",
                )
            )
    if issues:
        raise ValidationError(issues)


def _run_material(plan: dict[str, list[dict[str, Any]]], snapshot_sha256: str) -> dict[str, Any]:
    return {
        "candidates": plan["candidates"],
        "exceptions": plan["exceptions"],
        "provenance": plan["provenance"],
        "reconciliation": plan["reconciliation"],
        "ruleset_version": RULESET_VERSION,
        "snapshot_sha256": snapshot_sha256,
    }


def _completion_record(
    snapshot_record: dict[str, Any], dry_record: dict[str, Any], fidelity_record: dict[str, Any]
) -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "dry_run_sha256": canonical_sha256(dry_record),
        "fidelity_report_sha256": canonical_sha256(fidelity_record),
        "run_id": dry_record["run_id"],
        "snapshot_sha256": snapshot_record["snapshot_sha256"],
    }


def _disposition(item: dict[str, Any]) -> dict[str, str | None]:
    path = item["relative_path"]
    if item["kind"] == "inaccessible":
        return {
            "disposition": "quarantine",
            "mapping_rule": "source-inaccessible",
            "code": item["error"],
            "reason": "source item was not consumed",
        }
    if item["kind"] == "symlink":
        code = None if item["symlink_inside_source"] else ErrorCode.MIGRATION_SYMLINK_OUT_OF_SCOPE
        return {
            "disposition": "quarantine",
            "mapping_rule": "symlink-metadata-only",
            "code": code,
            "reason": "symlink target is never traversed",
        }
    if item["kind"] == "directory":
        return {
            "disposition": "reference-only",
            "mapping_rule": "directory-metadata",
            "code": None,
            "reason": "directory is inventory metadata",
        }
    if path == ".git" or path.startswith(".git/") or "/.git/" in path:
        return {
            "disposition": "reference-only",
            "mapping_rule": "git-provenance",
            "code": None,
            "reason": "Git metadata is provenance only",
        }
    if "/tasks/" in f"/{path}" or "/artifacts/" in f"/{path}":
        return {
            "disposition": "transform",
            "mapping_rule": "historical-nonauthoritative",
            "code": None,
            "reason": "historical material cannot create current commitment or acceptance",
        }
    if item["is_binary"]:
        return {
            "disposition": "exact-copy",
            "mapping_rule": "binary-evidence",
            "code": None,
            "reason": "bytes are copied only to staging",
        }
    if path.endswith(".md"):
        return {
            "disposition": "transform",
            "mapping_rule": "historical-markdown-candidate",
            "code": None,
            "reason": "candidate remains non-authoritative",
        }
    return {
        "disposition": "skip",
        "mapping_rule": "unsupported-default",
        "code": "UNSUPPORTED",
        "reason": "unsupported item is reported, not dropped",
    }


def _candidate(item: dict[str, Any], disposition: dict[str, str | None]) -> dict[str, Any]:
    material = {"rule": disposition["mapping_rule"], "source": item}
    return {
        "candidate_id": f"candidate_sha256_{canonical_sha256(material)}",
        "disposition": disposition["disposition"],
        "mapping_rule": disposition["mapping_rule"],
        "source_content_sha256": item["content_sha256"],
        "source_relative_path": item["relative_path"],
        "proposed_target": _proposed_target(item, disposition),
        "target_authority": "historical_non_authoritative",
    }


def _proposed_target(item: dict[str, Any], disposition: dict[str, str | None]) -> str:
    if disposition["disposition"] == "transform":
        return "historical/" + Path(item["relative_path"]).stem + ".json"
    return "evidence/" + canonical_sha256(item)[0:16]


def _collision_exceptions(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate["proposed_target"], []).append(candidate)
    return [
        {
            "code": "TARGET_COLLISION",
            "relative_path": candidate["source_relative_path"],
            "reason": "multiple source items propose the same staging target",
        }
        for target, group in sorted(grouped.items())
        if len(group) > 1
        for candidate in group
    ]


def _is_source_relative_path(path: object) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    return all(component not in {"", ".", ".."} for component in path.split("/"))


def _raise(code: ErrorCode, path: str, message: str) -> None:
    raise ValidationError([Issue(code, path, message)])
