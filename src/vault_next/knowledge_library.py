"""S4-B synthetic, candidate-only knowledge and experience library.

The coordinator stores only caller-supplied invented candidates in a disposable runtime.  It does
not intake sources, infer claims, promote knowledge, or broaden the S3-B source retrieval scope.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.lifecycle import fold_session_states
from vault_next.records import SchemaRegistry
from vault_next.runtime import CaseSessionRuntime


_KINDS = frozenset({"knowledge_candidate", "experience_candidate"})
_PURPOSES = frozenset({"learning", "career_preparation", "historical_recall"})
_METRIC_STATES = frozenset({"measured", "estimated", "unknown"})
_INDEX_VERSION = "s4b-0.1.0"


class SyntheticKnowledgeLibraryCoordinator:
    """Create provisional candidates and query only explicitly scoped synthetic candidates."""

    def __init__(self, runtime: CaseSessionRuntime, schemas: SchemaRegistry) -> None:
        self.runtime = runtime
        self.schemas = schemas

    def record_candidate(self, session_id: str, proposal: dict[str, object]) -> dict[str, object]:
        """Append one immutable provisional candidate after exact synthetic-source checks."""

        session = self._active_session(session_id)
        events = self.runtime.semantic.read_all()
        candidate_state = self._state(events)
        candidate = self._normalize_proposal(proposal, session, events, candidate_state)
        event_type = f"{candidate['record_kind'].removesuffix('_candidate')}.candidate_recorded"
        recorded = self.runtime.record_reasoning_event(
            session_id,
            event_type,
            {"candidate": candidate, "candidate_sha256": candidate["candidate_sha256"]},
            subject_refs=[candidate["candidate_id"]],
            provenance=[
                {"ref": binding["registration_event_id"], "relation": "derives_from"}
                for binding in candidate["source_bindings"]
            ],
        )
        result: dict[str, object] = {
            "status": "complete",
            "candidate": {**candidate, "event_id": recorded["event_id"]},
            "event_id": recorded["event_id"],
            "promotion": "unavailable: S4-B records provisional candidates only",
        }
        predecessor = candidate["supersedes_candidate_id"]
        if predecessor is not None:
            previous = candidate_state.get(predecessor)
            if previous is None or previous["lifecycle_state"] != "provisional":
                raise _invalid("$supersedes_candidate_id", "candidate is not available for supersession")
            if previous["candidate"]["record_kind"] != candidate["record_kind"]:
                raise _invalid("$supersedes_candidate_id", "candidate kind cannot change during supersession")
            superseded = self.runtime.record_reasoning_event(
                session_id,
                event_type.replace("recorded", "superseded"),
                {
                    "candidate_id": predecessor,
                    "successor_candidate_id": candidate["candidate_id"],
                    "reason": "caller-supplied synthetic correction",
                },
                subject_refs=[predecessor, candidate["candidate_id"]],
                provenance=[{"ref": recorded["event_id"], "relation": "caused_by"}],
            )
            result["supersession_event_id"] = superseded["event_id"]
        return result

    def withdraw_candidate(self, session_id: str, candidate_id: str, *, reason: str) -> dict[str, object]:
        """Withdraw a provisional candidate without deleting its historic immutable record."""

        if not isinstance(reason, str) or not reason.strip():
            raise _invalid("$reason", "withdrawal reason must be a nonempty string")
        session = self._active_session(session_id)
        state = self._state(self.runtime.semantic.read_all())
        item = state.get(candidate_id)
        if item is None or item["candidate"]["case_id"] != session.case_id:
            raise _invalid("$candidate_id", "candidate is unavailable in the current case")
        if item["lifecycle_state"] != "provisional":
            raise _invalid("$candidate_id", "only a provisional candidate can be withdrawn")
        event_type = f"{item['candidate']['record_kind'].removesuffix('_candidate')}.candidate_withdrawn"
        event = self.runtime.record_reasoning_event(
            session_id,
            event_type,
            {"candidate_id": candidate_id, "reason": reason},
            subject_refs=[candidate_id],
        )
        return {"status": "complete", "candidate_id": candidate_id, "event_id": event["event_id"]}

    def rebuild(
        self,
        session_id: str,
        request: dict[str, object],
    ) -> dict[str, object]:
        """Build one sealed local FTS5 derivative for an exact already-validated candidate scope."""

        scope = self._scope(session_id, request)
        if scope["status"] != "complete":
            return scope
        candidates = scope["candidates"]
        assert isinstance(candidates, list)
        material = self._index_material(candidates)
        build_material = {"material": material, "nonce": scope["rebuild_nonce"]}
        build_id = f"knowledge_library_{canonical_sha256(build_material)[:26]}"
        root = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.derived_root / "knowledge-library"
        )
        builds = self.runtime.paths.ensure_runtime_write_target(root / "builds")
        builds.mkdir(parents=True, exist_ok=True)
        destination = self.runtime.paths.ensure_runtime_write_target(builds / build_id)
        loaded = self._load_build(destination)
        if loaded is None:
            stage = self.runtime.paths.ensure_runtime_write_target(
                self.runtime.paths.staging_root / "knowledge-library" / build_id
            )
            if stage.exists() or destination.exists():
                return _unavailable("interrupted or malformed candidate-library build is unavailable")
            stage.mkdir(parents=True, exist_ok=False)
            database = stage / "index.sqlite3"
            self._write_index(database, candidates)
            database_bytes = database.read_bytes()
            manifest = {
                "schema_version": "1.0",
                "build_id": build_id,
                "index_version": _INDEX_VERSION,
                "candidate_material_sha256": canonical_sha256(material),
                "candidate_watermark": scope["candidate_watermark"],
                "source_watermark": scope["source_watermark"],
                "candidate_count": len(candidates),
                "sqlite_sha256": sha256_hex(database_bytes),
                "sqlite_byte_count": len(database_bytes),
            }
            _write_json(stage / "manifest.json", manifest)
            os.replace(stage, destination)
            loaded = (manifest, destination / "index.sqlite3")
        manifest, _database = loaded
        if (
            manifest["candidate_material_sha256"] != canonical_sha256(material)
            or manifest["candidate_watermark"] != scope["candidate_watermark"]
            or manifest["source_watermark"] != scope["source_watermark"]
        ):
            return _unavailable("candidate-library build is bound to different candidate state")
        _write_json(root / "active.json", {"build_id": build_id, "manifest_sha256": canonical_sha256(manifest)})
        return {
            "status": "complete",
            "index": {"build_id": build_id, "index_version": _INDEX_VERSION, "state": "fresh"},
            "candidate_watermark": scope["candidate_watermark"],
            "source_watermark": scope["source_watermark"],
        }

    def search(self, session_id: str, request: dict[str, object]) -> dict[str, object]:
        """Return bounded lexical matches from the exact validated candidate allowlist only."""

        scope = self._scope(session_id, request)
        if scope["status"] != "complete":
            return scope
        query = request.get("query")
        budget = request.get("response_budget")
        if not isinstance(query, str) or not query or len(query.encode("utf-8")) > 512:
            raise _invalid("$query", "query must be a nonempty string of at most 512 UTF-8 bytes")
        if not isinstance(budget, int) or not 1 <= budget <= 8:
            raise _invalid("$response_budget", "response budget must be an integer from 1 to 8")
        loaded = self._load_active()
        if loaded is None:
            return _unavailable("no verified active candidate-library index is available")
        manifest, database = loaded
        candidates = scope["candidates"]
        assert isinstance(candidates, list)
        material = self._index_material(candidates)
        if (
            manifest["candidate_material_sha256"] != canonical_sha256(material)
            or manifest["candidate_watermark"] != scope["candidate_watermark"]
            or manifest["source_watermark"] != scope["source_watermark"]
        ):
            return _unavailable("active candidate-library index is stale for the requested scope")
        try:
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    "SELECT candidate_id, candidate_sha256 FROM candidate_fts "
                    "WHERE candidate_fts MATCH ? LIMIT 64",
                    (query,),
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error:
            return _unavailable("active candidate-library index could not execute the bounded lexical query")
        selected_ids = [row[0] for row in rows[:budget]]
        by_id = {item["candidate"]["candidate_id"]: item for item in candidates}
        selected = [self._result_candidate(by_id[candidate_id], by_id) for candidate_id in selected_ids]
        return {
            "status": "complete",
            "purpose": request["purpose"],
            "candidate_watermark": scope["candidate_watermark"],
            "source_watermark": scope["source_watermark"],
            "index": {"build_id": manifest["build_id"], "index_version": _INDEX_VERSION, "state": "fresh"},
            "candidates": selected,
            "omissions": ([{"reason": "no_lexical_match", "ref": "candidate_allowlist"}] if not selected else []),
            "limitations": ["provisional synthetic candidates are not reviewed knowledge or owner decisions"],
        }

    def _scope(self, session_id: str, request: dict[str, object]) -> dict[str, object]:
        session = self._active_session(session_id)
        expected_keys = {
            "purpose",
            "candidate_ids",
            "record_kinds",
            "confidentiality_space",
            "expected_candidate_watermark",
            "expected_source_watermark",
            "query",
            "response_budget",
            "rebuild_nonce",
        }
        if set(request) != expected_keys:
            raise _invalid("$request", "library request has unexpected or missing fields")
        if request["purpose"] not in _PURPOSES:
            raise _invalid("$purpose", "unsupported synthetic library purpose")
        candidate_ids = request["candidate_ids"]
        kinds = request["record_kinds"]
        space = request["confidentiality_space"]
        if (
            not isinstance(candidate_ids, list)
            or not 1 <= len(candidate_ids) <= 8
            or len(set(candidate_ids)) != len(candidate_ids)
            or not all(isinstance(item, str) and item for item in candidate_ids)
        ):
            raise _invalid("$candidate_ids", "candidate allowlist must contain one to eight unique IDs")
        if not isinstance(kinds, list) or not kinds or not set(kinds).issubset(_KINDS):
            raise _invalid("$record_kinds", "requested record kinds are invalid")
        if not isinstance(space, str) or not space:
            raise _invalid("$confidentiality_space", "confidentiality space must be a nonempty string")
        if (
            not isinstance(request["rebuild_nonce"], str)
            or not request["rebuild_nonce"]
            or len(request["rebuild_nonce"]) > 64
        ):
            raise _invalid("$rebuild_nonce", "rebuild nonce must be a nonempty string of at most 64 characters")
        state = self._state(self.runtime.semantic.read_all())
        candidates: list[dict[str, Any]] = []
        for candidate_id in candidate_ids:
            item = state.get(candidate_id)
            if item is None:
                return _unavailable("requested candidate is unavailable")
            candidate = item["candidate"]
            if (
                candidate["record_kind"] not in kinds
                or candidate["confidentiality_space"] != space
                or item["lifecycle_state"] != "provisional"
                or self._source_is_stale(candidate, self.runtime.semantic.read_all())
                or not self._candidate_visible(candidate, item["event_id"], session)
            ):
                return _unavailable("requested candidate is unavailable under the current scope")
            candidates.append(item)
        candidate_watermark = canonical_sha256(
            [
                {
                    "candidate_id": item["candidate"]["candidate_id"],
                    "event_sha256": item["event_sha256"],
                    "state": item["lifecycle_state"],
                }
                for item in sorted(candidates, key=lambda value: value["candidate"]["candidate_id"])
            ]
        )
        source_watermark = canonical_sha256(
            [
                item["candidate"]["source_watermark"]
                for item in sorted(candidates, key=lambda value: value["candidate"]["candidate_id"])
            ]
        )
        if (
            request["expected_candidate_watermark"] != candidate_watermark
            or request["expected_source_watermark"] != source_watermark
        ):
            return _unavailable("requested candidate or source watermark is stale")
        return {
            "status": "complete",
            "candidates": candidates,
            "candidate_watermark": candidate_watermark,
            "source_watermark": source_watermark,
            "rebuild_nonce": request["rebuild_nonce"],
        }

    def watermarks(self, candidate_ids: list[str]) -> dict[str, str]:
        """Expose exact expected watermarks for a caller that already knows its candidate IDs."""

        state = self._state(self.runtime.semantic.read_all())
        selected = [state[item] for item in candidate_ids if item in state]
        if len(selected) != len(candidate_ids) or len(set(candidate_ids)) != len(candidate_ids):
            raise _invalid("$candidate_ids", "candidate watermark request is unavailable")
        return {
            "candidate_watermark": canonical_sha256(
                [
                    {
                        "candidate_id": item["candidate"]["candidate_id"],
                        "event_sha256": item["event_sha256"],
                        "state": item["lifecycle_state"],
                    }
                    for item in sorted(selected, key=lambda value: value["candidate"]["candidate_id"])
                ]
            ),
            "source_watermark": canonical_sha256(
                [
                    item["candidate"]["source_watermark"]
                    for item in sorted(selected, key=lambda value: value["candidate"]["candidate_id"])
                ]
            ),
        }

    def _normalize_proposal(
        self,
        proposal: dict[str, object],
        session: Any,
        events: list[dict[str, Any]],
        state: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        allowed = {
            "record_kind",
            "title",
            "statement",
            "applicability",
            "limitations",
            "source_bindings",
            "counterevidence_candidate_ids",
            "confidentiality_space",
            "supersedes_candidate_id",
            "contribution", "metrics",
        }
        required = allowed - {"contribution", "metrics"}
        if set(proposal) - allowed or not required.issubset(proposal):
            raise _invalid("$proposal", "candidate proposal has unexpected or missing fields")
        kind = proposal["record_kind"]
        if kind not in _KINDS:
            raise _invalid("$record_kind", "only provisional knowledge or experience candidates are supported")
        for name in ("title", "statement", "applicability", "confidentiality_space"):
            if not isinstance(proposal[name], str) or not proposal[name].strip():
                raise _invalid(f"${name}", "candidate text field must be nonempty")
        limitations = proposal["limitations"]
        if (
            not isinstance(limitations, list)
            or not limitations
            or not all(isinstance(item, str) and item for item in limitations)
        ):
            raise _invalid("$limitations", "candidate must disclose at least one limitation")
        bindings = self._validated_bindings(proposal["source_bindings"], session, events)
        counters = proposal["counterevidence_candidate_ids"]
        if (
            not isinstance(counters, list)
            or len(set(counters)) != len(counters)
            or not all(isinstance(item, str) for item in counters)
        ):
            raise _invalid("$counterevidence_candidate_ids", "counterevidence references must be unique IDs")
        for candidate_id in counters:
            item = state.get(candidate_id)
            if item is None or item["candidate"]["case_id"] != session.case_id:
                raise _invalid("$counterevidence_candidate_ids", "counterevidence candidate is unavailable")
        predecessor = proposal["supersedes_candidate_id"]
        if predecessor is not None:
            previous = state.get(predecessor) if isinstance(predecessor, str) else None
            if (
                previous is None
                or previous["lifecycle_state"] != "provisional"
                or previous["candidate"]["case_id"] != session.case_id
                or previous["candidate"]["record_kind"] != kind
            ):
                raise _invalid("$supersedes_candidate_id", "superseded candidate is unavailable")
        if kind == "experience_candidate":
            contribution = proposal.get("contribution")
            metrics = proposal.get("metrics")
            if (
                not isinstance(contribution, dict)
                or set(contribution) != {"personal", "team"}
                or not all(isinstance(value, str) for value in contribution.values())
            ):
                raise _invalid("$contribution", "experience candidate needs personal and team contribution labels")
            valid_metric = lambda item: (
                isinstance(item, dict)
                and set(item) == {"label", "value", "uncertainty"}
                and isinstance(item["label"], str)
                and isinstance(item["value"], str)
                and item["uncertainty"] in _METRIC_STATES
            )
            if not isinstance(metrics, list) or not metrics or not all(valid_metric(item) for item in metrics):
                raise _invalid("$metrics", "experience metrics require label, value, and uncertainty")
        elif proposal.get("contribution") is not None or proposal.get("metrics") is not None:
            raise _invalid("$proposal", "knowledge candidate cannot carry experience contribution or metrics")
        candidate_id = self.runtime.ids.new(kind)
        candidate = {
            "schema_version": "0.1.0",
            "candidate_id": candidate_id,
            "record_kind": kind,
            "case_id": session.case_id,
            "review_state": "provisional",
            "title": proposal["title"],
            "statement": proposal["statement"],
            "applicability": proposal["applicability"],
            "limitations": list(limitations),
            "source_bindings": bindings,
            "source_watermark": canonical_sha256(bindings),
            "counterevidence_candidate_ids": list(counters),
            "confidentiality_space": proposal["confidentiality_space"],
            "sensitivity_labels": sorted(
                {label for binding in bindings for label in binding["sensitivity_labels"]}
            ),
            "supersedes_candidate_id": predecessor,
            "contribution": proposal.get("contribution"),
            "metrics": proposal.get("metrics"),
        }
        candidate["candidate_sha256"] = canonical_sha256(candidate)
        return candidate

    def _validated_bindings(
        self, value: object, session: Any, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not 1 <= len(value) <= 8:
            raise _invalid("$source_bindings", "candidate requires one to eight exact source bindings")
        event_index = {event["event_id"]: event for event in events}
        bindings: list[dict[str, Any]] = []
        for binding in value:
            required = {
                "registration_event_id",
                "source_version_id",
                "content_sha256",
                "extraction_id",
                "anchor",
            }
            if not isinstance(binding, dict) or set(binding) != required:
                raise _invalid("$source_bindings", "source binding has unexpected or missing fields")
            registration = event_index.get(binding["registration_event_id"])
            if (
                registration is None
                or registration["event_type"] != "source.version_registered"
                or registration["case_id"] != session.case_id
            ):
                raise _invalid("$source_bindings", "source registration is unavailable in the current case")
            allowed = {item["ref"]: item for item in session.manifest["authorized_context"]}
            authorization = allowed.get(registration["event_id"])
            version = registration["payload"]["version"]
            if (
                authorization is None
                or version["source_version_id"] != binding["source_version_id"]
                or version["content_sha256"] != binding["content_sha256"]
            ):
                raise _invalid("$source_bindings", "source version is not authorized exactly")
            extraction = next(
                (
                    event
                    for event in reversed(events)
                    if event["event_type"] == "source.extraction_recorded"
                    and event["payload"]["extraction"]["extraction_id"]
                    == binding["extraction_id"]
                    and event["payload"]["extraction"]["source_version_id"]
                    == binding["source_version_id"]
                ),
                None,
            )
            if extraction is None:
                raise _invalid("$source_bindings", "source extraction is unavailable")
            chunk = next(
                (
                    item
                    for item in extraction["payload"]["extraction"]["chunks"]
                    if item["anchor"] == binding["anchor"]
                ),
                None,
            )
            if chunk is None:
                raise _invalid("$source_bindings", "source anchor is unavailable")
            labels = version["sensitivity_labels"]
            if not set(labels).issubset(set(authorization["sensitivity_labels"])) or not set(
                labels
            ).issubset(set(session.manifest["sensitivity_labels"])):
                raise _invalid("$source_bindings", "source sensitivity is not authorized")
            bindings.append(
                {
                    **binding,
                    "parent_anchor": chunk["parent_anchor"],
                    "sensitivity_labels": labels,
                }
            )
        if len({canonical_sha256(item) for item in bindings}) != len(bindings):
            raise _invalid("$source_bindings", "source bindings must be unique")
        return sorted(bindings, key=lambda item: (item["registration_event_id"], item["anchor"]))

    def _active_session(self, session_id: str) -> Any:
        states, issues = fold_session_states(self.runtime.semantic.read_all())
        if issues:
            raise ValidationError(issues)
        state = states.get(session_id)
        if state is None or state.frozen or state.status != "active" or state.manifest is None:
            raise _invalid("$session_id", "selected active session is unavailable")
        return state

    @staticmethod
    def _state(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        state: dict[str, dict[str, Any]] = {}
        for event in events:
            event_type = event["event_type"]
            if event_type.endswith("candidate_recorded") and event_type.split(".")[0] in {
                "knowledge",
                "experience",
            }:
                candidate = event["payload"]["candidate"]
                state[candidate["candidate_id"]] = {
                    "candidate": candidate,
                    "event_id": event["event_id"],
                    "event_sha256": event["integrity"]["event_sha256"],
                    "lifecycle_state": "provisional",
                }
            elif event_type.endswith("candidate_superseded") or event_type.endswith("candidate_withdrawn"):
                candidate_id = event["payload"]["candidate_id"]
                if candidate_id in state:
                    state[candidate_id]["lifecycle_state"] = (
                        "superseded" if event_type.endswith("superseded") else "withdrawn"
                    )
        return state

    def _candidate_visible(self, candidate: dict[str, Any], event_id: str, session: Any) -> bool:
        if candidate["case_id"] == session.case_id:
            return True
        allowed = {item["ref"]: item for item in session.manifest["authorized_context"]}
        authorization = allowed.get(event_id)
        if authorization is None or not set(candidate["sensitivity_labels"]).issubset(
            set(authorization["sensitivity_labels"])
        ):
            return False
        return all(binding["registration_event_id"] in allowed for binding in candidate["source_bindings"])

    @staticmethod
    def _source_is_stale(candidate: dict[str, Any], events: list[dict[str, Any]]) -> bool:
        latest: dict[str, str] = {}
        registration_by_id = {
            event["event_id"]: event
            for event in events
            if event["event_type"] == "source.version_registered"
        }
        for event in registration_by_id.values():
            version = event["payload"]["version"]
            latest[version["source_family_id"]] = version["source_version_id"]
        for binding in candidate["source_bindings"]:
            registration = registration_by_id.get(binding["registration_event_id"])
            if registration is None:
                return True
            version = registration["payload"]["version"]
            if latest.get(version["source_family_id"]) != binding["source_version_id"]:
                return True
        return False

    @staticmethod
    def _index_material(candidates: list[dict[str, Any]]) -> list[dict[str, str]]:
        return [
            {
                "candidate_id": item["candidate"]["candidate_id"],
                "candidate_sha256": item["candidate"]["candidate_sha256"],
            }
            for item in sorted(candidates, key=lambda value: value["candidate"]["candidate_id"])
        ]

    def _write_index(self, database: Path, candidates: list[dict[str, Any]]) -> None:
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE VIRTUAL TABLE candidate_fts USING "
                "fts5(candidate_id UNINDEXED, candidate_sha256 UNINDEXED, body)"
            )
            for item in candidates:
                candidate = item["candidate"]
                body = "\n".join(
                    [
                        candidate["title"],
                        candidate["statement"],
                        candidate["applicability"],
                        *candidate["limitations"],
                    ]
                )
                connection.execute(
                    "INSERT INTO candidate_fts(candidate_id, candidate_sha256, body) "
                    "VALUES (?, ?, ?)",
                    (candidate["candidate_id"], candidate["candidate_sha256"], body),
                )
            connection.commit()
            connection.execute("PRAGMA optimize")
        finally:
            connection.close()

    def _load_active(self) -> tuple[dict[str, Any], Path] | None:
        root = self.runtime.paths.derived_root / "knowledge-library"
        active = root / "active.json"
        if active.is_symlink() or not active.is_file():
            return None
        try:
            pointer = _read_json(active)
            loaded = self._load_build(root / "builds" / pointer["build_id"])
            if loaded is None or canonical_sha256(loaded[0]) != pointer["manifest_sha256"]:
                return None
            return loaded
        except (OSError, KeyError, TypeError, ValueError):
            return None

    def _load_build(self, directory: Path) -> tuple[dict[str, Any], Path] | None:
        manifest_path = directory / "manifest.json"
        database = directory / "index.sqlite3"
        if (
            manifest_path.is_symlink()
            or database.is_symlink()
            or not manifest_path.is_file()
            or not database.is_file()
        ):
            return None
        try:
            manifest = _read_json(manifest_path)
            content = database.read_bytes()
            if sha256_hex(content) != manifest["sqlite_sha256"] or len(content) != manifest["sqlite_byte_count"]:
                return None
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    return None
            finally:
                connection.close()
            return manifest, database
        except (OSError, KeyError, TypeError, ValueError, sqlite3.Error):
            return None

    @staticmethod
    def _result_candidate(
        item: dict[str, Any], visible: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        candidate = item["candidate"]
        counterevidence = [
            {
                "candidate_id": candidate_id,
                "candidate_sha256": visible[candidate_id]["candidate"]["candidate_sha256"],
            }
            for candidate_id in candidate["counterevidence_candidate_ids"]
            if candidate_id in visible
        ]
        omissions = [
            {"reason": "counterevidence_out_of_scope", "ref": candidate_id}
            for candidate_id in candidate["counterevidence_candidate_ids"]
            if candidate_id not in visible
        ]
        return {
            "candidate_id": candidate["candidate_id"],
            "candidate_sha256": candidate["candidate_sha256"],
            "record_kind": candidate["record_kind"],
            "lifecycle_state": item["lifecycle_state"],
            "statement": candidate["statement"],
            "applicability": candidate["applicability"],
            "limitations": candidate["limitations"],
            "citations": [
                {
                    key: binding[key]
                    for key in (
                        "registration_event_id",
                        "source_version_id",
                        "content_sha256",
                        "extraction_id",
                        "anchor",
                    )
                }
                for binding in candidate["source_bindings"]
            ],
            "parent_context": [
                {
                    "source_version_id": binding["source_version_id"],
                    "parent_anchor": binding["parent_anchor"],
                }
                for binding in candidate["source_bindings"]
            ],
            "counterevidence": counterevidence,
            "omissions": omissions,
            "contribution": candidate["contribution"],
            "metrics": candidate["metrics"],
        }


def _invalid(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])


def _unavailable(message: str) -> dict[str, object]:
    return {"status": "unavailable", "limits": [message], "candidates": []}


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_bytes(value) + b"\n")
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value
