"""Narrow read-only adapter for explicitly selected historical weekly packages.

The adapter opens only an exact event record and its event-bound weekly package object.  It does not walk a
directory, open source objects, read receipts or Keychain material, or write derived state.  Semantic
cross-week mappings remain caller supplied to :mod:`cross_week_operating_view`; this reader never matches
labels, dates, or people by itself.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.cross_week_operating_view import (
    AdmittedWeeklySnapshot,
    CitedWeeklyState,
    CrossWeekOperatingViewError,
    StandalonePrimaryArtifact,
    WeeklyCoverageSummary,
)


COMPONENT = "vault-next-cross-week-operating-view-real-u0/0.1.0"
_EVENT = re.compile(r"^event_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VIEWS = frozenset(
    {
        "timeline",
        "strands",
        "project_status_transitions",
        "meeting_conversation_artifact_inventory",
        "decision_lineage",
        "people",
        "missing_evidence",
    }
)


class RealCrossWeekOperatingViewError(RuntimeError):
    """An explicitly selected historical weekly package cannot safely be read as U0 input."""


@dataclass(frozen=True)
class WeeklyEventScope:
    """One exact admitted event and its package; no discovery is permitted."""

    event_id: str
    package_digest: str


class RealCrossWeekOperatingViewReader:
    """Load two or more fixed weekly packages as verified read-only snapshots."""

    def __init__(self, bundle_root: Path, *, scopes: tuple[WeeklyEventScope, ...]) -> None:
        self.root = _open_root(bundle_root)
        if len(scopes) < 2 or len({scope.event_id for scope in scopes}) != len(scopes):
            raise RealCrossWeekOperatingViewError("cross-week U0 requires distinct exact event scopes")
        if len({scope.package_digest for scope in scopes}) != len(scopes):
            raise RealCrossWeekOperatingViewError("cross-week U0 package scope is duplicated")
        if any(not _EVENT.fullmatch(scope.event_id) or not _DIGEST.fullmatch(scope.package_digest) for scope in scopes):
            raise RealCrossWeekOperatingViewError("cross-week U0 event or package scope is invalid")
        self.scopes = scopes

    def snapshots(self) -> tuple[AdmittedWeeklySnapshot, ...]:
        """Return sealed caller-supplied-view snapshots without reading a source or receipt."""

        snapshots = tuple(self._snapshot(scope) for scope in self.scopes)
        try:
            # The source-free coordinator performs chronological and immutable-summary validation.
            from vault_next.cross_week_operating_view import CrossWeekOperatingViewCoordinator

            CrossWeekOperatingViewCoordinator(snapshots)
        except CrossWeekOperatingViewError as exc:
            raise RealCrossWeekOperatingViewError("cross-week U0 snapshot validation failed") from exc
        return snapshots

    def primary_artifacts(self) -> tuple[StandalonePrimaryArtifact, ...]:
        """Return every retained primary-artifact relationship disposition, not just linked entries."""

        results: list[StandalonePrimaryArtifact] = []
        for scope in self.scopes:
            event = self._event(scope)
            package = self._package(scope)
            if event["package_digest"] != scope.package_digest or event["event_id"] != scope.event_id:
                raise RealCrossWeekOperatingViewError("cross-week U0 event package binding changed")
            for observation in (*package["item_observations"], *package["conversation_observations"]):
                entries = observation.get("generated_artifacts", observation.get("outputs", []))
                if not isinstance(entries, list):
                    raise RealCrossWeekOperatingViewError("cross-week U0 artifact list is invalid")
                for index, entry in enumerate(entries):
                    label = entry.get("label") if isinstance(entry, dict) else None
                    refs = entry.get("citation_refs") if isinstance(entry, dict) else None
                    coverage = _label_field(label, "coverage")
                    relationship = _label_field(label, "relationship")
                    if coverage != "primary artifact":
                        continue
                    if relationship not in {"linked", "standalone", "unsupported"}:
                        raise RealCrossWeekOperatingViewError("primary artifact relationship is unavailable")
                    if not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], str):
                        raise RealCrossWeekOperatingViewError("primary artifact citation is invalid")
                    if not isinstance(observation.get("observation_id"), str):
                        raise RealCrossWeekOperatingViewError("primary artifact observation identity is invalid")
                    results.append(
                        StandalonePrimaryArtifact(
                            scope.event_id,
                            f"{observation['observation_id']}:artifact:{index}",
                            refs[0],
                            relationship,  # type: ignore[arg-type]
                            "retained event-linked primary artifact disposition",
                        )
                    )
        return tuple(results)

    def _snapshot(self, scope: WeeklyEventScope) -> AdmittedWeeklySnapshot:
        event = self._event(scope)
        package = self._package(scope)
        if (
            event["package_digest"] != scope.package_digest
            or event["event_id"] != scope.event_id
            or not _same_instant(event["week_start"], package["week_start"])
            or not _same_instant(event["week_end"], package["week_end"])
            or event["candidate_only"] is not True
            or package.get("candidate_only") is not True
            or package.get("no_current_work") is not True
            or package.get("no_promotion") is not True
            or package.get("no_activation") is not True
            or package.get("no_u2") is not True
        ):
            raise RealCrossWeekOperatingViewError("cross-week U0 event or package binding changed")
        views = package.get("support_views")
        primary = package.get("primary_artifact")
        wave = package.get("weekly_wave")
        if (
            not isinstance(views, dict)
            or set(views) != _VIEWS
            or not isinstance(primary, dict)
            or not isinstance(wave, dict)
        ):
            raise RealCrossWeekOperatingViewError("cross-week U0 weekly presentation is invalid")
        citations = self._citations(package)
        self._presentation(primary, "artifact_digest", citations)
        for view in views.values():
            self._presentation(view, "view_digest", citations)
        strands = _states(wave.get("strands"), "status")
        projects = _states(wave.get("projects"), "movement")
        coverage = _coverage(package)
        return AdmittedWeeklySnapshot(
            event_id=scope.event_id,
            package_digest=scope.package_digest,
            week_start=event["week_start"],
            week_end=event["week_end"],
            primary_title=primary["title"],
            primary_artifact_digest=primary["artifact_digest"],
            strand_view_digest=views["strands"]["view_digest"],
            project_view_digest=views["project_status_transitions"]["view_digest"],
            inventory_view_digest=views["meeting_conversation_artifact_inventory"]["view_digest"],
            citation_refs=tuple(sorted(citations)),
            strands=strands,
            projects=projects,
            coverage=coverage,
            synthetic_only=False,
        ).sealed()

    def _event(self, scope: WeeklyEventScope) -> dict[str, Any]:
        path = _inside(
            self.root,
            self.root / "canonical" / "historical-weekly-activity-events" / f"{scope.event_id}.json",
        )
        event = _json(path, "cross-week U0 event")
        required = {
            "schema_version", "event_id", "publication_type", "parent_bindings", "parent_set_digest",
            "catalogue_set_digest", "manifest_digest", "package_digest", "receipt_id", "candidate_only",
            "recorded_at", "week_start", "week_end",
        }
        if set(event) != required or event.get("publication_type") != "historical_weekly_activity_reconstruction":
            raise RealCrossWeekOperatingViewError("cross-week U0 event shape is invalid")
        return event

    def _package(self, scope: WeeklyEventScope) -> dict[str, Any]:
        path = _inside(
            self.root,
            self.root / "canonical" / "historical-weekly-activity-packages" / scope.package_digest,
        )
        package = _json(path, "cross-week U0 package")
        material = {key: value for key, value in package.items() if key != "package_digest"}
        if package.get("package_digest") != scope.package_digest or canonical_sha256(material) != scope.package_digest:
            raise RealCrossWeekOperatingViewError("cross-week U0 package digest changed")
        if package.get("component") != "vault-next-historical-weekly-activity-reconstruction/1.0.0":
            raise RealCrossWeekOperatingViewError("cross-week U0 package component is unsupported")
        return package

    @staticmethod
    def _citations(package: dict[str, Any]) -> set[str]:
        citations: set[str] = set()
        for observation in (*package.get("item_observations", []), *package.get("conversation_observations", [])):
            if not isinstance(observation, dict) or not isinstance(observation.get("citation_refs"), list):
                raise RealCrossWeekOperatingViewError("cross-week U0 observation citation is invalid")
            citations.update(ref for ref in observation["citation_refs"] if isinstance(ref, str))
        if not citations:
            raise RealCrossWeekOperatingViewError("cross-week U0 package lacks citations")
        return citations

    @staticmethod
    def _presentation(record: Any, digest_field: str, citations: set[str]) -> None:
        if not isinstance(record, dict) or set(record) != {"title", "markdown", "citation_refs", digest_field}:
            raise RealCrossWeekOperatingViewError("cross-week U0 presentation shape is invalid")
        if (
            not isinstance(record["title"], str)
            or not isinstance(record["markdown"], str)
            or not record["markdown"].startswith("# ")
            or not isinstance(record["citation_refs"], list)
            or set(record["citation_refs"]) - citations
        ):
            raise RealCrossWeekOperatingViewError("cross-week U0 presentation citation changed")
        material = {key: value for key, value in record.items() if key != digest_field}
        if record.get(digest_field) != canonical_sha256(material):
            raise RealCrossWeekOperatingViewError("cross-week U0 presentation digest changed")


def _states(value: Any, status_field: str) -> tuple[CitedWeeklyState, ...]:
    if not isinstance(value, list) or not value:
        raise RealCrossWeekOperatingViewError("cross-week U0 states are unavailable")
    states: list[CitedWeeklyState] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("label"), str)
            or not item["label"].strip()
            or not isinstance(item.get(status_field), str)
            or not item[status_field].strip()
        ):
            raise RealCrossWeekOperatingViewError("cross-week U0 state is invalid")
        states.append(CitedWeeklyState(item["label"], item[status_field]))
    if len({item.label for item in states}) != len(states):
        raise RealCrossWeekOperatingViewError("cross-week U0 state label is duplicated")
    return tuple(states)


def _coverage(package: dict[str, Any]) -> WeeklyCoverageSummary:
    entries: list[tuple[str, str]] = []
    meeting_relationships: list[str] = []
    conversations: list[str] = []
    for observation in package.get("item_observations", []):
        if not isinstance(observation, dict):
            raise RealCrossWeekOperatingViewError("cross-week U0 item observation is invalid")
        item_class = observation.get("item_class")
        artifact_entries = _artifact_dispositions(observation.get("generated_artifacts"))
        if item_class in {"meeting_transcript", "meeting_notes", "meeting_debrief", "multi_meeting_bundle"}:
            relationships = {relationship for _, relationship in artifact_entries}
            if "linked" in relationships:
                meeting_relationships.append("linked")
            elif "unsupported" in relationships:
                meeting_relationships.append("unsupported")
            elif "standalone" in relationships:
                meeting_relationships.append("standalone")
            else:
                raise RealCrossWeekOperatingViewError("meeting evidence has no relationship disposition")
        entries.extend(artifact_entries)
    for observation in package.get("conversation_observations", []):
        if not isinstance(observation, dict):
            raise RealCrossWeekOperatingViewError("cross-week U0 conversation observation is invalid")
        conversations.append(str(observation.get("observation_id")))
        entries.extend(_artifact_dispositions(observation.get("outputs")))
    primary = [(coverage, relationship) for coverage, relationship in entries if coverage == "primary artifact"]
    return WeeklyCoverageSummary(
        selected_count=len(package.get("item_observations", [])) + len(package.get("conversation_observations", [])),
        primary_linked_count=sum(relationship == "linked" for _, relationship in primary),
        primary_standalone_count=sum(relationship == "standalone" for _, relationship in primary),
        meeting_linked_count=meeting_relationships.count("linked"),
        meeting_standalone_count=meeting_relationships.count("standalone"),
        meeting_unsupported_count=meeting_relationships.count("unsupported"),
        conversation_linked_count=len(conversations),
        conversation_standalone_count=0,
        silent_orphan_count=0,
    )


def _artifact_dispositions(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        raise RealCrossWeekOperatingViewError("cross-week U0 artifact disposition is invalid")
    result: list[tuple[str, str]] = []
    for entry in value:
        label = entry.get("label") if isinstance(entry, dict) else None
        coverage = _label_field(label, "coverage")
        relationship = _label_field(label, "relationship")
        if coverage is None and relationship is None:
            # Older bounded packages retain additional exact evidence anchors beside a classified output.
            # They are supplemental citations, not independently reconstructed artifacts.
            continue
        if coverage is None or relationship is None:
            raise RealCrossWeekOperatingViewError("cross-week U0 artifact disposition is incomplete")
        result.append((coverage, relationship))
    return result


def _label_field(label: Any, name: str) -> str | None:
    if not isinstance(label, str):
        return None
    match = re.search(rf"(?:^|;)\s*{re.escape(name)}=([^;]+)", label)
    return match.group(1).strip() if match else None


def _same_instant(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        left_time = datetime.fromisoformat(left.replace("Z", "+00:00"))
        right_time = datetime.fromisoformat(right.replace("Z", "+00:00"))
    except ValueError:
        return False
    return left_time.tzinfo is not None and right_time.tzinfo is not None and left_time == right_time


def _open_root(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise RealCrossWeekOperatingViewError("cross-week U0 bundle root is unsafe")
    resolved = root.resolve(strict=True)
    if resolved != root.absolute() or resolved.stat().st_mode & 0o077:
        raise RealCrossWeekOperatingViewError("cross-week U0 bundle root is unsafe")
    return resolved


def _inside(root: Path, path: Path) -> Path:
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RealCrossWeekOperatingViewError("cross-week U0 selected object is unavailable") from exc
    if resolved_parent != root and root not in resolved_parent.parents:
        raise RealCrossWeekOperatingViewError("cross-week U0 path escaped the private bundle")
    if path.is_symlink() or not path.is_file():
        raise RealCrossWeekOperatingViewError("cross-week U0 selected object is unavailable")
    return path


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RealCrossWeekOperatingViewError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise RealCrossWeekOperatingViewError(f"{label} is invalid")
    return value
