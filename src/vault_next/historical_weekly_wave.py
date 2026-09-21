"""Source-free calendar-week operating reconstruction for historical migration.

Calendar membership bounds processing and coverage only.  Every strand, project, status, decision,
and cross-week transition requires retained evidence from already validated observations.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_bytes, canonical_sha256
from vault_next.errors import ValidationError
from vault_next.records import SchemaRegistry


WAVE_COMPONENT = "vault-next-historical-weekly-operating-wave/1.0.0"
RECONCILIATION_COMPONENT = "vault-next-historical-weekly-cross-wave-reconciliation/1.0.0"
COMPLETENESS = frozenset({"partial", "complete", "exception_pending"})
CONFIDENCES = frozenset({"high", "medium", "low", "unavailable"})
PROJECT_STATUSES = frozenset(
    {
        "not_observed",
        "reported_planning",
        "reported_active",
        "reported_blocked",
        "reported_waiting",
        "reported_paused",
        "reported_complete",
        "reported_superseded",
        "unclear",
    }
)
MOVEMENTS = frozenset(
    {
        "newly_visible",
        "advanced",
        "stalled_reported",
        "blocked_reported",
        "redirected",
        "completed_reported",
        "superseded",
        "no_observed_movement",
        "unknown",
    }
)
MOVEMENT_BASES = frozenset({"source_reported", "evidence_comparison", "absence_only", "unknown"})
DECISION_STATES = frozenset(
    {"proposal", "source_reported_decision", "commitment", "follow_up", "unknown"}
)
TRANSITIONS = frozenset(
    {
        "continues",
        "advanced",
        "stalled_reported",
        "blocked_reported",
        "reversed",
        "redirected",
        "completed_reported",
        "superseded",
        "reappeared_after_gap",
        "unresolved_gap",
    }
)


class HistoricalWeeklyWaveError(RuntimeError):
    """A weekly reconstruction asserted unsupported meaning or changed a bound package."""


@dataclass(frozen=True)
class PreparedWeeklyWave:
    package: dict[str, Any]


@dataclass(frozen=True)
class PreparedWeeklyReconciliation:
    package: dict[str, Any]


class HistoricalWeeklyWaveCoordinator:
    """Build cited weekly operating views without source discovery, publication, or authority."""

    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas

    def build_wave(
        self,
        *,
        wave_id: str,
        week_start: str,
        week_end: str,
        catalogue_digest: str,
        observations: tuple[dict[str, Any], ...],
        strands: tuple[dict[str, Any], ...],
        projects: tuple[dict[str, Any], ...],
        decisions: tuple[dict[str, Any], ...] = (),
        completeness: str = "partial",
    ) -> PreparedWeeklyWave:
        """Create one Monday-to-Monday candidate operating reconstruction."""

        start, end = self._week(week_start, week_end)
        if not wave_id or completeness not in COMPLETENESS or not observations:
            raise HistoricalWeeklyWaveError("weekly wave identity, scope, or completeness is invalid")
        if len(catalogue_digest) != 64:
            raise HistoricalWeeklyWaveError("weekly wave catalogue binding is invalid")
        observation_by_id: dict[str, dict[str, Any]] = {}
        citation_refs: set[str] = set()
        for observation in observations:
            self._observation(observation)
            if not self._in_week(observation, start, end):
                raise HistoricalWeeklyWaveError("weekly observation has no supported time in its week")
            identifier = observation["observation_id"]
            if identifier in observation_by_id:
                raise HistoricalWeeklyWaveError("weekly observation identity is duplicated")
            observation_by_id[identifier] = observation
            citation_refs.update(observation["citation_refs"])

        normalized_strands = sorted(
            (self._strand(item, observation_by_id, citation_refs) for item in strands),
            key=lambda item: item["strand_id"],
        )
        strand_ids = {item["strand_id"] for item in normalized_strands}
        if len(strand_ids) != len(normalized_strands):
            raise HistoricalWeeklyWaveError("weekly strand identity is duplicated")
        normalized_projects = sorted(
            (
                self._project(item, observation_by_id, strand_ids, citation_refs)
                for item in projects
            ),
            key=lambda item: item["project_id"],
        )
        project_ids = {item["project_id"] for item in normalized_projects}
        if len(project_ids) != len(normalized_projects):
            raise HistoricalWeeklyWaveError("weekly project identity is duplicated")
        if any(set(item["project_ids"]) - project_ids for item in normalized_strands):
            raise HistoricalWeeklyWaveError("weekly strand names an unavailable project")
        normalized_decisions = sorted(
            (self._decision(item, observation_by_id, project_ids, citation_refs) for item in decisions),
            key=lambda item: item["decision_id"],
        )
        if len({item["decision_id"] for item in normalized_decisions}) != len(normalized_decisions):
            raise HistoricalWeeklyWaveError("weekly decision identity is duplicated")

        inventory = self._inventory(observations)
        views = self._views(
            wave_id,
            week_start,
            week_end,
            completeness,
            observation_by_id,
            normalized_strands,
            normalized_projects,
            normalized_decisions,
            inventory,
        )
        package = {
            "schema_version": "1.0",
            "component": WAVE_COMPONENT,
            "wave_id": wave_id,
            "week_start": week_start,
            "week_end": week_end,
            "catalogue_digest": catalogue_digest,
            "completeness": completeness,
            "observation_digests": sorted(
                observation["observation_digest"] for observation in observations
            ),
            "strands": normalized_strands,
            "projects": normalized_projects,
            "decisions": normalized_decisions,
            "inventory": inventory,
            "views": views,
            "chronology_creates_relationships": False,
            "no_observed_movement_is_not_stalled": True,
            **self._fences(),
        }
        package["wave_digest"] = canonical_sha256(package)
        self._wave(package)
        return PreparedWeeklyWave(package)

    def reconcile(
        self,
        *,
        waves: tuple[PreparedWeeklyWave, ...],
        strand_aliases: tuple[dict[str, Any], ...] = (),
        project_aliases: tuple[dict[str, Any], ...] = (),
        transitions: tuple[dict[str, Any], ...] = (),
    ) -> PreparedWeeklyReconciliation:
        """Build evidence-backed status and identity continuity across weekly packages."""

        if not waves:
            raise HistoricalWeeklyWaveError("weekly reconciliation requires at least one wave")
        ordered = sorted(waves, key=lambda item: item.package["week_start"])
        for wave in ordered:
            self._wave(wave.package)
        if len({wave.package["wave_id"] for wave in ordered}) != len(ordered):
            raise HistoricalWeeklyWaveError("weekly reconciliation repeats a wave")
        catalogue_digests = {wave.package["catalogue_digest"] for wave in ordered}
        if len(catalogue_digests) != 1:
            raise HistoricalWeeklyWaveError("weekly reconciliation changed catalogues")

        citations = self._all_citations(ordered)
        strand_ids = {
            strand["strand_id"]
            for wave in ordered
            for strand in wave.package["strands"]
        }
        project_ids = {
            project["project_id"]
            for wave in ordered
            for project in wave.package["projects"]
        }
        aliases_strand = sorted(
            (self._alias(item, strand_ids, citations) for item in strand_aliases),
            key=lambda item: (item["canonical_id"], item["alias_id"]),
        )
        aliases_project = sorted(
            (self._alias(item, project_ids, citations) for item in project_aliases),
            key=lambda item: (item["canonical_id"], item["alias_id"]),
        )
        normalized_transitions = sorted(
            (self._transition(item, ordered, citations) for item in transitions),
            key=lambda item: (item["project_id"], item["from_wave_id"], item["to_wave_id"]),
        )
        package = {
            "schema_version": "1.0",
            "component": RECONCILIATION_COMPONENT,
            "wave_digests": [wave.package["wave_digest"] for wave in ordered],
            "strand_aliases": aliases_strand,
            "project_aliases": aliases_project,
            "transitions": normalized_transitions,
            "global_views": self._global_views(ordered, normalized_transitions),
            **self._fences(),
        }
        package["reconciliation_digest"] = canonical_sha256(package)
        self._reconciliation(package)
        return PreparedWeeklyReconciliation(package)

    def rebuild_views(
        self,
        derived_root: Path,
        waves: tuple[PreparedWeeklyWave, ...],
        reconciliation: PreparedWeeklyReconciliation,
    ) -> str:
        """Rebuild one deterministic derived weekly dashboard from canonical packages."""

        for wave in waves:
            self._wave(wave.package)
        self._reconciliation(reconciliation.package)
        if derived_root.exists() and (derived_root.is_symlink() or not derived_root.is_dir()):
            raise HistoricalWeeklyWaveError("weekly derived root is unsafe")
        derived_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if derived_root.stat().st_mode & 0o077:
            raise HistoricalWeeklyWaveError("weekly derived root is not owner-only")
        body = {
            "schema_version": "1.0",
            "component": WAVE_COMPONENT,
            "weekly_views": [wave.package["views"] for wave in waves],
            "global_views": reconciliation.package["global_views"],
            "candidate_only": True,
            "no_current_work": True,
        }
        body["rebuild_digest"] = canonical_sha256(body)
        self._atomic(derived_root / "weekly-operating-views.json", canonical_bytes(body))
        return body["rebuild_digest"]

    def _strand(
        self,
        item: dict[str, Any],
        observations: dict[str, dict[str, Any]],
        citations: set[str],
    ) -> dict[str, Any]:
        required = {
            "strand_id",
            "label",
            "observation_ids",
            "project_ids",
            "citation_refs",
            "confidence",
            "aliases",
            "conflicts",
            "omissions",
        }
        if (
            set(item) != required
            or not item["strand_id"]
            or not item["label"]
            or not item["observation_ids"]
            or not item["citation_refs"]
            or set(item["observation_ids"]) - set(observations)
            or set(item["citation_refs"]) - citations
            or item["confidence"] not in CONFIDENCES
        ):
            raise HistoricalWeeklyWaveError("weekly strand lacks exact evidence")
        return json.loads(json.dumps(item))

    def _project(
        self,
        item: dict[str, Any],
        observations: dict[str, dict[str, Any]],
        strand_ids: set[str],
        citations: set[str],
    ) -> dict[str, Any]:
        required = {
            "project_id",
            "label",
            "strand_ids",
            "observation_ids",
            "start_status",
            "end_status",
            "movement",
            "movement_basis",
            "membership_citation_refs",
            "movement_citation_refs",
            "confidence",
            "aliases",
            "conflicts",
            "omissions",
        }
        if (
            set(item) != required
            or not item["project_id"]
            or not item["label"]
            or not item["strand_ids"]
            or set(item["strand_ids"]) - strand_ids
            or not item["observation_ids"]
            or set(item["observation_ids"]) - set(observations)
            or item["start_status"] not in PROJECT_STATUSES
            or item["end_status"] not in PROJECT_STATUSES
            or item["movement"] not in MOVEMENTS
            or item["movement_basis"] not in MOVEMENT_BASES
            or not item["membership_citation_refs"]
            or set(item["membership_citation_refs"]) - citations
            or set(item["movement_citation_refs"]) - citations
            or item["confidence"] not in CONFIDENCES
        ):
            raise HistoricalWeeklyWaveError("weekly project status or membership is invalid")
        movement = item["movement"]
        basis = item["movement_basis"]
        evidence = item["movement_citation_refs"]
        if movement == "no_observed_movement":
            if basis != "absence_only" or evidence or item["start_status"] != item["end_status"]:
                raise HistoricalWeeklyWaveError("absence cannot be represented as a reported stall")
        elif movement == "unknown":
            if basis != "unknown" or evidence:
                raise HistoricalWeeklyWaveError("unknown movement cannot claim evidence")
        elif movement == "stalled_reported":
            if basis != "source_reported" or not evidence:
                raise HistoricalWeeklyWaveError("reported stall requires explicit evidence")
        elif basis not in {"source_reported", "evidence_comparison"} or not evidence:
            raise HistoricalWeeklyWaveError("weekly movement requires exact evidence")
        return json.loads(json.dumps(item))

    def _decision(
        self,
        item: dict[str, Any],
        observations: dict[str, dict[str, Any]],
        project_ids: set[str],
        citations: set[str],
    ) -> dict[str, Any]:
        required = {
            "decision_id",
            "label",
            "state",
            "project_ids",
            "observation_ids",
            "citation_refs",
            "confidence",
            "conflicts",
            "omissions",
        }
        if (
            set(item) != required
            or not item["decision_id"]
            or not item["label"]
            or item["state"] not in DECISION_STATES
            or set(item["project_ids"]) - project_ids
            or not item["observation_ids"]
            or set(item["observation_ids"]) - set(observations)
            or not item["citation_refs"]
            or set(item["citation_refs"]) - citations
            or item["confidence"] not in CONFIDENCES
        ):
            raise HistoricalWeeklyWaveError("weekly decision lineage is invalid")
        return json.loads(json.dumps(item))

    @staticmethod
    def _inventory(observations: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        meetings = [
            item["observation_id"]
            for item in observations
            if item.get("item_class")
            in {"meeting_transcript", "meeting_notes", "meeting_debrief", "multi_meeting_bundle"}
        ]
        conversations = [
            item["observation_id"]
            for item in observations
            if item.get("observation_type") == "historical_conversation_execution"
        ]
        generated = sum(len(item.get("generated_artifacts", item.get("outputs", []))) for item in observations)
        inputs = sum(len(item.get("inputs", [])) for item in observations)
        return {
            "observation_count": len(observations),
            "meeting_count": len(meetings),
            "conversation_count": len(conversations),
            "input_count": inputs,
            "generated_artifact_count": generated,
            "meeting_observation_ids": sorted(meetings),
            "conversation_observation_ids": sorted(conversations),
        }

    @staticmethod
    def _views(
        wave_id: str,
        week_start: str,
        week_end: str,
        completeness: str,
        observations: dict[str, dict[str, Any]],
        strands: list[dict[str, Any]],
        projects: list[dict[str, Any]],
        decisions: list[dict[str, Any]],
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        assigned = {identifier for item in projects for identifier in item["observation_ids"]}
        conflicts = [
            {"observation_id": item["observation_id"], "value": value}
            for item in observations.values()
            for value in item.get("conflicts", [])
        ]
        omissions = [
            {"observation_id": item["observation_id"], "value": value}
            for item in observations.values()
            for value in item.get("omissions", [])
        ]
        return {
            "weekly_overview": {
                "wave_id": wave_id,
                "week_start": week_start,
                "week_end": week_end,
                "completeness": completeness,
                **{key: value for key, value in inventory.items() if key.endswith("_count")},
                "strand_count": len(strands),
                "project_count": len(projects),
                "decision_lineage_count": len(decisions),
                "unassigned_observation_count": len(set(observations) - assigned),
            },
            "strands": strands,
            "project_status_transitions": projects,
            "meeting_conversation_artifact_inventory": inventory,
            "decision_lineage": decisions,
            "missing_evidence": {
                "conflicts": conflicts,
                "omissions": omissions,
                "unassigned_observation_ids": sorted(set(observations) - assigned),
            },
        }

    @staticmethod
    def _global_views(
        waves: list[PreparedWeeklyWave], transitions: list[dict[str, Any]]
    ) -> dict[str, Any]:
        strand_history: dict[str, dict[str, Any]] = {}
        project_history: dict[str, dict[str, Any]] = {}
        seen_strands: set[str] = set()
        seen_projects: set[str] = set()
        new_by_wave = []
        for prepared in waves:
            wave = prepared.package
            wave_strands = {item["strand_id"] for item in wave["strands"]}
            wave_projects = {item["project_id"] for item in wave["projects"]}
            new_by_wave.append(
                {
                    "wave_id": wave["wave_id"],
                    "new_strand_ids": sorted(wave_strands - seen_strands),
                    "new_project_ids": sorted(wave_projects - seen_projects),
                }
            )
            seen_strands.update(wave_strands)
            seen_projects.update(wave_projects)
            for strand in wave["strands"]:
                entry = strand_history.setdefault(
                    strand["strand_id"], {"wave_ids": [], "project_ids": set()}
                )
                entry["wave_ids"].append(wave["wave_id"])
                entry["project_ids"].update(strand["project_ids"])
            for project in wave["projects"]:
                entry = project_history.setdefault(
                    project["project_id"], {"strand_ids": set(), "weekly_states": []}
                )
                entry["strand_ids"].update(project["strand_ids"])
                entry["weekly_states"].append(
                    {
                        "wave_id": wave["wave_id"],
                        "start_status": project["start_status"],
                        "end_status": project["end_status"],
                        "movement": project["movement"],
                    }
                )
        return {
            "weekly_overviews": [wave.package["views"]["weekly_overview"] for wave in waves],
            "strand_history": {
                key: {"wave_ids": value["wave_ids"], "project_ids": sorted(value["project_ids"])}
                for key, value in sorted(strand_history.items())
            },
            "project_history": {
                key: {
                    "strand_ids": sorted(value["strand_ids"]),
                    "weekly_states": value["weekly_states"],
                }
                for key, value in sorted(project_history.items())
            },
            "transition_network": transitions,
            "new_identities_by_wave": new_by_wave,
        }

    def _transition(
        self,
        item: dict[str, Any],
        waves: list[PreparedWeeklyWave],
        citations: set[str],
    ) -> dict[str, Any]:
        required = {
            "project_id",
            "from_wave_id",
            "to_wave_id",
            "transition",
            "evidence_refs",
            "confidence",
            "conflicts",
            "omissions",
        }
        by_wave = {wave.package["wave_id"]: wave.package for wave in waves}
        if (
            set(item) != required
            or item["from_wave_id"] not in by_wave
            or item["to_wave_id"] not in by_wave
            or by_wave[item["from_wave_id"]]["week_start"]
            >= by_wave[item["to_wave_id"]]["week_start"]
            or item["transition"] not in TRANSITIONS
            or item["confidence"] not in CONFIDENCES
            or set(item["evidence_refs"]) - citations
        ):
            raise HistoricalWeeklyWaveError("weekly transition is invalid")
        for wave_id in (item["from_wave_id"], item["to_wave_id"]):
            if item["project_id"] not in {
                project["project_id"] for project in by_wave[wave_id]["projects"]
            }:
                raise HistoricalWeeklyWaveError("weekly transition project endpoint is unavailable")
        if item["transition"] == "unresolved_gap":
            if item["evidence_refs"] or not item["omissions"]:
                raise HistoricalWeeklyWaveError("unresolved weekly gap must remain unevidenced")
        elif not item["evidence_refs"]:
            raise HistoricalWeeklyWaveError("cross-week status transition requires exact evidence")
        return json.loads(json.dumps(item))

    @staticmethod
    def _alias(item: dict[str, Any], identities: set[str], citations: set[str]) -> dict[str, Any]:
        required = {"canonical_id", "alias_id", "evidence_refs", "confidence", "conflicts"}
        if (
            set(item) != required
            or item["canonical_id"] not in identities
            or item["alias_id"] not in identities
            or item["canonical_id"] == item["alias_id"]
            or not item["evidence_refs"]
            or set(item["evidence_refs"]) - citations
            or item["confidence"] not in CONFIDENCES
        ):
            raise HistoricalWeeklyWaveError("weekly identity alias lacks exact evidence")
        return json.loads(json.dumps(item))

    def _wave(self, package: dict[str, Any]) -> None:
        try:
            self.schemas.require("historical-weekly-operating-wave", package)
        except ValidationError as exc:
            raise HistoricalWeeklyWaveError("weekly wave schema is invalid") from exc
        self._week(package["week_start"], package["week_end"])
        material = {key: value for key, value in package.items() if key != "wave_digest"}
        if package["wave_digest"] != canonical_sha256(material) or not all(
            package.get(key) is True
            for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
        ):
            raise HistoricalWeeklyWaveError("weekly wave binding changed")
        if package["chronology_creates_relationships"] is not False:
            raise HistoricalWeeklyWaveError("chronology cannot create a semantic relationship")

    def _reconciliation(self, package: dict[str, Any]) -> None:
        try:
            self.schemas.require("historical-weekly-cross-wave-reconciliation", package)
        except ValidationError as exc:
            raise HistoricalWeeklyWaveError("weekly reconciliation schema is invalid") from exc
        material = {key: value for key, value in package.items() if key != "reconciliation_digest"}
        if package["reconciliation_digest"] != canonical_sha256(material) or not all(
            package.get(key) is True
            for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
        ):
            raise HistoricalWeeklyWaveError("weekly reconciliation binding changed")

    def _observation(self, observation: dict[str, Any]) -> None:
        schema = {
            "historical_item": "historical-item-observation",
            "historical_conversation_execution": "historical-conversation-execution-observation",
        }.get(observation.get("observation_type"))
        if schema is None:
            raise HistoricalWeeklyWaveError("weekly observation type is unsupported")
        self.schemas.require(schema, observation)
        material = {key: value for key, value in observation.items() if key != "observation_digest"}
        if observation["observation_digest"] != canonical_sha256(material):
            raise HistoricalWeeklyWaveError("weekly observation binding changed")

    @staticmethod
    def _in_week(observation: dict[str, Any], start: datetime, end: datetime) -> bool:
        assertions = list(observation.get("temporal_assertions", []))
        for occurrence in observation.get("child_event_occurrences", []):
            assertions.extend(occurrence.get("temporal_assertions", []))
        relevant = {
            "event_started_at",
            "conversation_started_at",
            "artifact_generated_at",
            "effective_at",
        }
        for assertion in assertions:
            if assertion.get("field") not in relevant:
                continue
            for key in ("value", "earliest", "latest"):
                value = assertion.get(key)
                if value:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if start <= parsed < end:
                        return True
        return False

    @staticmethod
    def _week(week_start: str, week_end: str) -> tuple[datetime, datetime]:
        try:
            start = datetime.fromisoformat(week_start.replace("Z", "+00:00"))
            end = datetime.fromisoformat(week_end.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise HistoricalWeeklyWaveError("weekly boundary is invalid") from exc
        if (
            start.tzinfo != UTC
            or end.tzinfo != UTC
            or start.weekday() != 0
            or start.time() != datetime.min.time()
            or end != start + timedelta(days=7)
        ):
            raise HistoricalWeeklyWaveError("wave must be one Monday-to-Monday UTC calendar week")
        return start, end

    @staticmethod
    def _all_citations(waves: list[PreparedWeeklyWave]) -> set[str]:
        citations: set[str] = set()
        for prepared in waves:
            for strand in prepared.package["strands"]:
                citations.update(strand["citation_refs"])
            for project in prepared.package["projects"]:
                citations.update(project["membership_citation_refs"])
                citations.update(project["movement_citation_refs"])
            for decision in prepared.package["decisions"]:
                citations.update(decision["citation_refs"])
        return citations

    @staticmethod
    def _fences() -> dict[str, bool]:
        return {
            "candidate_only": True,
            "no_current_work": True,
            "no_promotion": True,
            "no_activation": True,
            "no_u2": True,
        }

    @staticmethod
    def _atomic(path: Path, material: bytes) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(material)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
