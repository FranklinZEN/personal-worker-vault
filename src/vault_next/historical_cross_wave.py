"""Source-free cross-wave reconciliation for candidate historical migrations.

The coordinator accepts already validated observations and catalogue metadata.  It cannot discover or
open a source, publish a canonical event, invoke authority, or adopt historical state as current.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_bytes, canonical_sha256
from vault_next.errors import ValidationError
from vault_next.records import SchemaRegistry


COMPONENT = "vault-next-historical-cross-wave-reconciliation/1.0.0"
METHOD = "historical_cross_wave_reconciler/1.0.0"
COVERAGE_STATES = frozenset(
    {"admitted", "calibrated_only", "excluded", "unsupported", "deferred", "failed", "unresolved"}
)
RELATION_STATUSES = frozenset(
    {"candidate", "source_reported", "structurally_verified", "rejected", "superseded"}
)
TIME_FIELDS = frozenset(
    {
        "source_created_at", "source_modified_at", "event_started_at", "event_ended_at",
        "conversation_started_at", "conversation_ended_at", "artifact_generated_at", "effective_at",
        "recorded_at",
    }
)


class HistoricalCrossWaveError(RuntimeError):
    """Cross-wave identity, scope, lineage, or rebuild validation failed closed."""


@dataclass(frozen=True)
class PreparedCrossWaveReconciliation:
    package: dict[str, Any]


class HistoricalCrossWaveCoordinator:
    """Build deterministic candidate-only reconciliation packages without source access."""

    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas

    def coverage_register(
        self,
        *,
        catalogue: dict[str, Any],
        observations: tuple[dict[str, Any], ...],
        calibrated_member_refs: tuple[str, ...] = (),
        dispositions: dict[str, tuple[str, str]] | None = None,
        cohort_memberships: dict[str, tuple[str, ...]] | None = None,
    ) -> dict[str, Any]:
        """Account for every catalogue member exactly once without reading member content."""

        self._catalogue(catalogue)
        dispositions = dispositions or {}
        cohort_memberships = cohort_memberships or {}
        available = {entry["member_ref"]: entry for entry in catalogue["entries"]}
        calibrated = set(calibrated_member_refs)
        if calibrated - set(available) or set(dispositions) - set(available):
            raise HistoricalCrossWaveError("coverage selection is outside the catalogue")
        by_member: dict[str, list[dict[str, Any]]] = {}
        for observation in observations:
            self._observation(observation)
            member_ref = observation["member_ref"]
            if member_ref not in available:
                raise HistoricalCrossWaveError("admitted observation is outside the catalogue")
            by_member.setdefault(member_ref, []).append(observation)
        entries: list[dict[str, Any]] = []
        for member_ref in sorted(available):
            admitted = by_member.get(member_ref, [])
            if admitted:
                if member_ref in calibrated or member_ref in dispositions:
                    raise HistoricalCrossWaveError("coverage member has overlapping dispositions")
                state, reason = "admitted", "validated observation lineage is admitted"
            elif member_ref in calibrated:
                if member_ref in dispositions:
                    raise HistoricalCrossWaveError("coverage member has overlapping dispositions")
                state, reason = "calibrated_only", "temporary calibration only; no admission authority"
            else:
                state, reason = dispositions.get(member_ref, ("unresolved", "not yet selected"))
            if state not in COVERAGE_STATES or not isinstance(reason, str) or not reason:
                raise HistoricalCrossWaveError("coverage disposition is invalid")
            cohorts = sorted(set(cohort_memberships.get(member_ref, ())))
            if state != "admitted" and cohorts:
                raise HistoricalCrossWaveError("non-admitted coverage member names a cohort")
            entries.append(
                {
                    "member_ref": member_ref,
                    "object_digest": available[member_ref]["content_sha256"],
                    "state": state,
                    "reason": reason,
                    "observation_ids": sorted({item["observation_id"] for item in admitted}),
                    "cohort_ids": cohorts,
                }
            )
        counts = {state: sum(item["state"] == state for item in entries) for state in sorted(COVERAGE_STATES)}
        register = {
            "schema_version": "1.0", "component": COMPONENT,
            "catalogue_digest": catalogue["catalogue_digest"], "entries": entries, "counts": counts,
            "candidate_only": True, "no_current_work": True, "no_promotion": True,
            "no_activation": True, "no_u2": True,
        }
        register["coverage_digest"] = canonical_sha256(register)
        self._coverage(register)
        return register

    def build_relationship(
        self,
        *,
        relationship_id: str,
        subject_ref: str,
        object_ref: str,
        predicate: str,
        evidence_refs: tuple[str, ...],
        basis_type: str = "content_evidence",
        status: str = "candidate",
        confidence: str = "medium",
        effective_at: str | None = None,
        conflicts: tuple[str, ...] = (),
        omissions: tuple[str, ...] = (),
        prior: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one immutable relationship version; endpoints and predicate never mutate."""

        version = 1
        predecessor = None
        if prior is not None:
            self._relationship_shape(prior)
            if (
                prior["relationship_id"] != relationship_id
                or prior["subject_ref"] != subject_ref
                or prior["object_ref"] != object_ref
                or prior["predicate"] != predicate
            ):
                raise HistoricalCrossWaveError("relationship identity or meaning changed")
            version = prior["relationship_version"] + 1
            predecessor = prior["relationship_digest"]
        relationship = {
            "schema_version": "1.0", "relationship_id": relationship_id,
            "relationship_version": version, "predecessor_digest": predecessor,
            "subject_ref": subject_ref, "object_ref": object_ref, "predicate": predicate,
            "basis_type": basis_type, "evidence_refs": sorted(set(evidence_refs)),
            "status": status, "confidence": confidence, "effective_at": effective_at,
            "conflicts": list(conflicts), "omissions": list(omissions), "method_version": METHOD,
            "candidate_only": True, "no_current_work": True,
        }
        relationship["relationship_digest"] = canonical_sha256(relationship)
        self._relationship_shape(relationship)
        return relationship

    def prepare_incremental(
        self,
        *,
        cohort_id: str,
        catalogue_digest: str,
        new_observations: tuple[dict[str, Any], ...],
        prior_observations: tuple[dict[str, Any], ...],
        prior_lineages: tuple[dict[str, Any], ...],
        relationships: tuple[dict[str, Any], ...],
        prior_relationships: tuple[dict[str, Any], ...],
        selected_prior_endpoint_digests: tuple[str, ...],
        coverage_register: dict[str, Any],
        prior_cohort_digests: tuple[str, ...] = (),
    ) -> PreparedCrossWaveReconciliation:
        """Prepare one exact incremental cohort over new observations and used prior endpoints only."""

        if not cohort_id or not new_observations:
            raise HistoricalCrossWaveError("incremental cohort is empty")
        self._coverage(coverage_register)
        if coverage_register["catalogue_digest"] != catalogue_digest:
            raise HistoricalCrossWaveError("cohort catalogue binding changed")
        all_observations = (*prior_observations, *new_observations)
        by_id = self._observation_map(all_observations)
        new_ids = {item["observation_id"] for item in new_observations}
        new_versions = {
            (item["observation_id"], item["observation_version"])
            for item in new_observations
        }
        if len(new_versions) != len(new_observations):
            raise HistoricalCrossWaveError("cohort repeats a new observation version")
        prior_ids = {item["observation_id"] for item in prior_observations}
        lineages = self._lineages(prior_lineages, all_observations, cohort_id, new_ids)
        required_prior: set[str] = set()
        citations = {ref for observation in all_observations for ref in observation["citation_refs"]}
        prior_relationship_by_id = {item["relationship_id"]: item for item in prior_relationships}
        for relationship in relationships:
            self._relationship(relationship, by_id, citations, prior_relationship_by_id)
            for endpoint in (relationship["subject_ref"], relationship["object_ref"]):
                if endpoint in prior_ids and endpoint not in new_ids:
                    required_prior.add(by_id[endpoint]["observation_digest"])
        if required_prior != set(selected_prior_endpoint_digests):
            raise HistoricalCrossWaveError("cohort prior endpoint scope changed or expanded")
        self._strands(all_observations, cohort_id)
        temporal = self._temporal(all_observations, relationships)
        global_views = self._views(all_observations, relationships, coverage_register, temporal)
        package = {
            "schema_version": "1.0", "component": COMPONENT,
            "reconciliation_version": 1, "reconciliation_kind": "incremental",
            "cohort_id": cohort_id, "catalogue_digest": catalogue_digest,
            "prior_cohort_digests": list(prior_cohort_digests),
            "new_observation_digests": [item["observation_digest"] for item in new_observations],
            "prior_endpoint_digests": sorted(required_prior), "lineages": lineages,
            "relationships": list(relationships), "temporal_reconciliation": temporal,
            "coverage_register": coverage_register, "global_views": global_views,
            "candidate_only": True, "no_current_work": True, "no_promotion": True,
            "no_activation": True, "no_u2": True,
        }
        package["reconciliation_digest"] = canonical_sha256(package)
        self._package(package)
        return PreparedCrossWaveReconciliation(package)

    def prepare_full_corpus(
        self,
        *,
        closure_id: str,
        catalogue_digest: str,
        observations: tuple[dict[str, Any], ...],
        lineages: tuple[dict[str, Any], ...],
        relationships: tuple[dict[str, Any], ...],
        coverage_register: dict[str, Any],
        cohort_digests: tuple[str, ...],
    ) -> PreparedCrossWaveReconciliation:
        """Build periodic/final closure from the admitted union without rewriting parent waves."""

        if not closure_id or not cohort_digests:
            raise HistoricalCrossWaveError("full-corpus closure is incomplete")
        self._coverage(coverage_register)
        by_id = self._observation_map(observations)
        citations = {ref for observation in observations for ref in observation["citation_refs"]}
        relationship_by_id: dict[str, dict[str, Any]] = {}
        for relationship in relationships:
            self._relationship(relationship, by_id, citations, relationship_by_id)
            relationship_by_id[relationship["relationship_id"]] = relationship
        merged = self._lineages(lineages, observations, closure_id, set())
        temporal = self._temporal(observations, relationships)
        views = self._views(observations, relationships, coverage_register, temporal)
        package = {
            "schema_version": "1.0", "component": COMPONENT,
            "reconciliation_version": 1, "reconciliation_kind": "full_corpus",
            "cohort_id": closure_id, "catalogue_digest": catalogue_digest,
            "prior_cohort_digests": list(cohort_digests), "new_observation_digests": [],
            "prior_endpoint_digests": sorted(item["observation_digest"] for item in observations),
            "lineages": merged, "relationships": list(relationships),
            "temporal_reconciliation": temporal, "coverage_register": coverage_register,
            "global_views": views, "candidate_only": True, "no_current_work": True,
            "no_promotion": True, "no_activation": True, "no_u2": True,
        }
        package["reconciliation_digest"] = canonical_sha256(package)
        self._package(package)
        return PreparedCrossWaveReconciliation(package)

    def rebuild_views(
        self, derived_root: Path, packages: tuple[PreparedCrossWaveReconciliation, ...]
    ) -> str:
        """Rebuild disposable/derived global views from exact package bytes."""

        if not packages:
            raise HistoricalCrossWaveError("global rebuild requires reconciliation packages")
        resolved_parent = derived_root.parent.resolve(strict=True)
        if derived_root.exists() and (derived_root.is_symlink() or not derived_root.is_dir()):
            raise HistoricalCrossWaveError("global derived root is unsafe")
        if derived_root.exists() and derived_root.resolve(strict=True).parent != resolved_parent:
            raise HistoricalCrossWaveError("global derived root escaped its parent")
        derived_root.mkdir(mode=0o700, exist_ok=True)
        if derived_root.stat().st_mode & 0o077:
            raise HistoricalCrossWaveError("global derived root is not owner-only")
        material = []
        for prepared in packages:
            self._package(prepared.package)
            material.append(
                {
                    "reconciliation_digest": prepared.package["reconciliation_digest"],
                    "coverage_digest": prepared.package["coverage_register"]["coverage_digest"],
                    "global_views": prepared.package["global_views"],
                }
            )
        rebuild = {
            "schema_version": "1.0", "component": COMPONENT, "packages": material,
            "candidate_only": True, "no_current_work": True,
        }
        rebuild["rebuild_digest"] = canonical_sha256(rebuild)
        self._atomic(derived_root / "global-reconciliation.json", canonical_bytes(rebuild))
        return rebuild["rebuild_digest"]

    def verify_rebuild(
        self, derived_root: Path, packages: tuple[PreparedCrossWaveReconciliation, ...]
    ) -> str:
        expected = self.rebuild_views(derived_root, packages)
        stored = json.loads((derived_root / "global-reconciliation.json").read_text())
        if stored.get("rebuild_digest") != expected or canonical_sha256(
            {key: value for key, value in stored.items() if key != "rebuild_digest"}
        ) != expected:
            raise HistoricalCrossWaveError("global derived rebuild changed")
        return expected

    def _lineages(
        self,
        prior_lineages: tuple[dict[str, Any], ...],
        observations: tuple[dict[str, Any], ...],
        cohort_id: str,
        new_ids: set[str],
    ) -> list[dict[str, Any]]:
        lineages: dict[str, dict[str, Any]] = {}
        observation_to_source: dict[str, str] = {}
        for prior in prior_lineages:
            self._lineage(prior)
            source = prior["source_identity"]
            if source in lineages:
                raise HistoricalCrossWaveError("prior source lineage is duplicated")
            lineages[source] = json.loads(json.dumps(prior))
            observation_to_source[prior["observation_id"]] = source
        ordered = sorted(
            observations,
            key=lambda item: (
                item["member_ref"], item["logical_record_id"], item["observation_version"]
            ),
        )
        for observation in ordered:
            source = self._source_identity(observation)
            existing_source = observation_to_source.get(observation["observation_id"])
            if existing_source is not None and existing_source != source:
                raise HistoricalCrossWaveError("observation identity was reused for another source")
            observation_to_source[observation["observation_id"]] = source
            version = {
                "observation_version": observation["observation_version"],
                "observation_digest": observation["observation_digest"],
                "parser_version": observation["parser_version"],
                "method_version": observation["method_version"],
                "prompt_version": observation["prompt_version"],
                "recorded_at": observation["recorded_at"],
            }
            if source not in lineages:
                lineages[source] = {
                    "source_identity": source, "parent_event_id": observation["parent_event_id"],
                    "member_ref": observation["member_ref"],
                    "logical_record_id": observation["logical_record_id"],
                    "object_digest": observation["object_digest"],
                    "observation_id": observation["observation_id"], "versions": [],
                    "cohort_ids": [], "candidate_only": True, "no_current_work": True,
                }
            lineage = lineages[source]
            if (
                lineage["observation_id"] != observation["observation_id"]
                or lineage["object_digest"] != observation["object_digest"]
            ):
                raise HistoricalCrossWaveError("exact source was assigned a second observation lineage")
            by_version = {item["observation_version"]: item for item in lineage["versions"]}
            previous = by_version.get(observation["observation_version"])
            if previous is not None and previous != version:
                raise HistoricalCrossWaveError("observation version was mutated")
            if previous is None:
                if by_version and observation["observation_version"] != max(by_version) + 1:
                    raise HistoricalCrossWaveError("observation revision is not append-only")
                lineage["versions"].append(version)
                lineage["versions"].sort(key=lambda item: item["observation_version"])
            if observation["observation_id"] in new_ids:
                lineage["cohort_ids"] = sorted(set((*lineage["cohort_ids"], cohort_id)))
        result = sorted(lineages.values(), key=lambda item: item["source_identity"])
        for lineage in result:
            self._lineage(lineage)
        return result

    def _temporal(
        self, observations: tuple[dict[str, Any], ...], relationships: tuple[dict[str, Any], ...]
    ) -> dict[str, Any]:
        assertions: list[dict[str, Any]] = []
        findings: list[dict[str, str]] = []
        for observation in observations:
            per_field: dict[str, list[dict[str, Any]]] = {}
            for value in observation["temporal_assertions"]:
                field = value.get("field")
                if field not in TIME_FIELDS:
                    raise HistoricalCrossWaveError("temporal field is unsupported")
                self._time_values(value)
                entry = {"observation_id": observation["observation_id"], **value}
                assertions.append(entry)
                per_field.setdefault(field, []).append(value)
                for conflict in value.get("conflicts", []):
                    findings.append(
                        {
                            "kind": "source_conflict",
                            "observation_id": observation["observation_id"],
                            "detail": str(conflict),
                        }
                    )
            recorded = observation["recorded_at"]
            self._timestamp(recorded)
            assertions.append(
                {
                    "observation_id": observation["observation_id"], "field": "recorded_at",
                    "value": recorded, "earliest": None, "latest": None, "precision": "instant",
                    "basis": "observation_record", "confidence": "high", "citation_refs": [],
                    "conflicts": [], "timezone_assumption": None,
                }
            )
            ranges = (
                ("event_started_at", "event_ended_at"),
                ("conversation_started_at", "conversation_ended_at"),
            )
            for start, end in ranges:
                if start in per_field and end in per_field:
                    start_value = per_field[start][0].get("value")
                    end_value = per_field[end][0].get("value")
                    if (
                        start_value
                        and end_value
                        and self._timestamp(end_value) < self._timestamp(start_value)
                    ):
                        findings.append(
                            {
                                "kind": "impossible_ordering",
                                "observation_id": observation["observation_id"],
                                "detail": f"{end} precedes {start}",
                            }
                        )
        for relationship in relationships:
            if relationship["effective_at"]:
                self._timestamp(relationship["effective_at"])
                assertions.append(
                    {
                        "observation_id": relationship["relationship_id"], "field": "effective_at",
                        "value": relationship["effective_at"], "earliest": None, "latest": None,
                        "precision": "instant", "basis": "relationship_assertion",
                        "confidence": relationship["confidence"],
                        "citation_refs": relationship["evidence_refs"], "conflicts": relationship["conflicts"],
                        "timezone_assumption": None,
                    }
                )
        assertions.sort(
            key=lambda item: (
                item.get("value") is None, item.get("value") or "",
                item["observation_id"], item["field"],
            )
        )
        return {"assertions": assertions, "findings": findings}

    @staticmethod
    def _views(
        observations: tuple[dict[str, Any], ...], relationships: tuple[dict[str, Any], ...],
        coverage: dict[str, Any], temporal: dict[str, Any],
    ) -> dict[str, Any]:
        strands: dict[str, set[str]] = {}
        conflicts: list[dict[str, Any]] = []
        omissions: list[dict[str, Any]] = []
        for observation in observations:
            for strand in observation.get("strands", []):
                strands.setdefault(strand["label"], set()).add(observation["observation_id"])
            conflicts.extend(
                {"observation_id": observation["observation_id"], "value": item}
                for item in observation.get("conflicts", [])
            )
            omissions.extend(
                {"observation_id": observation["observation_id"], "value": item}
                for item in observation.get("omissions", [])
            )
        return {
            "coverage_counts": coverage["counts"],
            "timeline": temporal["assertions"], "temporal_findings": temporal["findings"],
            "relationship_network": [
                {
                    "relationship_id": item["relationship_id"],
                    "relationship_version": item["relationship_version"],
                    "relationship_digest": item["relationship_digest"],
                    "subject_ref": item["subject_ref"], "object_ref": item["object_ref"],
                    "predicate": item["predicate"], "status": item["status"],
                }
                for item in relationships
            ],
            "strands": {key: sorted(value) for key, value in sorted(strands.items())},
            "conflicts": conflicts, "omissions": omissions,
        }

    def _observation_map(self, observations: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for observation in observations:
            self._observation(observation)
            identifier = observation["observation_id"]
            existing = result.get(identifier)
            if existing is not None:
                if self._source_identity(existing) != self._source_identity(observation):
                    raise HistoricalCrossWaveError("observation identity was reused for another source")
                if existing["observation_version"] == observation["observation_version"]:
                    if existing["observation_digest"] != observation["observation_digest"]:
                        raise HistoricalCrossWaveError("observation version was mutated")
                    continue
                if existing["observation_version"] > observation["observation_version"]:
                    continue
            result[identifier] = observation
        return result

    def _observation(self, observation: dict[str, Any]) -> None:
        kind = observation.get("observation_type")
        schema = {
            "historical_item": "historical-item-observation",
            "historical_conversation_execution": "historical-conversation-execution-observation",
        }.get(kind)
        if schema is None:
            raise HistoricalCrossWaveError("cross-wave observation type is unsupported")
        self.schemas.require(schema, observation)
        material = {key: value for key, value in observation.items() if key != "observation_digest"}
        if observation["observation_digest"] != canonical_sha256(material) or not all(
            observation.get(key) is True
            for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
        ):
            raise HistoricalCrossWaveError("cross-wave observation binding changed")

    @staticmethod
    def _source_identity(observation: dict[str, Any]) -> str:
        return canonical_sha256(
            {
                "parent_event_id": observation["parent_event_id"],
                "member_ref": observation["member_ref"],
                "logical_record_id": observation["logical_record_id"],
            }
        )

    def _strands(self, observations: tuple[dict[str, Any], ...], cohort_id: str) -> None:
        forbidden = {cohort_id, f"cohort:{cohort_id}", f"packet:{cohort_id}", f"wave:{cohort_id}"}
        for observation in observations:
            for strand in observation.get("strands", []):
                if strand.get("label") in forbidden or not strand.get("citation_refs"):
                    raise HistoricalCrossWaveError("cohort membership cannot establish a semantic strand")

    def _relationship(
        self, relationship: dict[str, Any], observations: dict[str, dict[str, Any]],
        citations: set[str], prior_by_id: dict[str, dict[str, Any]],
    ) -> None:
        self._relationship_shape(relationship)
        if (
            relationship["subject_ref"] not in observations
            or relationship["object_ref"] not in observations
            or relationship["subject_ref"] == relationship["object_ref"]
            or set(relationship["evidence_refs"]) - citations
        ):
            raise HistoricalCrossWaveError("cross-wave relationship endpoint or evidence changed")
        prior = prior_by_id.get(relationship["relationship_id"])
        if relationship["relationship_version"] == 1:
            if prior is not None or relationship["predecessor_digest"] is not None:
                raise HistoricalCrossWaveError("relationship first version is not new")
        else:
            if (
                prior is None
                or relationship["relationship_version"] != prior["relationship_version"] + 1
                or relationship["predecessor_digest"] != prior["relationship_digest"]
                or any(
                    relationship[key] != prior[key]
                    for key in ("relationship_id", "subject_ref", "object_ref", "predicate")
                )
            ):
                raise HistoricalCrossWaveError("relationship revision is not append-only")

    def _relationship_shape(self, relationship: dict[str, Any]) -> None:
        self.schemas.require("historical-cross-wave-relationship", relationship)
        material = {key: value for key, value in relationship.items() if key != "relationship_digest"}
        if (
            relationship["relationship_digest"] != canonical_sha256(material)
            or relationship["status"] not in RELATION_STATUSES
            or relationship["method_version"] != METHOD
            or relationship["candidate_only"] is not True
            or relationship["no_current_work"] is not True
            or not relationship["evidence_refs"]
        ):
            raise HistoricalCrossWaveError("cross-wave relationship binding changed")

    def _lineage(self, lineage: dict[str, Any]) -> None:
        required = {
            "source_identity", "parent_event_id", "member_ref", "logical_record_id", "object_digest",
            "observation_id", "versions", "cohort_ids", "candidate_only", "no_current_work",
        }
        versions = lineage.get("versions", [])
        version_keys = {
            "observation_version", "observation_digest", "parser_version", "method_version",
            "prompt_version", "recorded_at",
        }
        if (
            set(lineage) != required or lineage["candidate_only"] is not True
            or lineage["no_current_work"] is not True or not versions
            or any(set(item) != version_keys for item in versions)
            or any(
                not isinstance(item["observation_version"], int)
                or item["observation_version"] < 1
                for item in versions
            )
            or any(
                not isinstance(item["observation_digest"], str)
                or len(item["observation_digest"]) != 64
                for item in versions
            )
            or len({item["observation_version"] for item in versions}) != len(versions)
            or [item["observation_version"] for item in versions] != sorted(
                item["observation_version"] for item in versions
            )
        ):
            raise HistoricalCrossWaveError("observation lineage is invalid")
        if [item["observation_version"] for item in versions] != list(
            range(versions[0]["observation_version"], versions[-1]["observation_version"] + 1)
        ):
            raise HistoricalCrossWaveError("observation lineage has a version gap")
        for item in versions:
            self._timestamp(item["recorded_at"])

    def _coverage(self, register: dict[str, Any]) -> None:
        self.schemas.require("historical-coverage-register", register)
        material = {key: value for key, value in register.items() if key != "coverage_digest"}
        if register["coverage_digest"] != canonical_sha256(material) or not all(
            register.get(key) is True
            for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
        ):
            raise HistoricalCrossWaveError("coverage register binding changed")
        refs = [item["member_ref"] for item in register["entries"]]
        expected = {
            state: sum(item["state"] == state for item in register["entries"])
            for state in sorted(COVERAGE_STATES)
        }
        if (
            len(refs) != len(set(refs))
            or any(not isinstance(value, int) or value < 0 for value in register["counts"].values())
            or register["counts"] != expected
        ):
            raise HistoricalCrossWaveError("coverage register accounting changed")

    def _package(self, package: dict[str, Any]) -> None:
        try:
            self.schemas.require("historical-cross-wave-reconciliation", package)
        except ValidationError as exc:
            raise HistoricalCrossWaveError("cross-wave reconciliation schema is invalid") from exc
        material = {key: value for key, value in package.items() if key != "reconciliation_digest"}
        if package["reconciliation_digest"] != canonical_sha256(material) or not all(
            package.get(key) is True
            for key in ("candidate_only", "no_current_work", "no_promotion", "no_activation", "no_u2")
        ):
            raise HistoricalCrossWaveError("cross-wave reconciliation binding changed")
        self._coverage(package["coverage_register"])
        if package["coverage_register"]["catalogue_digest"] != package["catalogue_digest"]:
            raise HistoricalCrossWaveError("cross-wave coverage catalogue changed")
        for lineage in package["lineages"]:
            self._lineage(lineage)
        for relationship in package["relationships"]:
            self._relationship_shape(relationship)
        expected_network = [
            item["relationship_digest"] for item in package["relationships"]
        ]
        actual_network = [
            item.get("relationship_digest")
            for item in package["global_views"].get("relationship_network", [])
        ]
        if expected_network != actual_network:
            raise HistoricalCrossWaveError("cross-wave relationship view changed")

    @staticmethod
    def _catalogue(catalogue: dict[str, Any]) -> None:
        entries = catalogue.get("entries")
        digest = catalogue.get("catalogue_digest")
        if not isinstance(entries, list) or not entries or not isinstance(digest, str):
            raise HistoricalCrossWaveError("archive catalogue is invalid")
        material = {key: value for key, value in catalogue.items() if key != "catalogue_digest"}
        if digest != canonical_sha256(material):
            raise HistoricalCrossWaveError("archive catalogue digest changed")
        refs = [item.get("member_ref") for item in entries]
        if len(refs) != len(set(refs)) or any(
            not isinstance(item.get("content_sha256"), str) for item in entries
        ):
            raise HistoricalCrossWaveError("archive catalogue identities are ambiguous")

    @staticmethod
    def _time_values(value: dict[str, Any]) -> None:
        candidates = [value.get(key) for key in ("value", "earliest", "latest") if value.get(key)]
        parsed = [HistoricalCrossWaveCoordinator._timestamp(item) for item in candidates]
        if value.get("earliest") and value.get("latest") and parsed[-1] < parsed[-2]:
            raise HistoricalCrossWaveError("temporal interval is reversed")

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise HistoricalCrossWaveError("temporal value is invalid") from exc
        if parsed.tzinfo is None:
            raise HistoricalCrossWaveError("temporal value lacks timezone")
        return parsed

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
