"""Additive multi-parent publication for one candidate historical calendar week.

This sibling leaves the original single-parent H2 publisher untouched.  It accepts only caller-
supplied, already parsed records and observations and cannot discover sources, invoke a model, or
adopt historical work as current.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.historical_activity import (
    HistoricalActivityCaps,
    HistoricalActivityCoordinator,
    HistoricalActivityError,
    LogicalRecord,
)
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-historical-weekly-activity-reconstruction/1.0.0"
PURPOSE = "historical_weekly_activity_reconstruction"
FAMILY = "meeting_workstream_history"
DISCLOSURE = "hybrid_visible_hosted_exact_packs_local_private_storage"
OPERATIONS = (
    "append_candidate_historical_weekly_activity",
    "build_candidate_weekly_fts5",
    "build_historical_weekly_views",
)
VIEW_NAMES = (
    "timeline",
    "strands",
    "project_status_transitions",
    "meeting_conversation_artifact_inventory",
    "decision_lineage",
    "people",
    "missing_evidence",
)
SOURCE_LANES = frozenset({"legacy_vault", "claude_export", "codex_export"})


class HistoricalWeeklyActivityError(HistoricalActivityError):
    """A multi-parent weekly package failed closed."""


class ExistingV2HistoricalWeeklyActivityAuthority(Protocol):
    def authorize_historical_weekly_activity_reconstruction(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def verify_historical_weekly_activity_reconstruction(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def read_historical_weekly_activity_reconstruction_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_historical_weekly_activity_reconstruction(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PreparedHistoricalWeeklyActivity:
    manifest: dict[str, Any]
    package: dict[str, Any]


@dataclass(frozen=True)
class HistoricalWeeklyActivityResult:
    status: str
    event_id: str
    receipt_id: str


class HistoricalWeeklyActivityCoordinator(HistoricalActivityCoordinator):
    """Publish one exact multi-parent week under one purpose-separated v2 receipt."""

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: ExistingV2HistoricalWeeklyActivityAuthority,
        *,
        caps: HistoricalActivityCaps = HistoricalActivityCaps(),
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        fail_before_event: bool = False,
    ) -> None:
        super().__init__(
            bundle_root,
            schemas,
            authority,  # type: ignore[arg-type]
            caps=caps,
            id_factory=id_factory,
            fail_before_event=fail_before_event,
        )

    def prepare(
        self,
        *,
        bundle_id: str,
        week_start: str,
        week_end: str,
        parent_bindings: tuple[dict[str, str], ...],
        selected_sources: tuple[dict[str, str], ...],
        records: tuple[LogicalRecord, ...],
        item_observations: tuple[dict[str, Any], ...],
        conversation_observations: tuple[dict[str, Any], ...],
        weekly_wave: dict[str, Any],
        cross_wave_reconciliation: dict[str, Any],
        primary_artifact: dict[str, Any],
        support_views: dict[str, dict[str, Any]],
        expires_at: datetime,
    ) -> PreparedHistoricalWeeklyActivity:
        """Bind parents, exact source identities, semantics, and presentation into one proposal."""

        self._records(records)
        bindings = self._parent_bindings(parent_bindings)
        parent_set_digest = canonical_sha256(list(bindings))
        catalogue_set_digest = canonical_sha256(
            [binding["catalogue_digest"] for binding in bindings]
        )
        start, end = self._week(week_start, week_end)
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise HistoricalWeeklyActivityError("historical weekly expiry is invalid")
        if not bundle_id:
            raise HistoricalWeeklyActivityError("historical weekly bundle identity is absent")

        by_record = {(record.member_ref, record.logical_record_id): record for record in records}
        if len(by_record) != len(records):
            raise HistoricalWeeklyActivityError("historical weekly logical identity is duplicated")
        sources = self._selected_sources(selected_sources, by_record, bindings)
        if len(sources) != len(records):
            raise HistoricalWeeklyActivityError("historical weekly source accounting changed")

        observations = (*item_observations, *conversation_observations)
        if len(observations) != len(records):
            raise HistoricalWeeklyActivityError("historical weekly observation accounting changed")
        binding_keys = {self._binding_key(binding) for binding in bindings}
        identities: set[tuple[str, ...]] = set()
        for observation in item_observations:
            record = by_record.get((observation["member_ref"], observation["logical_record_id"]))
            if record is None:
                raise HistoricalWeeklyActivityError("historical weekly item source was substituted")
            self._item(observation, record)
            self._observation_parent(observation, binding_keys)
            identities.add(self._coverage_identity(observation))
        for observation in conversation_observations:
            record = by_record.get((observation["member_ref"], observation["logical_record_id"]))
            if record is None:
                raise HistoricalWeeklyActivityError(
                    "historical weekly conversation source was substituted"
                )
            self._conversation(observation, record)
            self._observation_parent(observation, binding_keys)
            identities.add(self._coverage_identity(observation))
        if len(identities) != len(observations):
            raise HistoricalWeeklyActivityError("historical weekly exactly-once identity repeated")

        observation_digests = [item["observation_digest"] for item in observations]
        self.schemas.require("historical-weekly-multi-parent-wave", weekly_wave)
        self.schemas.require(
            "historical-weekly-multi-parent-reconciliation", cross_wave_reconciliation
        )
        if (
            weekly_wave["week_start"] != week_start
            or weekly_wave["week_end"] != week_end
            or weekly_wave["parent_set_digest"] != parent_set_digest
            or weekly_wave["catalogue_set_digest"] != catalogue_set_digest
            or set(weekly_wave["observation_digests"]) != set(observation_digests)
            or cross_wave_reconciliation["parent_set_digest"] != parent_set_digest
            or cross_wave_reconciliation["catalogue_set_digest"] != catalogue_set_digest
            or set(cross_wave_reconciliation["new_observation_digests"])
            != set(observation_digests)
        ):
            raise HistoricalWeeklyActivityError("historical weekly semantic binding changed")
        self._digest(weekly_wave, "wave_digest")
        self._digest(cross_wave_reconciliation, "reconciliation_digest")

        citations = {ref for item in observations for ref in item["citation_refs"]}
        primary = self._presentation(primary_artifact, "artifact_digest", citations)
        if set(support_views) != set(VIEW_NAMES):
            raise HistoricalWeeklyActivityError("historical weekly support view set changed")
        views = {
            name: self._presentation(support_views[name], "view_digest", citations)
            for name in VIEW_NAMES
        }

        package = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "family": FAMILY,
            "week_start": week_start,
            "week_end": week_end,
            "parent_bindings": list(bindings),
            "parent_set_digest": parent_set_digest,
            "catalogue_set_digest": catalogue_set_digest,
            "selected_sources": list(sources),
            "logical_records": [record.descriptor() for record in records],
            "item_observations": list(item_observations),
            "conversation_observations": list(conversation_observations),
            "weekly_wave": weekly_wave,
            "cross_wave_reconciliation": cross_wave_reconciliation,
            "primary_artifact": primary,
            "support_views": views,
            **self._fences(),
        }
        package["package_digest"] = canonical_sha256(package)
        manifest = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID,
            "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id,
            "family": FAMILY,
            "week_start": timestamp(start),
            "week_end": timestamp(end),
            "parent_bindings": list(bindings),
            "parent_set_digest": parent_set_digest,
            "catalogue_set_digest": catalogue_set_digest,
            "selected_sources": list(sources),
            "logical_record_digests": [record.logical_record_digest for record in records],
            "item_observation_digests": [item["observation_digest"] for item in item_observations],
            "conversation_observation_digests": [
                item["observation_digest"] for item in conversation_observations
            ],
            "weekly_wave_digest": weekly_wave["wave_digest"],
            "cross_wave_reconciliation_digest": cross_wave_reconciliation[
                "reconciliation_digest"
            ],
            "primary_artifact_digest": primary["artifact_digest"],
            "support_view_digests": {
                name: views[name]["view_digest"] for name in VIEW_NAMES
            },
            "disclosure": DISCLOSURE,
            "candidate_only": True,
            "operations": list(OPERATIONS),
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._prepared(PreparedHistoricalWeeklyActivity(manifest, package))
        return PreparedHistoricalWeeklyActivity(manifest, package)

    def authorize(self, prepared: PreparedHistoricalWeeklyActivity) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_historical_weekly_activity_reconstruction(
            prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(
        self, prepared: PreparedHistoricalWeeklyActivity, *, receipt_id: str
    ) -> HistoricalWeeklyActivityResult:
        self._prepared(prepared)
        root = self._root()
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing["receipt_id"] != receipt_id:
                raise HistoricalWeeklyActivityError("historical weekly receipt replay changed")
            self._archived(receipt_id, prepared.manifest, root)
            self._verify_package(root, prepared)
            self._rebuild(root, existing, prepared)
            return HistoricalWeeklyActivityResult("already_complete", existing["event_id"], receipt_id)

        receipt = self.authority.verify_historical_weekly_activity_reconstruction(
            receipt_id, prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_historical_weekly_activity_reconstruction_evidence(
            receipt_id, prepared.manifest
        )
        self._initialize(root)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".historical-weekly-{prepared.manifest['admission_id']}-",
                dir=root / "staging" / "historical-weekly-activity",
            )
        )
        try:
            event = self._event(prepared, receipt_id)
            self.schemas.require("historical-weekly-activity-reconstruction-event", event)
            materials = {
                "manifest.json": canonical_bytes(prepared.manifest),
                "package.json": canonical_bytes(prepared.package),
                "display.json": display,
                "receipt.json": signed,
                "event.json": canonical_bytes(event),
            }
            for name, material in materials.items():
                self._immutable(stage / name, material)
            if self.fail_before_event:
                raise HistoricalWeeklyActivityError(
                    "injected interruption before historical weekly event"
                )
            targets = {
                "manifest.json": root / "canonical" / "historical-weekly-activity-manifests"
                / prepared.manifest["manifest_digest"],
                "package.json": root / "canonical" / "historical-weekly-activity-packages"
                / prepared.package["package_digest"],
                "display.json": root / "evidence" / "historical-weekly-activity"
                / f"{receipt_id}.json",
                "receipt.json": root / "receipts" / "historical-weekly-activity"
                / f"{receipt_id}.json",
                "event.json": root / "canonical" / "historical-weekly-activity-events"
                / f"{event['event_id']}.json",
            }
            for name, target in targets.items():
                self._publish(stage / name, target, sha256_hex(materials[name]))
            self._rebuild(root, event, prepared)
            return HistoricalWeeklyActivityResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def verify_restart(
        self, prepared: PreparedHistoricalWeeklyActivity, *, receipt_id: str
    ) -> HistoricalWeeklyActivityResult:
        self._prepared(prepared)
        root = self._root()
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None or event["receipt_id"] != receipt_id:
            raise HistoricalWeeklyActivityError("historical weekly event is unavailable")
        self._archived(receipt_id, prepared.manifest, root)
        self._verify_package(root, prepared)
        self._rebuild(root, event, prepared)
        return HistoricalWeeklyActivityResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        root = self._root()
        if not root.is_relative_to(Path("/private/tmp")):
            raise HistoricalWeeklyActivityError("historical weekly rollback is mirror-only")
        record = {
            "schema_version": "1.0",
            "rollback_type": "logical_historical_weekly_activity_views",
            "target_event_id": event_id,
            "parent_events_unchanged": True,
        }
        record["rollback_sha256"] = canonical_sha256(record)
        self._immutable(
            root / "canonical" / "historical-weekly-activity-rollbacks"
            / f"{self.ids.new('event')}.json",
            canonical_bytes(record),
        )
        return record

    def _prepared(self, prepared: PreparedHistoricalWeeklyActivity) -> None:
        self.schemas.require("historical-weekly-activity-reconstruction-manifest", prepared.manifest)
        self._digest(prepared.manifest, "manifest_digest")
        self._digest(prepared.package, "package_digest")
        manifest = prepared.manifest
        package = prepared.package
        if (
            manifest["component"] != COMPONENT
            or manifest["purpose"] != PURPOSE
            or manifest["authority_id"] != AUTHORITY_ID
            or manifest["family"] != FAMILY
            or manifest["disclosure"] != DISCLOSURE
            or manifest["candidate_only"] is not True
            or manifest["operations"] != list(OPERATIONS)
            or package["component"] != COMPONENT
            or package["parent_bindings"] != manifest["parent_bindings"]
            or package["parent_set_digest"] != manifest["parent_set_digest"]
            or package["catalogue_set_digest"] != manifest["catalogue_set_digest"]
            or package["selected_sources"] != manifest["selected_sources"]
            or package["weekly_wave"]["wave_digest"] != manifest["weekly_wave_digest"]
            or package["cross_wave_reconciliation"]["reconciliation_digest"]
            != manifest["cross_wave_reconciliation_digest"]
            or package["primary_artifact"]["artifact_digest"]
            != manifest["primary_artifact_digest"]
            or {
                name: package["support_views"][name]["view_digest"] for name in VIEW_NAMES
            }
            != manifest["support_view_digests"]
            or not all(package.get(key) is True for key in self._fences())
        ):
            raise HistoricalWeeklyActivityError("historical weekly prepared package changed")
        if manifest["logical_record_digests"] != [
            item["logical_record_digest"] for item in package["logical_records"]
        ]:
            raise HistoricalWeeklyActivityError("historical weekly logical records changed")
        if manifest["item_observation_digests"] != [
            item["observation_digest"] for item in package["item_observations"]
        ]:
            raise HistoricalWeeklyActivityError("historical weekly item observations changed")
        if manifest["conversation_observation_digests"] != [
            item["observation_digest"] for item in package["conversation_observations"]
        ]:
            raise HistoricalWeeklyActivityError(
                "historical weekly conversation observations changed"
            )

        bindings = self._parent_bindings(tuple(package["parent_bindings"]))
        if canonical_sha256(list(bindings)) != manifest["parent_set_digest"]:
            raise HistoricalWeeklyActivityError("historical weekly parent set changed")
        if canonical_sha256(
            [binding["catalogue_digest"] for binding in bindings]
        ) != manifest["catalogue_set_digest"]:
            raise HistoricalWeeklyActivityError("historical weekly catalogue set changed")

        descriptors = {
            (item["member_ref"], item["logical_record_id"]): item
            for item in package["logical_records"]
        }
        if len(descriptors) != len(package["logical_records"]):
            raise HistoricalWeeklyActivityError("historical weekly logical identity repeated")
        binding_keys = {self._binding_key(binding) for binding in bindings}
        source_identities = {
            (
                item["parent_event_id"],
                item["parent_manifest_digest"],
                item["catalogue_digest"],
                item["member_ref"],
                item["logical_record_id"],
                item["object_digest"],
                item["parser_identity"],
            )
            for item in package["selected_sources"]
        }
        if len(source_identities) != len(package["selected_sources"]):
            raise HistoricalWeeklyActivityError("historical weekly exact source repeated")

        observations = (
            *package["item_observations"],
            *package["conversation_observations"],
        )
        coverage_identities: set[tuple[str, ...]] = set()
        citations: set[str] = set()
        for index, observation in enumerate(observations):
            schema = (
                "historical-item-observation"
                if index < len(package["item_observations"])
                else "historical-conversation-execution-observation"
            )
            self.schemas.require(schema, observation)
            self._digest(observation, "observation_digest")
            descriptor = descriptors.get(
                (observation["member_ref"], observation["logical_record_id"])
            )
            if descriptor is None or observation["object_digest"] != descriptor["object_digest"]:
                raise HistoricalWeeklyActivityError(
                    "historical weekly observation source changed"
                )
            self._observation_parent(observation, binding_keys)
            identity = self._coverage_identity(observation)
            if identity in coverage_identities or not any(
                identity
                == (
                    source["parent_event_id"],
                    source["parent_manifest_digest"],
                    source["catalogue_digest"],
                    source["member_ref"],
                    source["logical_record_id"],
                    source["object_digest"],
                    source["parser_identity"],
                )
                for source in package["selected_sources"]
            ):
                raise HistoricalWeeklyActivityError(
                    "historical weekly exactly-once identity changed"
                )
            coverage_identities.add(identity)
            allowed = {anchor["anchor_id"] for anchor in descriptor["anchors"]}
            if set(observation["citation_refs"]) - allowed:
                raise HistoricalWeeklyActivityError(
                    "historical weekly observation citation changed"
                )
            citations.update(observation["citation_refs"])

        wave = package["weekly_wave"]
        reconciliation = package["cross_wave_reconciliation"]
        self.schemas.require("historical-weekly-multi-parent-wave", wave)
        self.schemas.require(
            "historical-weekly-multi-parent-reconciliation", reconciliation
        )
        self._digest(wave, "wave_digest")
        self._digest(reconciliation, "reconciliation_digest")
        observation_digests = {item["observation_digest"] for item in observations}
        if (
            wave["parent_set_digest"] != manifest["parent_set_digest"]
            or wave["catalogue_set_digest"] != manifest["catalogue_set_digest"]
            or set(wave["observation_digests"]) != observation_digests
            or reconciliation["parent_set_digest"] != manifest["parent_set_digest"]
            or reconciliation["catalogue_set_digest"] != manifest["catalogue_set_digest"]
            or set(reconciliation["new_observation_digests"]) != observation_digests
        ):
            raise HistoricalWeeklyActivityError("historical weekly semantic binding changed")
        self._presentation(package["primary_artifact"], "artifact_digest", citations)
        if set(package["support_views"]) != set(VIEW_NAMES):
            raise HistoricalWeeklyActivityError("historical weekly support view set changed")
        for name in VIEW_NAMES:
            self._presentation(package["support_views"][name], "view_digest", citations)

    @staticmethod
    def _week(week_start: str, week_end: str) -> tuple[datetime, datetime]:
        try:
            start = datetime.fromisoformat(week_start.replace("Z", "+00:00"))
            end = datetime.fromisoformat(week_end.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise HistoricalWeeklyActivityError("historical weekly interval is invalid") from exc
        if (
            start.tzinfo is None
            or end.tzinfo is None
            or start.weekday() != 0
            or end.weekday() != 0
            or (end - start).days != 7
        ):
            raise HistoricalWeeklyActivityError("historical weekly interval is not Monday-to-Monday")
        return start, end

    @staticmethod
    def _binding_key(binding: dict[str, str]) -> tuple[str, str, str]:
        return (
            binding["parent_event_id"],
            binding["parent_manifest_digest"],
            binding["catalogue_digest"],
        )

    def _parent_bindings(
        self, bindings: tuple[dict[str, str], ...]
    ) -> tuple[dict[str, str], ...]:
        if len(bindings) < 2:
            raise HistoricalWeeklyActivityError("historical weekly requires multiple parents")
        expected = {
            "parent_event_id", "parent_manifest_digest", "catalogue_digest", "source_lane"
        }
        seen: set[tuple[str, str, str]] = set()
        result: list[dict[str, str]] = []
        for binding in bindings:
            if (
                set(binding) != expected
                or binding["source_lane"] not in SOURCE_LANES
                or not binding["parent_event_id"]
                or len(binding["parent_manifest_digest"]) != 64
                or len(binding["catalogue_digest"]) != 64
            ):
                raise HistoricalWeeklyActivityError("historical weekly parent binding is invalid")
            key = self._binding_key(binding)
            if key in seen:
                raise HistoricalWeeklyActivityError("historical weekly parent binding is duplicated")
            seen.add(key)
            result.append(json.loads(json.dumps(binding)))
        return tuple(result)

    def _selected_sources(
        self,
        sources: tuple[dict[str, str], ...],
        records: dict[tuple[str, str], LogicalRecord],
        bindings: tuple[dict[str, str], ...],
    ) -> tuple[dict[str, str], ...]:
        expected = {
            "parent_event_id", "parent_manifest_digest", "catalogue_digest", "member_ref",
            "logical_record_id", "object_digest", "parser_identity",
        }
        binding_keys = {self._binding_key(binding) for binding in bindings}
        seen: set[tuple[str, ...]] = set()
        result: list[dict[str, str]] = []
        for source in sources:
            record = records.get((source.get("member_ref", ""), source.get("logical_record_id", "")))
            identity = (
                source.get("parent_event_id", ""),
                source.get("parent_manifest_digest", ""),
                source.get("catalogue_digest", ""),
                source.get("member_ref", ""),
                source.get("logical_record_id", ""),
                source.get("object_digest", ""),
                source.get("parser_identity", ""),
            )
            if (
                set(source) != expected
                or identity[:3] not in binding_keys
                or record is None
                or source["object_digest"] != record.object_digest
                or not source["parser_identity"]
                or identity in seen
            ):
                raise HistoricalWeeklyActivityError("historical weekly exact source changed")
            seen.add(identity)
            result.append(json.loads(json.dumps(source)))
        if set(records) != {(item["member_ref"], item["logical_record_id"]) for item in result}:
            raise HistoricalWeeklyActivityError("historical weekly selected record set changed")
        return tuple(result)

    def _observation_parent(
        self, observation: dict[str, Any], binding_keys: set[tuple[str, str, str]]
    ) -> None:
        key = (
            observation["parent_event_id"],
            observation["parent_manifest_digest"],
            observation["catalogue_digest"],
        )
        if key not in binding_keys:
            raise HistoricalWeeklyActivityError("historical weekly observation parent changed")

    @staticmethod
    def _coverage_identity(observation: dict[str, Any]) -> tuple[str, ...]:
        return (
            observation["parent_event_id"],
            observation["parent_manifest_digest"],
            observation["catalogue_digest"],
            observation["member_ref"],
            observation["logical_record_id"],
            observation["object_digest"],
            observation["parser_version"],
        )

    @staticmethod
    def _digest(record: dict[str, Any], field: str) -> None:
        material = {key: value for key, value in record.items() if key != field}
        if record.get(field) != canonical_sha256(material):
            raise HistoricalWeeklyActivityError(f"historical weekly {field} changed")

    @staticmethod
    def _presentation(
        record: dict[str, Any], digest_field: str, citations: set[str]
    ) -> dict[str, Any]:
        expected = {"title", "markdown", "citation_refs", digest_field}
        if (
            set(record) != expected
            or not record["title"]
            or not record["markdown"].startswith("# ")
            or set(record["citation_refs"]) - citations
        ):
            raise HistoricalWeeklyActivityError("historical weekly presentation is invalid")
        material = {key: value for key, value in record.items() if key != digest_field}
        if record[digest_field] != canonical_sha256(material):
            raise HistoricalWeeklyActivityError("historical weekly presentation digest changed")
        return json.loads(json.dumps(record))

    @staticmethod
    def _receipt(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        expected = {
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
        }
        if not isinstance(receipt, dict) or any(
            receipt.get(key) != value for key, value in expected.items()
        ):
            raise HistoricalWeeklyActivityError("historical weekly receipt binding is invalid")

    @staticmethod
    def _initialize(root: Path) -> None:
        for relative in (
            "canonical/historical-weekly-activity-manifests",
            "canonical/historical-weekly-activity-packages",
            "canonical/historical-weekly-activity-events",
            "canonical/historical-weekly-activity-rollbacks",
            "staging/historical-weekly-activity",
            "receipts/historical-weekly-activity",
            "evidence/historical-weekly-activity",
            "derived/historical-weekly-activity",
            "workspace/History/Weeks",
        ):
            path = root / relative
            if path.exists():
                if path.is_symlink() or not path.is_dir():
                    raise HistoricalWeeklyActivityError("historical weekly layout is unsafe")
            else:
                path.mkdir(mode=0o700, parents=True)
            if path.stat().st_mode & 0o077:
                raise HistoricalWeeklyActivityError("historical weekly layout is not owner-only")

    def _event(
        self, prepared: PreparedHistoricalWeeklyActivity, receipt_id: str
    ) -> dict[str, Any]:
        manifest = prepared.manifest
        return {
            "schema_version": "1.0",
            "event_id": self.ids.new("event"),
            "publication_type": PURPOSE,
            "week_start": manifest["week_start"],
            "week_end": manifest["week_end"],
            "parent_bindings": manifest["parent_bindings"],
            "parent_set_digest": manifest["parent_set_digest"],
            "catalogue_set_digest": manifest["catalogue_set_digest"],
            "manifest_digest": manifest["manifest_digest"],
            "package_digest": prepared.package["package_digest"],
            "receipt_id": receipt_id,
            "candidate_only": True,
            "recorded_at": timestamp(aware_utc_now()),
        }

    @staticmethod
    def _root_for(bundle_root: Path) -> Path:
        PrivateBundleLayout.validate(bundle_root)
        return bundle_root.resolve(strict=True)

    def _root(self) -> Path:
        return self._root_for(self.root)

    def _matching(self, root: Path, digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "historical-weekly-activity-events"
        if not directory.exists():
            return None
        matches = []
        for path in directory.iterdir():
            if path.is_file() and not path.is_symlink():
                record = self._json(path)
                if record.get("manifest_digest") == digest:
                    matches.append(record)
        if len(matches) > 1:
            raise HistoricalWeeklyActivityError("historical weekly event is duplicated")
        return matches[0] if matches else None

    def _archived(self, receipt_id: str, manifest: dict[str, Any], root: Path) -> None:
        self.authority.verify_archived_historical_weekly_activity_reconstruction(
            receipt_id,
            manifest,
            display_root=root / "evidence" / "historical-weekly-activity",
            receipt_root=root / "receipts" / "historical-weekly-activity",
        )

    @staticmethod
    def _verify_package(root: Path, prepared: PreparedHistoricalWeeklyActivity) -> None:
        path = root / "canonical" / "historical-weekly-activity-packages" / prepared.package[
            "package_digest"
        ]
        if path.is_symlink() or not path.is_file() or path.read_bytes() != canonical_bytes(
            prepared.package
        ):
            raise HistoricalWeeklyActivityError("historical weekly package object is invalid")

    def _rebuild(
        self,
        root: Path,
        event: dict[str, Any],
        prepared: PreparedHistoricalWeeklyActivity,
    ) -> None:
        self._initialize(root)
        package = prepared.package
        derived = {
            "schema_version": "1.0",
            "event_id": event["event_id"],
            "manifest_digest": event["manifest_digest"],
            "package_digest": event["package_digest"],
            "parent_set_digest": event["parent_set_digest"],
            "catalogue_set_digest": event["catalogue_set_digest"],
            "primary_artifact": package["primary_artifact"],
            "support_views": package["support_views"],
            "weekly_wave_digest": package["weekly_wave"]["wave_digest"],
            "cross_wave_reconciliation_digest": package["cross_wave_reconciliation"][
                "reconciliation_digest"
            ],
            "candidate_only": True,
            "no_current_work": True,
        }
        derived["rebuild_digest"] = canonical_sha256(derived)
        path = root / "derived" / "historical-weekly-activity" / f"{event['event_id']}.json"
        self._atomic(path, canonical_bytes(derived))
        self._fts(root, event, package)
        self._workspace(root, event, package)

    @staticmethod
    def _atomic(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        staged = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(material)
            os.chmod(staged, 0o600)
            os.replace(staged, path)
            os.chmod(path, 0o600)
        finally:
            if staged.exists():
                staged.unlink()

    def _fts(
        self, root: Path, event: dict[str, Any], package: dict[str, Any]
    ) -> None:
        target = root / "derived" / "historical-weekly-activity" / f"{event['event_id']}.sqlite3"
        staged = target.with_suffix(".stage")
        if staged.exists():
            staged.unlink()
        database = sqlite3.connect(staged)
        try:
            database.execute("CREATE TABLE views(event_id TEXT, view_name TEXT, body TEXT)")
            database.execute("CREATE VIRTUAL TABLE views_fts USING fts5(view_name, body)")
            entries = {"primary": package["primary_artifact"], **package["support_views"]}
            for name, item in entries.items():
                database.execute(
                    "INSERT INTO views VALUES (?, ?, ?)",
                    (event["event_id"], name, item["markdown"]),
                )
                database.execute(
                    "INSERT INTO views_fts VALUES (?, ?)", (name, item["markdown"])
                )
            database.commit()
        finally:
            database.close()
        os.replace(staged, target)
        os.chmod(target, 0o600)

    @staticmethod
    def _workspace(root: Path, event: dict[str, Any], package: dict[str, Any]) -> None:
        folder = root / "workspace" / "History" / "Weeks" / event["event_id"]
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        pages = {"Weekly Operating Reconstruction.md": package["primary_artifact"]["markdown"]}
        for name in VIEW_NAMES:
            pages[f"{name.replace('_', ' ').title()}.md"] = package["support_views"][name][
                "markdown"
            ]
        for name, body in pages.items():
            path = folder / name
            path.write_text(body, encoding="utf-8")
            os.chmod(path, 0o600)
