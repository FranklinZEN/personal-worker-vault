"""Append-only repair of a saved multi-source wave's broken derived citation rows.

This coordinator deliberately accepts no filesystem locator for a legacy source.  It reads only the
parent event and the four source-object digests named by that event, recreates bounded Markdown
anchors, and can append recovery lineage after a separate purpose-specific U1 receipt verifies.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.content_profiles import ContentProfileRouter
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-citation-recovery/1.0.0"
PURPOSE = "chat_first_u1_citation_recovery"
ROLES = ("M1", "W1", "W2", "W3")
_SECTIONS = (
    "executive_spine", "reconciliation", "decision_dependency_ledger", "next_evidence", "omissions",
)


class CitationRecoveryError(RuntimeError):
    """The fixed recovery lineage is missing, substituted, or not safely publishable."""


class ExistingV2CitationRecoveryAuthority(Protocol):
    def authorize_chat_first_u1_citation_recovery(self, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def verify_chat_first_u1_citation_recovery(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def read_chat_first_u1_citation_recovery_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...
    def verify_archived_chat_first_u1_citation_recovery(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CitationRecoveryAudit:
    parent_event: dict[str, Any]
    parent_artifact: dict[str, Any]
    source_items: tuple[dict[str, str], ...]
    audit: dict[str, Any]
    supplement: dict[str, Any]
    evidence_text: dict[str, str]


@dataclass(frozen=True)
class CitationRecoveryResult:
    status: str
    recovery_event_id: str
    receipt_id: str


class CitationRecoveryCoordinator:
    """Build and publish only an append-only evidence supplement for one selected parent event."""

    def __init__(
        self, bundle_root: Path, schemas: SchemaRegistry, authority: ExistingV2CitationRecoveryAuthority,
        *, id_factory: ULIDFactory = DEFAULT_FACTORY,
    ) -> None:
        self.root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.ids = id_factory

    def audit(self, *, parent_event_id: str, parent_artifact_sha256: str) -> CitationRecoveryAudit:
        """Read exactly the selected event/artifact and source-object members; perform no writes."""

        root = self._root()
        event = self._json(root / "canonical" / "events" / f"{parent_event_id}.json")
        if (
            event.get("event_id") != parent_event_id
            or event.get("publication_type") != "chat_first_u1_multi_source_save"
            or event.get("artifact_object_sha256") != parent_artifact_sha256
        ):
            raise CitationRecoveryError("citation recovery parent event binding is invalid")
        raw_items = event.get("source_items")
        if not isinstance(raw_items, list) or tuple(
            item.get("role") for item in raw_items if isinstance(item, dict)
        ) != ROLES:
            raise CitationRecoveryError("citation recovery source packet is invalid")
        source_items = tuple(self._source_item(item) for item in raw_items)
        artifact_path = root / "canonical" / "artifact-objects" / parent_artifact_sha256
        artifact_bytes = self._bytes(artifact_path, parent_artifact_sha256)
        artifact = self._decode(artifact_bytes)
        if (
            artifact.get("artifact_kind") != "work_continuity_wave"
            or artifact.get("wave_id") != "S6-W2-C1"
        ):
            raise CitationRecoveryError("citation recovery parent artifact is outside S6-W2")
        catalog = self._catalog(artifact)
        evidence = self._extract(root, source_items)
        claims = self._claims(artifact)
        bindings: list[dict[str, Any]] = []
        recovered = 0
        withheld = 0
        for ordinal, claim in enumerate(claims, start=1):
            statement, anchors, section = claim
            claim_bindings: list[dict[str, str]] = []
            valid = True
            for anchor in anchors:
                item = evidence.get(anchor)
                if item is None:
                    valid = False
                    continue
                digest, _text, source = item
                existing = catalog.get(anchor)
                # Parent catalogue may omit an anchor, but a different digest is a substitution.
                if existing is not None and existing != digest:
                    valid = False
                    continue
                claim_bindings.append({
                    "anchor": anchor, "evidence_sha256": digest, "role": source["role"],
                    "source_sha256": source["source_sha256"], "source_version_id": source["source_version_id"],
                })
            disposition = (
                "recovered" if valid and len(claim_bindings) == len(anchors) else "withheld"
            )
            if disposition == "recovered":
                recovered += 1
            else:
                withheld += 1
            bindings.append({
                "ordinal": ordinal, "section": section, "claim_sha256": sha256_hex(statement.encode()),
                "disposition": disposition, "bindings": claim_bindings,
            })
        if not recovered:
            raise CitationRecoveryError("citation recovery has no deterministic claim to recover")
        audit_material = {
            "schema_version": "1.0", "record_type": "citation_recovery_audit/1.0",
            "parent_event_id": parent_event_id, "parent_artifact_sha256": parent_artifact_sha256,
            "source_items": list(source_items), "parent_catalog_anchor_count": len(catalog),
            "extracted_anchor_count": len(evidence), "claim_count": len(claims),
            "parent_catalogue_missing_anchor_count": sum(1 for anchor in evidence if anchor not in catalog),
            "disposition": "append_only_supplement_required",
        }
        audit = {**audit_material, "audit_sha256": canonical_sha256(audit_material)}
        supplement_material = {
            "schema_version": "1.0", "record_type": "citation_recovery_supplement/1.0",
            "parent_event_id": parent_event_id, "parent_artifact_sha256": parent_artifact_sha256,
            "audit_sha256": audit["audit_sha256"], "claim_bindings": bindings,
            "no_new_meaning": True,
        }
        supplement = {**supplement_material, "supplement_sha256": canonical_sha256(supplement_material)}
        return CitationRecoveryAudit(
            event, artifact, source_items, audit, supplement,
            {key: value[1] for key, value in evidence.items()},
        )

    def build_manifest(
        self, audit: CitationRecoveryAudit, *, bundle_id: str, expires_at: datetime
    ) -> dict[str, Any]:
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise CitationRecoveryError("citation recovery proposal expiry is invalid")
        bindings = audit.supplement["claim_bindings"]
        recovered = sum(1 for item in bindings if item["disposition"] == "recovered")
        manifest = {
            "schema_version": "1.0", "component": COMPONENT, "purpose": PURPOSE, "authority_id": AUTHORITY_ID,
            "admission_id": self.ids.new("private_admission"), "bundle_id": bundle_id,
            "parent_event_id": audit.parent_event["event_id"],
            "parent_artifact_sha256": audit.parent_event["artifact_object_sha256"],
            "source_items": list(audit.source_items), "audit_sha256": audit.audit["audit_sha256"],
            "supplement_sha256": audit.supplement["supplement_sha256"], "claim_count": len(bindings),
            "recovered_claim_count": recovered, "withheld_claim_count": len(bindings) - recovered,
            "disclosure": "local_private_no_hosted_reasoning", "retention": "R1_immutable_parent_plus_recovery",
            "operations": [
                "stage_citation_recovery", "append_citation_recovery_event",
                "rebuild_recovery_fts5", "build_recovery_projections",
            ],
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self.schemas.require("chat-first-u1-citation-recovery-manifest", manifest)
        return manifest

    def authorize(self, manifest: dict[str, Any]) -> dict[str, Any]:
        self._manifest(manifest)
        receipt = self.authority.authorize_chat_first_u1_citation_recovery(manifest)
        self._receipt(receipt, manifest)
        return receipt

    def render_u0_views(self, audit: CitationRecoveryAudit) -> dict[str, tuple[str, dict[str, Any]]]:
        """Return clean, ephemeral recovery views and compact companion bindings without writes."""

        sections = {
            "continuity": ("executive_spine", "reconciliation", "omissions"),
            "decision-dependency": ("decision_dependency_ledger",),
            "next-evidence": ("next_evidence", "omissions"),
        }
        parent_claims = {
            ordinal: (statement, anchors)
            for ordinal, (statement, anchors, _section) in enumerate(
                self._claims(audit.parent_artifact), start=1
            )
        }
        views: dict[str, tuple[str, dict[str, Any]]] = {}
        for intent, section_names in sections.items():
            recovered = [
                item for section in section_names for item in audit.supplement["claim_bindings"]
                if item["section"] == section and item["disposition"] == "recovered"
            ]
            anchors = tuple(
                dict.fromkeys(
                    binding["anchor"] for item in recovered for binding in item["bindings"]
                )
            )
            numbers = {anchor: index for index, anchor in enumerate(anchors, start=1)}
            lines = [
                f"# {intent.replace('-', ' ').title()}", "",
                "Recovered from immutable saved S6-W2 evidence. Claims remain source-reported.", "",
            ]
            for item in recovered:
                statement, claim_anchors = parent_claims[item["ordinal"]]
                markers = " ".join(f"[E{numbers[anchor]}]" for anchor in claim_anchors)
                lines.append(f"- {statement} {markers}")
            if not recovered:
                lines.append("No claim has complete retained citation bindings for this view.")
            views[intent] = (
                "\n".join(lines) + "\n",
                {
                    "parent_event_id": audit.parent_event["event_id"],
                    "parent_artifact_sha256": audit.parent_event["artifact_object_sha256"],
                    "intent": intent,
                    "citations": [
                        {
                            "ordinal": numbers[anchor], "anchor": anchor,
                            "evidence_sha256": next(
                                binding["evidence_sha256"] for item in recovered
                                for binding in item["bindings"] if binding["anchor"] == anchor
                            ),
                        }
                        for anchor in anchors
                    ],
                    "withheld_claim_count": sum(
                        1 for item in audit.supplement["claim_bindings"]
                        if item["section"] in section_names and item["disposition"] == "withheld"
                    ),
                    "ephemeral": True,
                },
            )
        return views

    def publish(
        self, audit: CitationRecoveryAudit, manifest: dict[str, Any], *, receipt_id: str
    ) -> CitationRecoveryResult:
        """Publish only after the custom U1 receipt verifies; the parent remains immutable."""

        self._manifest(manifest)
        root = self._root()
        existing = self._matching(root, manifest["manifest_digest"])
        if existing is not None:
            if existing.get("receipt_id") != receipt_id:
                raise CitationRecoveryError("citation recovery replay receipt changed")
            self.authority.verify_archived_chat_first_u1_citation_recovery(
                receipt_id, manifest, display_root=root / "evidence" / "u1-citation-recovery",
                receipt_root=root / "receipts" / "chat-first-u1-citation-recovery",
            )
            return CitationRecoveryResult("already_recovered", existing["event_id"], receipt_id)
        receipt = self.authority.verify_chat_first_u1_citation_recovery(receipt_id, manifest)
        self._receipt(receipt, manifest)
        display, signed = self.authority.read_chat_first_u1_citation_recovery_evidence(
            receipt_id, manifest
        )
        stage = self._stage(root, manifest["admission_id"])
        try:
            self._immutable(stage / "audit.json", canonical_bytes(audit.audit))
            self._immutable(stage / "supplement.json", canonical_bytes(audit.supplement))
            self._immutable(stage / "manifest.json", canonical_bytes(manifest))
            self._immutable(stage / "display.json", display)
            self._immutable(stage / "receipt.json", signed)
            event = self._event(manifest, receipt_id)
            self._immutable(stage / "event.json", canonical_bytes(event))
            self._publish_immutable(
                stage / "audit.json", root / "canonical" / "citation-recovery-audits" / audit.audit["audit_sha256"],
                sha256_hex(canonical_bytes(audit.audit)),
            )
            self._publish_immutable(
                stage / "supplement.json",
                root / "canonical" / "citation-recovery-supplements" / audit.supplement["supplement_sha256"],
                sha256_hex(canonical_bytes(audit.supplement)),
            )
            self._publish_immutable(
                stage / "manifest.json",
                root / "canonical" / "citation-recovery-manifests" / manifest["manifest_digest"],
                sha256_hex(canonical_bytes(manifest)),
            )
            self._publish_immutable(
                stage / "display.json", root / "evidence" / "u1-citation-recovery" / f"{receipt_id}.json",
                sha256_hex(display),
            )
            self._publish_immutable(
                stage / "receipt.json", root / "receipts" / "chat-first-u1-citation-recovery" / f"{receipt_id}.json",
                sha256_hex(signed),
            )
            self._publish_immutable(
                stage / "event.json", root / "canonical" / "citation-recovery-events" / f"{event['event_id']}.json",
                sha256_hex(canonical_bytes(event)),
            )
            self._build_fts(root, event, audit)
            self._build_projections(root, event, audit)
            return CitationRecoveryResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                for child in stage.iterdir():
                    child.unlink()
                stage.rmdir()

    def verify_restart(self, manifest: dict[str, Any], *, receipt_id: str) -> CitationRecoveryResult:
        root = self._root()
        event = self._matching(root, manifest["manifest_digest"])
        if event is None:
            raise CitationRecoveryError("citation recovery event is unavailable")
        self.authority.verify_archived_chat_first_u1_citation_recovery(
            receipt_id, manifest, display_root=root / "evidence" / "u1-citation-recovery",
            receipt_root=root / "receipts" / "chat-first-u1-citation-recovery",
        )
        audit = self.audit(
            parent_event_id=manifest["parent_event_id"],
            parent_artifact_sha256=manifest["parent_artifact_sha256"],
        )
        if (
            audit.audit["audit_sha256"] != manifest["audit_sha256"]
            or audit.supplement["supplement_sha256"] != manifest["supplement_sha256"]
        ):
            raise CitationRecoveryError("citation recovery audit lineage changed")
        self._build_fts(root, event, audit)
        self._build_projections(root, event, audit)
        return CitationRecoveryResult("complete", event["event_id"], receipt_id)

    def _extract(
        self, root: Path, items: tuple[dict[str, str], ...]
    ) -> dict[str, tuple[str, str, dict[str, str]]]:
        output: dict[str, tuple[str, str, dict[str, str]]] = {}
        router = ContentProfileRouter(max_anchors=2048)
        for item in items:
            material = self._bytes(
                root / "canonical" / "source-objects" / item["source_sha256"], item["source_sha256"]
            )
            normalized = router.route(
                material, declared_media_type="text/markdown", declared_extension=".md"
            )
            for evidence in normalized.anchors:
                key = f"{item['role']}:{evidence.anchor}"
                if key in output:
                    raise CitationRecoveryError("citation recovery anchor is ambiguous")
                output[key] = (evidence.text_sha256, evidence.text, item)
        return output

    @staticmethod
    def _source_item(raw: object) -> dict[str, str]:
        required = {
            "role", "source_locator", "safe_label", "profile_id", "source_sha256", "source_size",
            "source_version_id", "provenance_sha256",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise CitationRecoveryError("citation recovery source member shape is invalid")
        result = {key: raw[key] for key in ("role", "source_sha256", "source_version_id", "profile_id")}
        if (
            not all(isinstance(value, str) and value for value in result.values())
            or result["profile_id"] != "markdown_text"
        ):
            raise CitationRecoveryError("citation recovery source member is invalid")
        return result

    @staticmethod
    def _catalog(artifact: dict[str, Any]) -> dict[str, str]:
        raw = artifact.get("citation_text")
        if not isinstance(raw, list):
            raise CitationRecoveryError("citation recovery parent catalogue is invalid")
        result: dict[str, str] = {}
        for row in raw:
            if (
                not isinstance(row, list) or len(row) != 2
                or not all(isinstance(value, str) for value in row) or row[0] in result
            ):
                raise CitationRecoveryError("citation recovery parent catalogue row is invalid")
            result[row[0]] = row[1]
        return result

    @staticmethod
    def _claims(artifact: dict[str, Any]) -> tuple[tuple[str, tuple[str, ...], str], ...]:
        result = artifact.get("result")
        if not isinstance(result, dict):
            raise CitationRecoveryError("citation recovery parent result is invalid")
        claims: list[tuple[str, tuple[str, ...], str]] = []
        for section in _SECTIONS:
            values = result.get(section)
            if not isinstance(values, list):
                raise CitationRecoveryError("citation recovery parent result section is invalid")
            for value in values:
                if (
                    not isinstance(value, dict) or not isinstance(value.get("statement"), str)
                    or not isinstance(value.get("citations"), list)
                ):
                    raise CitationRecoveryError("citation recovery claim is invalid")
                anchors = tuple(value["citations"])
                if not anchors or any(not isinstance(anchor, str) for anchor in anchors):
                    raise CitationRecoveryError("citation recovery claim citations are invalid")
                claims.append((value["statement"], anchors, section))
        return tuple(claims)

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        root = self.root.resolve(strict=True)
        if root.is_symlink():
            raise CitationRecoveryError("citation recovery root is unsafe")
        return root

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require("chat-first-u1-citation-recovery-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest.get("manifest_digest") != canonical_sha256(material):
            raise CitationRecoveryError("citation recovery manifest digest changed")
        if (
            manifest.get("purpose") != PURPOSE
            or tuple(item.get("role") for item in manifest["source_items"]) != ROLES
        ):
            raise CitationRecoveryError("citation recovery manifest purpose changed")

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self.schemas.require("chat-first-u1-citation-recovery-receipt", receipt)
        if (
            any(receipt.get(key) != manifest.get(key) for key in ("admission_id", "bundle_id", "manifest_digest"))
            or receipt.get("purpose") != PURPOSE
        ):
            raise CitationRecoveryError("citation recovery receipt binding changed")

    def _stage(self, root: Path, admission_id: str) -> Path:
        parent = root / "staging" / "u1-citation-recovery"
        parent.mkdir(mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
            raise CitationRecoveryError("citation recovery staging root is unsafe")
        return Path(tempfile.mkdtemp(prefix=f".recovery-{admission_id}-", dir=parent))

    def _event(self, manifest: dict[str, Any], receipt_id: str) -> dict[str, Any]:
        return {
            "schema_version": "1.0", "publication_type": PURPOSE, "event_id": self.ids.new("event"),
            "admission_id": manifest["admission_id"], "receipt_id": receipt_id,
            "manifest_digest": manifest["manifest_digest"], "parent_event_id": manifest["parent_event_id"],
            "parent_artifact_sha256": manifest["parent_artifact_sha256"], "audit_sha256": manifest["audit_sha256"],
            "supplement_sha256": manifest["supplement_sha256"], "recorded_at": timestamp(aware_utc_now()),
        }

    @staticmethod
    def _immutable(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise CitationRecoveryError("citation recovery immutable target exists")
        path.write_bytes(material)
        os.chmod(path, 0o600)

    @staticmethod
    def _publish_immutable(staged: Path, target: Path, digest: str) -> None:
        if sha256_hex(staged.read_bytes()) != digest:
            raise CitationRecoveryError("citation recovery staged object digest changed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_hex(target.read_bytes()) != digest:
                raise CitationRecoveryError("citation recovery immutable target conflicts")
            staged.unlink()
            return
        os.replace(staged, target)

    def _matching(self, root: Path, manifest_digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "citation-recovery-events"
        if not directory.exists():
            return None
        matches = [
            self._json(path)
            for path in directory.iterdir()
            if path.is_file() and not path.is_symlink()
            and self._json(path).get("manifest_digest") == manifest_digest
        ]
        if len(matches) > 1:
            raise CitationRecoveryError("citation recovery event is duplicated")
        return matches[0] if matches else None

    def _build_fts(self, root: Path, event: dict[str, Any], audit: CitationRecoveryAudit) -> None:
        database = root / "derived" / "fts5" / f"recovery-{event['event_id']}.sqlite3"
        temporary = database.with_name(f".{database.name}.tmp")
        bindings = audit.supplement["claim_bindings"]
        rows = []
        seen: set[str] = set()
        for claim in bindings:
            if claim["disposition"] != "recovered":
                continue
            for binding in claim["bindings"]:
                anchor = binding["anchor"]
                if anchor in seen:
                    continue
                text = audit.evidence_text[anchor]
                if sha256_hex(text.encode()) != binding["evidence_sha256"]:
                    raise CitationRecoveryError("citation recovery evidence text digest changed")
                seen.add(anchor)
                rows.append((event["event_id"], anchor, text))
        connection = sqlite3.connect(temporary)
        try:
            connection.execute(
                "CREATE VIRTUAL TABLE citations USING fts5(event_id UNINDEXED, anchor UNINDEXED, text)"
            )
            connection.executemany("INSERT INTO citations VALUES (?, ?, ?)", rows)
            connection.commit()
        finally:
            connection.close()
        os.chmod(temporary, 0o600)
        os.replace(temporary, database)

    def _build_projections(self, root: Path, event: dict[str, Any], audit: CitationRecoveryAudit) -> None:
        for intent, (body, companion_data) in self.render_u0_views(audit).items():
            target = root / "workspace" / "_views" / "recovery" / event["event_id"] / f"{intent}.md"
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
            os.chmod(target, 0o600)
            sidecar = target.with_suffix(".citations.json")
            companion = canonical_bytes({
                **companion_data, "event_id": event["event_id"],
                "recovery_event_id": event["event_id"],
            })
            if sidecar.exists():
                if sidecar.is_symlink() or sidecar.read_bytes() != companion:
                    raise CitationRecoveryError("citation recovery projection sidecar changed")
            else:
                self._immutable(sidecar, companion)

    @staticmethod
    def _bytes(path: Path, digest: str) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise CitationRecoveryError("citation recovery canonical object is unavailable")
        material = path.read_bytes()
        if sha256_hex(material) != digest:
            raise CitationRecoveryError("citation recovery canonical object digest changed")
        return material

    @staticmethod
    def _decode(material: bytes) -> dict[str, Any]:
        try:
            value = json.loads(material)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CitationRecoveryError("citation recovery canonical JSON is invalid") from exc
        if not isinstance(value, dict) or canonical_bytes(value) != material:
            raise CitationRecoveryError("citation recovery canonical JSON is not canonical")
        return value

    def _json(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise CitationRecoveryError("citation recovery canonical record is unavailable")
        return self._decode(path.read_bytes())
