"""Hostile-synthetic coverage for the purpose-separated S6-W3 K1 publication sibling."""

from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.knowledge_lineage import KnowledgeLineageError, S6KnowledgeLineageCoordinator
from vault_next.multi_source_admission import (
    KNOWLEDGE_LINEAGE_PROFILE,
    WORK_CONTINUITY_PROFILE,
    MultiSourceAdmissionError,
    MultiSourceAdmissionInput,
    MultiSourceAdmissionPublisher,
    MultiSourceItem,
    build_multi_source_u1_manifest,
)
from vault_next.private_admission import PrivateAdmissionPublisher
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout, PrivateWorkspaceItem
from vault_next.working_artifact import WorkingArtifactCoordinator


class FakeProfileAuthority:
    """A disposable, exact-purpose v2 double.  No real identity or Keychain is involved."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def _authorize(self, manifest: dict, profile) -> dict:
        receipt = {
            "schema_version": "1.0", "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID, "purpose": profile.purpose,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": "2026-09-15T00:00:00Z",
            "expires_at": manifest["expires_at"],
        }
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID,
            "authority_bundle_id": self.harness.ids.new("bundle"), "purpose": profile.purpose,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        signed = {
            "schema_version": "1.0", "receipt_type": profile.purpose, "authority_id": AUTHORITY_ID,
            "authority_bundle_id": display["authority_bundle_id"], "algorithm": "ed25519", "key_id": "a" * 64,
            "receipt": receipt, "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(canonical_bytes(display)),
            "confirmed_at": receipt["issued_at"], "signature_base64": "fixture-signature",
        }
        self.harness.schemas.require(profile.display_schema, display)
        self.harness.schemas.require(profile.signed_schema, signed)
        self.records[receipt["receipt_id"]] = (receipt, canonical_bytes(display), canonical_bytes(signed))
        return receipt

    def _verify(self, receipt_id: str, manifest: dict, profile) -> dict:
        receipt, _display, _signed = self.records[receipt_id]
        if receipt["purpose"] != profile.purpose or receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("hostile fixture receipt substitution")
        return receipt

    def _evidence(self, receipt_id: str, manifest: dict, profile) -> tuple[bytes, bytes]:
        self._verify(receipt_id, manifest, profile)
        _receipt, display, signed = self.records[receipt_id]
        return display, signed

    def _archived(
        self, receipt_id: str, manifest: dict, profile, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("hostile fixture archive substitution")
        return self._verify(receipt_id, manifest, profile)

    def authorize_chat_first_u1_multi_source_save(self, manifest: dict) -> dict:
        return self._authorize(manifest, WORK_CONTINUITY_PROFILE)

    def verify_chat_first_u1_multi_source_save(self, receipt_id: str, manifest: dict) -> dict:
        return self._verify(receipt_id, manifest, WORK_CONTINUITY_PROFILE)

    def read_chat_first_u1_multi_source_save_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        return self._evidence(receipt_id, manifest, WORK_CONTINUITY_PROFILE)

    def verify_archived_chat_first_u1_multi_source_save(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        return self._archived(
            receipt_id, manifest, WORK_CONTINUITY_PROFILE,
            display_root=display_root, receipt_root=receipt_root,
        )

    def authorize_chat_first_u1_multi_source_knowledge_save(self, manifest: dict) -> dict:
        return self._authorize(manifest, KNOWLEDGE_LINEAGE_PROFILE)

    def verify_chat_first_u1_multi_source_knowledge_save(self, receipt_id: str, manifest: dict) -> dict:
        return self._verify(receipt_id, manifest, KNOWLEDGE_LINEAGE_PROFILE)

    def read_chat_first_u1_multi_source_knowledge_save_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        return self._evidence(receipt_id, manifest, KNOWLEDGE_LINEAGE_PROFILE)

    def verify_archived_chat_first_u1_multi_source_knowledge_save(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        return self._archived(
            receipt_id, manifest, KNOWLEDGE_LINEAGE_PROFILE,
            display_root=display_root, receipt_root=receipt_root,
        )


class KnowledgeLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-knowledge-u1-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeProfileAuthority(self.harness)
        self.publisher = MultiSourceAdmissionPublisher(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids,
            clock=lambda: self.harness.current, profile=KNOWLEDGE_LINEAGE_PROFILE,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _items(self, roles: tuple[str, str, str, str]) -> tuple[MultiSourceItem, ...]:
        return tuple(
            MultiSourceItem(
                role=role, source_locator=f"/hostile/{role.lower()}.md",
                safe_label=f"{role.lower()}.md",
                source_bytes=f"# {role}\nInvented hostile {role} evidence.\n".encode(),
                source_version={
                    "source_version_id": self.harness.ids.new("source_version"),
                    "content_sha256": sha256_hex(
                        f"# {role}\nInvented hostile {role} evidence.\n".encode()
                    ),
                    "byte_count": len(f"# {role}\nInvented hostile {role} evidence.\n".encode()),
                    "profile_id": "markdown_text",
                    "provenance_sha256": str(roles.index(role) + 1) * 64,
                },
            ) for role in roles
        )

    def _packet(self, profile=KNOWLEDGE_LINEAGE_PROFILE) -> MultiSourceAdmissionInput:
        items = self._items(profile.roles)
        citation_rows = tuple(
            (f"{item.role}:line:000002-000002", sha256_hex(f"Invented hostile {item.role} evidence.".encode()))
            for item in items
        )
        family = "knowledge" if profile == KNOWLEDGE_LINEAGE_PROFILE else "work"
        view = "articles" if family == "knowledge" else "reported"
        workspace = (
            PrivateWorkspaceItem(
                item_id=f"invented-{family}", version_id=f"{family}-v1", family=family,
                view=view, status="reported", display_alias=f"Invented {family}",
                canonical_object_sha256="0" * 64,
                admission_event_id="event-placeholder", body=f"# {family}\n\nInvented record.",
                citations=(citation_rows[0][0],), candidate_inactive=True,
            ),
        )
        if profile == KNOWLEDGE_LINEAGE_PROFILE:
            candidate = {
                "schema_version": "1.0", "candidate_id": self.harness.ids.new("skill_candidate"),
                "family": "knowledge_lineage", "method_name": "knowledge-lineage",
                "method_version": "0.1.0", "method_source_sha256": sha256_hex(items[0].source_bytes),
                "method_source_markdown": items[0].source_bytes.decode(),
                "portable_core": ["Invented lineage."], "prohibitions": ["no_knowledge_promotion"],
                "lifecycle": "inactive",
            }
        else:
            candidate = {
                "schema_version": "1.0", "candidate_id": self.harness.ids.new("skill_candidate"),
                "family": "work_continuity", "method_name": "state-check", "method_version": "0.1.0",
                "method_source_sha256": sha256_hex(items[0].source_bytes),
                "method_source_markdown": items[0].source_bytes.decode(),
                "portable_core": ["Invented continuity."], "prohibitions": ["no_current_work"], "lifecycle": "inactive",
            }
        relation = {
            "assertion_id": self.harness.ids.new("relationship_ledger"),
            "origin_version_id": items[0].source_version["source_version_id"],
            "target_version_id": workspace[0].version_id,
            "type": "supports", "source_anchor": citation_rows[0][0], "state": "reported",
        }
        artifact = {
            "schema_version": "1.0",
            "artifact_kind": "knowledge_lineage_wave" if family == "knowledge" else "work_continuity_wave",
            "u0_result_sha256": "3" * 64, "citation_text": [list(row) for row in citation_rows],
            "workspace_items": [PrivateAdmissionPublisher._item_record(item) for item in workspace],
        }
        manifest = build_multi_source_u1_manifest(
            ids=self.harness.ids, expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"), source_items=items,
            u0_result_sha256="3" * 64, artifact_sha256=canonical_sha256(artifact),
            candidate_package_sha256=canonical_sha256(candidate),
            relationship_ledger_sha256=canonical_sha256([relation]),
            citations=tuple(row[0] for row in citation_rows),
            schemas=self.harness.schemas, profile=profile,
        )
        return MultiSourceAdmissionInput(
            manifest, items, artifact, candidate, (relation,), citation_rows, workspace
        )

    def test_k1_01_purpose_order_substitution_restart_fts_and_idempotence(self) -> None:
        packet = self._packet()
        receipt = self.authority.authorize_chat_first_u1_multi_source_knowledge_save(packet.manifest)["receipt_id"]
        self.assertEqual(self.publisher.publish(packet, receipt).status, "complete")
        self.assertEqual(self.publisher.verify_restart()["event_count"], 1)
        with sqlite3.connect(self.root / "derived" / "fts5" / "citations.sqlite3") as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM citations").fetchone()[0], 4)
            result = connection.execute(
                "SELECT text FROM citations WHERE anchor = 'K1:line:000002-000002'"
            ).fetchone()[0]
            self.assertIn("Invented hostile K1 evidence.", result)
        self.assertTrue(list((self.root / "workspace" / "Knowledge").rglob("*.md")))
        self.assertEqual(self.publisher.publish(packet, receipt).status, "already_admitted")
        with self.assertRaises(MultiSourceAdmissionError):
            self.publisher.publish(
                MultiSourceAdmissionInput(
                    **{**packet.__dict__, "source_items": packet.source_items[::-1]}
                ),
                receipt,
            )
        with self.assertRaises(MultiSourceAdmissionError):
            substituted = self.authority.authorize_chat_first_u1_multi_source_save(
                self._packet(WORK_CONTINUITY_PROFILE).manifest
            )["receipt_id"]
            self.publisher.publish(packet, substituted)

    def test_k1_02_union_rebuild_and_disposable_mirror_rollback(self) -> None:
        work_packet = self._packet(WORK_CONTINUITY_PROFILE)
        work = MultiSourceAdmissionPublisher(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        work_receipt = self.authority.authorize_chat_first_u1_multi_source_save(
            work_packet.manifest
        )["receipt_id"]
        work.publish(work_packet, work_receipt)
        packet = self._packet()
        receipt = self.authority.authorize_chat_first_u1_multi_source_knowledge_save(packet.manifest)["receipt_id"]
        self.publisher.publish(packet, receipt)
        self.publisher.verify_restart()
        self.assertTrue(list((self.root / "workspace" / "Work").rglob("*.md")))
        self.assertTrue(list((self.root / "workspace" / "Knowledge").rglob("*.md")))
        mirror = Path(self.temporary.name) / "mirror"
        shutil.copytree(self.root, mirror)
        for path in (mirror / "workspace").rglob("*.md"):
            path.unlink()
        (mirror / "derived" / "fts5" / "citations.sqlite3").unlink()
        mirror_publisher = MultiSourceAdmissionPublisher(
            mirror, self.harness.schemas, self.authority, id_factory=self.harness.ids,
            clock=lambda: self.harness.current, profile=KNOWLEDGE_LINEAGE_PROFILE,
        )
        mirror_publisher.verify_restart()
        self.assertTrue(list((mirror / "workspace" / "Knowledge").rglob("*.md")))
        self.assertTrue(list((self.root / "workspace" / "Knowledge").rglob("*.md")))

    def test_k1_03_coordinator_rejects_wrong_order_and_out_of_scope_citation(self) -> None:
        coordinator = S6KnowledgeLineageCoordinator(
            self.harness.schemas, id_factory=self.harness.ids
        )
        items = self._items(("K1", "K2", "K3", "K4"))
        def assertion(anchor: str) -> dict:
            return {
                "claim_class": "reported", "statement": "Invented claim.",
                "citations": [anchor], "owner": None, "due": None,
            }
        result = {section: [assertion("K1:line:000001-000001")] for section in (
            "executive_spine", "version_timeline", "knowledge_lineage",
            "deep_dive_navigation", "omissions",
        )}
        result["deep_dive_navigation"][0]["claim_class"] = "proposed"
        result["omissions"][0]["claim_class"] = "unknown"
        wave = coordinator.prepare_u0(
            source_items=items, hosted_result=result,
            portable_core=("Keep chronology explicit.",),
        )
        self.assertEqual(wave.candidate_package["lifecycle"], "inactive")
        with self.assertRaises(KnowledgeLineageError):
            coordinator.prepare_u0(
                source_items=items[::-1], hosted_result=result,
                portable_core=("Keep chronology explicit.",),
            )
        result["executive_spine"][0]["citations"] = ["outside:line:000001-000001"]
        with self.assertRaises(KnowledgeLineageError):
            coordinator.prepare_u0(
                source_items=items, hosted_result=result,
                portable_core=("Keep chronology explicit.",),
            )

    def test_k1_04_coordinator_builds_timeline_workspace_and_publishes(self) -> None:
        coordinator = S6KnowledgeLineageCoordinator(
            self.harness.schemas, id_factory=self.harness.ids
        )
        items = self._items(("K1", "K2", "K3", "K4"))
        def assertion(section: str) -> dict:
            claim_class = "proposed" if section == "deep_dive_navigation" else "reported"
            if section == "omissions":
                claim_class = "unknown"
            return {
                "claim_class": claim_class, "statement": f"Invented {section} claim.",
                "citations": ["K1:line:000002-000002"], "owner": None, "due": None,
            }
        wave = coordinator.prepare_u0(
            source_items=items,
            hosted_result={section: [assertion(section)] for section in (
                "executive_spine", "version_timeline", "knowledge_lineage",
                "deep_dive_navigation", "omissions",
            )},
            portable_core=("Keep lineage explicit.",),
        )
        working_root = Path(self.temporary.name) / "working"
        working_root.mkdir(mode=0o700)
        work = WorkingArtifactCoordinator(
            working_root, self.harness.schemas, citation_catalog=wave.citation_catalog
        )
        views = tuple(
            work.create(
                artifact_kind=kind, display_alias=f"Invented {kind}",
                markdown=f"# {kind}\\n\\nInvented review artifact.",
                citations=("K1:line:000002-000002",), provenance=wave.provenance,
                idempotency_key=f"knowledge-{kind}",
            ) for kind in ("knowledge", "timeline", "deep_dive")
        )
        packet = coordinator.build_packet(
            wave=wave, source_items=items,
            selections=tuple(
                work.select_for_u1(view.artifact_id, view.revision_id, target_state="review_copy")
                for view in views
            ),
            coordinator=work, bundle_id=self.harness.ids.new("private_bundle"),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_chat_first_u1_multi_source_knowledge_save(
            packet.manifest
        )["receipt_id"]
        self.assertEqual(self.publisher.publish(packet, receipt).status, "complete")
        self.assertTrue(list((self.root / "workspace" / "Knowledge").rglob("*.md")))


if __name__ == "__main__":
    unittest.main()
