"""Hostile-synthetic tests for append-only S6-W2 citation recovery."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.citation_recovery import CitationRecoveryCoordinator, CitationRecoveryError, PURPOSE
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeRecoveryAuthority:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_chat_first_u1_citation_recovery(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0", "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE, "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"], "manifest_digest": manifest["manifest_digest"],
            "issued_at": "2026-09-14T00:00:00Z", "expires_at": manifest["expires_at"],
        }
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID,
            "authority_bundle_id": self.harness.ids.new("bundle"), "purpose": PURPOSE,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        signed = {
            "schema_version": "1.0", "receipt_type": PURPOSE, "authority_id": AUTHORITY_ID,
            "authority_bundle_id": display["authority_bundle_id"], "algorithm": "ed25519", "key_id": "f" * 64,
            "receipt": receipt, "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(canonical_bytes(display)), "confirmed_at": receipt["issued_at"],
            "signature_base64": "fixture-signature",
        }
        self.harness.schemas.require("chat-first-u1-citation-recovery-display", display)
        self.harness.schemas.require("chat-first-u1-citation-recovery-signed-receipt", signed)
        self.records[receipt["receipt_id"]] = receipt, canonical_bytes(display), canonical_bytes(signed)
        return receipt

    def verify_chat_first_u1_citation_recovery(self, receipt_id: str, manifest: dict) -> dict:
        receipt, _display, _signed = self.records[receipt_id]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("fixture manifest mismatch")
        return receipt

    def read_chat_first_u1_citation_recovery_evidence(self, receipt_id: str, manifest: dict) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_citation_recovery(receipt_id, manifest)
        _receipt, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_chat_first_u1_citation_recovery(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("fixture archived evidence mismatch")
        return self.verify_chat_first_u1_citation_recovery(receipt_id, manifest)


class CitationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-recovery-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeRecoveryAuthority(self.harness)
        self.coordinator = CitationRecoveryCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )
        self.event_id, self.artifact_sha = self._parent()

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _parent(self) -> tuple[str, str]:
        source_items = []
        for role in ("M1", "W1", "W2", "W3"):
            body = (
                f"# {role}\n\nInvented hostile {role} evidence one.\n\n"
                f"Invented hostile {role} evidence two.\n"
            ).encode()
            digest = sha256_hex(body)
            (self.root / "canonical" / "source-objects" / digest).write_bytes(body)
            source_items.append({
                "role": role, "source_locator": f"/synthetic/{role}.md", "safe_label": f"{role}.md",
                "profile_id": "markdown_text", "source_sha256": digest, "source_size": len(body),
                "source_version_id": self.harness.ids.new("source_version"),
                "provenance_sha256": role.lower() * 32,
            })
        catalog = {}
        for item in source_items:
            role = item["role"]
            catalog[f"{role}:line:000003-000003"] = sha256_hex(f"Invented hostile {role} evidence one.".encode())
        result = {
            "executive_spine": [self._claim("spine", ["M1:line:000003-000003"])],
            "reconciliation": [self._claim("continuity", ["W1:line:000003-000003"])],
            "decision_dependency_ledger": [self._claim("ledger", ["W2:line:000003-000003"])],
            # W3 is intentionally absent from parent catalogue: supplement may prove it.
            "next_evidence": [self._claim("next evidence", ["W3:line:000003-000003"])],
            "omissions": [self._claim("omission", ["M1:line:000003-000003"])],
            "result_sha256": "0" * 64,
        }
        material = {key: value for key, value in result.items() if key != "result_sha256"}
        result["result_sha256"] = canonical_sha256(material)
        artifact = {
            "schema_version": "1.0", "artifact_kind": "work_continuity_wave", "wave_id": "S6-W2-C1",
            "u0_result_sha256": result["result_sha256"], "result": result,
            "citation_text": [[key, value] for key, value in catalog.items()], "workspace_items": [],
        }
        artifact_sha = canonical_sha256(artifact)
        (self.root / "canonical" / "artifact-objects" / artifact_sha).write_bytes(canonical_bytes(artifact))
        event_id = self.harness.ids.new("event")
        event = {
            "schema_version": "1.0", "publication_type": "chat_first_u1_multi_source_save", "event_id": event_id,
            "admission_id": self.harness.ids.new("private_admission"), "manifest_digest": "a" * 64,
            "receipt_id": self.harness.ids.new("receipt"), "source_items": source_items,
            "artifact_object_sha256": artifact_sha, "candidate_package_object_sha256": "b" * 64,
            "relationship_ledger_object_sha256": "c" * 64, "recorded_at": "2026-09-14T00:00:00Z",
        }
        (self.root / "canonical" / "events" / f"{event_id}.json").write_bytes(canonical_bytes(event))
        return event_id, artifact_sha

    @staticmethod
    def _claim(statement: str, citations: list[str]) -> dict:
        return {"claim_class": "reported", "statement": statement, "citations": citations, "owner": None, "due": None}

    def test_append_only_recovery_rebuilds_evidence_text_and_restarts(self) -> None:
        audit = self.coordinator.audit(
            parent_event_id=self.event_id, parent_artifact_sha256=self.artifact_sha
        )
        self.assertEqual(audit.supplement["claim_bindings"][3]["disposition"], "recovered")
        manifest = self.coordinator.build_manifest(
            audit, bundle_id=self.harness.ids.new("private_bundle"), expires_at=datetime.now(UTC) + timedelta(minutes=5)
        )
        receipt = self.coordinator.authorize(manifest)
        result = self.coordinator.publish(audit, manifest, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")
        database = self.root / "derived" / "fts5" / f"recovery-{result.recovery_event_id}.sqlite3"
        rows = __import__("sqlite3").connect(database).execute("SELECT anchor, text FROM citations").fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(
            len(text) != 64
            and text == audit.evidence_text[anchor]
            and sha256_hex(text.encode()) == next(
                binding["evidence_sha256"]
                for claim in audit.supplement["claim_bindings"]
                for binding in claim["bindings"]
                if binding["anchor"] == anchor
            )
            for anchor, text in rows
        ))
        self.assertEqual(
            self.coordinator.verify_restart(manifest, receipt_id=receipt["receipt_id"]).status,
            "complete",
        )
        self.assertEqual(
            self.coordinator.publish(audit, manifest, receipt_id=receipt["receipt_id"]).status,
            "already_recovered",
        )

    def test_parent_or_source_substitution_fails_closed(self) -> None:
        with self.assertRaises(CitationRecoveryError):
            self.coordinator.audit(parent_event_id=self.event_id, parent_artifact_sha256="0" * 64)
        event = self.root / "canonical" / "events" / f"{self.event_id}.json"
        record = __import__("json").loads(event.read_text())
        record["source_items"][0]["role"] = "W1"
        event.write_bytes(canonical_bytes(record))
        with self.assertRaises(CitationRecoveryError):
            self.coordinator.audit(parent_event_id=self.event_id, parent_artifact_sha256=self.artifact_sha)
