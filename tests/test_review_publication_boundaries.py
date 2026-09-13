"""Hostile synthetic S1-B review-packet and publication-boundary regressions."""

from __future__ import annotations

import copy
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ValidationError
from vault_next.publication import publication_issues
from vault_next.records import SchemaRegistry
from vault_next.review import (
    ReviewRepository,
    SemanticReviewCoordinator,
    build_review_packet,
)


class _CountingPassReviewer:
    reviewer_id = "synthetic-counting-reviewer"
    reviewer_version = "1.0"

    def __init__(self) -> None:
        self.calls = 0

    def review(self, packet: dict) -> tuple[str, str, list[dict]]:
        self.calls += 1
        return "pass", "invented reviewer saw a complete packet", []


class ReviewPacketBoundaryTests(unittest.TestCase):
    """Exercise bounded exact-content packet construction with invented material only."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.harness.start()
        self.harness.append(
            self.harness.candidate(
                "question.recorded",
                {"question": "Which invented option contains the planted contradiction?"},
                session_id=self.harness.session_id,
            )
        )
        self.recommendation_id = self.harness.ids.new("recommendation")
        self.target = self.harness.append(
            self.harness.candidate(
                "recommendation.issued",
                {
                    "recommendation_id": self.recommendation_id,
                    "revision": 1,
                    "summary": "Use the blue synthetic option despite the recorded green constraint.",
                },
                session_id=self.harness.session_id,
                subject_refs=[self.recommendation_id],
            )
        )
        self.repository = ReviewRepository(self.harness.paths, self.harness.schemas)
        self.coordinator = SemanticReviewCoordinator(self.repository, self.harness.schemas)

    def tearDown(self) -> None:
        self.harness.close()

    def _packet(self, events: list[dict] | None = None, **kwargs: object) -> dict:
        return build_review_packet(
            events or self.harness.semantic.read_all(),
            review_id=self.harness.ids.new("review"),
            session_id=self.harness.session_id,
            target_type="recommendation",
            target_ref=self.recommendation_id,
            schemas=self.harness.schemas,
            **kwargs,
        )

    def test_b_t01_exact_recommendation_payload_is_reviewable_and_bound(self) -> None:
        packet = self._packet()

        target = packet["subject"]["target_content"]
        self.assertTrue(packet["reviewability"]["complete"])
        self.assertEqual(target["status"], "present")
        self.assertEqual(target["representation"], "event_payload")
        self.assertEqual(target["source_event_id"], self.target["event_id"])
        self.assertEqual(target["content"], self.target["payload"])
        self.assertEqual(target["content_sha256"], self.target["integrity"]["payload_sha256"])
        self.assertEqual(target["byte_count"], len(canonical_bytes(target["content"])))

    def test_b_t02_checkpoint_and_context_payloads_are_exact_not_summaries(self) -> None:
        checkpoint_id = self.harness.ids.new("checkpoint")
        checkpoint_payload = {
            "checkpoint_id": checkpoint_id,
            "summary": "The invented contradiction remains open.",
            "state": {"constraint": "green remains mandatory", "defect": "blue was proposed"},
            "open_questions": ["Which fact defeats blue?"],
            "contract_sha256": "a" * 64,
            "source_event_ids": [self.target["event_id"]],
            "source_watermark": self.target["integrity"]["event_sha256"],
        }
        checkpoint = {
            "event_id": self.harness.ids.new("event"),
            "event_type": "checkpoint.recorded",
            "session_id": self.harness.session_id,
            "case_id": self.harness.case_id,
            "sensitivity": "none",
            "payload": checkpoint_payload,
            "integrity": {
                "payload_sha256": canonical_sha256(checkpoint_payload),
                "event_sha256": "b" * 64,
            },
        }
        assumption = {
            "event_id": self.harness.ids.new("event"),
            "event_type": "assumption.recorded",
            "session_id": self.harness.session_id,
            "case_id": self.harness.case_id,
            "sensitivity": "none",
            "payload": {"assumption_id": "assumption_synthetic", "statement": "Green is required."},
            "integrity": {
                "payload_sha256": canonical_sha256(
                    {"assumption_id": "assumption_synthetic", "statement": "Green is required."}
                ),
                "event_sha256": "d" * 64,
            },
        }
        packet = build_review_packet(
            [*self.harness.semantic.read_all(), assumption, checkpoint],
            review_id=self.harness.ids.new("review"),
            session_id=self.harness.session_id,
            target_type="checkpoint",
            target_ref=checkpoint_id,
            schemas=self.harness.schemas,
        )

        self.assertTrue(packet["reviewability"]["complete"])
        self.assertEqual(packet["subject"]["target_content"]["content"], checkpoint_payload)
        context = packet["subject"]["context_records"]
        self.assertEqual(context[-1]["payload"], assumption["payload"])
        self.assertEqual(context[-1]["payload_sha256"], assumption["integrity"]["payload_sha256"])

    def test_b_t03_artifact_text_and_evidence_are_verified_before_packet_inclusion(self) -> None:
        artifact = b"The invented draft asserts blue while the stated constraint requires green."
        evidence = b"Synthetic observation: only green satisfies the test fixture."
        artifact_version_id = self.harness.ids.new("artifact_version")
        artifact_id = self.harness.ids.new("artifact")
        artifact_digest = sha256_hex(artifact)
        evidence_digest = sha256_hex(evidence)
        artifact_payload = {
            "version": {
                "artifact_id": artifact_id,
                "version_id": artifact_version_id,
                "content_sha256": artifact_digest,
                "byte_count": len(artifact),
                "media_type": "text/plain",
            }
        }
        artifact_event = {
            "event_id": self.harness.ids.new("event"),
            "event_type": "artifact.version_created",
            "session_id": self.harness.session_id,
            "case_id": self.harness.case_id,
            "sensitivity": "none",
            "payload": artifact_payload,
            "integrity": {"payload_sha256": canonical_sha256(artifact_payload), "event_sha256": "f" * 64},
        }
        evidence_id = f"evidence_sha256_{evidence_digest}"
        evidence_payload = {
            "metadata": {
                "evidence_id": evidence_id,
                "content_sha256": evidence_digest,
                "byte_count": len(evidence),
                "content_type": "text/plain",
            }
        }
        evidence_event = {
            "event_id": self.harness.ids.new("event"),
            "event_type": "evidence.registered",
            "session_id": self.harness.session_id,
            "case_id": self.harness.case_id,
            "sensitivity": "none",
            "payload": evidence_payload,
            "integrity": {"payload_sha256": canonical_sha256(evidence_payload), "event_sha256": "2" * 64},
        }
        packet = build_review_packet(
            [*self.harness.semantic.read_all(), artifact_event, evidence_event],
            review_id=self.harness.ids.new("review"),
            session_id=self.harness.session_id,
            target_type="artifact_version",
            target_ref=artifact_version_id,
            schemas=self.harness.schemas,
            artifact_loader=lambda version: artifact,
            evidence_loader=lambda metadata: evidence,
        )

        self.assertTrue(packet["reviewability"]["complete"])
        target = packet["subject"]["target_content"]
        self.assertEqual(target["text"], artifact.decode())
        self.assertEqual(target["content_sha256"], artifact_digest)
        self.assertEqual(packet["subject"]["evidence"][0]["text"], evidence.decode())
        self.assertEqual(packet["subject"]["evidence"][0]["content_sha256"], evidence_digest)

    def test_b_t04_tampered_or_unavailable_object_is_an_explicit_nonpass_omission(self) -> None:
        artifact = b"Synthetic target with an intentional integrity failure."
        artifact_version_id = self.harness.ids.new("artifact_version")
        artifact_id = self.harness.ids.new("artifact")
        artifact_payload = {
            "version": {
                "artifact_id": artifact_id,
                "version_id": artifact_version_id,
                "content_sha256": "0" * 64,
                "byte_count": len(artifact),
                "media_type": "text/plain",
            }
        }
        artifact_event = {
            "event_id": self.harness.ids.new("event"),
            "event_type": "artifact.version_created",
            "session_id": self.harness.session_id,
            "case_id": self.harness.case_id,
            "sensitivity": "none",
            "payload": artifact_payload,
            "integrity": {"payload_sha256": canonical_sha256(artifact_payload), "event_sha256": "4" * 64},
        }
        packet = build_review_packet(
            [*self.harness.semantic.read_all(), artifact_event],
            review_id=self.harness.ids.new("review"),
            session_id=self.harness.session_id,
            target_type="artifact_version",
            target_ref=artifact_version_id,
            schemas=self.harness.schemas,
            artifact_loader=lambda version: artifact,
        )

        self.assertFalse(packet["reviewability"]["complete"])
        self.assertEqual(packet["subject"]["target_content"]["status"], "omitted")
        self.assertEqual(packet["reviewability"]["omissions"][0]["category"], "target_content")

    def test_b_t05_repository_loaders_verify_bytes_before_exposing_content(self) -> None:
        artifact = b"Invented artifact bytes."
        artifact_digest = sha256_hex(artifact)
        artifact_path = self.harness.paths.artifact_root / "objects" / "sha256" / artifact_digest[:2]
        artifact_path.mkdir(parents=True)
        artifact_path = artifact_path / artifact_digest
        artifact_path.write_bytes(artifact)
        version = {
            "object_ref": f"sha256/{artifact_digest[:2]}/{artifact_digest}",
            "content_sha256": artifact_digest,
            "byte_count": len(artifact),
        }
        self.assertEqual(self.repository.read_verified_artifact(version), artifact)
        artifact_path.write_bytes(b"tampered invented artifact")
        with self.assertRaises(ValueError):
            self.repository.read_verified_artifact(version)

        evidence = b"Invented evidence bytes."
        evidence_digest = sha256_hex(evidence)
        evidence_path = self.harness.paths.evidence_root / "objects" / "sha256" / evidence_digest[:2]
        evidence_path.mkdir(parents=True)
        evidence_path = evidence_path / evidence_digest
        evidence_path.write_bytes(evidence)
        metadata = {
            "object_ref": f"sha256/{evidence_digest[:2]}/{evidence_digest}",
            "content_sha256": evidence_digest,
            "byte_count": len(evidence),
        }
        self.assertEqual(self.repository.read_verified_evidence(metadata), evidence)
        evidence_path.write_bytes(b"tampered invented evidence")
        with self.assertRaises(ValueError):
            self.repository.read_verified_evidence(metadata)

    def test_b_t06_oversize_invalid_text_and_excess_context_are_never_truncated(self) -> None:
        target = copy.deepcopy(self.target)
        target["payload"]["summary"] = "x" * 20000
        target["integrity"]["payload_sha256"] = canonical_sha256(target["payload"])
        context = []
        for index in range(33):
            context.append(
                {
                    "event_id": self.harness.ids.new("event"),
                    "event_type": "claim.recorded",
                    "session_id": self.harness.session_id,
                    "case_id": self.harness.case_id,
                    "sensitivity": "none",
                    "payload": {"claim_id": f"claim-{index}", "statement": "invented context"},
                    "integrity": {
                        "payload_sha256": canonical_sha256(
                            {"claim_id": f"claim-{index}", "statement": "invented context"}
                        ),
                        "event_sha256": "6" * 64,
                    },
                }
            )
        packet = self._packet([*self.harness.semantic.read_all()[:-1], target, *context])

        self.assertFalse(packet["reviewability"]["complete"])
        self.assertEqual(packet["subject"]["target_content"]["status"], "omitted")
        self.assertLessEqual(len(packet["subject"]["context_records"]), 32)
        categories = {item["category"] for item in packet["reviewability"]["omissions"]}
        self.assertEqual(categories, {"target_content", "context_records"})

    def test_b_t07_invalid_text_and_sensitive_sessions_are_withheld_nonpassing(self) -> None:
        evidence = b"\xff\xfe\x00"
        digest = sha256_hex(evidence)
        evidence_event = {
            "event_id": self.harness.ids.new("event"),
            "event_type": "evidence.registered",
            "session_id": self.harness.session_id,
            "case_id": self.harness.case_id,
            "sensitivity": "none",
            "payload": {
                "metadata": {
                    "evidence_id": f"evidence_sha256_{digest}",
                    "content_sha256": digest,
                    "byte_count": len(evidence),
                    "content_type": "application/octet-stream",
                }
            },
            "integrity": {"payload_sha256": "7" * 64, "event_sha256": "8" * 64},
        }
        packet = self._packet(
            [*self.harness.semantic.read_all(), evidence_event],
            evidence_loader=lambda metadata: evidence,
        )
        self.assertFalse(packet["reviewability"]["complete"])
        self.assertEqual(packet["reviewability"]["omissions"][0]["category"], "evidence")

        sensitive = copy.deepcopy(self.target)
        sensitive["sensitivity"] = "personal"
        packet = self._packet([*self.harness.semantic.read_all()[:-1], sensitive])
        self.assertFalse(packet["reviewability"]["complete"])
        self.assertEqual(packet["subject"]["target_content"]["status"], "withheld")
        self.assertEqual(packet["reviewability"]["omissions"][0]["category"], "sensitivity")

    def test_b_t08_incomplete_or_legacy_packet_never_calls_a_passing_reviewer(self) -> None:
        incomplete = self._packet()
        incomplete["reviewability"] = {
            "complete": False,
            "omissions": [{"category": "evidence", "ref": "synthetic", "reason": "unavailable"}],
        }
        reviewer = _CountingPassReviewer()
        attempt = self.coordinator.run(
            incomplete, canonical_sha256(incomplete), reviewer, attempt=1
        )
        self.assertEqual(reviewer.calls, 0)
        self.assertEqual(attempt.result["status"], "unavailable")

        legacy = self._packet()
        legacy.pop("reviewability")
        legacy["subject"].pop("target_content")
        legacy["subject"].pop("context_records")
        legacy["subject"].pop("evidence")
        second = self.coordinator.run(legacy, canonical_sha256(legacy), reviewer, attempt=2)
        self.assertEqual(reviewer.calls, 0)
        self.assertEqual(second.result["status"], "unavailable")

    def test_b_t09_new_packet_writer_rejects_missing_completeness_contract(self) -> None:
        packet = self._packet()
        packet.pop("reviewability")
        with self.assertRaises(ValidationError):
            self.repository.write_packet(packet)


class PublicationBoundaryTests(unittest.TestCase):
    """Verify Git publication checks with temporary repositories and invented path names."""

    def test_b_t12_repository_excludes_all_runtime_and_future_store_examples(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        self.assertEqual(publication_issues(repository_root), ())

    def test_b_t13_tracked_and_staged_private_runtime_paths_fail_the_check(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory(prefix="vault-next-publication-") as temporary:
            root = Path(temporary)
            shutil.copy(repository_root / ".gitignore", root / ".gitignore")
            self._git(root, "init", "-q")
            private_path = root / "data" / "reports" / "invented-owner-report.bin"
            private_path.parent.mkdir(parents=True)
            private_path.write_bytes(b"invented-private-report")
            self._git(root, "add", "-f", "data/reports/invented-owner-report.bin")

            issues = publication_issues(root)

        messages = "\n".join(issue.message for issue in issues)
        self.assertIn("tracked", messages)
        self.assertIn("staged", messages)

    @staticmethod
    def _git(root: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
