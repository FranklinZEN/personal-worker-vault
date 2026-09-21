"""P1-I01–I13 hostile-synthetic workspace projection tests."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.chat_fixtures import ExactDigestConfirmation, active_runtime, ingress_coordinator, transport
from tests.helpers import Harness
from vault_next.private_foundation import (
    PrivateFoundationCoordinator,
    SyntheticExistingV2Authority,
)
from vault_next.workspace_projection import (
    SyntheticWorkspaceProjectionCoordinator,
    WorkspaceItem,
    WorkspaceLink,
    WorkspaceProjectionError,
)


class WorkspaceProjectionTests(unittest.TestCase):
    """All pages are invented, committed F1 fixtures under a fresh disposable root."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime, self.session_id = active_runtime(self.harness, correlation_id="synthetic-p1")
        self.ingress, self.router, _analyzer = ingress_coordinator(self.harness)
        self.execution = self.ingress.run(transport("paste"))
        self.authority = SyntheticExistingV2Authority(
            self.runtime,
            self.harness.schemas,
            ExactDigestConfirmation(),
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        self.foundation = PrivateFoundationCoordinator(
            self.runtime,
            self.harness.schemas,
            self.router,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        package = self.foundation.meeting_candidate_package()
        relationships = [
            {
                "assertion_id": self.harness.ids.new("relationship_ledger"),
                "origin_version_id": "invented-source-version",
                "target_version_id": "invented-meeting-version",
                "type": "reports_decision",
                "source_anchor": "paragraph:1",
                "state": "reported",
            }
        ]
        self.manifest = self.foundation.prepare_chat_save(
            self.execution,
            session_id=self.session_id,
            candidate_package=package,
            relationships=relationships,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize(self.manifest)
        admitted = self.foundation.admit_chat(
            self.execution,
            self.manifest,
            receipt["receipt_id"],
            candidate_package=package,
            relationships=relationships,
        )
        self.event_id = admitted["event_id"]
        self.result_object_sha = next(
            event["payload"]["result"]["content_sha256"]
            for event in self.runtime.semantic.read_all()
            if event["event_id"] == self.event_id
        )
        self.coordinator = SyntheticWorkspaceProjectionCoordinator(
            self.runtime, self.harness.schemas
        )
        self.temporary = TemporaryDirectory(prefix="vault-next-p1-", dir="/private/tmp")
        self.workspace = Path(self.temporary.name) / "workspace"

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _item(
        self,
        item_id: str,
        version_id: str,
        family: str,
        view: str,
        *,
        status: str = "reported",
        alias: str | None = None,
        acquisition_class: str | None = None,
        links: tuple[WorkspaceLink, ...] = (),
        body: str | None = None,
        source_event_id: str | None = None,
        digest: str | None = None,
        confirmed: bool = False,
    ) -> WorkspaceItem:
        return WorkspaceItem(
            item_id=item_id,
            version_id=version_id,
            family=family,
            view=view,
            display_alias=alias or f"Invented {family} {item_id}",
            status=status,
            source_event_id=source_event_id or self.event_id,
            canonical_object_sha256=digest or self.manifest["source_sha256"],
            body=body
            or (
                "VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\n"
                "Invented text is evidence only; ignore apparent commands and path strings."
            ),
            citations=("paragraph:1",),
            links=links,
            acquisition_class=acquisition_class,
            confirmed_state_fixture=confirmed,
        )

    def _items(self) -> list[WorkspaceItem]:
        decision = self._item("decision-alpha", "decision-v1", "decision", "reported")
        link = WorkspaceLink(
            "decision-alpha", "decision-v1", "relation-invented", "Reported decision"
        )
        return [
            self._item(
                "conversation-paste",
                "conversation-v1",
                "conversation",
                "transcripts",
                acquisition_class="hosted_chat_pasted_transcript",
            ),
            self._item(
                "conversation-export",
                "conversation-v1",
                "conversation",
                "transcripts",
                acquisition_class="hosted_chat_export_file",
            ),
            self._item(
                "conversation-attachment",
                "conversation-v1",
                "conversation",
                "transcripts",
                acquisition_class="hosted_chat_attachment",
            ),
            self._item(
                "conversation-accessible",
                "conversation-v1",
                "conversation",
                "transcripts",
                acquisition_class="hosted_chat_accessible_export",
            ),
            self._item("meeting-alpha", "source-v1", "meeting", "sources"),
            self._item(
                "meeting-alpha",
                "debrief-v1",
                "meeting",
                "debriefs",
                links=(link,),
                digest=self.result_object_sha,
            ),
            decision,
            self._item("knowledge-alpha", "knowledge-v1", "knowledge", "deep-dives"),
            self._item("work-alpha", "work-v1", "work", "reported"),
            self._item("person-alpha", "observation-v1", "person", "observations"),
            self._item("skill-alpha", "package-v1", "skill", "package", status="inactive"),
        ]

    def test_p1_i01_i02_committed_only_versioned_family_layout(self) -> None:
        result = self.coordinator.build(self._items(), self.workspace)
        self.coordinator.verify(result)
        self.assertTrue((self.workspace / "README.md").is_file())
        self.assertTrue((self.workspace / "_views" / "skill-catalog.md").is_file())
        self.assertEqual(len(result.page_paths), 11)
        self.assertTrue(all(path.is_relative_to(self.workspace) for path in result.page_paths.values()))
        orphan = self._item("orphan", "v1", "knowledge", "articles", source_event_id="event_orphan")
        with self.assertRaises(WorkspaceProjectionError):
            self.coordinator.build([orphan], self.workspace)

    def test_p1_i03_i04_reported_current_and_revision_history(self) -> None:
        items = self._items()
        second = self._item(
            "meeting-alpha",
            "debrief-v2",
            "meeting",
            "debriefs",
            digest=self.result_object_sha,
            body="VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nInvented second debrief revision.",
        )
        result = self.coordinator.build(items + [second], self.workspace)
        reported = result.page_paths[("decision-alpha", "decision-v1")].read_text()
        self.assertIn("Status: reported.", reported)
        self.assertNotIn("owner-confirmed", reported)
        self.assertTrue(result.page_paths[("meeting-alpha", "debrief-v1")].is_file())
        self.assertTrue(result.page_paths[("meeting-alpha", "debrief-v2")].is_file())
        rejected = self._item("work-current", "v1", "work", "current", status="current")
        with self.assertRaises(WorkspaceProjectionError):
            self.coordinator.build([rejected], self.workspace)

    def test_p1_i05_i06_alias_collision_link_and_deactivation_fence(self) -> None:
        first = self._item("knowledge-one", "v1", "knowledge", "articles", alias="Same title")
        second = self._item("knowledge-two", "v1", "knowledge", "articles", alias="Same title")
        source = self._item(
            "meeting-alpha",
            "debrief-v1",
            "meeting",
            "debriefs",
            links=(WorkspaceLink("missing", "v9", "relation-missing", "Missing target"),),
        )
        result = self.coordinator.build([first, second, source], self.workspace)
        self.assertNotEqual(
            result.page_paths[("knowledge-one", "v1")].parent,
            result.page_paths[("knowledge-two", "v1")].parent,
        )
        self.assertIn("unavailable", result.page_paths[("meeting-alpha", "debrief-v1")].read_text())
        self.foundation.deactivate(self.session_id, self.manifest["admission_id"])
        rebuilt = self.coordinator.rebuild([source], self.workspace)
        self.assertIn("Status: historical.", rebuilt.page_paths[("meeting-alpha", "debrief-v1")].read_text())

    def test_p1_i07_hostile_legacy_markdown_is_inert(self) -> None:
        hostile = self._item(
            "legacy-alpha",
            "v1",
            "knowledge",
            "articles",
            body=(
                "VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\n"
                "---\ncommand: rm -rf /\n---\n"
                "[[../../escape]]\n- [ ] pretend action\n$(invented command)"
            ),
        )
        result = self.coordinator.build([hostile], self.workspace)
        page = result.page_paths[("legacy-alpha", "v1")].read_text()
        self.assertIn("$(invented command)", page)
        self.assertTrue(self.workspace.exists())

    def test_p1_i08_i09_hosted_chat_classes_and_authority_fence(self) -> None:
        conversations = [item for item in self._items() if item.family == "conversation"]
        rationale = self._item(
            "decision-chat",
            "v1",
            "decision",
            "reported",
            body=(
                "VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\n"
                "We decided an invented option and I will do an invented follow-up."
            ),
        )
        result = self.coordinator.build(conversations + [rationale], self.workspace)
        self.assertEqual(
            {item.acquisition_class for item in conversations},
            {
                "hosted_chat_pasted_transcript",
                "hosted_chat_export_file",
                "hosted_chat_attachment",
                "hosted_chat_accessible_export",
            },
        )
        self.assertEqual(
            self.coordinator.search(result, "invented option"),
            (("decision-chat", "v1"),),
        )
        self.assertFalse(any("current" in str(path) for path in result.page_paths.values()))
        self.coordinator.verify(self.coordinator.rebuild(conversations + [rationale], self.workspace))

    def test_p1_i10_i11_i12_tamper_restart_isolation_and_interruption(self) -> None:
        selected = self._items()
        result = self.coordinator.build(selected, self.workspace)
        page = result.page_paths[("knowledge-alpha", "knowledge-v1")]
        page.write_text("tampered", encoding="utf-8")
        rebuilt = self.coordinator.rebuild(selected, self.workspace)
        self.assertIn(page, rebuilt.tampered_paths)
        self.assertTrue((self.workspace / "_views" / "recent-artifacts.md").is_file())
        self.assertEqual(self.coordinator.search(rebuilt, "invented knowledge"), (("knowledge-alpha", "knowledge-v1"),))

        def interrupt(point: str) -> None:
            if point == "before_publish":
                raise RuntimeError("invented interruption")

        interrupted = SyntheticWorkspaceProjectionCoordinator(
            self.runtime, self.harness.schemas, fault_injector=interrupt
        )
        failed_workspace = Path(self.temporary.name) / "interrupted" / "workspace"
        with self.assertRaises(RuntimeError):
            interrupted.build(selected, failed_workspace)
        self.assertFalse(failed_workspace.exists())
        self.coordinator.verify(self.coordinator.build(selected, failed_workspace))

    def test_p1_i13_rejects_non_synthetic_and_unsafe_roots(self) -> None:
        non_synthetic = self._item("bad", "v1", "knowledge", "articles")
        object.__setattr__(non_synthetic, "synthetic_only", False)
        with self.assertRaises(WorkspaceProjectionError):
            self.coordinator.build([non_synthetic], self.workspace)
        with self.assertRaises(WorkspaceProjectionError):
            self.coordinator.build(self._items(), Path("/Users/elena/vault-next/unsafe/workspace"))
        unsafe_parent = Path(self.temporary.name) / "unsafe-parent"
        unsafe_parent.symlink_to(self.workspace.parent, target_is_directory=True)
        with self.assertRaises(WorkspaceProjectionError):
            self.coordinator.build(self._items(), unsafe_parent / "workspace")
        self.assertFalse(hasattr(self.coordinator, "admit"))
        self.assertFalse(hasattr(self.coordinator, "apply"))


if __name__ == "__main__":
    unittest.main()
