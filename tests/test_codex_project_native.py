"""C3-U01–U03 hostile synthetic checks for the current-project native U0 sibling."""

from __future__ import annotations

import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.chat_fixtures import FixtureMeetingDebriefAnalyzer, minimal_docx, synthetic_text
from tests.helpers import Harness
from vault_next.codex_project_native import (
    CodexProjectNativeU0Coordinator,
    CodexProjectNativeU0Error,
    NativeIngressMaterial,
)
from vault_next.meeting_debrief import MeetingDebriefError


class CodexProjectNativeU0Tests(unittest.TestCase):
    """All material here is invented; this suite never opens a real source or host adapter."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.coordinator = CodexProjectNativeU0Coordinator(self.harness.schemas, id_factory=self.harness.ids)

    def tearDown(self) -> None:
        self.harness.close()

    def _material(
        self,
        kind: str,
        content: bytes | None = None,
        *,
        label: str = "invented-meeting.txt",
        extension: str = ".txt",
        media_type: str = "text/plain",
        synthetic_only: bool = False,
    ) -> NativeIngressMaterial:
        return NativeIngressMaterial(
            ingress_kind=kind,
            material_bytes=content if content is not None else synthetic_text(),
            safe_label=label,
            declared_media_type=media_type,
            declared_extension=extension,
            opaque_id=f"invented-{kind}",
            host_task_id="invented-current-codex-task",
            synthetic_only=synthetic_only,
        )

    def test_c3_u01_current_task_contract_has_no_host_integration_or_runtime_write(self) -> None:
        before = sorted(self.harness.runtime_root.rglob("*"))
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")), patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("dns")
        ), patch.object(subprocess, "run", side_effect=AssertionError("subprocess")):
            prepared = self.coordinator.prepare(self._material("paste"))
            packet = self.coordinator.host_packet(prepared)
        self.assertEqual(before, sorted(self.harness.runtime_root.rglob("*")))
        self.assertEqual(packet["adapter"]["id"], "vault-next-codex-project-native-u0/0.1.0")
        self.assertEqual(packet["disclosure"]["vault_next_persistence"], "none")
        self.assertNotIn("save_to_vault_next", packet)

    def test_c3_u02_real_and_synthetic_contracts_are_non_interchangeable(self) -> None:
        prepared = self.coordinator.prepare(self._material("paste"))
        self.assertEqual(prepared.ingress_envelope["synthetic_only"], False)
        self.assertEqual(prepared.ingress_envelope["processing_surface"], "codex_project_native")
        with self.assertRaises(CodexProjectNativeU0Error):
            self.coordinator.prepare(self._material("paste", synthetic_only=True))
        with self.assertRaises(CodexProjectNativeU0Error):
            self.coordinator.prepare(self._material("acquired_link"))

    def test_c3_u03_invented_transport_representations_normalize_equally_and_local_reader_rejects_symlink(
        self,
    ) -> None:
        contents = synthetic_text()
        preparations = [
            self.coordinator.prepare(self._material(kind, contents))
            for kind in ("paste", "attachment", "local_file")
        ]
        self.assertEqual(len({item.evidence.evidence_sha256 for item in preparations}), 1)
        self.assertEqual(
            {item.ingress_envelope["ingress_kind"] for item in preparations},
            {"paste", "attachment", "local_file"},
        )
        with tempfile.TemporaryDirectory(prefix="vault-next-c3-test-") as raw_root:
            root = Path(raw_root)
            fixture = root / "invented-local.txt"
            fixture.write_bytes(contents)
            selected = self.coordinator.prepare_owner_selected_local_file(
                fixture.resolve(), host_task_id="invented-current-codex-task"
            )
            self.assertEqual(selected.evidence.evidence_sha256, preparations[0].evidence.evidence_sha256)
            link = root / "invented-link.txt"
            link.symlink_to(fixture)
            with self.assertRaises(CodexProjectNativeU0Error):
                self.coordinator.prepare_owner_selected_local_file(
                    link.absolute(), host_task_id="invented-current-codex-task"
                )

    def test_docx_profile_and_hosted_analysis_validation_are_bounded(self) -> None:
        prepared = self.coordinator.prepare(
            self._material(
                "attachment",
                minimal_docx(["Invented C3 DOCX meeting fact."]),
                label="invented.docx",
                extension=".docx",
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        )
        packet = self.coordinator.host_packet(prepared)
        analyzer = FixtureMeetingDebriefAnalyzer()
        analysis = analyzer.analyze(prepared.evidence, packet["request"])
        result = self.coordinator.validate_hosted_analysis(prepared, analysis)
        self.assertEqual(result["validation_status"], "accepted")
        self.assertEqual(result["vault_next_persistence"], "none")
        analysis["findings"][0]["citations"] = [{"anchor": "missing"}]
        with self.assertRaises(MeetingDebriefError):
            self.coordinator.validate_hosted_analysis(prepared, analysis)
