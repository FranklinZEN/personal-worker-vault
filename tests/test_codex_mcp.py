"""CF2-H01–H06 checks for the project-scoped hostile-synthetic Codex STDIO bridge."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.helpers import Harness
from vault_next.codex_mcp import CodexMcpApplication, StdioMcpServer
from vault_next.host_ingress import (
    ADAPTER_ID,
    DisposableFixtureRoot,
    HostIngressCoordinator,
    HostIngressError,
    NativeFileSelector,
)


class _StaticSelector:
    """Test-only single-item native-picker double with no process or ambient filesystem access."""

    def __init__(self, selected: object) -> None:
        self.selected = selected
        self.roots: list[Path] = []

    def choose_one(self, fixture_root: Path) -> Path | None:
        self.roots.append(fixture_root)
        return self.selected  # type: ignore[return-value]


class _Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


class CodexMcpTests(unittest.TestCase):
    """Every test uses only a fresh CF2 temporary root and invented marked fixture bytes."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.fixtures = DisposableFixtureRoot.create()
        self.clock = _Clock()
        self.selector = _StaticSelector(self.fixtures.root / "invented-meeting.txt")
        self.coordinator = HostIngressCoordinator(
            self.harness.schemas,
            self.fixtures,
            self.selector,
            id_factory=self.harness.ids,
            monotonic=self.clock,
        )
        self.application = CodexMcpApplication(self.coordinator)

    def tearDown(self) -> None:
        self.application.close()
        self.harness.close()

    def test_cf2_h01_project_scoped_stdio_surface_and_tools_are_exact(self) -> None:
        config_path = Path(__file__).resolve().parents[1] / ".codex" / "config.toml"
        config = config_path.read_text(encoding="utf-8")
        self.assertIn("[mcp_servers.vault_next_chat_first]", config)
        self.assertIn("vault_next.codex_mcp", config)
        self.assertNotIn("http", config.casefold())
        self.assertNotIn("proxy =", config.casefold())

        output = io.StringIO()
        server = StdioMcpServer(
            self.application,
            io.StringIO(
                "\n".join(
                    (
                        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                    )
                )
                + "\n"
            ),
            output,
        )
        self.assertEqual(server.serve(), 0)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(replies[0]["result"]["serverInfo"]["version"], "0.1.0")
        names = {item["name"] for item in replies[1]["result"]["tools"]}
        self.assertEqual(
            names,
            {
                "vault_next_prepare_meeting_debrief_paste",
                "vault_next_choose_meeting_debrief_fixture",
                "vault_next_validate_meeting_debrief",
            },
        )
        self.assertTrue(all("save" not in item["name"] for item in replies[1]["result"]["tools"]))

        declared = tomllib.loads(config)["mcp_servers"]["vault_next_chat_first"]
        environment = dict(os.environ)
        environment.update(declared["env"])
        stdin = "\n".join(
            (
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            )
        )
        process = subprocess.run(
            [declared["command"], *declared["args"]],
            check=False,
            capture_output=True,
            cwd=declared["cwd"],
            env=environment,
            input=stdin,
            text=True,
            timeout=15,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(process.stdout.splitlines()), 2)

    def test_cf2_h02_paste_and_native_fixture_are_distinct_and_normalize_equally(self) -> None:
        fixture_text = (self.fixtures.root / "invented-meeting.txt").read_text(encoding="utf-8")
        paste = self.coordinator.prepare_paste(fixture_text)
        selected = self.coordinator.choose_native_fixture()
        self.assertEqual(
            paste.preparation.evidence.evidence_sha256,
            selected.preparation.evidence.evidence_sha256,
        )
        self.assertEqual(paste.ingress_kind, "paste")
        self.assertEqual(selected.ingress_kind, "local_file")
        self.assertEqual(self.selector.roots, [self.fixtures.root])

    def test_cf2_h03_descriptor_selection_container_profile_expiry_and_mutation_fail_closed(self) -> None:
        self.selector.selected = self.fixtures.root
        with self.assertRaises(HostIngressError):
            self.coordinator.choose_native_fixture()

        self.selector.selected = (self.fixtures.root / "invented-meeting.txt",)
        with self.assertRaises(HostIngressError):
            self.coordinator.choose_native_fixture()

        selected = self.fixtures.root / "invented-meeting.txt"
        selected.unlink()
        selected.symlink_to(self.fixtures.root / "invented-meeting.md")
        self.selector.selected = selected
        with self.assertRaises(HostIngressError):
            self.coordinator.choose_native_fixture()

    def test_cf2_h03_spoofed_docx_and_expired_session_fail_before_analysis(self) -> None:
        spoofed = self.fixtures.root / "invented-meeting.docx"
        spoofed.write_bytes(b"VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nnot a DOCX container\n")
        self.selector.selected = spoofed
        with self.assertRaises(HostIngressError):
            self.coordinator.choose_native_fixture()

        session = self.coordinator.prepare_paste("VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nexpired\n")
        self.clock.value += 121.0
        with self.assertRaises(HostIngressError):
            self.coordinator.validate_host_analysis(session.session_id, _analysis(session))

    def test_cf2_h04_unbound_citations_owner_fields_and_effect_requests_are_rejected(self) -> None:
        session = self.coordinator.prepare_paste("VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nbounded\n")
        invalid_citation = _analysis(session)
        invalid_citation["findings"][0]["citations"] = [{"anchor": "absent"}]
        with self.assertRaises(Exception):
            self.coordinator.validate_host_analysis(session.session_id, invalid_citation)

        session = self.coordinator.prepare_paste("VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nbounded\n")
        invalid_owner = _analysis(session)
        invalid_owner["findings"][0]["owner"] = "Invented Owner"
        invalid_owner["findings"][0]["owner_citation"] = invalid_owner["findings"][0]["citations"][0]["anchor"]
        with self.assertRaises(Exception):
            self.coordinator.validate_host_analysis(session.session_id, invalid_owner)

        session = self.coordinator.prepare_paste("VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nbounded\n")
        effect_request = _analysis(session)
        effect_request["request_tool"] = "apply"
        with self.assertRaises(Exception):
            self.coordinator.validate_host_analysis(session.session_id, effect_request)

    def test_cf2_h05_u0_has_no_vault_next_write_or_external_boundary(self) -> None:
        before = _tree(self.harness.runtime_root)
        text = "VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nzero writes\n"
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")), patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("dns")
        ), patch.object(subprocess, "run", side_effect=AssertionError("subprocess")):
            session = self.coordinator.prepare_paste(text)
            result = self.coordinator.validate_host_analysis(session.session_id, _analysis(session))
        self.assertEqual(before, _tree(self.harness.runtime_root))
        self.assertEqual(result["authority_level"], "U0")
        self.assertEqual(result["debrief"]["persistence"], "ephemeral")

    def test_cf2_h06_visible_disclosure_method_and_restart_behavior_are_exact(self) -> None:
        session = self.coordinator.prepare_paste("VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nvisible\n")
        packet = self.coordinator.host_packet(session)
        self.assertEqual(packet["adapter"]["id"], ADAPTER_ID)
        self.assertEqual(packet["candidate"]["status"], "inactive-candidate evaluation")
        self.assertEqual(packet["disclosure"]["ingress_class"], "paste")
        self.assertIn("Hosted Codex", packet["disclosure"]["hosted_processing"])
        self.assertIn("Ephemeral U0", packet["disclosure"]["vault_next_state"])
        result = self.coordinator.validate_host_analysis(session.session_id, _analysis(session))
        self.assertIn("separate U1 authority", result["available_next_action"])
        self.assertEqual(result["debrief"]["candidate_lifecycle"], "inactive")
        with self.assertRaises(HostIngressError):
            self.coordinator.validate_host_analysis(session.session_id, _analysis(session))


def _analysis(session: object) -> dict[str, object]:
    prepared = getattr(session, "preparation")
    anchor = prepared.evidence.anchors[0].anchor
    statement = "Invented fixture finding is cited."
    return {
        "findings": [
            {
                "claim_class": "reported_fact",
                "statement": statement,
                "citations": [{"anchor": anchor}],
                "owner": None,
                "owner_citation": None,
                "due": None,
                "due_citation": None,
            }
        ],
        "summary": {"statement": statement, "citations": [{"anchor": anchor}]},
        "open_questions": ["Invented question."],
        "suggested_followups": ["Invented suggestion only."],
        "omissions": ["Synthetic fixture only."],
        "limitations": ["No external effect is available."],
    }


def _tree(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
