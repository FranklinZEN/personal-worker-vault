"""S5CF-T01/T04 hostile synthetic U0 Chat-first ingress tests."""

from __future__ import annotations

import socket
import subprocess
import unittest
from unittest.mock import patch

from tests.chat_fixtures import ingress_coordinator, synthetic_text, transport
from tests.helpers import Harness


class ChatIngressTests(unittest.TestCase):
    """Each test constructs only invented, marker-bound material and a fresh disposable harness."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.coordinator, self.router, self.analyzer = ingress_coordinator(self.harness)

    def tearDown(self) -> None:
        self.harness.close()

    def test_s5cf_t01_four_transport_doubles_normalize_equivalently_with_distinct_provenance(self) -> None:
        material = synthetic_text()
        executions = [
            self.coordinator.run(transport(kind, material))
            for kind in ("paste", "attachment", "local_file", "acquired_link")
        ]
        evidence_digests = {item.evidence.evidence_sha256 for item in executions}
        debrief_digests = {item.debrief["result_sha256"] for item in executions}
        provenance_kinds = {item.ingress_envelope["provenance"]["kind"] for item in executions}
        self.assertEqual(len(evidence_digests), 1)
        self.assertEqual(len(debrief_digests), 1)
        self.assertEqual(provenance_kinds, {"paste", "attachment", "local_file", "acquired_link"})

    def test_s5cf_t04_u0_is_ephemeral_and_cannot_invoke_external_boundaries(self) -> None:
        before = sorted(
            path.relative_to(self.harness.runtime_root).as_posix()
            for path in self.harness.runtime_root.rglob("*")
        )
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")), patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("dns")
        ), patch.object(subprocess, "run", side_effect=AssertionError("subprocess")):
            execution = self.coordinator.run(transport("paste"))
        after = sorted(
            path.relative_to(self.harness.runtime_root).as_posix()
            for path in self.harness.runtime_root.rglob("*")
        )
        self.assertEqual(execution.result["authority_level"], "U0")
        self.assertEqual(execution.result["debrief"]["persistence"], "ephemeral")
        self.assertEqual(before, after)
        self.assertEqual(len(self.analyzer.calls), 1)
