"""S3-C hostile synthetic tests; no test resolves, connects, or requests a public source."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.direct_https_transport import (
    COMPONENT_ID,
    COMPONENT_VERSION,
    REAL_COMPONENT_VERSION,
    RealDirectHttpsTransport,
    ResolvedAddress,
    SyntheticDirectHttpsTransport,
    SyntheticTransportEnvironment,
)
from vault_next.local_confirmation import KeychainStore
from vault_next.local_confirmation_v2 import (
    DurableLocalAuthority, LocalConfirmationV2Error, PUBLIC_RESEARCH_EXECUTION_ATTESTATION,
    PublicResearchReceiptVerifier, finalize_public_research_manifest,
)
from vault_next.public_research import (
    FIXED_URL, CitationOnlyPublicResearchCoordinator, PublicResearchError,
    PublicResearchRestartVerifier, SyntheticResponse, capability_report,
)
from vault_next.runtime import CaseSessionRuntime
from vault_next.validator import KernelValidator


class _MemoryKeychain(KeychainStore):
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}
    def find(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))
    def create(self, service: str, account: str, secret: bytes) -> None:
        self.items[(service, account)] = secret
    def remove(self, service: str, account: str) -> None:
        self.items.pop((service, account), None)


class _Confirmation:
    def confirm(self, _path: Path, digest: str) -> str:
        return digest


class _Transport:
    def __init__(self, response: SyntheticResponse | Exception) -> None:
        self.response = response
        self.calls: list[str] = []
    def get_exact(self, url: str) -> SyntheticResponse:
        self.calls.append(url)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _DirectBackend:
    def __init__(self, response: SyntheticResponse) -> None:
        self.response = response
        self.calls = 0

    def fetch_fixed(self) -> SyntheticResponse:
        self.calls += 1
        return self.response


class _Stream:
    def __init__(self, response: bytes) -> None:
        self.remaining = response
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        chunk, self.remaining = self.remaining[:size], self.remaining[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


class _Network:
    def __init__(self, stream: _Stream, *, address_class: str = "global_unicast") -> None:
        self.stream = stream
        self.address_class = address_class
        self.resolve_calls: list[tuple[str, int]] = []
        self.connect_calls: list[tuple[ResolvedAddress, str]] = []

    def resolve_exact(self, host: str, port: int) -> tuple[ResolvedAddress, ...]:
        self.resolve_calls.append((host, port))
        return (ResolvedAddress(2, 1, 6, ("203.0.113.99", port), self.address_class),)

    def connect_tls_exact(self, address: ResolvedAddress, hostname: str) -> _Stream:
        self.connect_calls.append((address, hostname))
        return self.stream


class PublicResearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime = CaseSessionRuntime(
            self.harness.paths, self.harness.schemas, id_factory=self.harness.ids,
            clock=lambda: self.harness.current, correlation_id="synthetic-s3c-public",
        )
        case = self.runtime.create_case("Invented hostile public-research case")
        self.case_id = case["case_id"]
        session = self.runtime.create_session(self.case_id, "Invented hostile citation request")
        self.session_id = session["session_id"]
        for state in ("routed", "authorized", "active"):
            self.runtime.transition_session(self.session_id, state, reason="synthetic public setup")
        self.temp = TemporaryDirectory(prefix="vault-next-s3c-public-authority-")
        self.authority_root = Path(self.temp.name) / "authority"
        self.authority = DurableLocalAuthority(
            self.harness.paths, self.authority_root, self.harness.schemas, _MemoryKeychain(),
            _Confirmation(), self.harness.ids, lambda: self.harness.current,
        )
        self.authority._signing_identity()  # only a disposable test identity; the public methods cannot bootstrap.
        self.verifier = PublicResearchReceiptVerifier(self.harness.paths, self.authority_root, self.harness.schemas)
        self.transport = _Transport(self._good_response())
        self.coordinator = CitationOnlyPublicResearchCoordinator(
            self.runtime, self.authority, self.verifier, self.transport
        )

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.harness.close()

    @staticmethod
    def _good_response() -> SyntheticResponse:
        return SyntheticResponse(
            200, "text/plain", b"VAULT_NEXT_SYNTHETIC_FIXTURE\nhostile invented RFC body", FIXED_URL
        )

    def _scope(self, *, expires_at=None):
        manifest = self.coordinator.propose_scope(
            self.case_id, self.session_id, self.harness.ids.new("request"), "synthetic-public-idempotency",
            expires_at=expires_at,
        )
        return self.coordinator.authorize_scope(manifest)

    def _events(self) -> list[dict]:
        return [e for e in self.runtime.semantic.read_all() if e["event_type"] == "public_research.citation_captured"]

    def test_s3c_r01_capability_report_excludes_all_live_surfaces(self) -> None:
        report = capability_report()
        self.assertTrue(report["synthetic_transport_double"])
        self.assertTrue(all(not report[name] for name in report if name != "synthetic_transport_double"))

    def test_s3c_r02_bad_or_expired_scope_never_calls_transport(self) -> None:
        with self.assertRaises(Exception):
            self.coordinator.retrieve_citation("receipt_00000000000000000000000000")
        self.assertEqual(self.transport.calls, [])
        expired = self._scope(expires_at=self.harness.current + timedelta(seconds=1))
        self.harness.current += timedelta(minutes=1)
        with self.assertRaises(PublicResearchError):
            self.coordinator.retrieve_citation(expired.receipt_id)
        self.assertEqual(self.transport.calls, [])

    def test_s3c_r03_transport_policy_rejects_redirect_disclosure_and_oversize(self) -> None:
        for response in (
            SyntheticResponse(200, "text/plain", b"x", FIXED_URL, redirect_chain=("https://evil.invalid",)),
            SyntheticResponse(200, "text/plain", b"x", FIXED_URL, used_proxy=True),
            SyntheticResponse(200, "text/plain", b"x" * 65537, FIXED_URL),
        ):
            self.transport.response = response
            output = self.coordinator.retrieve_citation(self._scope().receipt_id)
            self.assertEqual(output["status"], "rejected")
        self.assertFalse(self._events())

    def test_s3c_r04_never_retains_hostile_fixture_body(self) -> None:
        output = self.coordinator.retrieve_citation(self._scope().receipt_id)
        self.assertEqual(output["status"], "captured")
        serialized = "\n".join(str(event) for event in self.runtime.semantic.read_all())
        self.assertNotIn("hostile invented RFC body", serialized)
        self.assertIsNone(self._events()[0]["payload"]["citation"]["object_ref"])

    def test_s3c_r05_unavailable_transport_makes_no_item(self) -> None:
        self.transport.response = RuntimeError("synthetic transport failure")
        scope = self._scope()
        self.assertEqual(self.coordinator.retrieve_citation(scope.receipt_id)["status"], "unavailable")
        self.assertFalse(self._events())
        self.assertEqual(
            self.coordinator.retrieve_citation(scope.receipt_id)["status"], "needs_input"
        )

    def test_s3c_r06_restart_replays_each_exact_purpose_receipt(self) -> None:
        scope = self._scope()
        output = self.coordinator.retrieve_citation(scope.receipt_id)
        item = output["item_receipt"]
        restarted = PublicResearchReceiptVerifier(self.harness.paths, self.authority_root, self.harness.schemas)
        self.assertEqual(
            restarted.load_verified(scope.receipt_id, purpose="public_research_scope")[0].purpose,
            "public_research_scope",
        )
        self.assertEqual(
            restarted.load_verified(item.receipt_id, purpose="public_item_capture")[0].purpose,
            "public_item_capture",
        )
        self.assertTrue(KernelValidator(self.harness.paths, self.harness.schemas).validate().passed)
        self.assertEqual(
            PublicResearchRestartVerifier(
                self.harness.paths, self.authority_root, self.harness.schemas
            ).verify_scope(scope.receipt_id)["status"],
            "verified",
        )
        self.coordinator.retrieve_citation(scope.receipt_id)
        self.assertEqual(self.transport.calls, [FIXED_URL])

    def test_s3c_r07_purpose_substitution_is_rejected(self) -> None:
        scope = self._scope()
        self.assertEqual(
            self.verifier.verify(scope, purpose="public_item_capture").status.value, "rejected"
        )

    def test_s3c_live_t01_direct_component_is_synthetic_only(self) -> None:
        report = SyntheticDirectHttpsTransport.capability_report()
        self.assertEqual(report["component_id"], COMPONENT_ID)
        self.assertEqual(report["component_version"], COMPONENT_VERSION)
        self.assertTrue(report["synthetic_backend_only"])
        self.assertFalse(report["live_https"])
        self.assertFalse(report["dns"])
        self.assertFalse(report["socket"])

    def test_s3c_live_t02_host_state_and_second_direct_call_are_denied(self) -> None:
        backend = _DirectBackend(self._good_response())
        denied = SyntheticDirectHttpsTransport(
            backend, SyntheticTransportEnvironment(proxy_configured=True)
        )
        with self.assertRaises(Exception):
            denied.get_exact(FIXED_URL)
        self.assertEqual(backend.calls, 0)
        direct = SyntheticDirectHttpsTransport(backend)
        self.assertEqual(direct.get_exact(FIXED_URL).status, 200)
        with self.assertRaises(Exception):
            direct.get_exact(FIXED_URL)
        self.assertEqual(backend.calls, 1)

    def test_s3c_live_t03_transport_controls_and_audits_are_metadata_only(self) -> None:
        backend = _DirectBackend(
            SyntheticResponse(200, "text/plain", b"hostile direct fixture", FIXED_URL, tls_certificate_valid=False)
        )
        self.coordinator.transport = SyntheticDirectHttpsTransport(backend)
        scope = self._scope()
        self.assertEqual(self.coordinator.retrieve_citation(scope.receipt_id)["status"], "unavailable")
        self.assertEqual(backend.calls, 1)
        self.assertEqual(self.coordinator.retrieve_citation(scope.receipt_id)["status"], "needs_input")
        audits = self.coordinator.runtime.paths.audit_root
        self.assertNotIn(b"hostile direct fixture", b"".join(path.read_bytes() for path in audits.glob("*.jsonl")))
        attempts = self.coordinator.runtime.paths.audit_root
        self.assertTrue(any(attempts.glob("*.jsonl")))

    def test_s3c_live_t04_item_confirmation_failure_consumes_scope_without_a_citation(self) -> None:
        scope = self._scope()
        self.authority = DurableLocalAuthority(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            self.authority.keychain,
            type("Reject", (), {"confirm": lambda _self, _path, _digest: "wrong"})(),
            self.harness.ids,
            lambda: self.harness.current,
        )
        self.coordinator.authority = self.authority
        with self.assertRaises(PublicResearchError):
            self.coordinator.retrieve_citation(scope.receipt_id)
        self.assertFalse(self._events())
        self.assertEqual(
            PublicResearchRestartVerifier(
                self.harness.paths, self.authority_root, self.harness.schemas
            ).verify_scope(scope.receipt_id)["status"],
            "needs_input",
        )

    def test_s3c_live_t05_real_backend_is_exercised_only_through_a_fake_network(self) -> None:
        stream = _Stream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 7\r\n\r\nfixture"
        )
        network = _Network(stream)
        transport = RealDirectHttpsTransport(network)
        response = transport.get_exact(FIXED_URL)
        self.assertEqual(response.body, b"fixture")
        self.assertEqual(network.resolve_calls, [("www.rfc-editor.org", 443)])
        self.assertEqual(len(network.connect_calls), 1)
        self.assertEqual(
            stream.sent,
            [
                b"GET /rfc/rfc2606.txt HTTP/1.1\r\nHost: www.rfc-editor.org\r\n"
                b"Accept: text/plain\r\nConnection: close\r\n\r\n"
            ],
        )
        self.assertTrue(stream.closed)
        report = RealDirectHttpsTransport.capability_report()
        self.assertEqual(report["component_version"], REAL_COMPONENT_VERSION)
        self.assertTrue(report["requires_explicit_network_injection"])

    def test_s3c_live_t06_real_backend_rejects_address_and_hostile_framing_without_fallback(self) -> None:
        denied_network = _Network(_Stream(b""), address_class="private")
        with self.assertRaises(Exception):
            RealDirectHttpsTransport(denied_network).get_exact(FIXED_URL)
        self.assertEqual(denied_network.connect_calls, [])

        malformed_stream = _Stream(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n")
        malformed_network = _Network(malformed_stream)
        with self.assertRaises(Exception):
            RealDirectHttpsTransport(malformed_network).get_exact(FIXED_URL)
        self.assertEqual(len(malformed_network.connect_calls), 1)
        self.assertTrue(malformed_stream.closed)

    def test_s3c_live_t07_real_backend_fixture_captures_metadata_not_response_bytes(self) -> None:
        hostile_body = b"VAULT_NEXT_SYNTHETIC_FIXTURE\nreal-backend hostile invented body"
        stream = _Stream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(hostile_body)).encode("ascii")
            + b"\r\n\r\n"
            + hostile_body
        )
        network = _Network(stream)
        self.coordinator.transport = RealDirectHttpsTransport(network)
        output = self.coordinator.retrieve_citation(self._scope().receipt_id)
        self.assertEqual(output["status"], "captured")
        self.assertEqual(len(network.resolve_calls), 1)
        serialized = "\n".join(str(event) for event in self.runtime.semantic.read_all())
        self.assertNotIn("real-backend hostile invented body", serialized)

    def test_s3c_bound_t01_execution_scope_binds_live_controls_and_replays(self) -> None:
        runtime_root = Path("/private/tmp/vault-next-s3c-live.synthetic-bound")
        manifest = self.coordinator.propose_execution_scope(
            self.case_id,
            self.session_id,
            self.harness.ids.new("request"),
            "execution-bound-synthetic",
            t0=self.harness.current,
            runtime_root=runtime_root,
        )
        self.assertEqual(manifest["schema_version"], "2.1")
        self.assertEqual(manifest["execution_runtime_root"], str(runtime_root))
        self.assertEqual(manifest["owner_terms_rights_attestation"], PUBLIC_RESEARCH_EXECUTION_ATTESTATION)
        scope = self.coordinator.authorize_scope(manifest)
        self.assertEqual(scope.schema_version, "2.1")
        output = self.coordinator.retrieve_citation(scope.receipt_id)
        self.assertEqual(output["status"], "captured")
        item, item_manifest = self.verifier.load_verified(
            output["item_receipt"].receipt_id, purpose="public_item_capture"
        )
        self.assertEqual(item.schema_version, "2.1")
        self.assertEqual(item_manifest["execution_t0"], manifest["execution_t0"])
        self.assertEqual(
            PublicResearchRestartVerifier(
                self.harness.paths, self.authority_root, self.harness.schemas
            ).verify_scope(scope.receipt_id)["status"],
            "verified",
        )

    def test_s3c_bound_t02_execution_scope_rejects_unbound_or_changed_controls(self) -> None:
        base = self.coordinator.propose_execution_scope(
            self.case_id,
            self.session_id,
            self.harness.ids.new("request"),
            "execution-bound-reject",
            t0=self.harness.current,
            runtime_root=Path("/private/tmp/vault-next-s3c-live.synthetic-reject"),
        )
        for changed in (
            {"execution_component_version": "0.1.0"},
            {"execution_runtime_root": "/private/tmp/not-approved"},
            {"owner_terms_rights_attestation": "invented attestation"},
            {"expires_at": "2026-09-01T12:11:00Z"},
        ):
            candidate = finalize_public_research_manifest({**base, **changed, "manifest_digest": ""})
            with self.assertRaises(LocalConfirmationV2Error):
                self.coordinator.authorize_scope(candidate)
