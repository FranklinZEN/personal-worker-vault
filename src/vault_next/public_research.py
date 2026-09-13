"""S3-C citation-only public research boundary.

This module deliberately contains no HTTP, DNS, browser, proxy, connector, or model client.
Only a caller-supplied transport double can provide bytes during the synthetic proof stage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Protocol

from vault_next.canonical import canonical_sha256
from vault_next.direct_https_transport import COMPONENT_ID, COMPONENT_VERSION, REAL_COMPONENT_VERSION
from vault_next.errors import ValidationError
from vault_next.ledger import OperationalLedger
from vault_next.local_confirmation_v2 import (
    LocalConfirmationV2Error,
    PublicResearchReceipt,
    PublicResearchReceiptVerifier,
    DurableLocalAuthority,
    PUBLIC_RESEARCH_EXECUTION_ATTESTATION,
    finalize_public_research_manifest,
    require_public_research_manifest,
)
from vault_next.lifecycle import fold_session_states
from vault_next.records import RUNTIME_ACTOR, build_audit_record, timestamp
from vault_next.runtime import CaseSessionRuntime

FIXED_URL = "https://www.rfc-editor.org/rfc/rfc2606.txt"
RECIPIENT = "www.rfc-editor.org"
MAX_RESPONSE_BYTES = 65_536


class PublicResearchError(RuntimeError):
    """The bounded citation-only operation could not safely produce an item receipt."""


class PublicResearchTransport(Protocol):
    """A deliberately tiny seam; production transport is intentionally absent in S3-C."""

    def get_exact(self, url: str) -> "SyntheticResponse": ...


@dataclass(frozen=True)
class SyntheticResponse:
    """A hostile-test-only response shape; no response content is persisted by this module."""

    status: int
    media_type: str
    body: bytes
    final_url: str
    redirect_chain: tuple[str, ...] = ()
    used_proxy: bool = False
    sent_cookie: bool = False
    used_credentials: bool = False
    tls_hostname_valid: bool = True
    tls_certificate_valid: bool = True
    resolved_address_class: str = "global_unicast"
    response_framing_valid: bool = True
    authentication_challenge: bool = False


def capability_report() -> dict[str, bool]:
    return {
        "synthetic_transport_double": True,
        "live_https": False,
        "dns": False,
        "browser": False,
        "codex_desktop_adapter": False,
        "connector_plugin": False,
        "proxy": False,
        "search": False,
        "model_api": False,
    }


class CitationOnlyPublicResearchCoordinator:
    """Issue purpose-separated receipts and ledger citations without retaining a response body."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        authority: DurableLocalAuthority,
        verifier: PublicResearchReceiptVerifier,
        transport: PublicResearchTransport,
    ) -> None:
        self.runtime = runtime
        self.authority = authority
        self.verifier = verifier
        self.transport = transport

    def propose_scope(
        self, case_id: str, session_id: str, request_id: str, idempotency_key: str, *,
        expires_at: datetime | None = None,
    ) -> dict[str, object]:
        now = self.runtime.clock()
        return finalize_public_research_manifest({
            "schema_version": "2.0", "purpose": "public_research_scope",
            "scope_id": self.runtime.ids.new("research_scope"), "item_id": None,
            "scope_receipt_id": None, "case_id": case_id, "session_id": session_id,
            "request_id": request_id, "idempotency_key": idempotency_key,
            "url": FIXED_URL, "recipient": RECIPIENT, "retention": "citation_only",
            "permitted_model_recipients": [], "permitted_processors": [],
            "http_status": None, "media_type": None, "byte_count": None,
            "content_sha256": None, "final_url": None, "redirect_chain": None,
            "retrieved_at": None,
            "expires_at": timestamp(expires_at or now + timedelta(minutes=5)),
            "manifest_digest": "",
        })

    def authorize_scope(self, manifest: dict[str, object]) -> PublicResearchReceipt:
        return self.authority.authorize_public_research_scope(manifest)

    def propose_execution_scope(
        self,
        case_id: str,
        session_id: str,
        request_id: str,
        idempotency_key: str,
        *,
        t0: datetime,
        runtime_root: Path,
        attestation: str = PUBLIC_RESEARCH_EXECUTION_ATTESTATION,
    ) -> dict[str, object]:
        """Build the additive 2.1 scope that a future live authorization must exactly confirm."""

        if t0.tzinfo is None or t0.utcoffset() is None:
            raise PublicResearchError("execution T0 must be timezone-aware")
        base = self.propose_scope(
            case_id,
            session_id,
            request_id,
            idempotency_key,
            expires_at=t0 + timedelta(minutes=10),
        )
        return finalize_public_research_manifest(
            {
                **base,
                "schema_version": "2.1",
                "execution_component_id": COMPONENT_ID,
                "execution_component_version": REAL_COMPONENT_VERSION,
                "execution_mode": "live_one_request",
                "execution_runtime_root": str(runtime_root),
                "execution_t0": timestamp(t0),
                "owner_terms_rights_attestation": attestation,
                "manifest_digest": "",
            }
        )

    def retrieve_citation(self, scope_receipt_id: str) -> dict[str, object]:
        scope_receipt, scope = self.verifier.load_verified(
            scope_receipt_id, purpose="public_research_scope"
        )
        now = self.runtime.clock().astimezone(UTC)
        if scope_receipt.expires_at <= now:
            raise PublicResearchError("public-research scope receipt has expired")
        self._require_active_scope(scope)
        existing = self._existing(scope)
        if existing is not None:
            return existing
        if self._scope_is_consumed(scope_receipt):
            return {"status": "needs_input", "reason": "scope_consumed"}
        reservation = self._append_attempt_audit(
            scope_receipt, scope, send_state="not_sent", phase="preflight", result="succeeded"
        )
        try:
            response = self.transport.get_exact(FIXED_URL)
        except Exception:
            self._append_attempt_audit(
                scope_receipt,
                scope,
                send_state="possibly_sent",
                phase="response_policy",
                result="failed",
                error_code="transport_unavailable",
                output_refs=[reservation["operation_id"]],
            )
            return {"status": "unavailable", "reason": "transport_unavailable"}
        error = self._response_error(response)
        if error is not None:
            self._append_attempt_audit(
                scope_receipt,
                scope,
                send_state="possibly_sent",
                phase="response_policy",
                result="failed",
                error_code=error,
                output_refs=[reservation["operation_id"]],
            )
            return {"status": "rejected", "reason": error}
        retrieved_at = timestamp(now)
        item = finalize_public_research_manifest({
            **scope,
            "purpose": "public_item_capture",
            "item_id": self.runtime.ids.new("public_item"),
            "scope_receipt_id": scope_receipt.receipt_id,
            "http_status": response.status, "media_type": response.media_type.lower(),
            "byte_count": len(response.body), "content_sha256": sha256(response.body).hexdigest(),
            "final_url": response.final_url, "redirect_chain": list(response.redirect_chain),
            "retrieved_at": retrieved_at, "manifest_digest": "",
        })
        try:
            require_public_research_manifest(item, self.runtime.schemas)
            item_receipt = self.authority.authorize_public_item_capture(item)
        except (LocalConfirmationV2Error, ValidationError) as exc:
            self._append_attempt_audit(
                scope_receipt,
                scope,
                send_state="response_validated",
                phase="item_confirmation",
                result="cancelled",
                error_code="item_confirmation_unavailable",
                output_refs=[reservation["operation_id"]],
            )
            raise PublicResearchError("public item receipt could not be issued") from exc
        citation = {
            "schema_version": "1.0", "item_id": item["item_id"],
            "scope_receipt_id": scope_receipt.receipt_id, "item_receipt_id": item_receipt.receipt_id,
            "case_id": item["case_id"], "session_id": item["session_id"],
            "request_id": item["request_id"],
            "final_url": response.final_url, "http_status": response.status,
            "media_type": response.media_type.lower(), "byte_count": len(response.body),
            "content_sha256": item["content_sha256"], "redirect_chain": [],
            "retrieved_at": retrieved_at, "publication_date_status": "unknown",
            "retention": "citation_only", "source_class": "public_nonpersonal_citation_only",
            "object_ref": None,
        }
        self.runtime.schemas.require("public-research-citation", citation)
        event = self.runtime._append(
            "public_research.citation_captured", item["case_id"], item["session_id"],
            {"citation": citation, "citation_sha256": canonical_sha256(citation)},
            subject_refs=[scope_receipt.receipt_id, item_receipt.receipt_id],
            causation=self.runtime._last_session_event_id(item["session_id"]),
            actor=dict(RUNTIME_ACTOR), when=now,
        )
        self._append_attempt_audit(
            scope_receipt,
            scope,
            send_state="response_validated",
            phase="item_confirmation",
            result="succeeded",
            item_receipt_id=item_receipt.receipt_id,
            citation_event_id=event["event_id"],
            output_refs=[reservation["operation_id"]],
            semantic_event_refs=[event["event_id"]],
        )
        return {"status": "captured", "item_receipt": item_receipt, "event": event}

    def _require_active_scope(self, scope: dict[str, object]) -> None:
        states, _ = fold_session_states(self.runtime.semantic.read_all())
        state = states.get(scope["session_id"])
        if state is None or state.case_id != scope["case_id"] or state.status != "active":
            raise PublicResearchError("public-research scope is not bound to an active exact session")

    def _existing(self, scope: dict[str, object]) -> dict[str, object] | None:
        for event in self.runtime.semantic.read_all():
            if event["event_type"] != "public_research.citation_captured":
                continue
            citation = event["payload"].get("citation", {})
            if citation.get("request_id") == scope["request_id"]:
                if citation.get("case_id") != scope["case_id"] or citation.get("session_id") != scope["session_id"]:
                    raise PublicResearchError("public-research request ID conflicts with another case/session")
                return {"status": "captured", "item_receipt_id": citation["item_receipt_id"], "event": event}
        return None

    def _scope_is_consumed(self, receipt: PublicResearchReceipt) -> bool:
        return any(
            item.get("public_research_attempt", {}).get("scope_receipt_id") == receipt.receipt_id
            for item in OperationalLedger(self.runtime.paths, self.runtime.schemas).read_all()
            if isinstance(item.get("public_research_attempt"), dict)
        )

    def _append_attempt_audit(
        self,
        receipt: PublicResearchReceipt,
        scope: dict[str, object],
        *,
        send_state: str,
        phase: str,
        result: str,
        error_code: str | None = None,
        item_receipt_id: str | None = None,
        citation_event_id: str | None = None,
        output_refs: list[str] | None = None,
        semantic_event_refs: list[str] | None = None,
    ) -> dict[str, object]:
        attempt = {
            "scope_receipt_id": receipt.receipt_id,
            "component_id": scope.get("execution_component_id") or COMPONENT_ID,
            "component_version": scope.get("execution_component_version") or COMPONENT_VERSION,
            "fixed_url_sha256": sha256(FIXED_URL.encode("utf-8")).hexdigest(),
            "send_state": send_state,
            "phase": phase,
            "item_receipt_id": item_receipt_id,
            "citation_event_id": citation_event_id,
        }
        audit = build_audit_record(
            operation_class="transmit",
            target_summary="public-research fixed citation-only target",
            input_digest=receipt.manifest_digest,
            policy={"result": "allow", "reason_code": "exact_scope_receipt", "approval_ref": None},
            attempt_status="attempted" if send_state != "not_sent" else "not_attempted",
            result=result,
            case_id=scope["case_id"],
            session_id=scope["session_id"],
            output_refs=output_refs,
            semantic_event_refs=semantic_event_refs,
            error_code=error_code,
            public_research_attempt=attempt,
            attempted_at=self.runtime.clock(),
            id_factory=self.runtime.ids,
        )
        return OperationalLedger(self.runtime.paths, self.runtime.schemas).append(audit)

    @staticmethod
    def _response_error(response: SyntheticResponse) -> str | None:
        if response.status != 200:
            return "http_status"
        if response.media_type.lower() != "text/plain":
            return "media_type"
        if len(response.body) > MAX_RESPONSE_BYTES:
            return "byte_limit"
        if response.final_url != FIXED_URL or response.redirect_chain:
            return "redirect"
        if response.used_proxy or response.sent_cookie or response.used_credentials:
            return "transport_disclosure"
        if not response.tls_hostname_valid or not response.tls_certificate_valid:
            return "tls_validation"
        if response.resolved_address_class != "global_unicast":
            return "address_class"
        if not response.response_framing_valid or response.authentication_challenge:
            return "response_framing"
        return None


class PublicResearchRestartVerifier:
    """Verify saved citation metadata and fence a consumed scope from implicit refetching."""

    def __init__(self, paths, authority_root, schemas) -> None:
        self.paths = paths
        self.schemas = schemas
        self.receipts = PublicResearchReceiptVerifier(paths, authority_root, schemas)

    def verify_scope(self, scope_receipt_id: str) -> dict[str, object]:
        scope, scope_manifest = self.receipts.load_verified(
            scope_receipt_id, purpose="public_research_scope"
        )
        events = CaseSessionRuntime(self.paths, self.schemas).semantic.read_all()
        matching = [
            event for event in events
            if event["event_type"] == "public_research.citation_captured"
            and event["payload"].get("citation", {}).get("scope_receipt_id") == scope.receipt_id
        ]
        if len(matching) > 1:
            raise PublicResearchError("scope has more than one citation event")
        if matching:
            citation = matching[0]["payload"]["citation"]
            item, manifest = self.receipts.load_verified(
                citation["item_receipt_id"], purpose="public_item_capture"
            )
            if (
                manifest["scope_receipt_id"] != scope.receipt_id
                or citation["item_id"] != item.subject_id
                or citation["content_sha256"] != manifest["content_sha256"]
                or citation["byte_count"] != manifest["byte_count"]
            ):
                raise PublicResearchError("citation does not match the saved item receipt")
            if scope.schema_version == "2.1" and any(
                manifest.get(field) != scope_manifest.get(field)
                for field in (
                    "execution_component_id",
                    "execution_component_version",
                    "execution_mode",
                    "execution_runtime_root",
                    "execution_t0",
                    "owner_terms_rights_attestation",
                )
            ):
                raise PublicResearchError("execution-bound item receipt changed its scope bindings")
            return {"status": "verified", "event_id": matching[0]["event_id"]}
        consumed = any(
            item.get("public_research_attempt", {}).get("scope_receipt_id") == scope.receipt_id
            for item in OperationalLedger(self.paths, self.schemas).read_all()
            if isinstance(item.get("public_research_attempt"), dict)
        )
        return {"status": "needs_input" if consumed else "unavailable", "scope_receipt_id": scope.receipt_id}
