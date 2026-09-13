"""Authority-neutral exact policy material for immutable v3 work transactions."""

from __future__ import annotations

from typing import Any

from vault_next.contracts import work_transaction_source_ref, work_transaction_targets
from vault_next.policy import Proposal
from vault_next.records import RUNTIME_ACTOR


def policy_proposal_for_transaction(
    manifest: dict[str, Any], *, approval_ref: str | None = None
) -> Proposal:
    """Return the one protected proposal an authority receipt must bind exactly."""

    return Proposal(
        operation_class="commit",
        targets=work_transaction_targets(manifest),
        consequence_class="owner_decision",
        actor_id=RUNTIME_ACTOR["id"],
        source_refs=(work_transaction_source_ref(manifest),),
        approval_ref=approval_ref,
    ).finalized()
