# ADR-0011: Use versioned embedded work batches and fail-closed semantic readers

- Status: Accepted for S1-C D2 implementation
- Date: 2026-09-11
- Decision owner: Owner-approved S1-C D2 route
- Scope: Canonical work-change batches, semantic event compatibility, reader capability, and
  current-work visibility

## Context

The v1 semantic ledger appends one hash-chained event at a time. Work-item records and status
changes have no revision, batch identity, idempotency binding, trusted receipt reference, or
committed-state watermark. A separate transaction store or log would add a second canonical writer
and an unproven cross-store recovery problem.

S1-C D1 already established that a caller-supplied owner label is not trusted authority. D2 was
explicitly approved to choose the existing-ledger route, but does not authorize a real host,
connector, external service, or broad multi-store transaction protocol.

## Decision

1. Add the semantic event envelope version `2.0` only for the new
   `work_batch.committed` event. V1 event bytes, hashes, schemas, and event semantics remain
   unchanged.
2. Embed the complete immutable work-change proposal, exact owner-receipt envelope, typed
   operations, expected revisions, idempotency key, work receipt ID, and minimum-reader capability
   declaration in that one event. The event's verified hash-chain record is the committed-state
   watermark returned to callers; it is not recursively embedded in its own payload.
3. Use the existing semantic ledger append lock and post-write verification as the single logical
   commit boundary. A proposal has no business-state effect before that append. A failed append or
   prepared in-memory proposal is not committed; the existing corrupt-tail recovery discipline
   remains responsible for interrupted JSONL writes.
4. The v2 reader selects schemas from the envelope version. It upcasts v1 work records in memory by
   assigning their initial visible revision as 1 and each historical status change as the next
   visible revision. Upcasting never rewrites old events or invents an owner receipt.
5. Every v2 batch declares the minimum semantic schema version and runtime reader version. Readers
   reject an unsupported future envelope version or an incompatible capability declaration before
   treating the batch as state. Older readers fail closed when they encounter v2 rather than ignore
   it.
6. A duplicate batch ID or idempotency key returns the existing matching commit receipt; the same
   key with a different proposal digest is rejected. Revision mismatch rejects the whole batch
   before any work state becomes visible.

## Consequences

- Work status can be observed at or after the append's hash watermark without an additional
  canonical store.
- This is deliberately a one-ledger work-batch protocol, not a general transaction framework for
  artifacts, evidence, projections, indexes, or external actions. Those remain later, separately
  designed work.
- Production commits still fail closed until S1-D supplies a real approved receipt verifier. Tests
  use only registered disposable synthetic receipt verifiers.
- A downgrade that cannot read v2 data stops explicitly. It is not a data rollback, and old event
  hashes are never recalculated.
