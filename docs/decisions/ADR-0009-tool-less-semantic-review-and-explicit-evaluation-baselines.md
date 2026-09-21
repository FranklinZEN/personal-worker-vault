# ADR-0009: Keep Semantic Review Tool-less and Bind Evaluation Baselines Explicitly

Status: Owner approved; P5A and P7 remain unauthorized
Date: 2026-09-04

## Context

Vault Next needs qualitative coherence checks, but a reviewer must not silently acquire the ability
to alter the case, decide for the owner, approve an action, or access broader context. Review must
also remain meaningful when an artifact changes or a reviewer is unavailable. Evaluation baselines
must be inspectable rather than silently rewritten after a regression.

## Decision

The P5 implementation uses these boundaries:

1. A reviewer receives only a fixed, versioned review packet. Its policy declares no tools, writes,
   approvals, or decision authority.
2. Packets bind a specific recommendation event, artifact-version content hash, or checkpoint event
   hash. A result for one target does not clear review for a changed target.
3. Review packets include substantive content only when every session record is sensitivity `none`.
   Other sensitivities produce a withheld, non-passing packet; they are not silently exposed.
4. The reviewer is a pure packet-in/result-out interface. A separate runtime coordinator persists an
   immutable result record and may record a coordinator-attributed completion event.
5. Required review blocks final owner decisions and session closure until the latest exact result
   passes or the owner appends an explicit, exact-result waiver for a finding result.
6. Reviewer unavailability is a structured non-pass. It preserves draft state and permits a new
   immutable attempt against the same packet/target hash.
7. Evaluation runs are immutable, synthetic by default, and record routing, event-invariant,
   projection, and reviewer-rubric check digests. Establishing or changing a baseline requires an
   explicit owner-confirmed reviewed-change record.

## Alternatives considered

### Let the reviewer append findings directly to the semantic ledger

Rejected. It blurs analysis with authority and makes reviewer implementation a trusted writer.

### Treat reviewer unavailability as pass for non-destructive work

Rejected. Safe draft capture can continue, but a review-required finalization must remain pending.

### Reuse a prior review whenever a new revision has a similar summary

Rejected. Similar prose does not establish exact artifact or recommendation equivalence.

### Update evaluation baselines whenever a suite changes

Rejected. This would convert failures into unreviewable configuration drift.

## Consequences

- P5 adds immutable review artefacts, coordinator events, waiver handling, and synthetic evaluation
  records without granting any reviewer operational power.
- Review is intentionally withheld rather than redacted ad hoc above synthetic-safe sensitivity.
- A later personal-content review/redaction decision requires an explicitly approved protocol and a
  separate scope authorization; P5 does not provide either.
- Real model integration, prompts, connectors, asynchronous invocation, and review of personal
  material remain outside this ADR and the active P5 authorization.

## Approval boundary

The repository owner authorized the roadmap's exact synthetic-only P5 scope on 2026-09-04. This ADR
records the owner-approved contract; it does not authorize P5A, migration,
personal-content review, model calls, external services, adapters, scheduling, background work, or
draft-governance activation.
