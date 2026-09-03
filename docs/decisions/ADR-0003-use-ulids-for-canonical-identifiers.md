# ADR-0003: Use ULIDs for canonical identifiers

- Status: Accepted for Phase 1 implementation
- Date: 2026-09-01
- Decision owner: Phase 1 architecture under the approved roadmap
- Scope: Canonical case, session, triage, event, decision, recommendation, action, operation,
  approval, and review identifiers

## Context

Vault Next needs opaque, globally unique identifiers that sort approximately by creation time while
remaining independent of filenames and display names. The Phase 0 model allowed ULID or UUIDv7 but
required one choice before the first canonical record.

## Decision

Use ULID with the canonical prefixes defined in the decision-and-case model. The ULID body is the
26-character uppercase Crockford Base32 encoding of a 48-bit Unix millisecond timestamp and 80 bits
of randomness. A process-local generator increments the random component for calls in the same
millisecond and rejects timestamp rollback rather than emitting misleading order.

Tests may inject time and random bytes. Production generation uses an aware UTC clock and operating
system randomness. IDs are validated in full; shortened forms are display-only.

## Consequences

- IDs sort by generation time without being treated as authoritative event time.
- The implementation needs a small, tested encoder and monotonic factory.
- Clock order is never substituted for ledger order or `occurred_at`/`recorded_at` semantics.
- UUID interoperability, if later needed, uses an explicit mapping rather than changing existing IDs.

## Rejected alternative

UUIDv7 is sound, but Python 3.12 does not provide it in the standard library and the project already
uses ULID-shaped contracts. Selecting ULID avoids an extra dependency and contract churn.
