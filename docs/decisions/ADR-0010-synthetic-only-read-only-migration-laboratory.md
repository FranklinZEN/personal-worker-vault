# ADR-0010: Build Migration Tooling as a Synthetic-Only, Read-Only Laboratory First

Status: Owner approved; P7 remains separately unauthorized
Date: 2026-09-04

## Context

Migration must eventually inspect valuable historical material without treating it as current truth
or damaging either legacy source. The Phase 6 authorization was limited to development with synthetic
legacy trees. P5 and P6 evidence are approved, and the redaction protocol is approved as inactive
governance only; no P7 source access is authorized.

## Decision

1. The P6 migrator accepts a source only when it has an explicit synthetic-fixture marker. It refuses
   ordinary directories, including the protected legacy vault and rollback backup.
2. Discovery is metadata-first and does not follow symlinks. It reports files, directories, binary
   candidates, broken/out-of-scope links, Git metadata, nested repositories, ignored/untracked
   indicators, and read errors as data.
3. Every discovered item receives exactly one disposition or stable exception. Mapping never turns
   prose into an active owner commitment, accepted artifact, owner decision, or governance change.
4. Dry runs write solely below Vault Next's staging root. They create deterministic source snapshots,
   mapping plans, candidate IDs, provenance, fidelity reports, and exact-copy validations without
   changing canonical event, audit, evidence, artifact, package, review, or evaluation stores.
5. Any future pilot-commit command will remain a proposal-only interface until separately approved;
   it must flow through the normal policy and ledger boundaries.
6. Rollback/deactivation is logical and append-only: a run is marked deactivated/quarantined rather
   than deleted or used to mutate its source.

## Consequences

- P6 can prove read-only and deterministic behavior using hostile disposable fixtures now.
- No actual legacy directory is read by P6 development, even for metadata.
- A later redacted pilot needs separate owner approval of Phase 5 evidence, the redaction protocol,
  an exact source/purpose, and a P7 scope; this ADR supplies none of those permissions.
