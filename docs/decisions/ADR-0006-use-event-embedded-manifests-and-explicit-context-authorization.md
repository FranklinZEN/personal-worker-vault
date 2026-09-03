# ADR-0006: Use event-embedded manifest snapshots and explicit context authorization

- Status: Accepted for Phase 2 implementation
- Date: 2026-09-01
- Decision owner: Phase 2 architecture under the approved roadmap
- Scope: Case/session lifecycle, manifest persistence, context loading, sensitivity, and resumption

## Context

Phase 2 must make case and session continuity durable without relying on chat history. An active
session can change scope, but closure must freeze the exact manifest used. Writing a canonical
manifest file and a canonical event as two independent filesystem operations would create a
cross-store partial-commit risk before recovery/reconciliation exists.

Context also needs an inspectable allowlist. A case relationship alone must not authorize loading all
events or evidence in that case, and evidence content must never grant itself permission.

## Decision

1. The canonical case manifest and every session-manifest version are embedded as strict structured
   objects in semantic event payloads and addressed by their canonical SHA-256 digest.
2. `case.created` contains the immutable case manifest. `session.created` contains manifest version
   1 in `draft`. Scope/status changes append a complete next manifest and the prior manifest digest.
   `session.closed` embeds the final complete manifest and its frozen digest.
3. Generated manifest files and provenance reports are replaceable projections. They never become a
   competing canonical store.
4. Session lifecycle is validated as an event fold. Closed and abandoned sessions are immutable;
   continuing work creates a new session with `continues_session_id`.
5. A session manifest contains an explicit context allowlist. The loader returns only requested refs
   that appear in that list and belong to the authorized case/session scope.
6. Sensitivity propagates conservatively as the union of labels from the case, manifest, events, and
   evidence. Loading is denied if the resulting labels exceed the manifest declaration.
7. Phase 2 evidence ingestion accepts invented bytes only. Bytes are stored by full SHA-256 identity;
   metadata records source class, actor, capture time/method, sensitivity, trust, and access policy.
8. Evidence text is data. It cannot change permissions, lifecycle, owner decisions, or routing.

## Lifecycle contracts

Case transitions:

`open → dormant|closed`, `dormant → open|closed`, `closed → reopened`, and
`reopened → open|dormant|closed`.

Session transitions:

`draft → routed|abandoned`, `routed → authorized|abandoned`,
`authorized → active|blocked|abandoned`, `active → review_pending|blocked|closed|abandoned`,
`review_pending → closed|blocked|abandoned`, and `blocked → active|closed|abandoned`.

The Phase 1 `session.started` direct-start form remains readable as an `active` compatibility event,
but new Phase 2 sessions use the complete transition path.

## Consequences

- One append establishes both the semantic transition and exact manifest snapshot.
- Manifest history cannot silently drift from lifecycle history.
- Event payloads are larger, which is acceptable for local structured metadata.
- Fresh-process continuity is testable without chat or hidden model memory.
- A later file representation can be generated without changing canonical ownership.
- Context selection remains explicit even within the same case.
