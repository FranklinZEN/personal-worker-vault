# Vault Next Phase 2 Evidence

Status: Owner approved; Phase 2 gate closed  
Evidence date: 2026-09-02  
Scope: Exact roadmap Phase 2 scope, synthetic fixtures only

## Verdict

The technical Phase 2 gate passes. Case and session continuity is reconstructible from canonical
repository records without chat memory; invalid lifecycle changes fail before canonical append;
context loading is explicit and sensitivity-bounded; synthetic evidence is content-addressed; and
decision/recommendation history is folded without rewriting earlier events.

The repository owner approved this evidence and separately authorized the roadmap's exact
synthetic-only Phase 3 scope on 2026-09-02. That authorization does not activate draft governance,
authorize personal-content access or migration, or authorize external services.

## Authorized boundary observed

- Only invented identifiers, prose, event content, and evidence bytes were used.
- No content was read from the protected legacy source or rollback backup.
- No legacy location was written, moved, renamed, cleaned, or deleted.
- No remote, network service, connector, scheduler, model call, or external transmission was used.
- `docs/governance/AGENTS-v2-DRAFT.md` remains inactive.
- Phase 3 triage/profile composition and real skill/profile activation were not started.

## Delivered contracts and behavior

| Roadmap deliverable | Evidence |
|---|---|
| Full case/session manifests | Strict schemas plus complete event-embedded snapshots and SHA-256 digests |
| Case/session state machine | Pure folds with explicit transition tables; closed/abandoned sessions freeze |
| Context authorization | Exact per-reference allowlist, same-case restriction, and sensitivity-union checks |
| Lifecycle operations | Scope change, block/unblock, abandon, no-decision, close, and resume as a new session |
| Synthetic evidence | Immutable SHA-256-addressed objects with strict metadata and repository validation |
| Reasoning history | Assumptions, alternatives, disagreements, recommendation revisions/withdrawal |
| Current state | Deterministic case, session, decision, and reasoning folds |
| Provenance | Manifest chains, context provenance reports, event refs, and source event IDs |

ADR-0006 records the key Phase 2 contract: full manifest snapshots live in immutable semantic events;
generated views remain replaceable projections; context is explicitly authorized; and a terminal
session resumes only by creating a linked new session.

## Lifecycle guardrail

Accepted case transitions are:

- `open → dormant | closed`
- `dormant → open | closed`
- `closed → reopened`
- `reopened → open | dormant | closed`

Accepted Phase 2 session transitions are:

- `draft → routed | abandoned`
- `routed → authorized | abandoned`
- `authorized → active | blocked | abandoned`
- `active → review_pending | blocked | closed | abandoned`
- `review_pending → closed | blocked | abandoned`
- `blocked → active | closed | abandoned`

The Phase 1 direct `session.started → active` form remains readable as a compatibility rule. It does
not provide an alternate Phase 2 creation path. Tests prove that an invalid transition leaves the
canonical ledger byte-for-byte unchanged and that a terminal session cannot be mutated.

## Acceptance results

| Gate | Result | Structured evidence |
|---|---|---|
| AT-007 | Pass | A recommendation plus ambiguous agreement closes as `no_decision`; no owner-decision event exists |
| AT-008 | Pass | Explicit replacement links two owner decisions; original event bytes remain; current fold selects the replacement; cycles fail before append |
| AT-009 | Pass | A separate Python process reconstructs only three manifest-authorized prior events; unrelated-case content is absent |
| AT-010 | Pass | Phase 1 correction regression remains green; original event bytes survive and projection shows effective corrected values |
| Every loaded ref is in manifest | Pass | Loader uses exact allowlist membership and provenance report equality is asserted |
| Invalid lifecycle does not mutate canonical data | Pass | Pre/post canonical ledger bytes are equal for invalid transition and supersession-cycle tests |

The full decision-memo rendering portion of AT-006 remains intentionally deferred to Phase 4, as the
approved roadmap specifies.

## Verification record

The compliant workspace runtime was Python `3.12.13`; Vault Next reports tool version `0.2.0`.

```text
make verify PYTHON=python3

format-check: pass
lint: pass
typecheck/schema-load: pass
full test discovery: 39 passed
acceptance discovery: 20 passed (12 Phase 1 regression, 8 Phase 2)
```

The Phase 2 synthetic fixture is executed twice by an automated determinism test and must produce an
identical result record. Its clean validator result contains 22 semantic events, zero operational
records, and four generated projections (two session traces and two context reports).

| Evidence value | SHA-256 |
|---|---|
| Semantic fixture | `27ee317042896e0639593f9bf9a4491fb1535448d045af5d3abe174609edc8ad` |
| Operational fixture (canonical empty list) | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Synthetic evidence object | `8fcd9daebe93d4eeebcace005156bb95ac50cb40f2f8c1abe4ff77c5e3d90d8f` |
| First session projection | `a9f9b6b3bbef87e89fa880a4d3095ccf1a17306ec54829b6c6c3ea7d1bc45610` |
| Second session projection | `56fb60bfc2ec7f5cd635276cb74b5f98a1982fe53cbf14463e9ef603fccd35fe` |
| First context report | `f6d860a6073594c3aba684abb925964419ccd3dafd24aabfc5c9a88a286c564f` |
| Second context report | `3814e49d5bf58066cb1ff2c62b2c11e898f27fddbc647f44bd4760f29535d890` |

The operational hash is the expected canonical hash of an empty list because the Phase 2 fixture
performs no external or protected operation. Phase 1 continues to cover policy/audit behavior.

## Negative and coherence checks

- Unknown, malformed, cross-case, and over-sensitive context references fail closed.
- Evidence byte count and hash are revalidated; orphan objects are reported.
- Every active event type has a checked-in payload schema.
- Manifest identity, digest, prior digest, and exact version increment are validated before append.
- Owner decisions and revisions require owner actor attribution and explicit confirmation.
- Decision supersession requires both decisions to exist and cannot form a cycle.
- Reasoning revisions require an existing object; recommendation revisions increment exactly once.
- Current session projections include reasoning state and both historical/current decision state.
- All Phase 1 concurrency, crash-tail, recovery, policy, authority, projection, and protected-path
  tests remain green.

## Known limits and next decision

Phase 2 intentionally does not provide universal triage, profile matching, dynamic skill composition,
real skills or profiles, model execution, semantic review, complete decision memos/case journals,
migration, personal-data ingestion, connectors, scheduling, or a GUI.

The owner approved this evidence and separately authorized Phase 3. Phase 4 remains unauthorized and
requires a later evidence review and explicit scope decision.
