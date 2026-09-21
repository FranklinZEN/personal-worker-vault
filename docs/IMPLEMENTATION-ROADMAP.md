# Vault Next Implementation Roadmap

Status: P5 and P6 approved; P7 remains separately unauthorized
Date: 2026-09-01

## Executive plan

Build the smallest trustworthy kernel first: versioned schemas, typed policy decisions,
crash-safe append-only ledgers, deterministic projection/replay, synthetic fixtures, and negative
safety tests. Add session/case workflows, universal triage, configurable use-case profiles, dynamic
skill composition,
decision projections, semantic review, and migration only after the kernel proves its invariants.

Do not begin personal-content migration, connectors, scheduling, GUI work, or governed
self-improvement during the core build.

## Engineering operating cycle

Every milestone follows the same instruction loop. This is the default “understand, assess,
develop, test, next step” standard for Vault Next.

### 1. Understand

- Restate the user outcome and relevant acceptance tests.
- Identify canonical data owners and protected operations.
- Inspect current repository state and unresolved findings.
- Declare assumptions, exclusions, and upstream/downstream dependencies.
- Confirm that the change is inside the active phase and approval scope.

### 2. Assess and design

- Threat-model the change, including prompt injection, partial write, attribution, and recovery risks.
- Prefer a vertical slice over broad scaffolding with no demonstrated behavior.
- Write or update an ADR for a hard-to-reverse contract.
- Define schemas/interfaces and failure semantics before implementation.
- Map the change to acceptance-test IDs and add missing negative cases.
- Identify compatibility and migration effect for existing canonical records.

### 3. Develop

- Keep policy, storage, projection, review, and adapter boundaries separate.
- Make invalid states difficult to construct; validate at boundaries.
- Use explicit typed records rather than parsing prose for authority.
- Stage writes, validate, then commit atomically.
- Preserve the valid prefix/state on every failure path.
- Avoid network/runtime dependencies unless approved and justified by a requirement.
- Keep generated views clearly marked and reproducible.

### 4. Test

- Run focused unit and contract tests during implementation.
- Test denial, corruption, interruption, stale approval, wrong actor, and missing model—not only the
  happy path.
- Run affected integration and acceptance scenarios.
- Rebuild projections from an empty output directory.
- Replay accepted fixtures and compare semantic results.
- Verify no command/test targets the protected legacy source or backup for writes.

### 5. Review and decide the next step

- Review the diff against requirements, ADRs, schemas, and guardrails.
- Record known limitations and newly discovered assumptions.
- Run deterministic checks before semantic review.
- Resolve or explicitly owner-waive required findings; do not hide them in prose.
- Update architecture/model/roadmap only when implementation evidence changes them.
- Stop at the milestone gate and request approval for scope expansion or protected data use.

## Cross-cutting engineering standards

### Repository discipline

- Keep the repository local until explicitly approved otherwise.
- Use a small, documented source tree; no generated dependency/vendor trees committed by default.
- Pin approved dependencies and record their purpose.
- Keep fixtures synthetic unless a redacted case has explicit approval.
- Make every local command non-interactive or fail with a clear recovery message.
- Never rely on the current working directory to identify a destructive target; resolve and validate
  exact paths.

### Contract discipline

- Version every canonical schema and active triage/profile/skill/framework package.
- Do not rewrite canonical events to adopt a new schema; use readers/upcasters.
- Define stable error/reason codes for policy and validation failures.
- Bind approval to a canonical proposal digest and exact target set.
- Treat event types and projection semantics as public contracts requiring compatibility tests.

### Testing discipline

- Safety invariants require direct negative tests, not coverage-by-incidental-execution.
- Policy, actor authority, hash chaining, event folds, and protected-path checks require complete
  decision-branch test mapping.
- Aim for at least 90% branch coverage in the safety kernel while treating acceptance behavior as
  the real release bar.
- Property tests cover append-prefix preservation, ID uniqueness, approval non-reuse, deterministic
  replay, and supersession acyclicity.
- Time, randomness, and model output are injectable so tests remain reproducible.
- Test reports include tool/runtime/schema versions and fixture hashes.

### Review discipline

- Deterministic validation runs before semantic review.
- The semantic reviewer has no tools and cannot mutate, approve, or decide.
- A changed reviewed artifact hash requires a new review.
- High-severity findings block only the configured promotion/finalization, not safe provisional
  capture.
- Baseline changes require a reasoned review; never update a baseline solely because a test failed.

### Observability and recovery

- Structured safe logs use correlation IDs but avoid raw sensitive content.
- Every canonical write reports its resulting ID/hash.
- Every protected operation has a policy/audit record, including denials.
- Recovery procedures are automated and tested before personal data enters the system.
- No operation reports success before post-write verification completes.

## Dependency map

```text
P0 Planning foundation
  |
  v
P1 Contracts + safety kernel
  |
  v
P2 Case/session runtime
  |
  v
P3 Triage + profiles/skills
  |
  v
P3A Interaction-first contracts
  |
  v
P4 Projections
  |
  v
P5 Review + evaluation
          |
          v
P5A Personal use-case profile program
          |
          v
P6 Migration tooling
          |
          v
P7 Redacted pilot + migration wave
          |
          v
P8 Core cutover + thin adapters
          |
          v
Post-core evidence-driven improvement automation
```

P3A is a design-gated amendment that extends P2/P3 before P4 proceeds. Personal migration cannot
begin before P5 and P6 gates pass.

## P0 — Planning foundation

### Scope

- Product strategy and success criteria.
- Architecture candidates and recommendation.
- Decision/case/event model.
- Migration plan.
- Acceptance specification.
- Foundation ADR.
- Draft governance.
- Universal triage, layered use-case profile, dynamic fallback, and dedicated profile/skill lifecycle
  contracts.
- Ordered implementation roadmap.

### Completion gate

- All Phase 0 documents agree on terminology, ownership, permissions, and source/view boundaries.
- Phase 1 scope is explicit.
- No production feature code or personal corpus has been introduced.
- Owner reviews the five consequential design decisions and governance draft.

### Current status

Accepted as the implementation foundation. The governance document remains a separately inactive
draft, and migration remains unauthorized.

## P1 — Contracts and safety kernel

### Approval record

The repository owner authorized this exact Phase 1 scope in the Vault Next Codex conversation on
2026-09-01, using synthetic fixtures only. The authorization does not include legacy personal-content
reads or migration, real profile activation, draft-governance activation, external services,
remotes, or model-driven routing.

### Implementation status

The authorized deliverables are implemented and the deterministic Phase 1 verification suite passes.
See `docs/PHASE-1-EVIDENCE.md`. The owner approved that evidence on 2026-09-01 and separately
authorized the exact synthetic-only Phase 2 scope recorded below.

### Goal

Prove the smallest end-to-end trusted write: a synthetic question produces validated canonical
events, policy/audit records, and a deterministic projection that survives replay and corruption
tests.

### Authorized content scope

Synthetic fixtures and Phase 0 documents only. No legacy personal-content reads beyond separately
approved structural checks; no personal migration; no model call required.

### Deliverables

1. Python package/CLI skeleton with supported-version declaration.
2. Repository layout for schemas, synthetic fixtures, events, audit, staging, and generated
   projections.
3. ADRs resolving ULID versus UUIDv7, canonical JSON hashing, partition format, locking, and schema
   validation dependency.
4. Versioned schemas for:
   - event envelope and minimal Phase 1 event payloads;
   - operational audit record;
   - approval and policy proposal/result;
   - minimal case/session identity and manifest snapshot;
   - projection metadata.
5. Minimal versioned `TriagePlan`, profile precedence/lifecycle metadata, and immutable future
   profile/skill/framework active-version pointers; no real profile activation in P1.
6. Stable typed reason/error codes.
7. ID/time/canonicalization utilities with deterministic tests.
8. Policy engine covering protected paths/classes, exact-scope approval, and default-deny external
   actions.
9. Crash-safe semantic and operational ledger append with local writer lock, tail validation, and
   hash chaining.
10. Deterministic validator for schemas, references, actor authority, approval match, and protected
   paths.
11. Minimal event fold plus a generated session/trace projection.
12. Synthetic fixture builder and test harness.
13. Recovery/quarantine flow for malformed or partial tail records.
14. Local developer commands for format/lint/type/test/acceptance without network access after
    dependencies are installed.
15. Updated README with exact local verification instructions and generated-path warnings.

### Minimal Phase 1 event types

- `case.created`
- `question.recorded`
- `triage.completed`
- `session.started`
- `recommendation.issued`
- `owner_decision.recorded`
- `approval.granted` / `approval.denied`
- `action.proposed`
- `session.closed`
- `event.correction_recorded`

These types prove actor authority and append semantics; broader taxonomy waits for later milestones.

### P1 acceptance gate

Required acceptance scenarios:

- AT-007 — recommendation cannot become owner decision implicitly;
- AT-010 — correction preserves history;
- AT-012/AT-013 — denial and exact-scope approval;
- AT-014/AT-015 — malformed/interrupted append safety;
- AT-018 — projection rebuild/tamper detection;
- AT-019 — operational/semantic separation;
- synthetic protected-path subset of AT-020/AT-021.

Additional gates:

- zero unresolved safety-kernel failures;
- valid ledger prefix survives every injected failure;
- clean projection rebuild is semantically equivalent;
- all write targets resolve under Vault Next and never under either protected legacy root;
- no dependency or command requires an external service at runtime;
- owner reviews P1 evidence before P2.

### Explicit P1 deferrals

- no complete triage engine, profile/skill catalog, phrase resolver, or model router;
- no committee/brainstorming runtime;
- no semantic reviewer invocation;
- no complete decision memo/case journal;
- no legacy content transformer;
- no platform adapter;
- no scheduler, connector, GUI, vector retrieval, or self-improvement.

## P2 — Case and session runtime

### Approval record

The repository owner approved the Phase 1 evidence and authorized this roadmap's exact synthetic-only
Phase 2 scope in the Vault Next Codex conversation on 2026-09-01. The authorization excludes Phase 3
triage/profile composition, real profiles or skills, model calls, semantic review, migration,
personal-content access, external services, and draft-governance activation.

### Goal

Make case continuity and session lifecycle first-class, independent of chat memory.

### Deliverables

- Full case/session manifest schemas and state machine.
- Explicit context authorization and sensitivity propagation.
- Scope-change, block, abandon, no-decision, close, and resume-as-new-session behavior.
- Evidence metadata registration using synthetic content-addressed objects.
- Full core reasoning event types for assumptions, alternatives, disagreements, and recommendation
  revisions.
- Current-state folds for cases, sessions, and decisions.
- Manifest and context provenance report.

### Dependencies

P1 schemas, append, policy, validator, and recovery are stable.

### Implementation status

The authorized deliverables and structured completion gate are implemented using synthetic fixtures
only. See `docs/PHASE-2-EVIDENCE.md`. The owner subsequently approved that evidence and separately
authorized the exact synthetic-only Phase 3 scope recorded below.

### Completion gate

- AT-007 through AT-010 pass at the structured event/state level; full decision-memo rendering from
  AT-006 remains a P4 gate.
- AT-009 passes in a fresh process with no chat history.
- Every loaded context reference appears in the manifest.
- Invalid lifecycle transitions are rejected without canonical mutation.

## P3 — Universal triage, use-case profiles, and governed composer

### Approval record

The repository owner approved the Phase 2 evidence and authorized this roadmap's exact
synthetic-only Phase 3 scope in the Vault Next Codex conversation on 2026-09-02. The authorization
excludes Phase 4 projections, real/personal profiles or skills, model calls, semantic-review model
execution, migration, personal-content access, external services, and draft-governance activation.

### Goal

Implement a single triage path that applies explicit/inferred profiles when useful and dynamically
composes skills when none fits. Replace one-skill-per-session with a testable minimal-sufficient
composition policy. Use synthetic packages only in this milestone.

### Deliverables

- Canonical triage, profile-, skill-, and framework-package contracts plus immutable version and
  active-pointer behavior.
- `TriagePlan` generation across explicit shortcut, recognized phrase, inferred profile, and dynamic
  composer fallback.
- Layered configuration precedence: governance, owner defaults, family profile, named profile, safe
  session inference, and explicit owner override.
- Profile initialization contract: planning checklist, case behavior, review profile, output
  contract, permissions, and completion conditions.
- Broad synthetic family profiles plus the general dynamic route; no exhaustive taxonomy.
- Approved initial synthetic skills covering comprehension, option design, synthesis, and red team.
- Synthetic named profile shortcuts that exercise phrase recognition and automatic initialization without
  embedding real personal content.
- Catalog index generator and validator.
- Composer work-unit coverage, overlap/conflict, unique-contribution, and permission checks.
- Framework execution for specialist, committee, brainstorming, consultation, synthesis, and red team.
- Owner override event and manifest update flow.
- Routing evaluation fixtures and adjudication tool.
- Candidate lifecycle enforcement: design review evidence, evaluation result, exact approval,
  activation, suspension, and deprecation events/pointers.

### Completion gate

- AT-001 through AT-005 pass.
- AT-011, AT-023, AT-026 through AT-029 pass.
- An unapproved triage/profile/skill/framework version cannot match or execute.
- Every selected contribution is attributable and reviewable.
- No persistent-agent or platform-specific memory dependency appears.
- A behavioral edit cannot mutate an active package or bypass candidate replay/owner approval.

### Implementation status

The authorized synthetic-only deliverables and completion gate are implemented. Structured evidence,
deterministic hashes, acceptance results, negative checks, and known limits are recorded in
`docs/PHASE-3-EVIDENCE.md`. That evidence remains technically valid for the original scope. The
approved interaction-first amendment is implemented and evidenced in `docs/PHASE-3A-EVIDENCE.md`;
the combined Phase 3/P3A evidence was approved on 2026-09-04. P4 was then separately authorized and
is evidenced in `docs/PHASE-4-EVIDENCE.md`.

## P3A — Interaction-first session and working-artifact contracts

Status: Owner approved together with Phase 3; P4 subsequently authorized.

### Approval record

The repository owner approved the interaction-first design and ADR-0008 and authorized this
roadmap's exact synthetic-only P3A scope in the Vault Next Codex conversation on 2026-09-03. The
authorization excludes P4, personal profiles/content, model calls, external services, scheduling,
background work, platform adapters, migration, and draft-governance activation.

### Goal

Make collaborative exploration, mode changes, artifact review/revision, and repository-local current
work first-class contracts before building their human-readable projections.

### Dependencies

Approved `INTERACTION-FIRST-WORK-MODEL.md`, approved ADR-0008, stable P1 integrity contracts, P2
session lifecycle, and P3 triage/composition. The design approval and later P3A implementation
authorization are recorded separately above.

### Authorized synthetic-only deliverables

- Versioned interaction contract in `TriagePlan` and full session manifests, including mode source,
  initiative, artifact/checkpoint policy, completion conditions, and permitted transitions.
- Additive event schemas and actor/reference rules for interaction start/change, owner input,
  checkpoints, artifact versions/feedback/acceptance/withdrawal, and work-item changes.
- Mode-change flow that produces a new complete manifest, governed recomposition, and revalidation of
  context, permissions, framework compatibility, and active package versions.
- Concise checkpoint and owner-input capture sufficient for fresh-process continuity without storing
  hidden chain-of-thought or requiring a full transcript.
- Content-addressed working-artifact metadata, immutable version lineage, exact-hash feedback/review/
  acceptance binding, and current-pointer fold rules.
- Work-item lifecycle and authority rules that distinguish AI proposals, owner commitments, progress,
  waiting, completion, cancellation, and operational actions.
- Deterministic folds and structured read models needed by later artifact-history/current-work
  projectors; no user-facing P4 prose projector in P3A.
- Synthetic positive, near-miss, authority, corruption, replay, and regression fixtures for
  AT-030 through AT-034.

### Completion gate

- Contract and structured-state portions of AT-030 through AT-034 pass with synthetic fixtures.
- All P1, P2, and P3 acceptance and negative regressions remain passing.
- A session can pause/resume with a useful checkpoint and no artifact, decision, or work item.
- Artifact acceptance, owner decision, work commitment, durable-knowledge promotion, and external
  action approval remain independently enforced.
- A mode change cannot rewrite history or expand context, packages, or permissions implicitly.
- A system-proposed work item cannot become committed or done without explicit owner authority.
- Evidence records exact schema/runtime/fixture hashes and known deferrals for P4 and P8.

### Authorization boundary

P3A remains synthetic-only. It excludes personal profile activation, legacy/personal-content reads or
migration, full chat-transcript storage, model calls, external services, scheduling, background work,
platform adapters, and draft-governance activation.

### Implementation status

The authorized deliverables and structured P3A completion gate are implemented. Deterministic
results, hashes, negative checks, and deferred P4/P8 assertions are recorded in
`docs/PHASE-3A-EVIDENCE.md`. P4 was later separately authorized and is evidenced in
`docs/PHASE-4-EVIDENCE.md`. P5 was separately authorized later and is evidenced in
`docs/PHASE-5-EVIDENCE.md`; P5A remains unauthorized.

## P4 — Decision and case projections

Status: Owner approved; P5 subsequently authorized.

### Approval record

The repository owner approved the combined Phase 3/P3A evidence and authorized this roadmap's exact
synthetic-only P4 scope in the Vault Next Codex conversation on 2026-09-04. The authorization
excludes personal profile/content access, migration, model calls, external services, scheduling,
background work, platform adapters, and draft-governance activation.

### Goal

Produce usable decision memos, case journals, working-artifact histories, and current status from
canonical records.

### Deliverables

- Complete event folds and correction/supersession behavior.
- Decision memo projector with as-of-decision and current-outcome separation.
- Case journal and current-status projectors.
- Interaction-journey and checkpoint rendering with owner/model attribution.
- Working-artifact history with version comparison, feedback disposition, review state, and exact
  accepted-version identification.
- Repository-local current-work and “today” views covering explicit work items, blockers, reviews,
  accepted artifacts awaiting next steps, and source watermarks.
- Provenance report and source-watermark verification.
- Generated-file edit/tamper detection.
- Projection semantic/golden test suite.

### Completion gate

- AT-006, AT-008, AT-010, AT-018, AT-019, AT-025, and the projection portions of AT-032 and AT-033
  pass.
- No load-bearing claim lacks source or explicit inference/assumption label.
- Clean rebuild from empty projection directories is equivalent.
- Generated views clearly identify themselves and cannot be promoted by direct edit.

### Implementation status

The authorized deliverables and structured P4 completion gate are implemented. The runtime produces
hash-bound, provenance-labelled Markdown decision memos, case journals, working-artifact histories,
and current-work views. Generated-file edits are detected, quarantined, and replaced only by a clean
rebuild. A narrowly scoped owner-only `outcome.assessed` event separates later result/process review
from the historical owner decision. Deterministic evidence, negative checks, and known limits are
recorded in `docs/PHASE-4-EVIDENCE.md`. The owner approved P4 evidence on 2026-09-04 and separately
authorized P5, which is implemented and evidenced below.

## P5 — Semantic review and evaluation foundation

Status: Owner approved; P5A and P7 remain unauthorized.

### Approval record

The repository owner approved Phase 4 evidence and authorized this roadmap's exact synthetic-only P5
scope in the Vault Next Codex conversation on 2026-09-04. The authorization excludes personal
profile/content access, migration, model calls, external services, scheduling, background work,
platform adapters, and draft-governance activation.

### Goal

Add qualitative guardrails and regression replay without granting the reviewer authority.

### Deliverables

- Fixed review-packet schema and sensitivity rules.
- Exact-version working-artifact and checkpoint review packets, with latency/failure behavior that
  does not seize control of the live conversation.
- Tool-less semantic reviewer interface and structured finding schema.
- Reviewer unavailability, retry, waiver, and reviewed-hash behavior.
- Synthetic evaluation fixture registry, baselines, run reports, and adjudication workflow.
- Regression runner across routing, event invariants, projections, and reviewer rubrics.
- First approved redaction protocol; no historical case enters until separately authorized.

### Completion gate

- AT-016 and AT-017 pass.
- Full synthetic core suite passes.
- Reviewer cannot access tools, write state, approve, or decide.
- Baseline changes require explicit reviewed change records.
- One synthetic end-to-end case replays from question through outcome.

### Implementation status

The authorized P5 foundation is implemented and owner-approved. Fixed review packets, immutable result/waiver records,
exact reviewed-hash enforcement, non-passing unavailability/retry handling, synthetic regression
reports, and review-bound evaluation baselines are recorded in `docs/PHASE-5-EVIDENCE.md`. The
redaction protocol is owner-approved as inactive governance only, pending a separate exact
owner/source/purpose P7 authorization. P5A and P7 remain unauthorized.

## P5A — Personal use-case profile program

### Goal

Build and prioritize real owner-facing profiles one at a time through the dedicated lifecycle, after
triage/composer and evaluation/review foundations are proven. This is an extensible library program,
not a fixed four-profile delivery commitment.

### Initial prioritization

1. Establish global owner defaults and the general dynamic route.
2. Establish broad family profiles where they demonstrably reduce repeated setup.
3. Choose the highest-value named profile from the seed examples—`deep-dive`, `meeting-prep`,
   `interview-prep`, `resume`—or another owner-prioritized case.
4. Add subsequent profiles only when saved setup, consequence, or consistency justifies maintenance.

Each profile is a separate candidate/review/approval decision. Approval of one does not authorize
others, and implementation may stop when measured value does not justify the next.

### Deliverables per profile

- owner-confirmed purpose, phrase set, non-purpose, default interaction mode, artifact policy,
  completion conditions, and allowed mode behavior;
- complete profile contract and resolved skill/framework candidates;
- positive, near-miss, adversarial, missing-input, case-context, interaction-mode, mode-change,
  override, and permission fixtures;
- deterministic, semantic, red-team, and usability evaluation report;
- known limitations, monitoring signals, rollback/suspension plan;
- exact owner approval for candidate digest and active pointer.

### Completion gate per profile

- AT-026 passes for that profile’s accepted shortcut/phrase fixture family;
- AT-027 passes for its build, activation, and change-control path;
- AT-028 and AT-029 remain passing so catalog growth never removes dynamic fallback or changes
  configuration/permission precedence;
- AT-030 and AT-031 pass for the profile's default and permitted interaction behavior;
- all dependent routing, authority, provenance, and review tests pass;
- the profile starts from familiar language or inferred use-case intent without a redundant
  skill-selection question;
- actual resolved skills/framework and case context remain explicit in the manifest;
- no protected read, write, decision, or action permission is implied by invocation;
- owner accepts the interaction cost and output standard.

## P6 — Migration tooling

Status: Owner approved; P7 remains separately unauthorized.

### Authorization record

The repository owner requested Phase 6 start in the Vault Next Codex conversation on 2026-09-04 and
approved its evidence on 2026-09-04.
Work is limited to the roadmap's synthetic legacy-tree scope. Phase 5 evidence and the candidate
redaction protocol were pending owner review during P6 development; both are now approved, with the
protocol remaining inactive governance only. Neither protected legacy root was in scope for P6
development and neither is in scope for P7 without a separate exact authorization.

### Implementation status

The authorized synthetic-only P6 migration laboratory is implemented and evidenced in
`docs/PHASE-6-EVIDENCE.md`. It refuses unmarked sources before discovery, uses staging-only dry runs,
does not mutate canonical stores, and exposes a proposal-only pilot interface requiring normal policy
approval. P7 remains unauthorized.

### Goal

Implement read-only discovery, deterministic dry-run mapping, validation, exception reporting, and
logical rollback using synthetic legacy trees.

### Deliverables

- Protected-root deny-write enforcement at process and application layers.
- Snapshot manifest and nested-repository discovery.
- Mapping rule engine and disposition reconciliation.
- Mapping rules for historical artifacts and tasks as attributed history; no import rule may infer
  an active owner commitment or artifact acceptance from prose alone.
- Staging-only transformation runner.
- Provenance map, exception model, fidelity report, and rerun comparison.
- Exact-copy hash validation and transform golden tests.
- Pilot-commit interface that uses the normal policy/ledger kernel.
- Rollback/deactivation rehearsal.

### Completion gate

- AT-020 and AT-021 pass across normal and hostile synthetic fixtures.
- Synthetic subset of AT-022 passes.
- Zero source/backup mutations in fault injection.
- Every source item receives one disposition/error.
- Dry run is deterministic and canonical stores remain untouched.

## P7 — Redacted pilot and migration wave

Status: Not authorized. A completed and explicitly approved
[`P7 pilot authorization request`](P7-PILOT-AUTHORIZATION-REQUEST.md) is required before any P7
implementation or source access.

### Goal

Prove the system on a tiny explicitly approved sample before any corpus-scale migration.

### Recommended pilot order

1. Transform one legacy skill into an inactive candidate and run the full dedicated lifecycle
   evaluation without assuming legacy approval transfers.
2. Import one fully redacted historical case as non-authoritative history.
3. If attribution can be verified, promote one owner decision through explicit review.
4. Rebuild its decision memo and case journal.
5. Run one interactive continuation, one artifact revision/acceptance journey, and one current-work
   review using only explicitly approved redacted material.
6. Run rollback and rerun the same import for idempotency.

### Completion gate

- AT-022 passes on the approved redacted fixture.
- No unresolved high-severity migration/reviewer finding remains.
- Owner confirms attribution, sensitivity, and projection usefulness.
- Repeat import produces `already_imported`, not duplicates.
- Rollback/recovery and local backup restore pass.
- Owner approves or declines the next wave; no automatic expansion.

## P8 — Core cutover and thin platform adapters

### Goal

Make Vault Next the active system for explicitly approved workflows and expose the same canonical
contracts to Codex and ChatGPT Work.

### Deliverables

- Active approved governance at root after owner sign-off.
- Cutover checklist, local backup/restore runbook, and observation-period policy.
- Thin Codex and ChatGPT Work packet adapters.
- Live controls/packets for mode change, owner feedback, exact artifact acceptance, session pause/
  resume, and status-review entry.
- Adapter parity tests and failure/timeout behavior.
- Approved subset of active cases/skills/knowledge.
- Core operational handbook.

### Completion gate

- AT-024, AT-034, and the full core suite pass under both adapters.
- Legacy source and backup remain untouched.
- Owner approves the active workflow list and effective time.
- Rollback to legacy read-only operation is demonstrated.
- No external connector, remote, or scheduler is added implicitly.

## Post-core — Evidence-driven improvement automation

### Entry condition

Core operation and migration are stable, representative replay cases exist, and the owner approves a
separate system-initiated improvement design. Manual profile/skill candidate build and review already
use the core lifecycle.

### Workflow

`gap detected → candidate skill/framework → sandbox → replay evaluation → human approval → active → monitored → merge, revise, or deprecate`

### Guardrails

- Candidate cannot modify its own tests, baseline, promotion status, or active version pointer.
- Evaluation includes regression and adversarial cases, not only the gap that prompted it.
- Promotion approval binds candidate digest, evaluation run, and activation target.
- Monitoring compares expected and realized behavior; rollback is a first-class outcome.
- Governance/permission/identity changes remain outside skill self-improvement.

## Risk register

| Risk | Earliest signal | Mitigation | Stop/revisit trigger |
|---|---|---|---|
| Event model is too heavy for use | Session capture routinely bypassed or manually repaired | Automate mechanical capture; keep low-value events out | Owner cannot complete pilot cases without ceremony |
| File ledger performance fails | Validation/replay exceeds budgets | Partition/index; profile before redesign | Measured threshold fails twice on representative corpus |
| Projection hides important path | Acceptance/reviewer omissions | Trace matrix and materiality rules | Any owner decision cannot be reconstructed |
| Approval fatigue | Blanket approvals or repeated overrides | Consequence-based classes and exact diffs | Protected controls are routinely bypassed |
| Reviewer is noisy or authoritative | High false-positive rate or unreferenced findings | References, calibration, no tools/writes | Reviewer blocks usefulness without measurable value |
| Router over-composes | Average selected skills rises without quality gain | Minimality evaluation and per-skill contribution | Routing precision below target |
| Migration imports stale/false state | High ambiguity/exceptions | Quarantine and owner verification | Current-status attribution cannot be verified |
| Private data leaks to reports | Sensitive strings appear in low-sensitivity audit/report | Digest/safe summary and sensitivity propagation | Any unauthorized disclosure |
| Scope expands into platform work | New infrastructure not tied to acceptance test | Explicit deferral policy | Maintenance budget exceeds demonstrated value |
| Platform adapters diverge | Different skill/decision semantics | Shared normalized packets and parity tests | AT-024 fails |

## Explicit core deferrals

| Capability | Reason deferred | Reconsideration trigger |
|---|---|---|
| OpenWorker runtime | Not required and conflicts with canonical vault objective | No planned trigger in core |
| Connectors/MCP | External authority/privacy surface | Explicit approved use case after core |
| Scheduler | Native scheduled tasks are the stated later initiator | Approved routine after core |
| Custom GUI | Contracts and workflows must stabilize first | CLI/Markdown demonstrably blocks adoption |
| Vector database/RAG | Premature complexity | Retrieval acceptance/performance failure |
| Multi-user/concurrent writer | Single-owner core | Explicit collaboration requirement |
| Persistent agent teams/boards | Temporary frameworks cover composition | Measured framework inadequacy |
| Remote Git/publishing | Local-only safety boundary | Explicit owner approval and privacy plan |
| Autonomous self-modification | Violates authority model | Never; only governed candidate promotion |

## Five consequential implementation decisions

1. **Hybrid append-only ledger plus Markdown projections**, not Markdown-only state or a binary
   database as the initial canon.
2. **Explicit owner-decision events**, never inferred from recommendation, conversation tone, or
   action success.
3. **Universal triage plus configurable profiles and minimal governed composition**: recurring work
   receives prepopulated defaults, novel work remains dynamic, and actual skills/frameworks remain
   explicit.
4. **Separate semantic and operational ledgers**, connected by IDs but owned by different concerns.
5. **Synthetic-first, dry-run-first migration**, with personal content gated until the full safety,
   review, replay, and rollback foundation passes.

## Assumptions that could change the plan

- Multiple concurrent writers would push the store toward transactional database infrastructure.
- A requirement to verify records across untrusted machines would require signatures/key management.
- A very large searchable corpus with measured recall failure could justify an indexed or vector
  retrieval layer.
- Inability to capture explicit owner decisions in the platform interaction would require a separate
  local confirmation workflow before any decision becomes canonical.
- Rejection of generated, non-editable projections would favor a more document-centric architecture
  with weaker deterministic guarantees.

## Questions and approvals

No unresolved product question blocks writing Phase 1 contracts. The binding gate is explicit owner
approval of the Phase 1 scope and architecture direction.

The following choices block later personal migration, not Phase 1:

- source working-tree snapshot and sensitive read scope;
- verified owner-decision attribution in legacy records;
- Vault Next local backup/restore policy;
- governance activation;
- redacted pilot fixture approval.
- prioritization criteria and first personal use-case profile(s); the seed examples are not a closed
  catalog or mandatory fixed order.

## Approved Phase 1 scope statement

The owner authorized this exact scope on 2026-09-01:

> Build the local Python contracts and safety kernel using synthetic fixtures only: versioned
> schemas, ID/hash utilities, typed policy and exact-scope approvals, separate append-only semantic
> and operational ledgers, deterministic validation, minimal projection/replay, corruption recovery,
> minimal versioned TriagePlan/profile precedence and lifecycle metadata for future
> profile/skill/framework packages, and the listed Phase 1 tests. Do not build or activate real
> personal profiles, read or migrate personal legacy
> content, activate the draft governance, connect external services, create a remote, or implement
> model-driven routing.

Any broader work requires a new scope decision.
