# Vault Next Phase 3A Evidence

Status: Technical gate passes; awaiting owner review
Evidence date: 2026-09-03
Scope: Exact roadmap P3A scope, synthetic fixtures only

## Verdict

The technical P3A gate passes. Sessions now resolve a first-class interaction contract independently
of their profile, skills, and framework. The runtime supports material owner input and resumable
checkpoints, governed mode-change recomposition, immutable content-addressed artifact versions,
exact-version feedback and owner acceptance, and repository-local work items whose commitment and
status remain under explicit owner authority.

This evidence requests owner review. It does not authorize P4.

## Authorized boundary observed

- The repository owner approved the interaction-first design and ADR-0008, then authorized the
  roadmap's exact synthetic-only P3A scope on 2026-09-03.
- All questions, cases, artifacts, owner statements, tasks, dates, and expected results are invented.
- No content was read from the protected legacy source or rollback backup.
- No personal profile, skill, case, artifact, or task was created or activated.
- No model call, remote, connector, scheduler, adapter, background worker, or external transmission
  was used.
- The governance draft remains inactive, and P4 projections were not started.

## Delivered contracts and behavior

| P3A deliverable | Evidence |
|---|---|
| Interaction contract | Strict mode/source/initiative/artifact/checkpoint/completion/transition schema embedded in current triage plans and full session manifests |
| Mode resolution | Explicit, named-profile, family-profile, safe-inference, and owner-default sources with five supported initial modes |
| Governed mode change | Explicit owner event, prior/new contract and plan hashes, package diff, active-package checks, context/permission revalidation, and new full manifest |
| Material continuity | Owner-attributed input plus concise checkpoint state, complete source watermark, fresh-process allowlisted resume, and transcript/hidden-reasoning field rejection |
| Working artifacts | Content-addressed immutable bytes, numbered lineage, source watermark, prior-version link, addressed-feedback links, change summary, and tamper validation |
| Artifact authority | Feedback and acceptance bind an exact version/hash; model acceptance, wrong hash, duplicate acceptance, and implicit authority fail closed |
| Work items | Separate proposed/open/in-progress/waiting/done/cancelled lifecycle, real-date validation, explicit owner transitions, and no operational permission |
| Current-work read model | Deterministic separation of proposed/committed/terminal work, due/review items, active cases/sessions, accepted artifacts, source IDs, and watermark |
| Adapter-neutral core | Equivalent normalized synthetic journeys produce equivalent core semantics without chat history or adapter-owned state |

The runtime version is `0.4.0`. New canonical IDs cover artifacts, artifact versions, checkpoints,
owner inputs, feedback, and work items. New semantic types are validated by checked-in payload
schemas and ledger-level domain rules, not only convenience APIs.

## Acceptance results

| Gate | Result | Structured evidence |
|---|---|---|
| AT-030 | Pass for P3A | Exploration closes with owner input and a resumable checkpoint but no forced artifact, recommendation, decision, or work item; transcript-shaped state is rejected |
| AT-031 | Pass for P3A | Explore-to-artifact mode change preserves original bytes, recomposes skills/framework, increments the manifest once, and cannot be bypassed by direct manifest amendment |
| AT-032 | Pass for P3A | Three immutable versions prove exact feedback lineage, exact acceptance of version 2, and no floating acceptance to version 3; model and wrong-hash acceptance fail |
| AT-033 | Pass for P3A | Proposed and committed work remain separate, owner transitions rebuild deterministically, reads do not mutate state, and invalid dates/model completion fail |
| AT-034 | Pass for P3A core | Two normalized adapter-labeled journeys produce equivalent core contracts, artifacts, work state, and authority results without adapter memory |

AT-032/AT-033 human-readable projection assertions remain assigned to P4. Actual Codex and ChatGPT
Work adapter parity for AT-034 remains assigned to P8. These deferrals do not weaken the P3A
contract/state gate.

## Verification record

The compliant workspace runtime was Python `3.12.13`; Vault Next reports tool version `0.4.0`.

```text
make verify PYTHON=python3

format-check: pass
lint: pass
typecheck/schema-load: pass
full test discovery: 57 passed
acceptance discovery: 35 passed (12 Phase 1, 8 Phase 2, 10 Phase 3, 5 Phase 3A)
```

The P3A fixture is executed twice by an automated determinism test. Each run activates the existing
20 synthetic packages, creates two sessions, changes interaction mode once, records one checkpoint,
creates and reviews two artifact versions, accepts an exact version, creates and explicitly commits
one work item, closes both sessions without an owner decision, and rebuilds two session traces.

| Evidence value | SHA-256 or stable value |
|---|---|
| Initial triage plan | `8f8793f2a861332c21327172f65e6411500ae0dcfdc640055f88ad92af7fb878` |
| Revised mode-change plan | `1350969746edb62477e2632e427822b984feb62498fd9131205ee4532960f908` |
| Artifact version 1 content | `c5834a5bb4219d01923d97a896e9e045a6bc54214700480f0ae9ffcfffaf81c3` |
| Artifact version 2 content | `551f124f628061992122ffbd6b96aad1273e366f8f44c1bfee04fdd66ec4b50a` |
| Current-work read model | `085c94f7b389ac350ebe173dd8664aa7effcfd0fd3e3a10e0ba6dead2c288f2f` |
| Semantic fixture | `54320235cc08b00419241a9b60efe52fec5fb721af905ce6d0f7ddc8ce5e4743` |
| Operational fixture (canonical empty list) | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Session 1 trace | `128bd1df1d9aee50ac54fecbfa09aab8877453d4c4128f663c163e25835a183a` |
| Session 2 trace | `10a9a8db17aa486f81b3a6239671a8b2845e785a0900d9a0cd1f6176a94e4731` |
| Semantic event count | `36` |
| Operational action count | `0` |

The generated fixture independently validates with zero findings and exactly two projections.

## Negative and coherence checks

- A direct manifest interaction edit without its matching canonical interaction event is rejected
  before append.
- A mode change must begin from the current plan/contract, name a permitted new mode, preserve the
  package diff, use active packages, and carry explicit owner attribution.
- Checkpoints reject fields that would make a transcript or hidden reasoning canonical.
- Artifact versions reject missing/non-current parents, unknown feedback, duplicate IDs, invalid
  source watermarks, changed content hashes, and disallowed artifact policy.
- Artifact bytes are checked for exact hash/size; tampering is reported without changing events.
- Artifact feedback, acceptance, and withdrawal require explicit owner attribution and an existing
  exact version/hash. Acceptance creates no owner decision, promotion, work commitment, or action.
- System-created work remains `proposed`; only explicit owner events can commit, advance, complete,
  or cancel it. Invalid state transitions and impossible calendar dates are rejected before append.
- All P1 crash recovery, policy, actor, protected-path, canonicalization, and concurrency checks;
  all P2 lifecycle/context checks; and all P3 package/routing/framework checks remain green.

## Known limits and next decision

P3A provides contracts, deterministic folds/read models, and JSON session traces. It intentionally
does not provide P4's finished decision memo, case journal, artifact-history page, or human-readable
“today” view. It uses deterministic synthetic contributions rather than model execution. Actual
personal profiles, personal content, platform adapters, external task/calendar synchronization,
proactive reminders, migration, and background operation remain out of scope.

Artifact registration appends the immutable artifact event before adding its version ID to the next
session-manifest snapshot. If that second append suffers an I/O failure, the artifact event and bytes
remain valid and discoverable while the manifest reference requires a later repair; no accepted or
owner-decision state is fabricated.

The next decision is whether to approve the combined Phase 3 and P3A evidence. P4 remains
unauthorized and requires a separate exact-scope authorization after that review.
