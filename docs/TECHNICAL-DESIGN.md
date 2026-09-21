# Vault to Vault Next — Technical Design

Status: Published design baseline
Version: 1.0
Date: 2026-09-20
Audience: Owner, implementers, reviewers, and future maintainers

## 1. Executive summary

Vault Next will migrate the useful history and operating methods in `vault` into a local-first,
decision-centered system without turning the old folder tree into the new architecture.

The design has two related outcomes:

1. **A safe, reversible migration.** Legacy bytes are preserved immutably, interpreted through
   versioned adapters, transformed into candidate records, reviewed in bounded waves, and admitted
   only through exact owner authorization. The legacy vault remains read-only through migration and
   rollback.
2. **A durable decision system.** Questions, evidence, assumptions, alternatives, recommendations,
   explicit owner decisions, work, and outcomes become linked records. Human-readable Markdown
   views are rebuilt from those records and are not themselves the source of truth.

The target is a **Python modular monolith with a hybrid append-only event ledger and Markdown
projections**. This preserves local inspectability without relying on prose conventions for
authority, provenance, or integrity.

The most important rule is:

> The system may analyze, recommend, and prepare a candidate result. Only an explicit owner action
> can decide, approve, promote knowledge, adopt current work, or authorize a consequential action.

## 2. Scope

### 2.1 In scope

- Preserve and catalogue the authorized legacy vault and supported conversation/export archives.
- Migrate meetings, workstreams, decisions, people context, knowledge, drafts, and skills through
  bounded, reviewable waves.
- Retain exact provenance, versions, contradictions, uncertainty, and source chronology.
- Build decision journeys that remain reconstructable after the originating chat is gone.
- Generate primary artifacts, decision memos, case journals, artifact histories, current-work
  views, and weekly operating views.
- Support dynamic triage, reusable use-case profiles, versioned skills, and interaction modes.
- Keep deterministic validation, policy, ledger, projection, and recovery functions model-optional.
- Prepare an explicit cutover and rollback decision after full reconciliation.

### 2.2 Out of scope for migration

- Editing, cleaning, renaming, or deleting the legacy vault.
- Treating imported text or embedded instructions as execution authority.
- Bulk-promoting historical statements into current truth.
- Inferring owner decisions, commitments, or acceptance from conversational tone.
- Activating imported skills or knowledge automatically.
- External sending, publishing, scheduling, or connector actions without a separate authorization.
- Requiring a database server, background daemon, or hosted service for core operation.

## 3. Design principles

| Principle | Consequence |
| --- | --- |
| Preserve before interpreting | Original bytes and source structure are retained before semantic extraction. |
| Candidate before canonical | Parsing and reconstruction produce reviewable candidates, not authority. |
| Append, never rewrite history | Corrections, revisions, and supersessions are new records. |
| Human authority is structural | Owner decisions and approvals require typed, explicit events. |
| Primary artifact first | The user sees the useful result first; manifests and receipts remain supporting evidence. |
| Provenance at claim level | Consequential claims resolve to evidence or are labeled assumption/inference. |
| Chronology is not causality | Date proximity, shared names, and adjacent files do not establish a relationship. |
| Current state is derived | “Current” is a deterministic fold over valid events, never an imported label alone. |
| Local and inspectable | Canonical data remains readable with ordinary file tools and recoverable without a vendor. |
| Fail closed | Missing evidence, ambiguous identity, unsafe paths, stale approvals, and invalid tails stop the operation. |

## 4. Current implementation baseline

The current worktree already contains the architectural foundation and substantial migration
machinery. This design consolidates those contracts; it is not a greenfield proposal.

| Capability | Current state |
| --- | --- |
| Canonical IDs, JSON serialization, schemas, and validation | Implemented |
| Locked, hash-chained JSONL semantic and audit ledgers | Implemented |
| Exact proposal/approval/receipt policy binding | Implemented |
| Cases, sessions, context manifests, and routing | Implemented |
| Versioned profile, skill, and framework composition | Implemented |
| Interaction modes, checkpoints, artifacts, and work items | Implemented |
| Decision/case/artifact/current-work projections | Implemented |
| Semantic review and repeatable evaluation baselines | Implemented |
| Read-only migration discovery and staging laboratory | Implemented |
| Archive preservation, primary-artifact publication, and private admission | Implemented in the local migration branch/worktree |
| Historical weekly reconstruction and rolling reconciliation | Implemented in the local migration branch/worktree |
| Compatible historical decision attribution and frozen advisor-retrieval evaluation contract | Implemented and verified for legacy reads, synthetic acceptance cases, and one bounded real-history no-write pilot |
| Complete corpus backfill and final current-state reconciliation | In progress |
| Skill-family migration, operational cutover, and ordinary daily operation | Planned after corpus gates |

“Implemented” means the mechanism exists and has automated evidence for its stated boundary. It
does not mean that every legacy item has been migrated or that a future wave is pre-authorized.

## 5. Target architecture

```text
                            OWNER / CHAT HOST
                                    |
                                    v
                      +-----------------------------+
                      | Intake + trust classifier   |
                      +-----------------------------+
                                    |
                                    v
                      +-----------------------------+
                      | Triage + context selection  |
                      | profile or dynamic route    |
                      +-----------------------------+
                                    |
                                    v
                      +-----------------------------+
                      | Session manifest            |
                      | skills + framework + mode   |
                      +-----------------------------+
                                    |
                                    v
       +------------------- INTERACTIVE RUNTIME --------------------+
       | evidence | reasoning | checkpoints | artifact versions     |
       | feedback | review    | recommendation | explicit decision  |
       +------------------------------------------------------------+
                 |                     |                    |
                 v                     v                    v
       semantic event ledger   operational audit    immutable objects
                 |                     |                    |
                 +---------------------+--------------------+
                                       |
                                       v
                         +---------------------------+
                         | Deterministic projectors  |
                         +---------------------------+
                                       |
                 +---------------------+----------------------+
                 |                     |                      |
                 v                     v                      v
          Decision memos         Case journals       Current-work views
          Primary artifacts      Weekly views        Knowledge candidates
```

The policy gate surrounds every write, promotion, protected-context expansion, and external action.

### 5.1 Deployment shape

- Python 3.12+ package and command-line runtime.
- Standard library first; no required runtime service.
- Single local writer for canonical state.
- Thin host adapters for Codex or ChatGPT Work; adapters may change transport and presentation but
  cannot change IDs, authority, event meaning, or approval semantics.
- Private runtime data excluded from the publishable source repository.

### 5.2 Logical components

| Component | Responsibility | Cannot do |
| --- | --- | --- |
| Intake/trust classifier | Capture request, source class, sensitivity, and instruction boundaries | Grant authority from source text |
| Triage | Resolve case, context, interaction mode, use-case profile, skills, framework, and questions | Silently expand protected context |
| Package registry/composer | Select immutable skill/framework versions with unique contributions | Activate an unevaluated candidate |
| Session runtime | Record interaction, reasoning state, artifacts, and checkpoints | Infer owner decisions |
| Evidence/object store | Retain immutable content-addressed bytes and metadata | Rewrite a prior version |
| Semantic ledger | Preserve meaning-changing events | Record tool attempts as decisions |
| Operational audit | Record attempted file/tool operations and results | Become decision rationale |
| Policy engine | Enforce target, consequence, digest, expiry, and receipt checks | Approve its own proposal |
| Validator | Enforce schemas, references, hashes, and state transitions | Judge semantic usefulness |
| Semantic reviewer | Find unsupported claims, contradictions, or omissions | Write, approve, decide, or act |
| Projector | Build replaceable Markdown and current-state views | Become canonical authority |
| Evaluation/replay | Re-run fixtures and compare exact structured outcomes | Change accepted baselines silently |

## 6. Canonical storage model

```text
governance/                       owner-approved policies
config/                           owner defaults and active pointers
use-cases/                        immutable use-case profiles
skills/                           immutable skill packages
frameworks/                       immutable collaboration frameworks
schemas/                          versioned JSON Schemas
cases/<case-id>/                  stable case metadata and links
sessions/<session-id>/            manifests, artifacts, and reviews
events/semantic/YYYY-MM/*.jsonl   canonical semantic history
audit/operations/YYYY-MM/*.jsonl  canonical operation history
evidence/objects/<sha256>         immutable source bytes
evidence/metadata/                source identity and provenance
knowledge/                        approved durable Markdown knowledge
projections/                      rebuildable human-readable views
indexes/                          disposable retrieval indexes
backups/                          local recovery snapshots
```

The exact physical paths may evolve, but canonical ownership does not:

- owner-authored governance and approved knowledge: versioned Markdown;
- events, approvals, manifests, receipts, and audit: strict structured records;
- raw evidence and artifact versions: immutable content-addressed objects;
- decision memos, case journals, status pages, indexes, and dashboards: rebuildable projections.

### 6.1 Event envelope

Every canonical semantic event carries, at minimum:

- schema and event type version;
- monotonic ULID event ID;
- case and session references where applicable;
- actor type and actor ID;
- recorded time and effective/observed time when different;
- subject and provenance references;
- sensitivity and authority metadata;
- typed payload;
- previous-record and partition hash bindings.

Canonical JSON uses stable key ordering and normalized encoding before SHA-256 hashing. Ledger
partitions are appended under a lock using crash-safe writes. Invalid tails are quarantined; they are
never accepted through a best-effort parse.

## 7. Decision system

### 7.1 Object model

```text
Case
 ├── Question
 ├── Session(s)
 │    ├── Triage plan + context manifest
 │    ├── Evidence / claims / assumptions
 │    ├── Alternatives / disagreements
 │    ├── Working artifact versions
 │    └── Recommendation revisions
 ├── Owner decision(s)
 ├── Work items and authorized actions
 ├── Outcomes and prediction assessments
 └── Durable-knowledge candidates
```

The boundaries are deliberate:

- A **recommendation** is system advice. It can be revised, withdrawn, accepted as input, or
  superseded. None of those states means a decision was made.
- An **owner decision** is an explicit human disposition: decided, deferred, declined, revisiting,
  or superseded. Missing rationale is recorded as “not stated,” not invented.
- A **working artifact acceptance** applies only to an exact content hash and stated purpose. It does
  not approve a later revision, create a decision, promote knowledge, or authorize an action.
- A **work item** tracks work. It is not permission to execute a tool or change an external system.
- An **outcome** evaluates what happened without rewriting the original decision context.

### 7.2 Decision flow

```text
Question
   |
   v
Triage and context authorization
   |
   v
Evidence -> assumptions -> alternatives -> disagreement
   |                                      |
   +------------------+-------------------+
                      v
               Recommendation
                      |
           explicit owner control
                      v
        decided / deferred / declined
                      |
        +-------------+--------------+
        |                            |
        v                            v
   Work/action                    No action
        |
        v
   Outcome observation -> reassessment or superseding decision
```

### 7.3 Triage and decision quality

Every material session produces a frozen plan that records:

1. the original question and any proposed reframe;
2. whether a named use-case profile matched or dynamic routing was used;
3. selected skill and framework versions and each one’s unique contribution;
4. interaction mode: explore, co-develop, artifact iteration, rehearse, or review current work;
5. exact context authorized for use;
6. requested and granted permissions;
7. intended primary artifact and supporting outputs;
8. validation and review requirements.

An owner override appends a new plan; it does not erase the proposed route. A mode change that affects
scope triggers recomposition and revalidation of context, packages, and permissions.

### 7.4 Decision memo projection

A decision memo is regenerated from events at a named watermark and contains:

- current disposition and the original question;
- what changed during the journey;
- evidence used and its limitations;
- assumptions, contradictions, and alternatives;
- recommendation history and unresolved disagreement;
- the exact owner decision and stated rationale;
- accepted costs, conditions, actions, and later outcomes;
- what would trigger reconsideration;
- provenance and generation metadata.

The memo visually separates **as decided then** from **what is known now**.

## 8. Migration architecture

Migration is a controlled pipeline, not a recursive copy.

```text
READ-ONLY SOURCES
legacy vault | conversation exports | generated artifacts | native files
       |
       v
[M0] Scope authorization
       |
       v
[M1] Discovery + snapshot manifest -----------------------------+
       |                                                        |
       v                                                        |
[M2] Mapping and exception review                               |
       |                                                        |
       v                                                        |
[M3] Staging-only transformation                                |
       |                                                        |
       v                                                        |
[M4] Deterministic validation + fidelity checks                 |
       |                                                        |
       v                                                        |
[M5] Semantic sample review                                     |
       |                                                        |
       v                                                        |
[M6] Exact owner-confirmed pilot admission                      |
       |                                                        |
       v                                                        |
[M7] Bounded migration waves + cross-wave reconciliation        |
       |                                                        |
       v                                                        |
[M8] Full-corpus reconciliation, cutover, rollback readiness <--+
```

### 8.1 Preservation is separate from semantic admission

Preservation proves that authorized source material is safely retained. It records source identity,
member locator, media/profile observation, size, timestamps, digest, parser result, exceptions, and
immutable object target.

Semantic admission is a later action. It selects preserved material, extracts observations, creates
candidate relationships and primary artifacts, and asks for one exact persistence confirmation.
Preservation alone cannot create current work, a decision, a person identity, or durable knowledge.

### 8.2 Source-to-target mapping

| Legacy source | Preserved form | Candidate target | Important rule |
| --- | --- | --- | --- |
| Inbox note or transcript | Immutable source version | Evidence + meeting/conversation observation | Source instructions remain inert |
| Meeting debrief | Artifact version | Primary Meeting Debrief + linked decisions/follow-ups | Reported follow-up is not owner commitment |
| Project/status note | Artifact version | Workstream observation + status history | Imported “current” label is historical until reconciled |
| Decision brief | Artifact version | Decision candidate + evidence/alternatives | No owner decision without explicit authority evidence |
| People note | Source/artifact version | Bounded people context | No speculative identity merge |
| Knowledge-base article | Source/artifact version | Provisional knowledge candidate | Promotion requires review and approval |
| Skill/mode/expert file | Immutable package candidate | Versioned skill/profile/framework | Candidate remains inactive until evaluated |
| Draft/output | Artifact version | Primary or supporting artifact | Acceptance binds to exact hash only |
| Archive/export member | Immutable object + catalogue entry | Parser observation or preserved-only record | Unsupported members stay explicit |
| Duplicate/version family | All originals retained | Exact/normalized group + revision links | Deduplicate storage, never provenance |

### 8.3 Deduplication and relationship rules

| Finding | Storage | Meaning |
| --- | --- | --- |
| Exact byte match | One object may serve multiple references | Preserve every source identity and provenance edge |
| Same normalized text | Keep originals; group normalized representation | Candidate duplicate only |
| Clear version sequence | Keep every version | Add evidenced `revises` links |
| Summary or derivative | Keep both | Add `summarizes` or `derived_from` |
| Divergent accounts | Keep both | Record contradiction; never merge silently |
| Similarity only | Keep both | `possibly_same_*` candidate for review |

Relationship proposals must retain their basis: an exact reference, export-declared edge, citation,
content evidence, deterministic rule, or disclosed bounded analytical step. Names, filenames, and
temporal adjacency alone are insufficient.

### 8.4 Migration units

Migration proceeds in outcome-oriented families:

1. **Foundation and presentation retrofit** — shared context selection, primary/support artifact
   contracts, and primary-first retrieval.
2. **Archive preservation** — exact member accounting, safe parsing boundaries, and recovery proof.
3. **Meeting and workstream reconstruction** — calendar-week waves, continuity, decisions,
   follow-ups, and source coverage.
4. **Knowledge, decision, and people reconstruction** — deep dives, decision briefs,
   contradictions, effective time, and bounded people context.
5. **Skill and workflow adaptation** — meeting; work/status/decision; research/knowledge;
   writing/revision; learning; executive reporting; then other demanded families.
6. **Current-state reconciliation** — whole-corpus lineage, unresolved exceptions, backup/restore,
   and source-independent replay.
7. **Operational cutover** — one-writer activation, ordinary use, and bounded later automation.

### 8.5 Weekly reconstruction algorithm

For historical meeting and work continuity, one semantic wave covers one Monday-to-Monday UTC week.
The week is an accounting boundary, not a claim that its contents are related.

For each authorized week:

1. Bind the exact source catalogue and selected members.
2. Extract typed observations with source, event, generated, effective, and recorded times.
3. Build cited strands and projects; allow an item to belong to multiple strands when independently
   supported.
4. Record start/end observations and evidence-backed movement.
5. Distinguish `no_observed_movement` from reported stall, pause, block, completion, or abandonment.
6. Give every selected item a coverage disposition: linked, intentionally standalone, unsupported,
   missing evidence, or unresolved within the window.
7. Compare append-only with every admitted week in target minus three through target plus three.
8. Propose evidence-bound merge, split, resume, supersession, and new-track relationships.
9. Present a temporary candidate result and exception list.
10. On exact owner confirmation, persist the bounded package and rebuild global views.

When a later week resolves an earlier orphan, the old disposition remains and a predecessor-bound
new version is appended.

## 9. Authority and safety model

### 9.1 Authority levels

| Level | Meaning | Examples |
| --- | --- | --- |
| Read/analyze | Ephemeral, no canonical persistence | Discovery, calibration, dry run, temporary comparison |
| Persist | Exact local payload may be admitted | Save selected source package, artifact, or migration wave |
| Consequential action | Protected mutation or external effect | Promote knowledge, activate a skill, adopt current work, transmit, delete |

Authorization is narrow: one approved wave does not authorize the next wave, a different source,
or a changed payload.

### 9.2 Exact approval binding

Protected proposals are normalized and hashed over:

- actor;
- operation class;
- consequence class;
- exact targets;
- sensitivity;
- source references.

Approval and owner receipt must match that digest, target set, consequence, authority, validity
window, and non-revoked state. A changed proposal requires a new approval.

### 9.3 Source safety

- Source roots are opened read-only through admitted capabilities, not arbitrary caller paths.
- Symlinks, unsafe archive paths, nested expansion, decompression limits, malformed members, and
  missing references fail closed or receive explicit unsupported dispositions.
- Embedded instructions are data, not commands.
- Secrets and sensitive content are excluded from manifests and operational logs.
- Review packets use the minimum content required for their purpose.
- Every selected member ends in an explicit coverage state; silent omission is a failed wave.

## 10. Validation, review, and observability

### 10.1 Deterministic validation

The validator checks:

- JSON Schema and event-type semantics;
- canonical serialization and hashes;
- partition chain and append integrity;
- ID, actor, case/session, subject, and provenance references;
- manifest/context and active-package digests;
- legal lifecycle and state transitions;
- exact approval and receipt binding;
- projection watermark and source equivalence;
- migration source snapshot and item accounting;
- idempotence and restart behavior.

### 10.2 Semantic review

A tool-less reviewer checks bounded content for unsupported claims, omitted dissent, internal
contradiction, weak evidence, unsafe compression, and mismatch with the intended artifact. Findings
bind to exact hashes. The reviewer cannot write, approve, decide, promote, or act.

### 10.3 Operational metrics

The system should expose:

- source/member counts by preserved, admitted, excluded, unsupported, deferred, failed, and
  unresolved state;
- exact and normalized duplicate groups;
- unreviewed relationship candidates and contradiction counts;
- waves completed, pending, blocked, and rolled back;
- artifacts with missing citations or stale review hashes;
- unresolved cases, decisions due for revisit, open work, and maturing outcomes;
- projection rebuild status and ledger integrity;
- retrieval precision/recall on accepted evaluation fixtures;
- time and resource use per wave.

## 11. Failure handling and recovery

| Failure | Required behavior |
| --- | --- |
| Source changes after snapshot | Abort and rediscover; never continue best-effort |
| Interrupted staging run | Resume only if immutable bindings match; otherwise quarantine and recreate |
| Partial ledger append | Ignore invalid tail, quarantine it, and append reviewed repair evidence |
| Duplicate migration attempt | Return prior admission lineage; do not create a second logical import |
| Unsupported or malformed member | Preserve when safe; mark unsupported with reason; no fallback parser |
| Ambiguous relationship | Retain both records and candidate status; request review only when consequential |
| Projection defect | Fix projector and rebuild; canonical history remains unchanged |
| Approval mismatch or expiry | Stop and request a new exact authorization |
| Canonical write fails after tool activity | Record orphaned operation and reconcile; never infer semantic success |
| Reviewer unavailable | Preserve draft; block only work whose policy explicitly requires review |
| Rollback after admitted wave | Restore canonical backup or append a compensating disposition; never edit source |

Recovery is proven with source-independent restart, deterministic replay, and disposable-mirror
restore tests before cutover.

## 12. Rollout plan

### Phase A — close historical coverage

- Preserve every separately authorized source lane.
- Complete catalogue and all-date coverage accounting.
- Calibrate supported parsers with no-write samples.
- Continue bounded weekly meeting/work reconstruction.
- Backfill earlier periods and disposition unresolved-date material.

Exit gate: every authorized logical member has a coverage state and no silent orphan.

### Phase B — reconstruct higher-order meaning

- Build knowledge, decision, and people-context waves.
- Resolve decision supersession and effective-time histories.
- Produce primary Deep Dives, Decision Briefs, and linked support packages.
- Keep all imported knowledge provisional until promotion.

Exit gate: representative decision journeys are complete, cited, replayable, and owner-useful.

### Phase C — migrate skills and workflows

- Adapt skill families to the canonical package contract.
- Declare required context, primary artifact, support outputs, tools, disclosure, and evaluation.
- Evaluate candidates across multiple fixtures and representative real cases.
- Activate only owner-approved versions.

Exit gate: the main daily workflows can run without reading legacy skill files.

### Phase D — reconcile and cut over

- Run full-corpus temporal and relationship-network reconciliation.
- Present historical, reported, candidate, conflicting, and proposed-current state separately.
- Ask the owner to adopt only selected current work and decisions.
- Prove backup, restore, source-independent startup, and rollback.
- Freeze legacy writes and activate a single canonical writer.

Exit gate: the owner can perform core work in Vault Next, retrieve migrated context, and roll back
without losing source or admitted history.

### Phase E — ordinary operation and bounded expansion

- Run the accepted chat-first journey with primary-first retrieval.
- Measure usefulness, retrieval quality, correction burden, and decision follow-through.
- Add committees, connectors, schedules, and consequential actions only through separate design and
  authorization gates.

## 13. Acceptance criteria

Migration is complete only when all of the following pass:

1. The legacy sources remain byte-unchanged and readable.
2. Every authorized logical source has exactly one admission lineage and an explicit disposition.
3. Every admitted artifact and consequential claim can resolve to retained provenance.
4. Exact duplicates lose no source identity; versions, derivatives, and contradictions remain visible.
5. Recommendations, decisions, artifact acceptance, work commitments, and approvals cannot be
   confused by schema or projection behavior.
6. Current state can be rebuilt deterministically from canonical events.
7. Decision memos preserve the original question, material alternatives, dissent, owner authority,
   and later outcomes.
8. Candidate history does not silently become current work or durable knowledge.
9. Interrupted writes, stale approvals, changed sources, and invalid ledger tails fail closed.
10. Backup/restore and source-independent replay pass on a clean mirror.
11. Core user journeys work without browsing internal manifests or receipts.
12. The owner explicitly approves cutover and the rollback window.

## 14. Key technical decisions and triggers to revisit

| Decision | Current choice | Revisit when |
| --- | --- | --- |
| Canonical persistence | File ledger + immutable objects | Concurrent writers or measured query limits appear |
| Human interface | Markdown projections | Users reject generated/non-editable views |
| Runtime | Python modular monolith | A second deployment model proves necessary |
| IDs | ULIDs | Cross-system constraints require another stable scheme |
| Integrity | Canonical JSON + SHA-256 chains | Threat model requires signed remote attestation |
| Retrieval | Metadata, FTS, and deterministic selectors | Accepted evaluations show recall/latency failure |
| Semantic processing | Bounded model-assisted candidates | A deterministic extractor is adequate for a source family |
| Migration wave | Calendar week plus rolling reconciliation | Evidence shows another unit improves completeness materially |
| Host | Thin interchangeable adapters | A host cannot honor canonical authority/receipt contracts |

## 15. Remaining owner decisions

The implementation can continue safely within already accepted contracts, but these decisions remain
human gates:

1. Exact scope of each next real migration wave.
2. Backfill order and treatment of unresolved-date material.
3. Consequential identity/relationship exceptions that evidence cannot settle.
4. Which reconstructed historical items, if any, become current work or active decisions.
5. Which skill candidates become active after evaluation.
6. Backup retention, cutover date, rollback window, and legacy read-only period.
7. Any future connector, external action, or proactive automation authority.

## 16. Normative implementation references

This document is the integrated system view. Detailed contracts remain in:

- [`TARGET-ARCHITECTURE.md`](TARGET-ARCHITECTURE.md) — component boundaries and architecture trade-offs;
- [`DECISION-AND-CASE-MODEL.md`](DECISION-AND-CASE-MODEL.md) — semantic objects, event taxonomy, authority, and projections;
- [`TRIAGE-AND-USE-CASE-DESIGN.md`](TRIAGE-AND-USE-CASE-DESIGN.md) — profile matching and dynamic routing;
- [`INTERACTION-FIRST-WORK-MODEL.md`](INTERACTION-FIRST-WORK-MODEL.md) — interaction modes, artifacts, and current work;
- [`SKILL-AND-PRESET-LIFECYCLE.md`](SKILL-AND-PRESET-LIFECYCLE.md) — package evaluation and activation;
- [`MIGRATION-PLAN.md`](MIGRATION-PLAN.md) — discovery, staging, validation, waves, cutover, and rollback;
- [`ACCEPTANCE-TESTS.md`](ACCEPTANCE-TESTS.md) — observable end-to-end gates;
- `decisions/ADR-0001` through `ADR-0011` — accepted architecture decisions;
- `schemas/v1/` — machine-enforced record contracts;
- `src/vault_next/` — current reference implementation;
- `tests/` — executable safety and behavior evidence.

Where this integrated design and a machine-enforced schema differ, the accepted ADR plus the current
schema governs implementation until the discrepancy is resolved explicitly.
