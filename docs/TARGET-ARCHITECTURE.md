# Vault Next Target Architecture

Status: Phase 0 draft for owner review  
Date: 2026-09-01

## Recommendation

Use a **local modular monolith with a hybrid append-only event ledger and Markdown
projections**.

- Every request passes through universal triage, which applies a configurable use-case profile when
  useful and dynamically composes skills/frameworks when no profile fits.
- Markdown is canonical for human-authored governance, approved skill instructions, and approved
  durable knowledge.
- Versioned structured files are canonical for event envelopes, manifests, approvals, evidence
  metadata, and operational audit records.
- Raw evidence is immutable and content-addressed.
- Decision memos, case journals, and current-status pages are generated Markdown projections and
  can be deleted and rebuilt without losing truth.
- A policy gate classifies every mutation before execution.
- Deterministic validators enforce structure, references, permission evidence, and ledger
  integrity.
- A tool-less semantic reviewer returns structured findings but cannot write, decide, approve, or
  act.

This candidate best fits the local-first and inspectable requirements without forcing every human
idea into a database or leaving safety dependent on Markdown conventions alone.

## Architecture qualities

The architecture is designed to be:

- local-first and operable without network access;
- inspectable with ordinary file and text tools;
- Markdown-first at every human review surface;
- structured and versioned where deterministic validation is required;
- append-only for semantic, decision, approval, and outcome history;
- explicit about canonical source versus generated view;
- single-owner and single-writer for the core phase;
- recoverable after interrupted writes or invalid generated output;
- portable across Codex and ChatGPT Work through thin adapters;
- testable with synthetic fixtures and deterministic replay;
- conservative about privileged writes and external actions.

## Shared terms

| Term | Meaning |
|---|---|
| Case | A durable thread of related questions, sessions, decisions, actions, and outcomes |
| Session | A bounded reasoning episode with one primary question and a frozen manifest on closure |
| Triage | Universal intake that resolves profile/dynamic route, case, defaults, composition, review, and material questions |
| Use-case profile | Configurable recurring-use-case defaults; a named shortcut may select it directly |
| Skill | A reusable contribution contract: scope, method, inputs, outputs, safety rules, and tests |
| Framework | A temporary collaboration/reasoning shape used to compose selected skills |
| Semantic event | An append-only record of what the case learned, proposed, decided, or observed |
| Operational audit record | An append-only record of a tool or filesystem operation attempted and its result |
| Owner decision | An explicit decision made by the owner; called a “Franklin decision” in the handoff |
| Projection | A replaceable human-readable view derived from canonical records |
| Promotion | A protected mutation that moves a provisional claim into authoritative status or durable knowledge |
| Approval | A scoped owner authorization for a specific protected proposal and target |

Triage/profile semantics are defined in `TRIAGE-AND-USE-CASE-DESIGN.md`; record semantics are defined
in `DECISION-AND-CASE-MODEL.md`.

## Architecture candidates

### Candidate A — hybrid event-ledger modular monolith (recommended)

**Shape.** A small local application owns schemas, policy, ledger append, projections, validation,
review orchestration, and replay. Events and manifests are structured files; governance, skills,
knowledge, and projections are Markdown-first.

**Strengths**

- Strong match to append-only history and rebuildable decision/case views.
- Structural invariants are deterministic rather than prompt-dependent.
- Human review remains natural because important outputs are Markdown.
- No database service, background daemon, or network dependency.
- Clear upgrade path: a later database can index the same event contracts without changing their
  meaning.

**Costs**

- Requires careful event schema and projection design.
- Humans should not hand-edit generated projections.
- File locking, crash-safe append, partition integrity, and repair tooling must be implemented.
- Some information appears in both canonical structured records and derived Markdown by design.

**Best when.** One owner, local files, high inspectability, and reliable historical replay matter
more than concurrent writes or complex queries.

### Candidate B — document-centric Markdown workflow

**Shape.** Sessions, decisions, and cases are hand-readable Markdown documents with YAML
frontmatter. History is preserved through append sections and superseding documents. Small scripts
validate links and required fields.

**Strengths**

- Lowest implementation burden and easiest direct editing.
- Closest to the legacy vault’s successful patterns.
- Minimal technical barrier to inspecting or repairing content.

**Costs**

- Append-only semantics, event ordering, correction, and projection provenance remain convention
  heavy.
- It is difficult to prove that a decision memo reflects the full historical path.
- Operational audit and semantic rationale tend to mix.
- Replay and regression comparisons are ambiguous when prose is the only source.
- Permission evidence is harder to bind precisely to the approved mutation.

**Why not recommended.** It preserves too much of the legacy system’s failure mode: important
invariants live in instructions that a model or human must remember to follow.

### Candidate C — SQLite event store with Markdown export

**Shape.** A local SQLite database is the canonical event, evidence-metadata, permission, and case
store. Markdown documents are exports. Skills and governance remain files.

**Strengths**

- Strong transactions, constraints, indexing, and query performance.
- Easy cross-case queries and materialized views.
- Concurrency and data volume have clearer scaling paths.

**Costs**

- Canonical history is less inspectable in ordinary repository review.
- Database migrations become a second lifecycle concern.
- Git-style diffing and manual recovery are weaker.
- A binary canonical artifact conflicts with the repository-as-readable-source principle.
- It is premature for single-writer local scale.

**Reconsider when.** Concurrent writers, high event volume, or query performance demonstrably exceed
partitioned file-ledger limits.

## Candidate comparison

| Criterion | A: hybrid ledger | B: Markdown only | C: SQLite |
|---|---:|---:|---:|
| Human inspectability | High | Very high | Medium |
| Deterministic integrity | High | Medium-low | Very high |
| Append-only replay | High | Medium | Very high |
| Local operational simplicity | High | Very high | Medium |
| Projection reliability | High | Medium-low | High |
| Precise permission binding | High | Medium | High |
| Concurrent-write scaling | Low-medium | Low | High |
| Phase 1 build cost | Medium | Low | Medium-high |
| Fit to stated requirements | Best | Incomplete | Overbuilt |

## Recommended logical architecture

```text
Owner question / approved source material
                 |
                 v
      Intake + trust classification
                 |
                 v
      Triage + profiles + interaction contract
                 |
                 v
       Composer + framework selection ----------> routing proposal + rationale
                 |                                           |
                 +------------------- owner override ---------+
                 |
                 v
         Frozen session manifest
                 |
                 v
     Interactive session runtime/workspace
          |       |        |       |       |
          |       |        |       |       +--> working artifact versions
          |       |        |       +----------> semantic reviewer findings
          |       |        +------------------> deterministic validation
          |       +---------------------------> operational audit
          +-----------------------------------> semantic event ledger
                                                    |
                   +----------------+---------------+----------------+
                   |                |               |                |
                   v                v               v                v
             decision memo     case journal    artifact history  current work
               projection       projection       projection       projection
                   |                |               |                |
                   +----------------+---------------+----------------+
                                                    |
                                                    v
                                              replay/evaluation
```

The policy gate surrounds every arrow that writes, promotes, acts, or expands protected context.

## Proposed repository boundaries

These are target paths for later phases, not Phase 0 implementation:

```text
governance/                 approved authority, permission, and operating policies
config/owner-defaults.yaml  versioned personal defaults
use-cases/                  family/named use-case profiles and shortcut registry
skills/                     canonical skill packages and catalog index
frameworks/                 reusable collaboration-shape specifications
schemas/                    versioned manifest, event, audit, review, and projection schemas
cases/<case-id>/            stable case metadata and case-scoped links
sessions/<session-id>/      manifest, input refs, artifacts, reviews; immutable after closure
events/semantic/YYYY-MM/events.jsonl      canonical partitioned semantic event ledger
audit/operations/YYYY-MM/operations.jsonl separate operational action audit ledger
evidence/objects/           immutable content-addressed evidence blobs
evidence/metadata/          source metadata, sensitivity, hash, and provenance
knowledge/                  approved durable Markdown knowledge
projections/decisions/      generated decision memos
projections/cases/          generated case journals
projections/artifacts/      generated working-artifact histories and accepted-version views
projections/status/         generated current-state views
evals/fixtures/             synthetic and later approved redacted cases
evals/baselines/            accepted expected structured results
evals/reports/              generated evaluation reports
src/                        future local runtime implementation
tests/                      future unit, contract, integration, and acceptance tests
```

Generated locations must carry a machine-readable marker and a human warning such as:
“Generated projection; do not edit. Rebuild from canonical events.”

## Canonical ownership

| Information | Canonical owner | Mutation rule | Derived consumers |
|---|---|---|---|
| Identity and personal principles | Owner-authored Markdown | Owner edit only | Skills, sessions, reviewers |
| Governance and permissions | Approved governance Markdown + versioned policy data | Explicit owner approval | Runtime and validators |
| Owner defaults | Owner-approved configuration | Explicit owner edit/approval | Triage and profiles |
| Use-case profile definition | Approved profile package | Evaluated candidate + owner promotion | Triage, composer, runtime |
| Skill definition | Approved skill package | Evaluated proposal + owner promotion | Composer and runtime |
| Framework definition | Approved framework package | Evaluated proposal + owner promotion | Composer and runtime |
| Triage result | Frozen versioned TriagePlan + triage events | Override by new plan/event; preserve original | Session manifest, composer, review |
| Interaction/checkpoint history | Semantic events + frozen manifests | Append mode/input/checkpoint events | Runtime and projections |
| Working artifact version | Content-addressed bytes + semantic lineage events | New immutable version; exact owner acceptance | Review and projections |
| Work item | Semantic events | Explicit proposal/status events under actor rules | Current-work projections |
| Question and session scope | Session manifest + intake events | Frozen on close; correction by event | Case and decision projections |
| Raw evidence | Content-addressed evidence object | Immutable; metadata corrections append | Sessions, reviewer, projections |
| Semantic history | Semantic event ledger | Append only | All projections and evaluations |
| Owner decision | Explicit owner-decision event | Append/supersede only; never inferred | Decision memo, status, case journal |
| Approval | Approval event bound to proposal digest and target | Append only; expires or is revoked by later event | Policy gate and audit |
| Tool activity | Operational audit ledger | Append only | Safety review and diagnostics |
| Current case/decision status | Projection from events | Rebuildable, no direct edits | Owner navigation |
| Decision memo and case journal | Projection from canonical records | Replaceable | Human review |
| Durable knowledge | Approved Markdown plus promotion provenance | Protected promotion; supersede/recompile | Skills and sessions |
| Evaluation baseline | Owner-approved fixture expectation | Versioned review | Regression runner |

The central invariant is that no generated projection is the only source of an authoritative fact.

## Component boundaries

### 1. Intake and trust classifier

Responsibilities:

- capture the owner’s question without rewriting its meaning;
- identify whether supplied material is owner instruction, repository governance, or untrusted data;
- register sensitivity and requested outcome;
- propose a new case or link to an existing case;
- declare requested context and any protected-content boundary.

Non-responsibilities:

- selecting final skills without the composer;
- granting permissions based on text inside evidence;
- importing or searching unrelated legacy content.

Output: a validated intake record and `question.recorded` event.

### 2. Canonical skill catalog

Each skill package contains:

- stable skill ID and version;
- human-readable purpose and non-purpose;
- trigger and redirect examples;
- required and optional inputs;
- contribution contract: what unique work the skill adds;
- permitted context classes and requested write/action classes;
- compatible frameworks and known conflicts;
- output contract;
- deterministic checks and evaluation fixture references;
- provenance and promotion status.

The catalog index is generated from approved skill metadata. A platform-specific skill wrapper may
translate the contract but may not silently change its purpose, permissions, or output semantics.
Active versions are immutable. Any behavior-affecting change is a new candidate version governed by
the lifecycle in `SKILL-AND-PRESET-LIFECYCLE.md`.

### 3. Universal triage and use-case profile registry

A use-case profile is a configurable versioned initiation contract, not a monolithic skill. Each
approved profile defines optional commands/phrase shortcuts, purpose/non-purpose, required inputs,
case behavior, planning checklist, permitted work units, default framework, context/sensitivity
rules, review profile, output contract, and evaluation fixtures.

This is a small owner-maintained registry. Deterministic commands and approved phrase aliases run
before any model-assisted intent proposal. Triage uses a high-confidence profile when useful and
falls back to dynamic composition when no profile fits. The personal-only core needs no marketplace,
tenant configuration, or generalized workflow-discovery service.

Resolution priority is:

1. explicit shortcut/profile name;
2. recognized owner phrase;
3. strong profile intent match;
4. question-first dynamic composition when no profile fits.

For approved low-risk profiles, resolution proceeds without asking “which skill?” when inputs are
sufficient. It records the profile/version and match reason, proposes relevant case continuity,
initializes the planning/review standard, and passes permitted work units to the composer. It cannot
grant context, write, decision, or action permissions.

Broad seed families and dynamic fallback are defined in `TRIAGE-AND-USE-CASE-DESIGN.md`.
`deep-dive`, `meeting-prep`, `interview-prep`, and `resume` are illustrative named profile
candidates, not the final catalog. Their lifecycle is defined in `SKILL-AND-PRESET-LIFECYCLE.md`.

### 4. Multi-skill composer

Inputs:

- the recorded question and desired outcome;
- the triage result and any matched profile/version with permitted/default work units;
- case context explicitly in scope;
- catalog metadata only, not arbitrary skill prose at first pass;
- governance and sensitivity constraints.

Algorithmic contract:

1. Identify the work units required by the question.
2. Select the smallest set of skills that covers those units.
3. Require a one-line unique contribution from every selected skill.
4. Detect overlapping, conflicting, or permission-incompatible skills.
5. Choose a framework that fits the work shape.
6. State omissions when an obvious skill is not selected.
7. Return the proposal for owner confirmation or override when consequence or ambiguity requires it.

Default behavior is one skill when one skill is sufficient. Two or three skills are normal for a
genuinely compound question. More than three requires a recorded necessity rationale; no hard
maximum is encoded because a rare complex case may justify more.

Output: a `RoutingPlan` containing skill versions, contribution statements, ordering/parallelism,
framework, triage/profile trace, assumptions, context budget, permission needs, and override
history.

### 5. Framework registry

Frameworks are temporary shapes, not persistent personas or autonomous teams.

| Framework | Use | Required record |
|---|---|---|
| Specialist | One dominant skill performs the work | Scope, method, and output |
| Committee | Independent skill contributions are compared before synthesis | Member contributions, disagreements, chair synthesis |
| Brainstorming | Divergent option generation precedes evaluation | Generation constraints, option set, deduplication, evaluation criteria |
| Consultation | A primary skill asks a bounded specialist question | Question, response, adoption/rejection rationale |
| Synthesis | Existing analyses are reconciled into one position | Inputs, contradictions, resolved/unresolved seams |
| Red team | A candidate recommendation is attacked before finalization | Target, failure modes, evidence gaps, resulting changes |

Framework execution may be sequential in one process. The architecture does not require persistent
agents or expose internal hidden reasoning. It records concise contributions and disagreements
needed to reconstruct the decision path.

### 5A. Interaction and working-state controller

The interaction controller resolves how the owner and runtime collaborate independently of the
profile, skills, and framework. Its initial modes are exploration, co-development, artifact
iteration, rehearsal, and status review.

Responsibilities:

- materialize the resolved interaction contract in triage and the full session manifest;
- support owner-initiated mode changes and invoke governed recomposition when required;
- capture material owner inputs and concise reasoning checkpoints without making the full transcript
  or hidden chain-of-thought canonical;
- register immutable content-addressed artifact versions and exact-version feedback/acceptance;
- maintain semantic work-item transitions separately from operational actions; and
- expose deterministic working-state reads for later artifact-history and current-work projectors.

Non-responsibilities:

- selecting capabilities in place of the composer;
- accepting an artifact, making a decision, or committing work on the owner's behalf;
- granting context, write, promotion, or external-action permissions; or
- scheduling, monitoring, or synchronizing an external task system.

The full contract and lifecycle are defined in `INTERACTION-FIRST-WORK-MODEL.md`.

### 6. Session manifest and workspace

The manifest is the runtime declaration of intent. It contains:

- schema version, session ID, case ID, timestamps, and lifecycle status;
- original question and requested deliverable;
- triage plan ID/version, route type, matched profile ID/version/method/reason, defaults, and overrides;
- interaction mode/source/rationale, initiative, artifact/checkpoint policy, completion conditions,
  and allowed transitions;
- selected skill IDs/versions and routing rationale;
- framework and role/contribution assignments;
- allowed context references and sensitivity;
- requested and granted permission classes;
- evidence, output, review, and event references;
- parent/related session references;
- closure disposition: completed, blocked, abandoned, or no-decision.

An active manifest may be amended through recorded scope-change events. On closure, a canonical
snapshot is frozen. Later correction adds an event and, if necessary, a new superseding manifest;
it never silently edits the historical scope.

The workspace is a staging area. Files do not become canonical merely because a model generated
them there.

### 7. Session runtime

The runtime is an orchestrator, not an authority. It:

- loads only approved manifest context;
- runs universal triage and resolves profile or dynamic route before skill composition;
- invokes skill contributions according to the framework;
- validates structured outputs before staging events;
- records disagreements, alternatives, recommendations, and scope changes;
- supports iterative owner input, checkpoints, mode changes, artifact versions, and work-item updates;
- asks the policy gate before protected reads/writes/actions;
- dispatches deterministic and semantic review;
- closes or leaves the session safely incomplete.

Proposed state machine:

```text
draft -> routed -> authorized -> active -> review_pending -> closed
   |        |           |          |             |
   +------> abandoned <-+----------+-------------+
                          \
                           -> blocked
```

Only valid transitions generate lifecycle events. `closed` is immutable; resumption creates a new
session linked to the same case.

### 8. Semantic event ledger

The ledger is canonical for case history. Events use a versioned envelope defined in the model
document. Core properties:

- append-only partitions by month, with case and session references;
- globally unique sortable event IDs;
- `occurred_at` distinct from `recorded_at`;
- explicit actor and provenance;
- correlation and causation references;
- sensitivity and approval references;
- payload hash and previous-event hash within a partition;
- correction/supersession by new event, never in-place mutation.

The hash chain is tamper-evident, not a claim of protection from a hostile machine owner. It detects
accidental edit, truncation, or inconsistent replay. Cryptographic signatures are deferred unless
the threat model changes.

#### Crash-safe append

1. Generate candidate event in a session staging directory.
2. Validate schema, references, actor authority, approval scope, and payload digest.
3. Acquire the local writer lock for the target partition.
4. Re-read the partition tail and compute the next chain hash.
5. Write and flush one complete event record atomically.
6. Re-read and verify the appended record.
7. Release the lock and emit a success audit record.

On failure, the candidate remains quarantined or is discarded; the last valid ledger tail remains
canonical. Recovery never rewrites a valid prior event.

### 9. Evidence store

Evidence bytes are stored by SHA-256 content hash. Metadata records:

- evidence ID and full hash;
- source class and original display name;
- capture time and, when known, source event time;
- sensitivity and access constraints;
- immutable source path/reference;
- content type and byte count;
- importer/tool version;
- relationship to an older legacy path without making that path executable authority.

Evidence may be referenced without copying during read-only discovery. Actual ingestion is a later,
explicitly approved migration action. Duplicate bytes resolve to one object with multiple provenance
records. Content hash equality does not imply semantic equivalence.

### 10. Knowledge layer

The knowledge layer preserves distinct epistemic roles instead of treating every Markdown file as
equivalent memory:

| Layer | Role | Canonical form | Write rule |
|---|---|---|---|
| Raw evidence | Immutable source material | Content-addressed object + provenance metadata | New object only; never edit bytes |
| Episodic/semantic history | What was asked, considered, recommended, decided, and observed over time | Append-only semantic events and closed manifests | Append correction/revision/supersession |
| Current status | What is active now | Generated case/decision/action projection | Rebuild only from events |
| Durable knowledge | Approved general claim, method, or principle | Versioned human-readable Markdown + promotion provenance | Protected promotion and approved recompile/supersession |
| Generated artifacts | Session work products and readable views | Marked Markdown/artifact with source watermark | Replaceable; never authoritative by itself |

The durable knowledge catalog exposes concise concept metadata and provenance so sessions can load
only relevant articles. Knowledge selection is recorded in the manifest. No model or platform keeps
a competing hidden memory layer, and a useful session output does not promote itself automatically.

### 11. Policy and approval gate

The policy gate receives a typed proposal, not free prose:

- operation class;
- exact targets;
- expected diff or effect;
- actor;
- sensitivity;
- source/causation;
- approval reference if required;
- proposal digest.

It returns `allow`, `deny`, or `requires_owner_approval` with a reason code. An approval is valid only
for the same proposal digest, target set, consequence class, and time/scope constraints. A changed
proposal requires a new approval.

Protected classes include identity, governance, permissions, profile/skill/framework activation, durable
knowledge promotion, owner decisions, current authoritative status, destructive operations,
external transmission, and consequential actions.

The runtime cannot override a denial. Reviewer output cannot serve as approval.

### 12. Operational action audit

The operational ledger records what the system attempted, separately from why the case reached a
decision. Each record includes:

- operation ID and timestamp;
- session/case and semantic event references;
- operation class, tool, and safe target description;
- input digest rather than sensitive free-form payload where possible;
- policy result and approval reference;
- attempted/not-attempted status;
- outcome, duration, and error category;
- resulting artifact hashes or event references.

A denied action is auditable even though it is not attempted. An action’s success never creates an
owner decision automatically.

### 13. Projection engine

Projectors are deterministic functions over a validated event stream plus approved canonical
documents. Initial projections:

- decision memo;
- case journal;
- current case/decision/action status;
- session summary;
- provenance report.

Each projection includes:

- generator and schema version;
- source event watermark or ordered event-ID list;
- generated time;
- a “do not edit” marker;
- unresolved validation/review warnings;
- enough source references to verify load-bearing content.

A clean rebuild into an empty projection directory must produce semantically equivalent output.
Timestamps or stable ordering rules must not create meaningless drift.

### 14. Deterministic validator

Blocking checks include:

- schema version and required fields;
- allowed enum values and state transitions;
- unique IDs and referential integrity;
- event ordering and hash-chain integrity;
- evidence hash and byte-count match;
- approval scope and proposal digest match;
- owner decision actor authority;
- projection watermark and rebuild equivalence;
- absence of direct writes to generated or immutable locations;
- legacy source/backup paths are never write targets;
- sensitive fields are not leaked into audit summaries.

Validation failures produce structured error codes and do not partially promote records.

### 15. Semantic reviewer

The reviewer receives a fixed, read-only review packet and no tools. It checks:

- whether the recommendation answers the recorded question;
- unsupported or misrepresented evidence claims;
- hidden load-bearing assumptions;
- alternatives that were dismissed without reason;
- unresolved contradictions or disagreements;
- whether the owner decision is being inferred or overstated;
- whether projections preserve material changes and dissent;
- whether a requested action exceeds the decision or approval.

It returns structured findings with severity, evidence/event references, explanation, and proposed
remediation. It may not mutate records. Missing reviewer availability blocks finalization only for
work classes whose approved policy requires semantic review; it never blocks safe draft capture.

### 16. Evaluation and replay layer

The evaluation layer runs without private data by default. A fixture contains:

- question, context, evidence stubs, and policy profile;
- expected acceptable routing set and unacceptable selections;
- expected profile match/non-match, dynamic fallback, configuration precedence, initialization, and
  override behavior where applicable;
- required/forbidden event properties;
- expected permission decisions;
- projection invariants;
- semantic-review rubric and adjudicated baseline.

Replay compares structured behavior first, then bounded semantic quality. Any approved redacted
historical case is immutable test input with documented consent and redaction provenance.

## End-to-end data flow

1. **Record the question.** Intake writes the verbatim owner question and trust classifications.
2. **Triage.** Resolve an explicit/inferred use-case profile or choose dynamic composition; resolve
   defaults, interaction mode, artifact/checkpoint policy, material missing inputs, review profile,
   and why the route was selected.
3. **Resolve case context.** The owner selects or confirms a case; only scoped references enter the
   manifest.
4. **Route.** The composer resolves the profile plan or proposes skills/framework directly, with
   contribution rationales and permission
   needs.
5. **Authorize scope.** The owner confirms or overrides protected context and consequential routing.
6. **Freeze the active plan.** The runtime records the manifest version used for execution.
7. **Attach evidence.** Evidence is hashed, classified, and referenced; embedded imperatives remain
   data.
8. **Run the live loop.** Skills contribute under the framework; the owner questions, corrects,
   adds knowledge, redirects, or changes mode.
9. **Capture material state.** Append attributed owner inputs, checkpoints, assumptions,
   alternatives, disagreements, recommendations, scope changes, and any governed recomposition.
10. **Iterate artifacts when requested.** Create immutable versions; bind feedback, review, and
    acceptance to exact hashes. A no-artifact close remains valid.
11. **Review.** Deterministic checks run first; semantic review follows for configured work classes.
12. **Ask for a decision when needed.** A recommendation or accepted artifact is shown separately
    from any owner-decision control.
13. **Record disposition.** An explicit owner action records decided, deferred, rejected, or
    no-decision. The model cannot synthesize this event from conversational tone.
14. **Project.** Decision memos, case journals, artifact histories, and current-work views are rebuilt
    from the validated stream.
15. **Act under policy.** Any action proposal is independently classified, approved if required,
    attempted, and audited.
16. **Observe outcomes.** Later evidence creates outcome events linked to the decision and action.
17. **Review over time.** A new session may reassess the case or current work; previous events remain
    unchanged.

## Platform adapter strategy

One canonical repository layer serves both platforms.

### Codex adapter

- local repository implementation, validation, migration, test, and review;
- reads/writes only through core policy and ledger interfaces;
- may expose command-line workflows but does not own separate skill definitions.
- does not own a separate triage/profile registry or invocation meaning.
- exposes interaction/mode, feedback, acceptance, pause/resume, and status-review operations only
  through canonical core contracts.

### ChatGPT Work adapter

- strategic discussion, qualitative review, and owner decision interaction;
- transfers a typed request/response packet rather than relying on remembered chat state;
- writes canonical records only through the same core interfaces or produces an import packet for
  local validation and approval.
- cannot use remembered chat state as the required source for interaction continuity.

### Adapter invariant

An adapter may change presentation and transport. It may not change IDs, permissions, event
semantics, triage/profile/skill versions, invocation meaning, interaction/acceptance authority, or
what counts as an owner decision.

External transfer/connectors are out of scope until separately approved. Phase 1 requires no
platform integration.

## Technology direction

Recommended Phase 1 baseline:

- Python 3.12+ local package and CLI, chosen for readable filesystem tooling and testing;
- standard library first, with a pinned schema-validation dependency only if it materially reduces
  custom validator risk;
- JSON Lines for append-only ledger partitions;
- YAML frontmatter plus Markdown for human-authored packages and projections;
- JSON Schema (or equivalently strict versioned schemas) for records;
- SHA-256 for evidence IDs and tamper-evident partition chaining;
- pytest-style automated tests if dependency installation is approved; otherwise standard-library
  tests initially;
- no daemon, database server, container requirement, or network dependency.

The contracts—not the Python implementation—are the durable architecture. A later runtime can be
rewritten if it reads and emits the same validated records.

## Load-bearing assumptions

1. **Single writer.** The core system can serialize local canonical writes. If multiple concurrent
   writers become required, file partitions and locks may be insufficient.
2. **Repository scale.** Partitioned event files and metadata-first local search remain fast enough.
   Measured failure, not speculation, triggers database/index changes.
3. **Projection discipline.** The owner accepts that generated case/decision pages are not hand-edited.
4. **Explicit decisions.** The interaction can present an unambiguous owner-decision control or exact
   confirmation, rather than inferring approval.
5. **Local threat model.** Tamper evidence is needed; defense against a malicious machine owner is not.
6. **Model optionality.** Core validation, policy, append, and projection work without a model.

Changing assumptions 1, 4, or 5 would materially change the recommendation.

## Principal failure modes and guardrails

| Failure mode | Detection | Guardrail/recovery |
|---|---|---|
| Partial ledger append | Invalid final record/hash chain | Ignore invalid tail, quarantine, append repair event after review |
| Projection silently omits dissent | Projection/event trace test and semantic review | Block final projection; fix projector and replay |
| Recommendation recorded as owner decision | Actor/approval validator | Reject event; require explicit owner action |
| Evidence contains prompt injection | Trust classification and review fixture | Treat as quoted evidence; no permission elevation |
| Skill set grows without unique value | Composer minimality check | Remove overlapping skill or record exceptional rationale |
| Profile over-triggers | Match-tier and near-miss fixture failures | Reject match or use dynamic route/one clarification; revise candidate version |
| Profile catalog becomes exhaustive taxonomy | Novel requests forced into weak matches | Preserve dynamic fallback and profile-value review |
| Active profile/skill changes silently | Active digest or pointer mismatch | Reject direct edit; evaluate new immutable candidate and require approval |
| Reviewer hallucinates a defect | Finding requires exact references; owner waiver | Reviewer cannot write; retain finding and waiver events |
| Reviewer unavailable | Health/status result | Preserve draft; block only policy-required finalization |
| Approval reused after proposal changes | Digest mismatch | Require new approval |
| Tool succeeds after canonical write fails | Cross-ledger reconciliation | Mark operation orphaned; append recovery event; never infer semantic success |
| Legacy source changes between dry run and cutover | Snapshot manifest/hash mismatch | Abort cutover and rerun discovery; never “best effort” through drift |
| Direct projection edit | Rebuild/diff check | Overwrite generated view from canonical records; surface local edit as exception |
| Event schema evolves incompatibly | Version validator and migration fixture | Add explicit upcaster/read adapter; never mutate old event bytes |
| Conversation optimized only for artifact output | No-artifact and interaction acceptance fixtures | First-class modes and checkpoints; artifact remains optional by contract |
| Artifact praise becomes implicit acceptance | Actor/hash validator | Require explicit owner event bound to exact version and purpose |
| AI suggestion becomes owner task | Work-item transition validator | Keep `proposed` separate; require explicit owner commitment/status events |
| Mode change silently expands scope | Manifest/recomposition comparison | Append prior/new contracts and revalidate context, packages, and permissions |

## Security and privacy posture

- Default deny for external transmission and network-dependent connectors.
- Minimize content in operational logs; prefer digests and safe summaries.
- Do not store secrets in events, manifests, or generated reports.
- Sensitivity labels propagate to projections and review packets.
- Context access is explicit in the manifest and reviewable after closure.
- Evidence objects are local and excluded from any future remote by default.
- Destructive or irreversible operations always require exact-target approval and separate audit.
- Local permissions are defense-in-depth, not a substitute for application policy.

## Deferred decisions and triggers

| Deferred choice | Trigger to revisit |
|---|---|
| SQLite or another database | File-ledger query/replay budget fails on measured corpus, or concurrent writers are approved |
| Embedding/vector retrieval | Metadata index plus local search misses approved recall targets at unacceptable rate |
| Cryptographic signatures | Records must be verified across untrusted machines or actors |
| Custom GUI | Core workflows pass acceptance but CLI/Markdown usability blocks adoption |
| Remote sync | Owner explicitly approves a privacy and conflict model |
| Connectors/MCP | A core use case cannot be met by approved local evidence import |
| Persistent multi-agent teams | Temporary framework execution cannot satisfy measured quality needs |

## Architecture completion gate

The architecture is ready to drive Phase 1 when the owner accepts:

- Candidate A as the default direction;
- canonical ownership and generated-projection boundaries;
- universal triage, configurable profiles, dynamic fallback, and dedicated profile/skill lifecycle;
- interaction modes, checkpoint continuity, immutable artifact versions, and work-item authority
  boundaries in the approved interaction-first design;
- explicit owner-decision semantics;
- the policy/approval model;
- Python plus file-ledger as the Phase 1 implementation baseline;
- no personal migration or external integration in Phase 1.
