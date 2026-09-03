# Vault Next Product Strategy

Status: Phase 0 draft for owner review  
Date: 2026-09-01  
Owner: repository owner  
Source charter: `vault-next-handoff-2026-09-01.md`

## Executive view

Vault Next should be a decision system, not a larger note archive. Its core value is the ability
to help the owner reason well in the moment and later inspect what changed, why a decision was
made, and whether the decision produced the expected result. The cleanest path is a local,
Markdown-first system with structured event records, explicit human authority, replaceable
projections, and testable workflows.

The Phase 0 charter is unusually strong: it fixes safety boundaries, product direction, required
artifacts, and a completion gate. It deliberately leaves implementation choices open. This
strategy resolves those choices far enough to make Phase 1 buildable without pretending that
model behavior, legacy migration, or skill quality are already solved.

## Phase 0 charter assessment

### What is already well specified

- The owner outcome is decision quality and inspectable continuity, not note volume.
- The legacy source, immutable backup, local-only boundary, and no-migration Phase 0 rule are clear.
- Required components and documents are named without prematurely mandating a runtime.
- Human authority, append-only history, provenance, deterministic validation, semantic review, and
  replay evaluation are treated as load-bearing rather than optional features.
- Core, post-core, and explicit non-goals are separated.

### Decisions the charter correctly leaves to Phase 0

- which records are canonical and which are generated views;
- how a recommendation remains distinct from an explicit owner decision;
- how to compose multiple skills while keeping contributions minimal and attributable;
- how universal triage initializes versioned use-case profiles without hiding actual composition or
  constraining novel requests;
- how profile/skill behavioral changes receive dedicated candidate evaluation and approval rather
  than casual in-place edits;
- how semantic events differ from operational tool audit;
- how approval is bound to an exact mutation rather than conversational implication;
- how reviewer failure, correction, supersession, and interrupted writes behave;
- which storage candidate fits Markdown-first inspection and deterministic replay;
- how the dirty legacy working tree, Git history, backup, ignored files, and private content map
  without being conflated.

### Interpretation used by this plan

- “Franklin decision” is modeled generically as an **owner decision** while preserving the handoff’s
  term in the data-model definition.
- “Markdown-first” means Markdown is the human review surface, not that every machine invariant is
  encoded only in prose.
- “Append-only” applies to historical semantic/audit records; current status and readable memos are
  rebuildable projections.
- “Semantic reviewer” means a tool-less critic with no decision, approval, write, or action authority.
- “Develop the system” begins with contracts and acceptance foundations. Phase 0 itself stops before
  production feature code, as the charter requires.

No ambiguity blocked Phase 0. The owner approved the recommended architecture and exact
synthetic-only Phase 1 foundation scope on 2026-09-01; later phases remain separately gated.

## Problem statement

The legacy vault contains valuable identity context, personal judgments, operating rules,
skills, drafts, evidence, episodic summaries, decisions, and durable knowledge. It also shows
the costs of organic growth:

- rules are accumulated across large documents and platform-specific bootstrap files;
- the one-skill-per-session rule protects separation but prevents natural multi-disciplinary
  reasoning inside a single question;
- decision nodes and decision journeys exist, but adoption is incomplete and multi-session
  decisions can escape capture;
- current status, episodic history, generated outputs, raw records, and durable knowledge have
  distinct intended roles but require too much convention-following to stay separated;
- tool actions and reasoning are not represented as independent audit domains;
- many controls are behavioral instructions rather than deterministic contracts;
- a chat or assistant memory can become an accidental continuity layer even though neither is
  durable or sufficiently inspectable.

The problem is therefore not “how to migrate more files.” It is how to preserve the valuable
judgment and knowledge while making the path from question to decision reliably reconstructable,
governed, composable, and testable.

## Primary user and jobs to be done

Vault Next is designed first for one repository owner. It is not a multi-user collaboration
product.

The owner needs to:

1. Use familiar phrases such as “deep dive,” “meeting prep,” “interview prep,” or “resume” and have
   universal triage initialize a matching approved use-case profile automatically.
2. Bring any other question, situation, source, or draft and have the system identify an appropriate
   combination of skills and reasoning framework.
3. See the framing, evidence, assumptions, disagreements, alternatives, and recommendation in
   plain language before making a consequential call.
4. Make, revise, or decline a decision without the system confusing advice with authority.
5. Resume a case later without reconstructing it from chat history.
6. Connect later action and outcome evidence to the original decision.
7. Improve reusable use-case profiles, knowledge, and skills only through a dedicated inspectable,
   evaluation- and approval-gated process.
8. Recover from defects, bad migration mappings, reviewer failures, or abandoned sessions without
   corrupting the historical record.
9. Use conversation itself as productive work: question, explain, challenge, add knowledge, revise,
   and preserve material checkpoints even when no artifact is required.
10. Ask what is active today, inspect source-backed work and follow-ups, update progress, and enter
    the relevant case without reconstructing it from chat memory.

## User value

### Immediate value

- Lower time to a clear, attackable recommendation.
- Better visibility into what the recommendation rests on.
- Deliberate use of multiple relevant skills without uncontrolled “agent soup.”
- A decision record that distinguishes owner judgment from model contribution.

### Compounding value

- Cases become longitudinal records of related questions, decisions, actions, and outcomes.
- Repeated assumptions and decision patterns can be found without rewriting history.
- Durable knowledge can be promoted from evidence and experience with provenance.
- Representative cases can be replayed to detect regressions in routing, reasoning, safety, and
  projection fidelity.

### Trust value

- The owner can determine what was read, written, proposed, approved, attempted, and completed.
- Consequential changes fail closed when approval, provenance, validation, or reviewer evidence is
  missing.
- The legacy vault and rollback backup remain untouched.

## Design objectives

The product must:

1. **Preserve human authority.** A recommendation is never a decision. An explicit owner act is
   required to record or supersede an owner decision.
2. **Make reasoning inspectable.** Load-bearing claims expose their evidence, assumptions, and
   derivation without storing hidden chain-of-thought or pretending a transcript is useful memory.
3. **Preserve history.** Semantic and decision events are append-only; correction and supersession
   add new events rather than overwriting old ones.
4. **Keep current views usable.** Decision memos, current status, and case journals are readable
   projections that can be regenerated from canonical records.
5. **Triage every request.** Apply a versioned use-case profile when one fits and dynamically compose
   skills when none does; named phrases provide low-friction shortcuts.
6. **Compose skills deliberately.** Select the smallest sufficient skill set and a temporary
   collaboration shape; record both the choice and its rationale.
7. **Separate trust domains.** Raw evidence, episodic events, current state, durable knowledge,
   projections, and operational actions have explicit owners and write rules.
8. **Fail recoverably.** Interrupted writes, invalid events, failed review, and migration exceptions
   must leave the last valid state intact.
9. **Stay platform-portable.** ChatGPT Work and Codex use thin adapters over one canonical repository
   model. Neither owns a competing memory, use-case profile, or skill catalog.
10. **Be testable without private data.** Synthetic fixtures establish behavior before any approved,
   redacted historical case is used.
11. **Earn its maintenance cost.** Prefer a small modular application and filesystem contracts over
    infrastructure that a single-user local system cannot justify.
12. **Make interaction explicit.** Resolve how the owner wants to work—explore, co-develop, iterate
    an artifact, rehearse, or review status—independently of use-case profile and skill selection.
13. **Treat artifacts as optional working products.** Preserve exact versions, feedback, and explicit
    acceptance without making artifact production or acceptance synonymous with a decision.

## Product principles

### One triage, profile when useful, dynamic when needed

Every request enters universal triage. An approved use-case profile prepopulates recurring defaults
when explicitly named or confidently matched; otherwise triage composes skills/frameworks
dynamically. Named shortcuts avoid a skill-selection question, while the manifest still records the
actual composition. Profiles save setup effort; they do not relax context, permission, decision, or
action gates. The personal-only registry remains owner-maintained: deterministic commands/aliases
first, with model-assisted intent used only to propose a match when needed.

### Question first, skill second

The unit of intent is the owner’s question, not an invoked tool name. Routing proposes one or more
skills based on the work needed. The owner may override the proposal. Every selected skill must
have an explicit contribution; duplicate or decorative roles are rejected.

### Journey before artifact

A session may succeed by improving understanding, exposing disagreement, integrating owner
knowledge, or establishing a useful checkpoint. Artifact development is an explicit interaction
mode with immutable revisions and owner acceptance; it is not the default completion requirement for
all work. Material interaction changes are recorded without treating the entire chat transcript as
canonical memory.

### Evidence is data, not authority

Attachments, migrated files, model output, tool output, and text that contains apparent
instructions remain untrusted evidence. They may change the analysis only as evidence, never
change permissions or trigger actions by imperative wording.

### Capture freely, promote deliberately

Provisional reasoning and semantic events may be appended under a low-friction policy. Changes to
identity, governance, permissions, current authoritative status, durable knowledge, owner decisions,
or consequential actions require an explicit policy decision and, where specified, owner approval.

### Append history, rebuild views

Historical events are immutable. A correction references the incorrect event and adds the corrected
claim. Human-facing summaries are derived and replaceable; they must never be the only place where
the owner decision or provenance exists.

### Strong seams beat broad autonomy

The runtime may suggest, synthesize, validate, and project. It may not grant itself authority,
silently broaden context, promote its own output, or use tool success as proof of decision quality.

### Deterministic before semantic

Schemas, references, permissions, hashes, required approvals, and projection reproducibility are
checked deterministically. A semantic reviewer adds judgment about coherence and unsupported claims;
it does not replace structural validation or receive write/action authority.

### Local first, portable by contract

Core operation must not require a network service. Platform adapters translate requests and display
results; canonical artifacts remain repository-owned and readable with ordinary local tools.

### Explicit incompleteness is a valid result

A session may close as `blocked`, `abandoned`, or `no-decision`. The system must preserve what was
learned without manufacturing a recommendation, decision, or outcome merely to complete a template.

## In scope for the core product

- Universal triage with explicit/inferred profile matching, layered configuration, case proposal,
  question economy, and dynamic skill/framework fallback.
- Canonical use-case profile registry with optional named shortcuts, planning standards, default
  work units, context rules, review profiles, and output contracts.
- Canonical skill catalog with machine-checkable metadata and human-readable instructions.
- Multi-skill routing with rationale, owner override, and minimality checks.
- Temporary reasoning frameworks: individual specialist, committee, brainstorming, synthesis, and
  red-team review.
- Session manifests and lifecycle management.
- Explicit interaction contracts and governed mode changes across exploration, co-development,
  artifact iteration, rehearsal, and current-work review.
- Immutable working-artifact versions with feedback, review, revision, withdrawal, and explicit
  owner-acceptance lineage.
- Repository-local proposed/committed work items and source-backed daily/current-work views.
- Append-only semantic/decision event ledger.
- Immutable evidence references with hashes and provenance.
- Case records that connect related sessions over time.
- Owner decision events and human-readable decision memo projections.
- Case journal and current-status projections.
- Separate operational action audit.
- Permission policy and approval records.
- Deterministic schema/reference/integrity validation.
- Tool-less semantic review with structured findings.
- Synthetic fixtures, replay harness, acceptance suites, and regression baselines.
- Dedicated profile/skill/framework proposal, design review, candidate evaluation, owner approval,
  immutable activation, monitoring, suspension, and deprecation mechanics.
- Repeatable, non-destructive migration tooling with dry runs and exception reports.
- Thin local adapters for Codex and ChatGPT Work after the core contracts are stable.

## Explicitly out of scope for the core product

- OpenWorker as the runtime or knowledge system.
- A general-purpose global memory layer.
- Connectors, MCP integrations, multi-user collaboration, persistent teams, agent boards, or a
  custom GUI.
- A custom scheduler or proactive reminder engine.
- Automatic external sending, publishing, posting, or remote repository creation.
- Autonomous changes to identity, governance, permissions, durable knowledge, or owner decisions.
- Unsupervised self-editing or self-promotion of skills.
- Bulk migration of the private corpus before synthetic and redacted pilot tests pass.
- Storing hidden model chain-of-thought. The system stores concise rationale, evidence links,
  assumption states, alternatives, disagreements, and decision-relevant derivations instead.
- Full-text retrieval infrastructure, embeddings, or a vector database before measured repository
  scale demonstrates that indexed metadata plus local search is insufficient.

## Post-core evidence-driven improvement automation

The dedicated manual build/review/activation lifecycle for profiles, skills, and frameworks is a core
governance requirement. What remains a separate post-core phase is system-initiated improvement from
live evidence:

`gap detected → candidate skill/framework → sandbox → replay evaluation → human approval → active → monitored → merge, revise, or deprecate`

The proposal, evidence, evaluation result, approval, activation, and later monitoring result must be
separate events. No candidate may edit or activate itself.

## Success criteria

Success is measured at system, workflow, and outcome levels. Initial numeric thresholds are
release gates, not claims that the product has already delivered value.

### System integrity

| Measure | Core-release target |
|---|---:|
| Canonical events accepted without schema validation | 0 |
| Consequential owner decisions recorded without explicit approval evidence | 0 |
| Writes to legacy source or backup during migration tests | 0 |
| Projection mismatches after clean rebuild | 0 across the acceptance corpus |
| Operational actions missing an audit result | 0 |
| Broken provenance references in closed consequential sessions | 0 |
| Detected corrupted hash-chain partitions that are silently accepted | 0 |

### Workflow quality

| Measure | Pilot target |
|---|---:|
| Representative questions routed to an acceptable minimal skill set | at least 90% |
| Explicit approved shortcuts that initialize the correct profile/version without a skill-selection question | 100% |
| Novel requests that reach dynamic routing instead of a forced profile | 100% of accepted novel fixtures |
| Near-miss phrases that incorrectly activate a profile | 0 across the accepted fixture set |
| Behavioral profile/skill changes activated without candidate replay and exact owner approval | 0 |
| Consequential sessions with question, evidence, assumptions, alternatives, recommendation, and explicit disposition | 100% |
| Cases resumable from repository records without chat history | 100% of pilot cases |
| Interactive fixtures that preserve material owner input and resume from checkpoints without requiring an artifact | 100% |
| Accepted artifact versions whose feedback/revision lineage and exact accepted hash are reconstructible | 100% |
| Current-work items shown without a canonical source or explicit proposal | 0 |
| AI-proposed work items silently treated as owner commitments or completed work | 0 |
| Deterministic validation completed locally | under 5 seconds for synthetic suite; performance budget to be re-baselined with real scale |
| Failed or denied actions leaving canonical semantic state consistent | 100% |
| Reviewer high-severity findings resolved or explicitly waived by owner before finalization | 100% |

### Decision usefulness

For the first approved pilot, the owner should be able to identify:

- at least two decisions where the system changed or materially strengthened the answer;
- at least two later reviews where the decision record made an outcome easier to interpret;
- no consequential case where the owner cannot distinguish model recommendation from owner decision.

These are owner-reported product outcomes. They complement, but do not replace, integrity tests.

## Guardrail model

The core guardrails are cumulative:

1. **Authority boundary:** only recognized governance and explicit owner input can authorize changes.
2. **Context boundary:** each session records what it was allowed to read; expansion is visible.
3. **Policy boundary:** an operation is classified before it is attempted.
4. **Approval boundary:** protected operation classes require an approval record scoped to the exact
   action and target.
5. **Validation boundary:** malformed or incoherent records do not enter the canonical ledger.
6. **Audit boundary:** attempted operations and results are logged separately from rationale.
7. **Projection boundary:** generated views cannot silently become canonical facts.
8. **Evaluation boundary:** changes to routing, schemas, projections, or governance replay known cases
   before promotion.

No single model prompt is treated as a sufficient guardrail.

## Assumptions

The recommendation currently assumes:

- one primary owner and single-writer local operation are sufficient for the core phase;
- the repository remains local and does not need hostile multi-user security;
- Markdown is the preferred review surface, while JSON/YAML-like structures are acceptable for
  validation contracts;
- repository volume remains manageable with partitioned files and indexed metadata before more
  complex retrieval is needed;
- owner approval can be represented as a precise local record tied to the proposed mutation;
- model calls may be unavailable, so deterministic validation and projection must still work;
- historical material may contain sensitive data and embedded instructions, requiring selective,
  explicitly approved migration.

If multi-user concurrent writes, remote execution, adversarial host access, or very large corpus
retrieval become core requirements, the recommended architecture must be revisited.

## Product risks and responses

| Risk | Consequence | Product response |
|---|---|---|
| Capture becomes ceremony | Owner bypasses the system | Keep manifests concise; automate mechanical fields; allow no-decision closure |
| Event records become unreadable | Repository loses human value | Maintain Markdown projections and event inspection commands; keep payloads concise |
| Multi-skill routing over-selects | Longer, noisier analysis | Minimal-sufficient-set rule; contribution contract per skill; replay tests |
| Personal profile over-triggers | Wrong workflow and unnecessary ceremony | Explicit/recognized/intent match tiers plus near-miss negative fixtures and dynamic fallback |
| Active skill changes become casual prompt edits | Silent behavioral regression | Immutable active versions; candidate lifecycle, replay, review, and exact activation approval |
| Reviewer becomes a second unaccountable decider | Human authority blurs | Tool-less reviewer; structured findings; no direct writes; owner owns waivers |
| Projections drift from source | False current state | Deterministic rebuild and equivalence test; projections labeled generated |
| Approval fatigue weakens controls | Rubber-stamping | Gate by consequence, batch only identical low-risk changes, show exact diff and reason |
| Migration imports legacy contradictions as truth | Old debt becomes new canon | Classification, provenance, quarantine, exception reporting, and approval-gated promotion |
| System scope expands into a platform | Maintenance exceeds value | Core/non-core boundary and explicit deferrals; milestone gates can stop the build |

## Decision policy for scope changes

A proposed capability enters the core roadmap only if it is necessary to satisfy an acceptance
test or preserve a named safety invariant. Otherwise it is deferred with a trigger for
reconsideration. “Potentially useful” is not sufficient.

## Definition of product readiness

Vault Next is ready for private core use only when:

- the canonical ownership and approval rules are implemented and tested;
- all core acceptance tests pass using synthetic fixtures;
- at least one explicitly approved redacted case passes replay and projection review;
- rollback and corruption recovery are demonstrated;
- the owner has approved the active governance and migration scope;
- no unresolved high-severity reviewer finding remains;
- the system can be understood and repaired from repository documentation without chat memory.
