# Vault Next Decision and Case Model

Status: Phase 0 draft for owner review  
Date: 2026-09-01

## Purpose

This model defines what Vault Next records, what each record means, who owns it, and how a
human-readable decision memo and case journal are derived without erasing the historical path.

The model stores inspectable decision-relevant rationale. It does not store hidden model
chain-of-thought or treat a verbatim transcript as useful durable reasoning.

## Core invariants

1. A recommendation is not an owner decision.
2. An owner decision is never inferred; it requires an explicit owner-authored or owner-approved
   event.
3. Semantic history is append-only. Correction, revision, withdrawal, reopening, and supersession
   add events.
4. Raw evidence is immutable. A later assessment does not alter the source.
5. Current status and human-readable memos are projections, not hidden alternative sources of truth.
6. Every material claim declares whether it is observed, owner-stated, inferred, or generated.
7. A tool operation records what happened operationally, not why a decision was made.
8. A case may contain multiple sessions and decisions; a session has one primary question but may
   use multiple skills.
9. Closing with no decision is valid and must not be “completed” by fabricating one.
10. Durable knowledge is promoted from evidence/history through approval; it is not an automatic
    side effect of a good-looking answer.

## Relationship map

```text
Case
├── Session 1
│   ├── Question
│   ├── Triage plan: profile or dynamic route, defaults, case, composition
│   ├── Evidence references
│   ├── Assumptions / alternatives / disagreements
│   ├── Recommendation revisions
│   └── Review
├── Session 2
│   └── Explicit owner decision
├── Action proposals and operational audit records
├── Later outcome observations
└── Generated case journal

Owner decision
├── question/case context
├── evidence and assumptions as-of the decision
├── alternatives and recommendation history
├── explicit owner disposition
├── action and outcome links
└── generated decision memo
```

## Identifier policy

Identifiers are opaque and stable. Display names and slugs may change without changing identity.

| Object | Form | Rule |
|---|---|---|
| Case | `case_<ULID>` | Created once; never reused |
| Session | `session_<ULID>` | New ID for every resumed reasoning episode |
| Triage plan | `triage_<ULID>` | Frozen routing/default/composition decision for one session |
| Event | `event_<ULID>` | Globally unique and time-sortable |
| Decision | `decision_<ULID>` | Stable across revisions; supersession points to a new decision when the call is replaced |
| Recommendation | `recommendation_<ULID>` | Stable thread for revisions within/across sessions |
| Action | `action_<ULID>` | Semantic action identity, distinct from attempts |
| Operation | `operation_<ULID>` | One operational attempt or denial |
| Evidence | `evidence_sha256_<64-hex>` | Identity is the full content hash |
| Approval | `approval_<ULID>` | Bound to exact proposal digest and scope |
| Review | `review_<ULID>` | One deterministic or semantic review result |

ULID is recommended for sortable local identifiers; UUIDv7 is an acceptable equivalent if selected
before implementation. Shortened hashes may be displayed but never stored as the canonical evidence
identity.

## Concept definitions

### Case

A case is the durable continuity boundary for a real question domain: a decision, situation,
initiative, relationship, or recurring problem that may require multiple sessions over time.

Canonical case metadata contains only stable identity and classification:

- case ID;
- owner-assigned or confirmed title;
- created time;
- sensitivity/access policy;
- optional related-case links;
- provenance of creation.

Case status, summary, active questions, decisions, actions, and outcomes are derived from events.
The case metadata file is not a hand-maintained journal.

Proposed lifecycle: `open`, `dormant`, `closed`, `reopened`. Transitions are events; the current
value is a projection. Closing a case does not delete its history.

### Session

A session is a bounded reasoning episode with one primary question. It may select multiple skills
and a temporary framework when the question needs them.

Required session data:

- session and case IDs;
- verbatim primary question;
- intended deliverable and audience;
- triage plan ID/version, route type, matched use-case profile ID/version/method/reason, defaults, and
  override history;
- selected skill/framework versions and rationale;
- authorized context and permission scope;
- evidence and prior-session references;
- produced artifact, event, review, and operation references;
- closure disposition and frozen manifest hash.

A materially different primary question starts a new session, normally in the same case. A minor
scope refinement appends a `session.scope_changed` event. A closed session is never reopened; a new
session links back with `continues_session_id`.

### Triage plan

The triage plan is the inspectable decision about how a session will begin. It records:

- explicit/inferred profile or dynamic route;
- matched profile/family/version and match reason/confidence, if any;
- case proposal and owner selection;
- classification axes such as purpose, object, audience, depth, stakes, input shape, and action intent;
- defaults applied and the configuration layer that supplied each value;
- explicit owner overrides and safe session inferences;
- missing material inputs and any clarification asked;
- resolved skills/framework contribution plan;
- context, review, output, and permission requirements.

The triage plan is frozen with the session manifest. A material route change appends a triage/routing
override event and a new manifest version. No-profile/dynamic is a valid plan, not an error.

### Question

The question is the owner’s situation or ask as received. Store the verbatim text plus an optional
normalized problem statement. The normalized form never replaces the original and records its actor
as system-generated.

Question events distinguish:

- `question.recorded` — original owner ask;
- `question.clarified` — owner clarification;
- `question.reframed` — proposed or accepted change to problem structure;
- `question.resolved` — explicit disposition, which may be no-decision.

A model-proposed reframe is an alternative until the owner accepts it or the manifest explicitly
authorizes it as the working frame.

### Interaction contract and checkpoint

The interaction contract states how the owner and system will work in a session. It records the
resolved mode, source and rationale, initiative policy, artifact policy, checkpoint policy,
completion conditions, and permitted mode transitions. The initial modes are `explore`,
`co_develop`, `artifact_iterate`, `rehearse`, and `status_review`.

Interaction mode is independent of the use-case profile, selected skills, framework, and artifact
type. A material change appends `interaction.mode_changed` and produces a new full manifest version;
it does not overwrite the prior route, expand permissions, or discard earlier contributions.

A checkpoint is a concise, externally useful representation of the current reasoning state needed
for review or continuation. It may include the working question, evidence, assumptions, options,
disagreements, provisional conclusions, owner input, and open questions. It is not hidden model
chain-of-thought, and a full chat transcript is neither required nor canonical.

### Evidence

Evidence is material used to support, challenge, or contextualize a claim. It can be:

- owner statement;
- immutable file/object;
- external source snapshot or citation;
- tool observation;
- prior semantic event;
- approved durable knowledge;
- model-generated analysis, which is never mislabeled as observed evidence.

Evidence metadata records source class, actor, time, hash/reference, sensitivity, capture method,
and trust classification. An evidence assessment may state relevance, reliability, conflicts,
freshness, and limitations. Assessment is an event and may change; the evidence bytes do not.

### Assumption

An assumption is a load-bearing proposition used where evidence does not fully settle the point.
It records:

- statement;
- grade: `held`, `unverified`, `unheld`, or `inferred`;
- actor who introduced it;
- evidence references, if any;
- what changes if false;
- a check that could settle it and expected cost/urgency;
- validity interval or review trigger where relevant.

Grades follow these meanings:

| Grade | Meaning |
|---|---|
| `held` | Verified sufficiently for this session and supported by referenced evidence |
| `unverified` | Believed but not checked; the settling check is known |
| `unheld` | Known to be absent; the conclusion is explicitly conditional |
| `inferred` | Derived by the system; no source states it directly |

Assumption revision adds an event referencing the prior assumption event. Projections show the
current grade and, for a decision memo, the as-of-decision grade.

### Alternative

An alternative is a materially distinct answer, path, or framing considered in the case. It
records description, origin actor, evaluation criteria, supporting/challenging evidence, known
costs, disposition, and reason.

Disposition is event-derived: `active`, `shortlisted`, `rejected`, `deferred`, `selected`, or
`superseded`. Rejection requires a reason. “Not selected” is not automatically “rejected.”

### Disagreement

A disagreement records incompatible claims, interpretations, priorities, or recommendations.
It preserves attribution and may be between the owner and system, among selected skills, between
evidence sources, or between reviewer and runtime.

Required fields:

- proposition in dispute;
- attributed positions;
- what the disagreement changes;
- supporting event/evidence references;
- status: `open`, `resolved`, `accepted_tension`, or `obsolete`;
- resolution actor and rationale when resolved.

Synthesis must not flatten unresolved disagreement into apparent consensus.

### Recommendation

A recommendation is advice produced by the system or a named skill/framework synthesis. It records:

- recommendation ID and revision number;
- affirmative proposal;
- actor/framework source;
- evidence, assumptions, and alternatives relied on;
- accepted costs and failure modes;
- conditions or thresholds that would change the recommendation;
- relationship to prior revision;
- review disposition.

Recommendation lifecycle is `proposed`, `revised`, `withdrawn`, `accepted_as_input`, or `superseded`.
None of these values means the owner decided.

### Owner decision (Franklin decision)

An owner decision is the human-owned disposition of a question or recommendation. The canonical
event must be generated from an explicit owner action whose displayed effect was unambiguous.

Required data:

- decision ID;
- explicit owner statement or exact accepted proposal;
- status: `decided`, `deferred`, `declined`, `revisiting`, or `superseded`;
- effective time and recorded time;
- linked question/recommendation, if applicable;
- stated rationale, if supplied;
- accepted costs, constraints, and conditions, if supplied;
- approval/interaction reference proving explicit owner action;
- provenance and sensitivity.

Rules:

- Silence, model interpretation, conversation closure, or action success cannot create a decision.
- The system may show a candidate decision statement for confirmation, clearly labeled as a
  candidate.
- The owner may decide without accepting the model recommendation.
- If the owner provides no rationale, record “not stated”; do not generate one and attribute it to
  the owner.
- A correction event may fix recording error without changing the underlying decision.
- A changed call appends a revision or superseding decision event; the old call remains visible
  historically.

### Action

An action is an intended consequence of a decision or recommendation. Semantic action data records:

- action ID, statement, owner, and linked decision/recommendation;
- consequence class and sensitivity;
- approval requirement;
- target, desired result, due/review trigger;
- semantic status such as `proposed`, `authorized`, `in_progress`, `completed`, `failed`, `cancelled`,
  or `superseded`.

Tool attempts are not embedded in the semantic action event. They use separate operational records
linked by action ID. An action can be completed by the owner outside the system through an explicit
outcome/confirmation event.

### Working artifact

A working artifact is a versioned output being developed with the owner. Each version is immutable
and content-addressed, and records its artifact/version IDs, purpose, media type, content hash,
storage reference, source-event watermark, producer, prior-version link, change summary, feedback,
and review references.

Lifecycle state is derived from events: `working`, `review_pending`, `accepted`, `withdrawn`, or
`superseded`. Feedback and review always bind to an exact content hash. Explicit owner acceptance
means only that the exact version is accepted for its stated purpose; it does not create an owner
decision, promote durable knowledge, commit work, approve an external action, or accept a later
revision.

### Work item

A work item is a repository-local follow-up or unit of work shown in current-work views. It is
distinct from an operational action: tracking work grants no permission to execute it or change an
external system.

A work item records its statement, actor/source, case and session links, priority if explicitly
assigned, due or next-review date, blocker, and status. Status is `proposed`, `open`, `in_progress`,
`waiting`, `done`, or `cancelled`. The system may create a clearly attributed proposal. Only an
explicit owner event or an approved authoritative source may create an owner commitment, change its
priority, or mark it done/cancelled.

### Review

A review is a bounded assessment of a manifest, event set, artifact, projection, migration report,
or action proposal.

Review kinds:

- deterministic validation;
- semantic coherence review;
- owner review;
- migration reconciliation;
- outcome review;
- evaluation adjudication.

A review records scope/hash, reviewer identity/type/version, findings, severity, disposition,
waivers, and the source watermark. A review of an earlier version does not automatically cover a
changed artifact.

### Outcome

An outcome is an observed result linked to one or more decisions/actions. It records:

- observation statement and time window;
- evidence and observer;
- relationship to predicted outcomes or thresholds;
- result state: `observed`, `partially_observed`, `not_observed`, or `not_yet_measurable`;
- attribution confidence and competing explanations;
- separate assessment of decision process quality and realized outcome quality.

Bad outcome does not prove bad decision process; good outcome does not prove good process. The model
keeps both assessments explicit.

### Durable knowledge

Durable knowledge is an approved, generalizable claim or method. It is not current case status and
not a copy of raw evidence. A promotion proposal includes claim, scope/limits, provenance, related
cases, contradiction search, and evaluation result. Activation requires owner approval.

Correction happens through a versioned recompilation or superseding article while retaining the
prior promotion and provenance events.

## Semantic event envelope

Every semantic event uses a strict versioned envelope. An illustrative representation:

```yaml
schema_version: "1.0"
event_id: event_<ULID>
event_type: recommendation.issued
occurred_at: 2026-09-01T14:30:00-04:00
recorded_at: 2026-09-01T14:30:02-04:00
actor:
  type: owner | runtime | skill | reviewer | importer
  id: <stable actor or version id>
case_id: case_<ULID>
session_id: session_<ULID>
subject_refs:
  - recommendation_<ULID>
correlation_id: <workflow id>
causation_event_id: event_<ULID> | null
provenance:
  - ref: evidence_sha256_<hash> | event_<ULID> | approved_document_ref
    relation: supports | challenges | quotes | derives_from | supersedes
sensitivity: none | personal | work | hr | political | legal | formal_eval | irreversible
approval_ref: approval_<ULID> | null
payload: <event-type-specific object>
integrity:
  payload_sha256: <hash of canonicalized payload>
  previous_event_sha256: <prior partition record hash or GENESIS>
  event_sha256: <hash of canonicalized event excluding this field, including previous hash>
```

### Time semantics

- `occurred_at` is when the underlying statement/action/observation happened.
- `recorded_at` is when Vault Next appended the event.
- Importers must preserve both; they may not backdate `recorded_at` to make history look native.
- If occurrence time is unknown, record an uncertainty field instead of inventing precision.

### Actor semantics

Actor type is mandatory. System-generated text is never attributed to the owner. Imported legacy
content uses `importer` as recording actor and preserves the original attributed author separately.

### Provenance relations

At minimum, support:

- `quotes` — exact or bounded excerpt;
- `summarizes` — lossy condensation;
- `supports` — evidence bearing in favor;
- `challenges` — evidence bearing against;
- `derives_from` — generated transformation;
- `responds_to` — conversational/logical response;
- `corrects` — recording correction;
- `supersedes` — replaces current meaning without deleting history;
- `caused_by` — workflow causation, not necessarily real-world causality.

Real-world causal claims belong in payload analysis and must carry uncertainty. A ledger link does
not prove causality.

## Minimum event taxonomy

### Intake and session

- `case.created`, `case.linked`, `case.status_changed`
- `question.recorded`, `question.clarified`, `question.reframed`, `question.resolved`
- `triage.completed`, `use_case_profile.matched`, `use_case_profile.overridden`, `routing.proposed`,
  `routing.overridden`, `skill.selected`,
  `framework.selected`
- `interaction.started`, `interaction.mode_changed`, `checkpoint.recorded`, `owner_input.recorded`
- `session.started`, `session.scope_changed`, `session.blocked`, `session.closed`

### Evidence and reasoning

- `evidence.registered`, `evidence.assessed`
- `claim.recorded`, `assumption.recorded`, `assumption.revised`
- `alternative.recorded`, `alternative.disposition_changed`
- `disagreement.recorded`, `disagreement.resolved`
- `recommendation.issued`, `recommendation.revised`, `recommendation.withdrawn`
- `artifact.version_created`, `artifact.feedback_recorded`, `artifact.accepted`,
  `artifact.withdrawn`

### Human authority and promotion

- `owner_decision.recorded`, `owner_decision.revised`, `owner_decision.superseded`
- `approval.granted`, `approval.denied`, `approval.revoked`, `approval.expired`
- `promotion.proposed`, `promotion.approved`, `promotion.rejected`, `promotion.activated`
- `package.candidate_created`, `package.evaluation_completed`, `package.approved`,
  `package.activated`, `package.suspended`, `package.deprecated`

### Action, review, and outcome

- `action.proposed`, `action.authorized`, `action.status_changed`
- `work_item.recorded`, `work_item.status_changed`
- `review.completed`, `review.finding_waived`
- `outcome.observed`, `prediction.assessed`
- `event.correction_recorded`

Event names are stable public contracts. New types require schema, projection behavior, migration
behavior, and tests before use.

## Correction, revision, and supersession

These operations are distinct:

| Operation | Meaning | Example |
|---|---|---|
| Correction | Prior record misstated what happened | Imported date was parsed incorrectly |
| Revision | The actor’s view or proposal changed | Recommendation changes after new evidence |
| Supersession | A newer object replaces the old object’s current authority | Owner replaces a prior decision |
| Reassessment | New evidence evaluates an unchanged prior object | Outcome review tests a prediction |

`event.correction_recorded` references the target event, identifies erroneous fields, states the
corrected representation, and provides provenance. Projectors apply corrections without removing
the original event from historical views.

No correction event may be used to conceal a real change of mind; that is a revision.

## Append-only versus refreshable

| Record/view | Append-only or immutable | Refreshable/replaceable | Notes |
|---|---:|---:|---|
| Raw evidence bytes | Yes | No | New source version gets a new hash |
| Evidence metadata history | Yes | No | Current metadata view may project corrections |
| Semantic events | Yes | No | Corrections and supersession append |
| Approval events | Yes | No | Revocation/expiry append |
| Operational audit | Yes | No | Attempt result is never erased |
| Closed session manifest snapshot | Yes | No | Active working manifest may change with scope events |
| Owner identity/governance source files | Versioned human source | Human-approved edit | Repository history records changes; runtime cannot edit autonomously |
| Approved triage/profile/skill/framework package | Versioned release | Approved new version | Active version pointer is refreshable through promotion event |
| Durable knowledge article | Versioned approved source | Approved recompile/supersede | Prior version retained in history |
| Case status projection | No | Yes | Rebuilt from events |
| Decision memo projection | No | Yes | Rebuilt as-of chosen watermark |
| Case journal projection | No | Yes | Rebuilt chronologically |
| Review report artifact | Immutable for reviewed hash | New report for new hash | Never silently repoint |
| Evaluation report | Immutable run result | New run | Baseline changes require approval |
| Working artifact version | Yes | No | Revision creates a new content hash and lineage event |
| Current artifact pointer/view | No | Yes | Folded from valid artifact events |
| Current-work/daily-status view | No | Yes | Folded from work-item and case/session events |

## Provenance requirements

### Claim-level provenance

Every load-bearing factual or attributed claim in a consequential recommendation or decision memo
must resolve to one or more evidence/event references, or be marked as assumption/inference.

Provenance must answer:

- who stated or generated it;
- what source bytes/event it came from;
- when it occurred and when it was recorded;
- whether it is quote, summary, inference, or assessment;
- what transformations were applied;
- what uncertainty or contradiction remains.

### Transformation provenance

Generated summaries and projections record generator version, source watermark, input hashes, and
schema version. A reviewer can therefore determine exactly which source set was reviewed.

### Legacy provenance

Imported records retain:

- legacy absolute source path as inert provenance text;
- source snapshot ID and content hash;
- legacy Git commit when applicable;
- working-tree status/classification at discovery;
- importer and mapping-rule versions;
- whether the import was exact, transformed, skipped, or quarantined.

The legacy path is never treated as a runtime directive or writable target.

## Decision journey representation

A decision journey is not a separate mutable essay. It is the ordered subset of events that shaped
a decision:

1. question and framing events;
2. relevant evidence and evidence assessments;
3. assumptions and contradictions;
4. alternatives and their disposition changes;
5. attributed disagreements;
6. recommendation revisions and reviews;
7. explicit owner decision;
8. later action and outcome links.

The projection may compress repeated low-value events but must preserve every material change of
frame, recommendation, owner position, unresolved disagreement, and accepted cost. Omitted events
remain listed in the provenance appendix/watermark so compression is inspectable.

## Decision memo derivation

The memo is regenerated from canonical records using these steps:

1. Select a decision ID and an event watermark.
2. Validate the relevant event partition(s), corrections, actor authority, and references.
3. Resolve the original question and any accepted reframes without dropping the verbatim original.
4. Assemble evidence used as-of the decision, grouped by supports/challenges/context.
5. Resolve assumption state as-of the decision, not today’s current state.
6. Assemble material alternatives, costs, and dispositions.
7. Render recommendation revisions and explain what caused material changes.
8. Render unresolved disagreements exactly as they stood at decision time.
9. Render the explicit owner decision; use “not stated” for missing owner rationale.
10. Link actions and outcomes in later sections without rewriting the original decision rationale.
11. Include generator version, source watermark, review state, and provenance appendix.
12. Run deterministic equivalence checks and configured semantic review.

Required memo sections:

```text
Decision and current disposition
Original question and accepted frame
Journey summary: what changed
Evidence used and limitations
Assumptions and contradictions
Alternatives considered
Recommendation history
Owner decision and stated rationale
Accepted costs / conditions
Actions and outcomes
Open reviews / what could change the call
Provenance and generation metadata
```

The top section may show current disposition, but the body must separate “as decided” from “what we
know now.”

## Case journal derivation

The case journal is chronological and cross-session. It contains:

- case purpose and current projected state;
- active questions and unresolved assumptions;
- session timeline with triage route/profile, resolved skills/framework, and outcome;
- decisions and supersession chain;
- actions, denials/failures that matter semantically, and current state;
- outcomes and prediction assessments;
- durable-knowledge promotions originating from the case;
- related cases;
- warnings, open findings, and provenance watermark.

The journal may link to operational audit records but does not narrate every tool call. Only an
operation that changed or failed to change the semantic case appears in the journal.

## Current-state projections

Current state is a fold over valid events:

- latest non-corrected/non-superseded case status;
- active decision in each supersession chain;
- most recent explicit action status;
- open assumptions, disagreements, findings, and review triggers;
- outcome maturity status.

Fold rules are deterministic, versioned, and covered by fixtures. If two events create an ambiguous
state, the projector fails with an explicit conflict instead of choosing silently.

## Operational audit model

The operational record envelope is separate from semantic events. Minimum fields:

```yaml
schema_version: "1.0"
operation_id: operation_<ULID>
attempted_at: <timestamp>
actor: <runtime/tool identity and version>
case_id: case_<ULID> | null
session_id: session_<ULID> | null
action_id: action_<ULID> | null
semantic_event_refs: [event_<ULID>, ...]
operation_class: read | write | promote | execute | transmit | delete
target_summary: <safe exact-enough description>
input_digest: <hash>
policy:
  result: allow | deny | requires_owner_approval
  reason_code: <code>
  approval_ref: approval_<ULID> | null
attempt_status: not_attempted | attempted
result: succeeded | failed | denied | cancelled
output_refs: [<hash or artifact/event ref>, ...]
error_code: <safe code> | null
```

The audit store avoids raw sensitive inputs. Detailed error payloads, if required, are protected
artifacts referenced by hash and access policy.

## Consistency invariants

The validator must enforce at least:

1. Every event references an existing case; session-scoped events reference an existing session.
2. Every triage/profile and selected skill/framework version is approved and exists.
3. Every closed session has a frozen manifest hash and closure event.
4. Every owner-decision event has owner actor type and valid explicit-action/approval provenance.
5. Recommendation actor is never owner unless the owner actually authored it.
6. Every evidence reference resolves and its content hash matches when bytes are local.
7. Every correction references an earlier event and cannot alter event ID or actor attribution.
8. Every superseded decision points to a valid newer decision; cycles are invalid.
9. Every protected promotion/action has a matching non-revoked approval for the exact digest.
10. Every projection watermark contains only validated events and matches clean rebuild output.
11. Semantic events never use operational success as implicit decision or approval.
12. Operational audit never contains hidden semantic rationale required to understand the case.
13. Artifact feedback, review, and acceptance reference an existing exact version and matching
    content hash; changed bytes require new review and acceptance.
14. Artifact acceptance cannot satisfy owner-decision, promotion, work-commitment, or external-action
    approval requirements.
15. Every material interaction-mode change preserves the prior contract, records its initiating
    actor, creates a new manifest version, and revalidates composition, context, and permissions.
16. A system-proposed work item cannot become `open`, `in_progress`, `done`, or `cancelled` without
    an explicit owner event or approved authoritative-source rule.
13. A generated projection cannot be a provenance source for canonical events except as a
    `summarizes` view pointing through to its canonical inputs.
14. Legacy paths are inert provenance and cannot resolve as writable runtime targets.

## Model evolution

- Schemas are versioned; old canonical events are never rewritten for a new schema.
- Readers support explicit upcasting to an in-memory current representation.
- Any lossy migration requires a new event or migration record and owner approval.
- A new event type is not active until its schema, fold behavior, projection behavior, and tests exist.
- Deprecated types remain readable and replayable.
- Model changes replay all accepted fixtures before promotion.

## Open choices that do not block Phase 1

- ULID versus UUIDv7, provided the choice is made once before the first canonical record.
- JSON Lines canonicalization library, provided hashes are deterministic across supported machines.
- Exact Markdown styling of projections, provided required sections and provenance remain.
- Whether review findings use one generic schema or specialized subtypes.

These choices should be resolved in Phase 1 ADRs before canonical data is created.
