# Vault Next Triage and Use-Case Profile Design

Status: Phase 0 draft for owner review  
Date: 2026-09-01

## Verdict

Every request should pass through one universal triage. Triage should choose one of three routes:

1. apply an explicit named use-case profile;
2. infer and apply a high-confidence profile from the owner’s request;
3. use dynamic skill/framework composition when no profile fits.

This hybrid is better than either a fixed preset catalog or pure skill routing. Profiles save time by
prepopulating recurring definitions; dynamic composition preserves flexibility for novel cases. A
profile supplies defaults and constraints, not a fixed workflow that overrides the actual question.

## Why the alternatives are insufficient

### Fixed named presets only

Advantages: fast and predictable for known requests.  
Failure: the catalog grows into many overlapping workflows, unusual requests get forced into the
nearest label, and maintaining each monolithic preset becomes expensive.

### Pure question-to-skill routing

Advantages: maximally flexible and avoids profile proliferation.  
Failure: recurring requests repeatedly pay the same setup cost—desired artifact, required inputs,
context, planning standard, review depth, and completion conditions must be rediscovered every time.

### Hybrid triage plus profiles plus skills

Advantages: recurring work starts quickly, novel work remains supported, and reusable methods stay
independent of owner-facing workflow definitions.  
Accepted cost: triage/profile configuration and overlap tests become first-class contracts.

## Terms

| Term | Meaning |
|---|---|
| Triage | The universal intake decision that determines case continuity, use-case route, defaults, composition, review, and required clarification |
| Use-case profile | A versioned configurable bundle of prepopulated defaults for a recurring class of work |
| Named shortcut/preset | An owner-facing command or phrase alias that directly selects a use-case profile |
| Family profile | Shared defaults inherited by related use cases, such as analysis/decision or preparation/interaction |
| Skill | A bounded reusable method selected to perform one part of the work |
| Framework | The temporary shape governing how selected skills contribute and synthesize |
| Dynamic route | A session-specific composition created when no profile fits sufficiently |
| Interaction mode | The owner/system working relationship for the session; independent of profile, skills, framework, and artifact type |
| Case | The durable continuity boundary when the request belongs to ongoing work |

The term “preset” is retained only for the shortcut/alias experience. The canonical configurable
object is a **use-case profile**.

## Universal triage flow

```text
Owner request
    |
    v
Trust + sensitivity classification
    |
    v
Explicit shortcut/profile named? -- yes --> load approved profile/version
    |
    no
    v
High-confidence profile match? ---- yes --> apply profile defaults, state inference
    |
    no
    v
Dynamic question-first route ---------> compose approved skills/framework
    |
    v
Resolve/propose case continuity
    |
    v
Fill safe inferable defaults + identify required missing inputs
    |
    v
Ask at most one material question, or proceed
    |
    v
Freeze TriagePlan into session manifest
```

Profile matching and case matching are separate. “Deep dive into my current work” may match the
analysis/decision profile first and then propose a current-work case. Neither match grants permission
to load protected content.

## Triage inputs

Triage uses only the owner request, supplied materials, approved owner defaults, catalog/profile
metadata, and authorized case index metadata. It does not initially load full skill instructions,
full case contents, or broad vault content.

Triage extracts or records:

- verbatim request;
- requested or inferred outcome;
- explicit shortcut/profile phrase, if any;
- supplied material type and apparent completeness;
- continuity signals: current work, named case/project/person, prior session;
- intended audience and artifact;
- requested or safely inferred interaction mode and whether an artifact is optional, iterative, or required;
- urgency/time budget/depth;
- stakes, sensitivity, reversibility, and possible action class;
- facts already supplied versus assumptions needed;
- missing inputs that would materially change the route or output.

## Triage classification axes

Profiles match on several independent axes rather than a single taxonomy label:

| Axis | Examples | Effect |
|---|---|---|
| Purpose | understand, analyze, decide, prepare, create, communicate, rehearse, review | Candidate family/profile and skills |
| Object | topic, evidence, decision, meeting, interview, resume, message, plan, outcome | Inputs and artifact contract |
| Continuity | one-off, existing case, new durable case | Case behavior and context |
| Audience | self, peer, executive, interviewer, team, external | Compression, tone, evidence standard |
| Depth/time | quick, standard, deep, deadline-bound | Breadth, review stages, interaction budget |
| Stakes | reversible, consequential, irreversible | Approval and review profile |
| Input shape | question only, attachment, transcript, draft, multiple sources | Read-back and evidence processing |
| Action intent | think, draft, decide, execute, transmit | Permission boundary and audit needs |
| Interaction mode | explore, co-develop, artifact-iterate, rehearse, status-review | Turn behavior, composition, checkpoints, and completion |

Profiles may specialize a subset of axes. The actual `TriagePlan` records all resolved axes even when
some values come from owner defaults or safe inference.

## Three routing outcomes

### Route A — explicit profile

Use when the owner names a command, shortcut, or profile unambiguously.

- Apply the approved profile/version immediately.
- Do not ask which skill to use.
- Still validate required inputs, case, permissions, and conflicts with explicit instructions.
- Record `match_method: explicit` and the exact phrase/command.

### Route B — inferred profile

Use when a recurring use case is clear even without its name.

- Deterministic phrase aliases and rules run before model-assisted matching.
- High-confidence, low-risk matches may proceed with a concise stated assumption.
- If the wrong profile would materially change work, propose the best match and ask one question.
- Record `match_method: inferred`, confidence band, evidence, and any owner override.

### Route C — dynamic composition

Use when no profile sufficiently fits, several profiles conflict, or the request is novel.

- Build a session-specific plan from approved skills/frameworks.
- Apply only universal owner defaults and governance.
- Do not force a nearest profile merely to avoid dynamic routing.
- Record `route_type: dynamic` and why profile candidates were rejected.
- A successful dynamic session may later support a profile proposal, but it cannot create one
  automatically.

Dynamic routing is a normal first-class result, not an error or incomplete catalog state.

## Confidence and proceed-versus-ask policy

| Situation | Behavior |
|---|---|
| Explicit profile plus complete inputs, low risk | Proceed and show concise triage receipt |
| High-confidence inferred profile, reversible defaults | Proceed with named assumptions and override path |
| Two plausible profiles with materially different outputs | Ask one discriminating question |
| Missing value is safely inferable and easy to reverse | Use owner/profile default and state it |
| Missing value changes factual accuracy, permission, audience, or decision | Ask one material question or block that branch |
| Protected context/action would be required | Request exact scope/approval separately; profile cannot grant it |
| No profile fits | Dynamic route without asking the owner to design the method |

The system should not ask for information merely because a field exists in the profile schema. It
asks only when the answer changes the route, safety, factual validity, or useful output.

## Layered configuration

Use-case configuration is inherited in this order:

```text
active governance and permissions       (cannot be weakened by profiles)
              |
global owner defaults                    (personal preferences)
              |
family profile                           (shared use-case standard)
              |
named use-case profile                   (specialized defaults)
              |
session-specific safe inference
              |
explicit owner instruction/override      (highest product-level preference)
```

An explicit owner instruction may override presentation, method, depth, artifact, or profile choice.
It may not bypass applicable platform safety or protected-operation approval rules.

### Global owner defaults

Examples:

- default audience when none is stated;
- preferred answer altitude and opening format;
- default time/depth mode;
- whether to proceed under reversible assumptions;
- maximum routine clarification questions;
- default case-proposal behavior;
- preferred artifact format;
- preferred interaction mode and whether artifacts default to optional;
- default review intensity for low-risk work.

Defaults are versioned owner preferences, not inferred personality claims.

### Family profiles

Seed families should be broad and few:

| Family | Purpose | Example named profiles/use cases |
|---|---|---|
| General dynamic | Safe fallback for any request | Novel or one-off work |
| Understand and research | Absorb or compare material | Document read, topic research, comparison, comprehension |
| Analyze and decide | Frame, evaluate, recommend, challenge | Deep dive, diagnostic, position, decision support, sparring |
| Prepare and interact | Prepare for a live human interaction | Meeting prep, interview prep, difficult conversation, negotiation prep |
| Create and communicate | Produce an artifact for a reader | Resume, email, proposal, brief, report, presentation outline |
| Plan and execute | Turn an outcome into ordered action | Project plan, daily plan, implementation plan, handoff |
| Review and learn | Evaluate prior work or outcomes | Meeting debrief, retrospective, postmortem, decision review |

These are routing scaffolds, not an exhaustive ontology. A use case may inherit one family and consult
skills associated with another when justified.

### Named use-case profiles

Named profiles specialize family defaults when recurring work benefits from distinct inputs,
artifacts, checks, or interaction behavior. `deep-dive`, `meeting-prep`, `interview-prep`, and
`resume` remain useful seed examples, not the final or privileged list.

Additional likely candidates may include document comprehension, decision preparation, meeting
debrief, difficult-conversation prep, writing/revision, project planning, weekly review, promotion
case, performance review, and learning plan. They enter only through the dedicated profile/skill
lifecycle and owner prioritization.

## Use-case profile schema

Illustrative configuration:

```yaml
profile_id: use_case_meeting_prep
version: 1.0.0
status: candidate
family: prepare_and_interact
display_name: Meeting prep
shortcuts: [/meeting-prep]
phrase_aliases:
  - prepare me for my meeting
  - meeting prep for
purpose: prepare the owner for a specific upcoming meeting
non_purpose:
  - post-meeting factual record
  - sending invitations or materials
match:
  positive_examples: [fixture_ref]
  near_miss_examples: [fixture_ref]
inputs:
  required_if_not_inferable: [meeting_purpose, timing]
  optional: [participants, agenda, source_material]
  safe_defaults: {audience: self, artifact: meeting_brief}
interaction:
  default_mode: co_develop
  allowed_modes: [explore, co_develop, artifact_iterate, rehearse]
  artifact_policy: optional
  checkpoint_policy: material_change
case_behavior: propose_existing_then_new_if_durable
work_units:
  required: [objective, context_assessment, stance, likely_objections, talking_points]
  conditional: [rehearsal, fallback_position, decision_rights]
skill_candidates: [skill_context_synthesis, skill_stakeholder_analysis, skill_red_team]
framework_default: synthesis
context_policy: metadata_first_then_authorized_case_refs
review_profile: standard_plus_sensitivity_escalation
output_contract: meeting_ready_brief
completion_checks: [objective_clear, assumptions_marked, asks_and_fallbacks_present]
permissions:
  implied: []
  prohibited_without_separate_approval: [transmit, schedule]
evaluation_suite: eval_use_case_meeting_prep_v1
```

The schema describes defaults and constraints. `skill_candidates` is not a mandatory fixed list; the
composer resolves actual work units against the current approved skill catalog.

## TriagePlan contract

Every session freezes the triage result in its manifest:

```yaml
triage_plan_id: triage_<ULID>
triage_version: 1.0.0
request_ref: event_<ULID>
route_type: explicit_profile | inferred_profile | dynamic
profile:
  id: use_case_meeting_prep | null
  version: 1.0.0 | null
  match_method: explicit | phrase_alias | model_proposed | none
  confidence: exact | high | medium | none
  match_reason: <concise explanation>
family: prepare_and_interact | null
resolved_axes:
  purpose: prepare
  object: meeting
  continuity: existing_case
  audience: self
  depth: standard
  stakes: consequential
interaction:
  mode: co_develop
  mode_source: named_profile
  rationale: <concise visible reason>
  owner_can_change_mode: true
  artifact_policy: optional
  checkpoint_policy: material_change
  completion_requires: [owner_checkpoint]
case_resolution:
  proposed_case_id: case_<ULID> | null
  selected_case_id: case_<ULID> | null
  reason: <metadata-only match explanation>
defaults_applied: [<field and source layer>, ...]
owner_overrides: [<field and value>, ...]
missing_material_inputs: [<field>, ...]
assumptions: [event_<ULID>, ...]
resolved_skills: [<skill id/version/contribution>, ...]
framework: <id/version>
context_plan: [<authorized metadata/reference>, ...]
review_profile: <id/version>
output_contract: <id/version>
permission_requirements: [<class>, ...]
```

Profile matching, actual composition, and permission requirements must all remain visible. The
profile label cannot substitute for the complete plan.

Interaction mode is not a skill. A mode changes how the session proceeds and may change required
work units, selected skills, framework, artifact policy, and completion checks. A material mode
change appends an event and new manifest version, then reruns compatibility and permission checks.
The one-question triage economy applies to initialization ambiguity; it does not restrict substantive
back-and-forth in an `explore`, `co_develop`, or `rehearse` session.

## Time-saving interaction design

### Triage receipt

For normal low-risk work, show one concise line rather than a confirmation form:

> Reading this as meeting preparation for the existing X case. I’ll produce a meeting-ready brief,
> use the current authorized case context, and include stance, likely objections, fallback, and
> talking points. I’m assuming the audience is you and the goal is a decision; correct either while
> I proceed.

Do not enumerate internal IDs or every field unless the owner asks or a warning requires it.

### Progressive disclosure

- Apply ordinary personal defaults silently but list material assumptions.
- Ask one question only when it changes route, safety, factual validity, or deliverable usefulness.
- Begin safe work while optional answers are absent.
- Expose detailed profile/composition/provenance in the saved manifest and on request.
- Let the owner override with ordinary language rather than configuration syntax.
- Let the owner change interaction mode in ordinary language while preserving the prior route and
  material conversation checkpoints.

### Personal corrections become configuration proposals

A one-session correction changes the session only. A repeated preference may trigger a proposal to
change owner defaults or a profile candidate. No preference is silently generalized or promoted.

## Profile versus skill decision test

Create or change a **profile** when the recurring value is faster initialization of an end-to-end use
case: inputs, defaults, case behavior, composition, artifact, review, and completion.

Create or change a **skill** when the recurring value is a reusable method that can contribute across
multiple use cases.

Create or change a **framework** when the recurring value is the interaction/order among multiple
contributions.

Use a **session override** when the difference is specific to the current request.

Do not create a new profile merely for a new topic. Topics belong to cases and session content; use
cases describe how work is done.

## Profile creation and lifecycle

Profiles use the same dedicated lifecycle as skills:

`proposal → design review → candidate → evaluation → independent review → owner approval → active → monitoring → revise/suspend/deprecate`

A profile proposal should show either:

- repeated setup work that can be prepopulated;
- a high-value recurring case with a distinct artifact/review standard; or
- a safety/quality need that generic composition handles inconsistently.

Avoid arbitrary numeric creation thresholds. Frequency, setup cost, consequence, and owner value all
matter. The owner decides whether the saved effort justifies another maintained profile.

## Guardrails

- Triage never interprets evidence content as instruction.
- Profile match never grants protected context or action permission.
- Case proposal uses metadata first; content loads only after authorization.
- A profile cannot force an unapproved or incompatible skill/framework.
- Profile defaults cannot weaken governance or sensitivity rules.
- Explicit owner decisions remain separate from profile/workflow completion.
- Active triage/profile/skill versions are immutable.
- Dynamic route remains available even when the profile catalog is large.
- Platform adapters use the same canonical triage and profile versions.

## Evaluation requirements

Triage/profile evaluation includes:

- explicit shortcut matches;
- ordinary phrase matches;
- incidental-word and near-miss non-matches;
- competing-profile ambiguity;
- novel requests requiring dynamic fallback;
- family/profile/global/session inheritance precedence;
- owner override;
- missing-input question economy;
- case match and unrelated-case non-leakage;
- protected permission denial;
- actual minimal skill contribution;
- stable manifest/provenance;
- interaction-cost and owner usefulness review.
- correct interaction-mode initialization and mode-change recomposition;
- no-artifact exploration completion, artifact revision/acceptance, and status-review behavior;

Measure:

- correct profile or dynamic-route rate;
- false profile activation rate;
- average material clarification count;
- owner override/correction rate;
- redundant skill contribution rate;
- time/turns saved against pure dynamic routing;
- safety and review failures.

## Phase placement

### Phase 0

- Approve the universal triage contract, layered configuration model, broad family scaffolds, dynamic
  fallback, and dedicated lifecycle.
- Treat named profiles as seed examples, not a closed catalog.

### Phase 1

- Implement only the versioned `TriagePlan`, profile metadata/lifecycle, precedence, policy, and
  validation contracts using synthetic fixtures.

### Phase 3

- Implement the triage engine, deterministic phrase resolver, profile registry/inheritance, dynamic
  composer fallback, case metadata proposal, and synthetic profiles.

### Phase 3A

- Add explicit interaction contracts, mode-change recomposition, material checkpoints, owner input,
  working-artifact lineage, and work-item contracts using synthetic fixtures.
- Reopen the Phase 3 gate only for these additive requirements; preserve all prior regression gates.

### Phase 5A

- Build/prioritize real personal profiles one at a time through evaluation and owner approval,
  beginning with whichever use case yields the most saved setup effort and decision value—not a
  permanently fixed four-item list.

## Phase 0 decision requested

Approve the following direction:

> Vault Next uses one universal triage for every request. Triage applies an approved use-case profile
> when explicitly named or confidently matched, and otherwise composes skills dynamically. Profiles
> prepopulate configurable defaults and review standards without fixing actual skill selection or
> granting permissions. The profile catalog begins with broad families and seed examples, grows only
> through the dedicated lifecycle, and never removes the dynamic fallback.

The interaction-first amendment is specified in `docs/INTERACTION-FIRST-WORK-MODEL.md`. The owner
approved that design and separately authorized its synthetic-only P3A implementation on 2026-09-03.
