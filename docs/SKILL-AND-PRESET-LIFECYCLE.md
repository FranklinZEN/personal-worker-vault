# Vault Next Use-Case Profile and Skill Lifecycle

Status: Phase 0 draft for owner review  
Date: 2026-09-01

## Purpose

Vault Next should respond naturally to familiar personal language while remaining open to novel
requests. Universal triage applies a use-case profile when one fits and composes skills dynamically
when none does. Named shortcuts such as “deep dive,” “meeting prep,” “interview prep,” or “resume”
can select profiles without requiring the owner to reconstruct the method each time.

This document separates triage/profile behavior from the reusable skills underneath it and defines a
dedicated build, review, approval, activation, and maintenance lifecycle. Active skills or profiles
are never casually edited in place. The general triage and layered configuration contract is defined
in `TRIAGE-AND-USE-CASE-DESIGN.md`.

Phase 0 defines these contracts. It does not build or activate the real personal profiles.

Because the system has one owner, the profile/shortcut registry should remain small and
owner-maintained.
Deterministic commands and approved phrase aliases resolve first; model-based intent matching may
propose a profile only when no explicit alias matches. No marketplace, tenant customization, or
general workflow-discovery service is required.

## Four distinct concepts

| Concept | Owner-facing role | System role | Example |
|---|---|---|---|
| Use-case profile | Configurable recurring-work defaults that triage may apply | Provides default plan, inputs, case/context rules, review profile, and output contract | Meeting preparation |
| Named shortcut/preset | Optional owner-facing alias for a profile | Selects an approved profile/version directly | “Deep dive into this topic” |
| Skill | Reusable bounded method | Contributes one unique capability to profiles or dynamic sessions | Source comprehension, option design, claim verification |
| Framework | Temporary collaboration shape | Controls how selected skills contribute and synthesize | Committee, brainstorming, consultation, red team |
| Case | Durable continuity boundary | Connects the new session to relevant prior questions, decisions, actions, and outcomes | Current-work initiative or interview search |

A profile is not a synonym for a skill. A profile may use one skill, compose several skills, or
change its composition according to the supplied material while preserving the same owner-visible
standard. A named preset/shortcut is only one way to select a profile; dynamic routing remains
available when no profile fits.

## Profile invocation and shortcut policy

### Resolution order

1. **Explicit profile shortcut/name.** A direct invocation such as `/meeting-prep` or “meeting prep
   for tomorrow” selects that approved profile/version.
2. **Recognized owner phrase.** A clear phrase such as “deep dive into,” “prepare me for an interview,”
   or “work on my resume” selects the corresponding profile.
3. **Intent match.** When the owner does not name a profile but the request clearly matches one,
   triage proposes it and may proceed under approved low-risk defaults. This is advisory matching,
   not authority to broaden the workflow.
4. **Question-first composition.** If no profile fits, triage builds a dynamic plan from approved
   skills/frameworks.

An explicit profile shortcut outranks a generic intent match, but never overrides governance,
permissions, sensitivity, missing required inputs, or an explicit owner instruction to use a
different method.

### Automatic initiation behavior

For an approved low-risk profile, a recognized phrase should:

1. record the verbatim question/request;
2. record the triage plan, matched profile ID/version, and match reason;
3. propose or resolve the relevant case when continuity is useful;
4. initialize the profile’s planning checklist and review profile;
5. resolve the smallest sufficient approved skill/framework composition;
6. load only authorized context;
7. continue without a separate “which skill?” question unless a missing input would materially
   change the result;
8. show the owner a concise recognition line, important assumptions, and any needed override.

The profile removes routine setup friction. It does not pre-approve protected reads, writes,
promotion, external actions, or owner decisions.

### Ambiguity and collision rules

- If a phrase could mean a shortcut or an ordinary word, use sentence position, requested outcome, and
  prior explicit syntax; do not trigger on a mere incidental mention.
- A direct `/profile-name` shortcut is unambiguous unless the profile is unavailable or suspended.
- When two profiles plausibly match and the difference would materially change work, propose the best
  match with one short rationale and ask at most one necessary clarification.
- A profile may redirect to another profile or dynamic routing when its non-purpose is clear, but the
  redirect is recorded.
- The owner may override or cancel the profile at any point. Preserve the original match and override.

## Use-case profile contract

Every profile package defines:

- stable profile ID, display name, version, lifecycle status, family, and owner;
- purpose, non-purpose, and redirect behavior;
- explicit commands, recognized phrases, positive examples, and near-miss negative examples;
- required and optional inputs;
- default case behavior: new, propose existing, or no case needed;
- initiation checklist and conditions that genuinely require a question;
- default skill work units and permitted alternative compositions;
- compatible/default frameworks;
- context-load policy and sensitivity defaults;
- artifact/output shape and audience defaults;
- deterministic validation profile;
- semantic/review profile, including red-team requirement where applicable;
- permission needs and prohibited actions;
- completion, no-decision, block, and handoff conditions;
- fixture/evaluation set and accepted baseline;
- changelog, provenance, and approval history.

The manifest records the complete triage plan, matched profile, and actual resolved skills/framework.
The profile name alone is never enough to reconstruct what ran.

## Named use-case seed examples

These are Phase 0 seed examples, not the full catalog and not active packages. Other profiles may be
added through the lifecycle; a novel request needs no profile because dynamic routing is first-class.

### Deep dive

**Recognized intent:** “deep dive into,” “analyze this deeply,” or an explicit `/deep-dive`.

**Automatic standard:**

1. Preserve the original question and desired decision/output.
2. If material is supplied, verify and summarize what was read, what matters, and what is absent.
3. Resolve or propose a case when the topic belongs to current work or an ongoing personal thread.
4. Frame the problem and surface decision-critical contradictions.
5. Record load-bearing assumptions and what would change the answer.
6. Select the smallest sufficient combination of comprehension, research/evidence assessment,
   option design, specialist consultation, synthesis, and red-team contributions.
7. Lead with a plain-language answer; expose derivation and alternatives underneath it.
8. Run deterministic checks and the configured semantic/red-team review before finalization.
9. Separate recommendation, owner decision, and any action proposal.

**Does not imply:** internet research, broad vault search, personal-content migration, or an external
action unless separately requested and authorized.

### Meeting prep

**Recognized intent:** “meeting prep,” “prepare me for my meeting,” or `/meeting-prep`.

**Automatic standard:**

1. Identify meeting purpose, participants, owner objective, desired decision/ask, timing, and
   sensitivity.
2. Link the relevant case and load only current, authorized status/evidence.
3. Separate known facts, stale context, assumptions, and participant-specific hypotheses.
4. Produce the recommended stance, agenda, key points, likely objections/questions, evidence, and
   decision rights.
5. Include fallback positions and what not to commit to when consequential.
6. Offer rehearsal or question simulation when useful.
7. Produce a concise meeting-ready artifact and a later debrief handoff hook.

**Does not imply:** inventing stakeholder details, sending invitations/material, or recording a
post-meeting decision before the owner confirms it.

### Interview prep

**Recognized intent:** “interview prep,” “prepare me for this interview,” or `/interview-prep`.

**Automatic standard:**

1. Identify role, organization, interview stage, format, competencies, and available materials.
2. Distinguish supplied facts from external research; ask before external research when policy
   requires it.
3. Build an evidence-backed story inventory from owner-approved experience.
4. Map likely questions to stories, gaps, and honest limitations.
5. Draft answer structures without inventing achievements.
6. Run mock questions and score against explicit criteria.
7. Prepare owner questions, decision criteria, and follow-up needs.

**Does not imply:** fabricating experience, submitting an application, or contacting anyone.

### Resume

**Recognized intent:** “resume,” “update my resume,” “tailor my resume,” or `/resume` when the request
is clearly about the owner’s career document.

**Automatic standard:**

1. Identify target role/audience and the current resume/source materials.
2. Inventory claims and supporting evidence before rewriting.
3. Mark unverifiable, overstated, stale, or missing claims; never invent metrics or ownership.
4. Select a structure and emphasis appropriate to the target.
5. Produce a clear revision with material before/after rationale.
6. Review factual accuracy, chronology, consistency, sensitivity, and target fit.
7. Keep output as a draft unless the owner explicitly approves a durable artifact or application
   action.

**Does not imply:** publishing, applying, uploading, or changing durable personal identity records.

## Case-aware profile behavior

When a profile is used for “something in my current work,” triage should search only the
authorized case index/metadata first and propose a matching case. It must not indiscriminately load
the whole vault.

The owner can accept, reject, or choose a different case. The manifest records:

- triage route and profile match;
- proposed and selected case;
- case-match rationale;
- context references actually loaded;
- any continuity assumptions or stale-status warnings.

If no case is suitable, create a case only when the work is likely to continue or create a decision,
action, or outcome trail. One-off drafting does not require a case by default.

## Skill package contract

Every skill package contains:

- stable skill ID and semantic version;
- lifecycle state and active-version pointer outside the immutable version package;
- purpose, non-purpose, and redirect examples;
- contribution metadata used by profiles/composer;
- required/optional inputs and context classes;
- method/instructions and concise rationale standard;
- unique contribution contract;
- input and output schemas where structure matters;
- compatible/conflicting skills and frameworks;
- requested permissions and prohibited actions;
- deterministic validations;
- positive, negative, adversarial, and regression fixtures;
- semantic quality rubric and accepted baseline;
- known limitations and failure modes;
- provenance, design decisions, changelog, and owner approvals.

A skill should be small enough to test as a method and substantial enough to change the output. A
prompt fragment, stylistic preference, persistent persona, and end-to-end workflow are not skills by
default.

## Dedicated build and review lifecycle

### Lifecycle states

```text
proposed -> design_review -> candidate -> evaluation_passed -> owner_approved -> active
               ^               |                 |                   |
               +---- revise <--+---- fail -------+                   v
                                                               monitored
                                                                   |
                                      +----------------------------+-------------------+
                                      v                            v                   v
                                   revise                       suspend            deprecate
```

`retired` is a terminal availability state after deprecation and retention review. Historical
manifests continue to reference the immutable version that ran.

### Stage 1 — Proposal

Required evidence:

- problem/gap and representative requests;
- why an existing profile, skill, framework, dynamic route, or ordinary instruction is insufficient;
- expected owner value and frequency;
- risks, sensitive context, and permission classes;
- proposed evaluation cases and success/failure measures.

A proposal may be rejected as unnecessary without creating a package.

### Stage 2 — Design review

Review:

- scope and non-scope boundaries;
- whether it is truly a profile, skill, framework, owner default, policy, or output template;
- overlap and conflict with active packages;
- required inputs and context minimization;
- attribution, provenance, owner-decision, and action boundaries;
- failure/recovery behavior;
- interaction cost and whether the profile actually saves owner effort.

Output: approved candidate design or reasoned rejection/revision.

### Stage 3 — Candidate implementation

- Create a new immutable candidate version; never edit the active version in place.
- Implement contract, schemas, fixtures, and change notes together.
- Use synthetic data by default.
- Keep permissions at the minimum needed.
- Add deterministic validation before semantic evaluation.

Candidate status grants no authority to execute in normal sessions.

### Stage 4 — Evaluation

Run:

- positive trigger/contribution cases;
- near-miss and non-trigger cases;
- overlap/conflict cases;
- missing, contradictory, stale, and malicious input cases;
- output-contract and provenance checks;
- permission-denial and no-action cases;
- semantic quality rubric;
- interaction-cost/usability checks;
- regression replay for every affected triage rule, profile, skill, framework, and baseline.

A profile additionally tests explicit/inferred matching, automatic initialization, case behavior,
actual skill resolution, dynamic fallback, override, and end-to-end completion.

### Stage 5 — Independent review

The review packet includes candidate digest, design, diff, fixtures, evaluation results, known
failures, and activation/rollback plan.

- Deterministic review verifies contracts, versions, permissions, and regression evidence.
- Semantic review examines method quality, blind spots, over-triggering, and whether the output earns
  its interaction cost.
- Red-team review attacks authority leakage, invented facts, unsafe context expansion, and output
  overconfidence.
- The candidate cannot review or approve itself.

### Stage 6 — Owner approval and activation

Approval binds:

- exact candidate digest and version;
- evaluation run/baseline versions;
- active profile/skill target;
- permission profile;
- known accepted limitations;
- monitoring and rollback conditions.

Activation changes only the approved active-version pointer and appends promotion events. It does not
rewrite historical versions or manifests.

### Stage 7 — Monitoring

Monitor:

- invocation count and explicit owner overrides;
- false-positive/false-negative profile matches and inappropriate dynamic fallbacks;
- missing or redundant skill contributions;
- interaction friction and clarification count;
- deterministic/reviewer failures;
- owner corrections and rejected recommendations;
- safety denials and permission requests;
- regression on replay fixtures.

Monitoring may propose revision, suspension, deprecation, or new fixtures. It cannot change the
active package autonomously.

## Change classification

| Change class | Examples | Version/review requirement |
|---|---|---|
| Documentation-only | Typo or explanation that cannot change runtime/model behavior | New patch version or immutable metadata correction; validation and diff review |
| Presentation behavior | Output order, headings, compression, owner-facing recognition line | New version; affected fixtures and owner review if materially different |
| Method/routing behavior | Instructions, profile matching, shortcuts, work units, framework/default composition | New minor/major version; full affected evaluation and owner activation |
| Context/permission/sensitivity | New files read, broader context, write/action class | Major protected change; threat review, full safety replay, explicit owner approval |
| Contract/schema | Input/output/event changes | Major or compatible version per contract; migration/upcaster design and full replay |
| Baseline/rubric | Accepted expected behavior changes | Independent adjudication and owner approval; never bundled to hide a regression |

Any active-package edit that could change selection, reasoning, content, context, permission,
validation, or output is behavioral even if it appears to be “just prompt wording.”

## Review cadence and deprecation

- Review high-use or high-risk active packages on evidence, not a calendar alone.
- Trigger review after repeated override, false trigger, safety failure, material owner correction,
  or dependent contract change.
- Low-use packages are candidates for simplification/deprecation, not automatic deletion.
- Suspension immediately prevents new selection while preserving history.
- Deprecation names replacement/redirect behavior and an observation window.
- Retirement removes normal availability only after references and replay compatibility are verified.

## Governance boundaries

- Profiles, skills, and frameworks cannot grant themselves permissions.
- Candidate packages cannot edit their own tests, baselines, approval, or active pointer.
- No package can treat its output as an owner decision or durable-knowledge promotion.
- The owner may invoke or override an active package, but override does not silently alter its
  definition.
- Emergency suspension may be policy-driven for a safety defect; reactivation requires owner review.
- Platform adapters expose the same canonical package versions and invocation semantics.

## Core versus post-core

The following belong in the core build:

- triage, profile, skill, and framework contracts;
- explicit/inferred profile resolution and dynamic fallback;
- versioning and active pointers;
- candidate/evaluation/approval/activation mechanics;
- synthetic candidate packages and acceptance fixtures;
- owner override and suspension behavior.

The following remain post-core:

- autonomous gap detection across live sessions;
- system-generated candidate proposals based on monitoring;
- automated experiment selection;
- any continuous improvement loop beyond reporting evidence and proposing a reviewed candidate.

The skill lifecycle is core governance. Self-improvement automation is not.

## Phase 0 decisions requested

Before Phase 1/P3 implementation, confirm:

1. Every request uses universal triage; no profile fit results in dynamic composition rather than a
   forced nearest match.
2. Named phrases may initialize approved profiles without a separate skill-selection question when
   inputs are sufficient.
3. `deep-dive`, `meeting-prep`, `interview-prep`, and `resume` are seed examples, not a closed or
   privileged profile catalog.
4. “Deep dive” is a profile/shortcut that may compose skills, not a single monolithic skill by
   definition.
5. Active triage/profile/skill versions are immutable; every behavioral change creates and evaluates
   a new candidate version.
6. Real personal profiles are prioritized and built only after synthetic triage/profile/skill
   lifecycle mechanics pass their acceptance gate.
