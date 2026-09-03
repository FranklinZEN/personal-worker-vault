# ADR-0008: Make Interaction Modes, Working Artifacts, and Work Items First-Class

Status: Accepted by repository owner  
Date: 2026-09-03

## Context

The current architecture models cases, sessions, triage, skills, frameworks, recommendations,
decisions, and generated outputs. It can preserve a reasoning journey, but it does not explicitly
define the live interaction mode, iterative artifact acceptance, or repository-backed daily work
review as first-class contracts. Without those distinctions, implementation could optimize for
artifact production and under-deliver the owner's primary value: collaborative understanding,
revision, and continuity.

## Decision

The repository owner approved this decision on 2026-09-03:

1. Every routed session resolves an explicit interaction contract independent of profile, skill,
   framework, and artifact type.
2. Supported initial modes are `explore`, `co_develop`, `artifact_iterate`, `rehearse`, and
   `status_review`.
3. A material mode change appends an event and a new full manifest version; any recomposition is
   governed by the existing active-package and permission rules.
4. The system records concise material checkpoints and owner inputs, not hidden chain-of-thought or
   an assumed full-transcript memory.
5. Working artifact versions are immutable and content-addressed. Feedback and revision lineage bind
   to exact versions.
6. Artifact acceptance is an explicit owner event distinct from owner decision, durable-knowledge
   promotion, work commitment, and external action approval.
7. Repository-local work items are semantic tracking objects distinct from operational actions. AI
   suggestions remain `proposed` until explicit owner commitment.
8. A deterministic current-status projection powers `status_review`; generation of the view never
   mutates canonical state.
9. P3A is inserted before P4 to implement these additions with synthetic fixtures only. P4 owns
   usable artifact lineage, case journey, current-work, and daily-status projections.

## Alternatives considered

### Treat interaction as presentation only

Rejected. Mode affects composition, completion conditions, checkpointing, artifact policy, and
continuity, so it must be inspectable in the manifest.

### Treat each mode as a skill

Rejected. Skills are reusable methods; interaction mode governs the owner/system relationship and
may select several skills.

### Store the complete chat transcript as canonical state

Rejected. It creates platform dependence, noise, privacy burden, and an implicit memory layer.
Material owner inputs, checkpoints, and provenance are sufficient for continuity.

### Make every generated artifact mutable until final

Rejected. In-place edits break review binding, provenance, comparison, and acceptance semantics.

### Reuse operational actions as personal follow-ups

Rejected. Tracking a task must not imply permission to execute a consequential external action.

## Consequences

- P1 invariants remain unchanged, but the schema and ledger vocabulary will grow additively.
- P2 manifests and runtime need interaction, checkpoint, artifact, and work-item fields/events.
- P3 evidence remains technically valid for its original scope but should not be finally approved
  until the P3A amendment is resolved and regression-tested.
- P4 receives a clearer and larger projection responsibility.
- Personal profiles must define expected interaction, not only inputs and output artifacts.
- Thin adapters must support live mode switching, feedback, artifact acceptance, and status review.
- Proactive scheduling and external connectors remain separate decisions.

## Approval boundary

Approval of this ADR approved the architecture decision only. The owner subsequently and separately
authorized the roadmap's exact synthetic-only P3A implementation scope on 2026-09-03. Neither
approval authorizes P4, personal content, adapters, model calls, external services, migration, or
draft-governance activation.
