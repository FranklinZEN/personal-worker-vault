# ADR-0002: Use universal triage with configurable use-case profiles and dynamic fallback

- Status: Accepted
- Date: 2026-09-01
- Accepted: 2026-09-01 by the repository owner
- Decision owner: repository owner
- Scope: Session initiation, workflow configuration, and skill composition

## Context

The owner wants recurring requests such as deep dives, current-work analysis, meeting preparation,
interview preparation, resume work, and future use cases to start with useful definitions already
populated. At the same time, Vault Next must support general and novel requests without requiring a
profile for every topic or forcing the owner to select internal skills.

Two simple designs are insufficient:

- a fixed catalog of named presets saves setup time but becomes brittle and incomplete as use cases
  grow;
- pure question-to-skill routing preserves flexibility but repeatedly rediscovers inputs, artifact,
  context, review, and completion standards for recurring work.

Because Vault Next is personal-only, configuration can remain owner-maintained and deterministic
without marketplace, tenant, or multi-user abstraction.

## Decision

1. Every request enters one versioned universal triage.
2. Triage selects one of three routes:
   - explicit use-case profile through a named shortcut/profile name;
   - inferred high-confidence use-case profile;
   - dynamic skill/framework composition when no profile sufficiently fits.
3. A use-case profile prepopulates recurring defaults: classification, inputs, case behavior, work
   units, context policy, review profile, output contract, completion checks, and permission needs.
4. A profile supplies candidates/defaults rather than a fixed skill list. The composer resolves the
   actual smallest sufficient skill/framework plan for the specific request.
5. The profile catalog begins with broad families and seed examples, not a closed ontology.
6. Dynamic routing remains a first-class permanent fallback even as the profile catalog grows.
7. Configuration precedence is:
   - active governance and permissions;
   - global owner defaults;
   - family profile;
   - named use-case profile;
   - safe session inference;
   - explicit owner instruction/override for product preferences.
8. No profile/default/override may weaken platform safety or protected-operation approval rules.
9. Triage asks at most one material clarification by default and proceeds under reversible stated
   assumptions when safe.
10. Active triage/profile/skill versions are immutable and use the dedicated candidate lifecycle.

## Seed profile families

- general dynamic;
- understand and research;
- analyze and decide;
- prepare and interact;
- create and communicate;
- plan and execute;
- review and learn.

Named examples such as `deep-dive`, `meeting-prep`, `interview-prep`, and `resume` may specialize
these families, but none has privileged or exhaustive status.

## Alternatives considered

### Maintain only named presets

Rejected because it encourages overlap, forces novel work into weak matches, and turns every new use
case into a maintained monolithic package.

### Use only skills and question-first composition

Rejected as the sole design because recurring work repeatedly pays avoidable setup and clarification
cost. Retained as the dynamic fallback.

### Hard-code workflows in governance

Rejected because configuration, versions, evaluation, and owner overrides would be difficult to
inspect or evolve without editing broad authority documents.

### Use a model to infer every route with no profile registry

Rejected because behavior and defaults would be less predictable, harder to test, and unable to
offer stable low-friction named standards.

## Consequences

### Positive

- Familiar requests start with less owner input.
- Novel requests remain fully supported.
- Shared family defaults reduce duplication across related profiles.
- Profile configuration is owner-visible and versioned.
- Actual skills, context, review, and permissions remain explicit.
- Personal-only scope keeps the registry and resolver small.

### Negative and accepted costs

- Triage, profile matching, inheritance, and dynamic fallback need dedicated schemas and tests.
- Profile overlap and stale defaults require monitoring.
- Configuration provenance adds manifest fields.
- Too many profiles can still create maintenance cost, so profile creation must show saved effort or
  quality/safety value.

## Guardrails

- A weak match chooses dynamic routing, not the nearest profile.
- Named shortcuts cannot grant protected permissions.
- Case matching uses authorized metadata first.
- Every applied default records its configuration source.
- The owner can override product preferences in ordinary language.
- A session override never silently edits owner defaults or profile definitions.
- Successful dynamic work does not automatically create a profile.

## Validation

Acceptance scenarios AT-026 through AT-029 must verify:

- profile match with minimal input;
- immutable profile/skill change lifecycle;
- novel-use-case dynamic fallback;
- layered configuration precedence and governance protection.

## Approval record and effect

The repository owner accepted this ADR in the Vault Next planning conversation on 2026-09-01. This
acceptance changes the Phase 0 architecture recommendation and Phase 1/P3 contracts. It does not
activate any profile, build the triage runtime, migrate personal content, or approve a named profile.
Each real profile still requires its own candidate evaluation and owner activation.
