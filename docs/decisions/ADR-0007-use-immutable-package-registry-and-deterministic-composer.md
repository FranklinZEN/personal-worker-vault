# ADR-0007: Use an immutable package registry and deterministic composer

- Status: Accepted for Phase 3 implementation
- Date: 2026-09-02
- Decision owner: Phase 3 architecture under the approved roadmap

## Context

Phase 3 introduces routing behavior that can change which methods, context classes, permissions, and
review requirements enter a session. Treating profiles or skills as ordinary editable configuration
would let a wording change silently alter behavior, bypass evaluation, or retroactively change the
meaning of historical manifests. A profile label also cannot replace an inspectable plan showing the
actual contributions selected.

## Decision

1. Profile, skill, and framework definitions are immutable, canonical JSON version objects addressed
   by package ID, semantic version, and SHA-256 digest.
2. Mutable availability lives only in a small active pointer. Historical manifests retain exact
   package ID, version, and digest and never resolve through the current pointer.
3. Candidate creation, design review, deterministic evaluation, independent review, exact owner
   approval, activation, suspension, and deprecation are recorded in a separate hash-chained package
   lifecycle ledger.
4. Only an active pointer whose target bytes match its recorded digest may match or execute.
   Candidate, suspended, deprecated, missing, and digest-mismatched versions fail closed.
5. Initial Phase 3 packages are invented fixtures. Their approvals and owner identities are synthetic
   test records; they do not activate real personal workflows or grant real permissions.
6. Universal triage evaluates explicit shortcuts, deterministic recognized phrases, inferred profile
   rules, and then dynamic fallback in that order. A weak nearest profile is never forced.
7. Composition is a deterministic minimum set-cover over declared work units. Every selected skill
   must add a unique contribution, be compatible with the framework and other skills, and request no
   permission outside the plan's granted set.
8. Layered product configuration records the winning value and source at each layer. Governance and
   protected permission keys cannot be weakened by lower layers.
9. Framework execution is local and synthetic in Phase 3. It records attributed contributions,
   stages, disagreements, findings, revisions, and explicit uphold dispositions; it does not invoke a
   model or create an owner decision.
10. Owner routing overrides append a new event and manifest version. The original proposal remains
    immutable and attributable to the runtime.
11. Routing evaluation fixtures and adjudication records are deterministic artifacts. A baseline
    change cannot be used to conceal a failed candidate.

## Consequences

- Repeated requests gain low-input initialization without making profiles ambient authority.
- Dynamic routing remains useful for novel requests and does not grow the catalog automatically.
- Package activation requires more ceremony, but behavioral changes are attributable, replayable,
  reversible by pointer change, and isolated from historical sessions.
- Phase 3 does not implement real personal packages, semantic-review model execution, persistent
  agents, platform memory, external connectors, migration, or Phase 4 decision memos.
