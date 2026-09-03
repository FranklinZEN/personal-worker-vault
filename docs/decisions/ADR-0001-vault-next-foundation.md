# ADR-0001: Build Vault Next as a clean local canonical system

- Status: Accepted from the 2026-09-01 owner handoff
- Date: 2026-09-01
- Decision owners: repository owner
- Scope: Vault Next foundation

## Context

The legacy personal advisory vault contains valuable personal context, judgments, skills, evidence,
decision history, and knowledge. It has also accumulated platform-specific governance, convention-
driven capture rules, mixed operational/historical substrates, and a blanket one-skill-per-session
constraint.

The owner needs a system aligned with ChatGPT Work and Codex that preserves human authority and
inspectable decision history without depending on a particular chat’s memory. The legacy vault must
remain available as a read-only source, and an existing backup must remain immutable for rollback.

OpenWorker and other agent-runtime patterns may provide useful design ideas, but adopting a global
runtime or external knowledge system would create a competing source of truth and expand the core
scope beyond the stated problem.

## Decision

1. Build Vault Next in the clean local workspace.
2. Treat the protected legacy source as read-only.
3. Treat the protected rollback backup as immutable.
4. Do not edit, move, delete, clean, rename, or commit either legacy location.
5. Keep Vault Next local. Do not create a remote, publish, transmit, schedule, or connect an external
   service without explicit owner approval.
6. Use OpenWorker only as a design reference. Do not install it, depend on it, or replace the owner’s
   vault/skill model with its global knowledge model.
7. Maintain one canonical knowledge, governance, event, triage/use-case-profile, skill, and framework
   layer in the repository.
8. Use thin platform adapters for ChatGPT Work and Codex only where presentation or execution
   plumbing differs. Adapters may not maintain competing memory, triage/profile rules, skills,
   permissions, or decision semantics.
9. Begin with a hybrid local architecture: human-authored Markdown where human review is primary,
   versioned structured records where validation/replay is required, append-only event history, and
   rebuildable human-readable projections.
10. Separate semantic/decision history from operational action audit.
11. Keep personal-content migration and production feature implementation outside Phase 0.

## Decision drivers

- Preserve the legacy source and rollback path.
- Make the repository, not chat/model memory, the durable source of truth.
- Preserve owner authority over identity, decisions, governance, permissions, and durable knowledge.
- Support multi-skill reasoning without creating persistent autonomous teams.
- Make historical change, provenance, and later outcomes inspectable.
- Allow deterministic validation, replay, and regression evaluation.
- Avoid infrastructure and integration complexity before it is justified by measured need.

## Alternatives considered

### Evolve the legacy repository in place

Rejected because it risks personal content, entangles redesign with accumulated conventions, makes
rollback harder to reason about, and violates the clean-foundation direction.

### Copy the full legacy vault into Vault Next and refactor it

Rejected for Phase 0 because it duplicates sensitive content before the target model, migration
rules, validation, and rollback behavior are proven.

### Adopt OpenWorker as the runtime and knowledge model

Rejected because it would add an out-of-scope dependency, introduce a competing knowledge model, and
weaken the single canonical repository principle.

### Maintain separate canonical layers for ChatGPT Work and Codex

Rejected because inevitable drift in skills, decisions, provenance, and permissions would make
neither trustworthy.

### Use a database as the initial canonical store

Deferred rather than permanently rejected. A database improves transactions and queries, but a
binary canonical store is less inspectable and premature for a local single-writer system. Revisit
after measured scale or concurrency requirements.

## Consequences

### Positive

- Legacy data and rollback backup remain untouched.
- The new model can be designed around explicit contracts rather than inherited directories.
- Both operating platforms can share the same durable skills, governance, and history.
- Append-only events make correction and supersession visible.
- Markdown projections keep decisions and cases readable.
- Core work can be tested on synthetic fixtures before private content enters.

### Negative and accepted costs

- The system must build import tooling instead of relying on a direct copy.
- Some information will exist in canonical structured form and generated Markdown form.
- Platform adapters require discipline to remain thin.
- Migration will be slower because attribution, sensitivity, and promotion require review.
- A local file ledger needs locking, chain validation, and recovery tooling.

## Constraints created by this decision

- No code may treat either protected legacy root as a writable target.
- No generated projection may become the only source of an authoritative fact.
- No adapter may grant permissions or infer owner decisions differently from the core.
- No migration may activate identity, governance, current status, skills, decisions, or durable
  knowledge merely because a legacy file occupied an authoritative-looking path.
- Architecture changes that introduce a database, remote, external service, or multiple canonical
  stores require a new ADR and explicit owner approval.

## Validation

This ADR is upheld when:

- Phase 0 concluded with planning documents only, before implementation authorization;
- protected legacy roots remain unmodified;
- architecture and model documents have one canonical ownership table;
- acceptance tests cover protected-path denial, adapter parity, projection rebuild, explicit owner
  decisions, and migration fidelity;
- every later phase stops at its approval gate before expanding scope.

## Follow-up decisions

Phase 1 should add ADRs for:

- identifier format (ULID versus UUIDv7);
- canonical JSON serialization and hash-chain format;
- partition and writer-lock strategy;
- schema-validation implementation/dependency;
- generated-projection formatting and equivalence semantics;
- local backup/restore design before any personal migration.
