# Vault Next Phase 6 Evidence

Status: Owner approved
Evidence date: 2026-09-04
Scope: Exact roadmap P6 scope, hostile synthetic legacy trees only

## Verdict

The technical P6 gate passes. Vault Next now provides a synthetic-only migration laboratory for
read-only discovery, deterministic staging dry runs, reconciliation, collision/exception reporting,
exact-copy fidelity checks, policy-bound pilot proposals, and logical deactivation.

The laboratory refuses any source directory without an explicit synthetic-fixture marker. It was not
used to read either protected real vault, and it cannot commit a pilot or write canonical state.

The owner approved this evidence on 2026-09-04. That approval does not authorize P7, a redacted
pilot, or personal-content access.

## Delivered behavior

| P6 deliverable | Evidence |
|---|---|
| Protected source boundary | Unmarked roots are rejected before discovery; a marked synthetic source is read only, never traversed through out-of-scope symlinks |
| Versioned contracts | Executable `migration-snapshot` and `migration-dry-run` schemas require contract version, source/snapshot/run digests, reconciliation, provenance, exceptions, and fidelity output |
| Snapshot discovery | Inventories files, directories, binary candidates, Git metadata/nested repository roots, symlinks, and inaccessible-item errors without modifying source or backup |
| Mapping/reconciliation | Every discovered item receives one mapping disposition or exception; unsupported, read-error, symlink, and collision cases remain visible |
| Historical authority | Task/artifact mappings are explicitly `historical_non_authoritative`; no prose creates a current work commitment, accepted artifact, owner decision, active package, or governance change |
| Staging-only transform | Dry-run reports and exact-copy bytes are written only under `data/staging/migrations`; semantic, audit, evidence, artifact, package, review, and evaluation stores remain untouched |
| Fidelity/collisions | Exact-copy target digests are compared to source digests; colliding proposed targets produce stable `TARGET_COLLISION` exceptions |
| Pilot interface | The pilot interface returns an exact `Proposal` requiring normal owner approval; it does not invoke policy approval, ledger writes, or canonical import |
| Rollback rehearsal | Deactivation adds an immutable marker while retaining staging evidence; neither sources nor records are deleted |

## Acceptance results

| Gate | Result | Structured evidence |
|---|---|---|
| AT-020 | Pass for P6 | Hostile synthetic source/backup before-after tree digests match; an external-target symlink is not followed; unmarked roots are denied |
| AT-021 | Pass for P6 | Repeated dry runs yield equivalent candidates/provenance/reconciliation; source, backup, and canonical semantic-store digests remain unchanged |
| Synthetic AT-022 boundary | Pass for P6 foundation | Historical mappings are non-authoritative and the pilot interface cannot import or activate a decision; no redacted/personal fixture was used |
| Pilot/rollback boundary | Pass for P6 | Pilot proposal receives `requires_owner_approval`; logical deactivation preserves staging evidence |

## Verification record

```text
format-check: pass
lint: pass
typecheck/schema-load: pass
full test discovery: 71 passed
acceptance discovery: 49 passed (12 Phase 1, 8 Phase 2, 10 Phase 3, 5 Phase 3A, 6 Phase 4, 5 Phase 5, 3 Phase 6)
```

## Known limits and next decision

P6 handles only disposable marked synthetic fixtures. It does not inspect, snapshot, hash, copy,
parse, transform, or migrate either protected real vault. It does not activate the redaction
protocol, write canonical migration events, run a pilot commit, or authorize a P7 sample.

The owner has approved P5 and P6 evidence and Redaction Protocol v1 as inactive governance only.
P7 remains independently unauthorized. A completed, exact pilot authorization request must be
approved before any P7 implementation or source access can begin.
