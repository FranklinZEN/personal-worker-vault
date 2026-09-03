# Vault Next Phase 1 Evidence

Status: Owner approved; Phase 1 gate closed  
Date: 2026-09-01  
Approved: 2026-09-01 by the repository owner  
Content scope: synthetic fixtures and Phase 0 documents only

## Outcome

Phase 1 proves the smallest trusted local write path:

`synthetic question → versioned triage/manifest metadata → policy decision → canonical semantic and
operational append → deterministic validation → generated session trace → replay/recovery`

No legacy personal content was read or migrated, neither protected legacy root was written, no real
profile was activated, no external service was connected, and the draft governance remains inactive.

## Implemented deliverables

| Roadmap requirement | Evidence |
|---|---|
| Python package and CLI | `src/vault_next`, `python -m vault_next` |
| Versioned schemas and payloads | `schemas/v1` and `schemas/v1/events` |
| Identifier decision | ADR-0003 and monotonic ULID tests |
| Canonical JSON, partitions, locking | ADR-0004, `canonical.py`, `ledger.py`, concurrency tests |
| Schema dependency decision | ADR-0005, checked-in schemas, strict supported-keyword loader |
| Minimal triage/profile metadata | `triage-plan.schema.json`, `triage.py`, `packages.py` |
| Policy and exact approvals | `policy.py`, approval mutation and protected-path tests |
| Separate semantic/operational ledgers | `SemanticLedger`, `OperationalLedger`, AT-019 |
| Deterministic validator | `validator.py`, cross-ledger and projection tests |
| Projection/replay | `projection.py`, AT-018 |
| Recovery/quarantine | `ledger.py`, partial-tail and wrong-chain AT-015 tests |
| Synthetic fixture harness | `fixtures.py`, `fixtures/synthetic/basic-session.json` |
| Offline developer commands | `Makefile`, `vault_next.dev` |

## Verification result

The full offline command completed successfully with Python 3.12.13:

```sh
make verify PYTHON=python3
```

- Format check: passed.
- Dependency-free lint check: passed.
- Compile/schema/public-annotation check: passed.
- Full suite: 29 tests passed.
- Acceptance-only run: 12 tests passed.
- Unresolved test failures: zero.

The deterministic vertical-slice validation report recorded:

| Field | Value |
|---|---|
| Tool version | `0.1.0` |
| Schema version | `1.0` |
| Runtime | Python `3.12.13` |
| Semantic events | 6 |
| Operational records | 1 |
| Projections | 1 |
| Semantic fixture hash | `ffbb02f8defd60dc48fd5d8b0959a36a166b1385c8c5dea7e140d3d52c09bcbb` |
| Operational fixture hash | `a46ef88a4b9397f3f46454c8b8b9be08a1a0bff3bd9efaf983b91117cfc19138` |
| Projection hash | `f73271a13152bfecbfc99ac58665a8f8d1f4b2192917767b2cafc6c0d750f337` |
| Deterministic issues | 0 |

## Acceptance mapping

| Scenario | Result | Direct evidence |
|---|---|---|
| AT-007 | Pass | Ambiguous agreement cannot append an owner decision; closure remains `no_decision` |
| AT-010 | Pass | Correction appends and projection marks the corrected value; original line is unchanged |
| AT-012 | Pass | Default-denied transmission is `not_attempted` and separately audited |
| AT-013 | Pass | Digest, target, consequence, expiry, and revocation changes fail closed |
| AT-014 | Pass | Structural, actor, and reference errors leave the ledger byte-identical |
| AT-015 | Pass | Partial and wrong-hash tails are quarantined; valid prefix bytes survive; changed tails invalidate recovery approval |
| AT-018 | Pass | Clean rebuild is byte-equivalent; tampered projection is detected and quarantined |
| AT-019 | Pass | Denied, failed, and successful operations remain outside semantic rationale |
| AT-020 subset | Pass | Synthetic source/backup and symlink write targets are denied without mutation |
| AT-021 subset | Pass | Pure synthetic candidate planning is deterministic and performs no runtime writes |

Additional direct checks cover 500 same-millisecond unique IDs, canonical object-order invariance,
concurrent writer serialization, schema fail-closed behavior, package-version immutability,
governance precedence, and cross-ledger reference validation.

## Known limits and deliberate deferrals

- The internal schema engine implements only the checked-in Phase 1 JSON Schema subset. Unknown
  keywords fail closed; it is not a general-purpose validator.
- Locking uses POSIX advisory locks and is currently supported for the local macOS/POSIX target.
- The ledger is tamper-evident, not cryptographically signed against a hostile machine owner.
- Branch coverage was not numerically measured because no third-party coverage dependency was
  introduced. Safety branches are exercised through direct negative and property-style tests.
- The dependency-free type command verifies compilation, schema loading, and public annotations; a
  mature static analyzer is a future development-tool decision.
- Complete lifecycle state machines, evidence storage, decision/case journals, semantic review,
  real profiles/skills, model routing, and migration are explicitly deferred to later milestones.
- Failed candidates remain in the local staging area for inspection; retention/cleanup policy is a
  future operational decision.

## Gate decision

The Phase 1 implementation gate is technically satisfied with no unresolved deterministic failure.
The repository owner approved this evidence in the Vault Next Codex conversation on 2026-09-01 and
separately authorized the roadmap's synthetic-only Phase 2 scope. This evidence does not authorize
personal content access, migration, governance activation, external services, or real profiles.
