# Vault Next Phase 3 Evidence

Status: Original-scope technical gate passes; interaction amendment implemented in P3A  
Evidence date: 2026-09-02  
Scope: Exact roadmap Phase 3 scope, synthetic fixtures only

## Verdict

The technical Phase 3 gate passes. Universal triage supports exact shortcuts, recognized phrases,
safe inferred profiles, and a general dynamic fallback. The composer chooses the smallest sufficient
set of active skills, requires a unique contribution from each, checks framework compatibility and
permissions, and records omissions. Package versions are immutable and cannot match or execute
until their exact digest has passed evaluation and independent review, received explicit owner
approval, and become the active pointer.

This evidence remains valid for the Phase 3 scope that was authorized. A subsequent product review
identified cross-cutting interaction requirements that were not explicit in that scope. The owner
approved the resulting design and separately authorized P3A, which is now implemented and evidenced
in `docs/PHASE-3A-EVIDENCE.md`. The two evidence packages now await combined owner approval; neither
authorizes Phase 4.

## Post-evidence design review finding

The implemented triage/composer can select a profile, skills, and framework, but the approved scope
did not make the owner/system interaction mode, no-artifact exploration, iterative artifact
acceptance, or repository-local work items first-class contracts. Implementing only Phase 4 would
produce additional views without repairing those missing session and authority semantics.

The approved resolution is documented in `INTERACTION-FIRST-WORK-MODEL.md` and ADR-0008. It added a
design-gated P3A before P4 and acceptance scenarios AT-030 through AT-034. P3A has now extended the
contracts and replayed all earlier regression gates. The original Phase 3 hashes and pass results
below are unchanged.

## Authorized boundary observed

- All profiles, skills, frameworks, prompts, identities, evidence, and expected outputs are invented.
- No content was read from the protected legacy source or rollback backup.
- No legacy location was written, moved, renamed, cleaned, or deleted.
- No remote, network service, connector, scheduler, model call, or external transmission was used.
- No real/personal package was created or activated.
- `docs/governance/AGENTS-v2-DRAFT.md` remains inactive.
- Phase 4 decision/case projections were not started.

## Delivered contracts and behavior

| Roadmap deliverable | Evidence |
|---|---|
| Canonical package contracts | Strict profile, skill, framework, lifecycle-event, evaluation, pointer, and triage schemas |
| Immutable versions and active pointers | Canonical version files; atomic pointers; direct mutation, stale digest, and reactivation fail closed |
| Universal triage | Explicit shortcut, recognized phrase, safe inference, near-miss rejection, and dynamic fallback |
| Low-input initialization | Profile case behavior, planning checklist, context policy, review profile, output contract, and completion checks |
| Layered configuration | Effective value and source recorded for governance, owner defaults, family, named profile, safe inference, and owner instruction |
| Synthetic catalog | Six families, four named profiles, four skills, and six frameworks; 20 active packages total |
| Minimal composer | Work-unit coverage, minimum-cardinality selection, conflicts, compatibility, permissions, unique value, and omitted-skill rationale |
| Framework execution | Specialist, committee, brainstorming, consultation, synthesis, and red-team stage contracts |
| Owner route override | Explicit owner event retains the original plan and updates the next full manifest to the revised active composition |
| Routing evaluation | Five checked-in positive, phrase, inference, near-miss, and dynamic fixtures with exact deterministic adjudication |
| Candidate lifecycle | Proposal, design review, evaluation, independent review, exact approval, activation, suspension, and deprecation contracts |

ADR-0007 records the governing design: immutable canonical package JSON, append-only lifecycle
events, mutable active pointers only, deterministic precedence and minimum-set composition, and no
persistent-agent or platform-specific memory.

## Package lifecycle guardrail

An initial package follows:

`proposed → design reviewed → candidate created → evaluated pass → independent review pass → exact owner approval → active`

Failed evaluation blocks approval. Approval binds the candidate digest, evaluation event, review
event, permission-profile digest, target version, and limitations. Active bytes cannot change in
place. A behavior, trigger, method, output, context, permission, schema, or baseline change must use a
new version and identify the superseded version and all affected fixture classes. A
documentation/presentation label cannot conceal a declared behavioral field. Suspension or
deprecation removes the package from selection while historical versions remain resolvable.

## Acceptance results

| Gate | Result | Structured evidence |
|---|---|---|
| AT-001 | Pass | Exactly comprehension, option-design, and red-team skills cover the three requested units; synthesis is explicitly omitted |
| AT-002 | Pass | Original route bytes survive; owner override is explicit; manifest points only to the revised active framework |
| AT-003 | Pass | Independently attributed contributions precede synthesis; dissent and recommendation remain in the session trace |
| AT-004 | Pass | Three distinct options exist before criteria; every option receives a reasoned disposition; no owner decision appears |
| AT-005 | Pass | Seeded weakness becomes a linked review finding and a recommendation revision without rewriting revision 1 |
| AT-011 | Pass | Injection text remains `untrusted_data`; external transmission is denied; no approval, decision, action, or governance event appears |
| AT-023 | Pass | Protected write denial remains intact while a justified three-skill composition succeeds |
| AT-026 | Pass | Shortcut, phrase, inference, near-miss, one-question missing-input behavior, initialization, and manifest composition validate |
| AT-027 | Pass | Mutation, self-promotion, mislabeled behavior, preapproval activation, and failed evaluation all fail; exact candidate activation and suspension pass |
| AT-028 | Pass | Novel fixture uses dynamic routing, creates no profile, and receives a minimal active composition |
| AT-029 | Pass | Every effective configuration value has a source; owner preference wins only for configurable fields; governance remains protected |

Additional acceptance coverage executes the specialist, consultation, and synthesis frameworks and
checks every declared stage in order. All six framework kinds therefore have an executable synthetic
contract.

## Verification record

The compliant workspace runtime was Python `3.12.13`; Vault Next reports tool version `0.3.0`.

```text
make verify PYTHON=python3

format-check: pass
lint: pass
typecheck/schema-load: pass
full test discovery: 50 passed
acceptance discovery: 30 passed (12 Phase 1, 8 Phase 2, 10 Phase 3)
```

The Phase 3 synthetic fixture is executed twice by an automated determinism test. Each run activates
20 packages through 140 lifecycle events, creates one fully routed committee session with 20
semantic events, builds one verified session projection, and produces no operational record.

| Evidence value | SHA-256 |
|---|---|
| Routing fixture suite | `0e41694e9611dd53c4db35e3dc607bdefa611f29d409d472853df1c69aafa054` |
| Catalog index | `c3103d0789225d0a3e19350cfbcada0e3a0e497487f4ddfd388e44a17f11832f` |
| Package lifecycle tail | `b76ce1804431d30e43046583b6f8f021645a30f0483a3a598f0009da70613910` |
| Triage plan | `20788f6df8fe159b70886034d9bf5e8aa63bade237510cdce5de330c751749cf` |
| Semantic fixture | `6102cf06a7935eb61c3019db2ad1abfcf69da3041049b0ddb5d3ace0dfde72a1` |
| Operational fixture (canonical empty list) | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Session projection | `50c903c2fbfa8ca840d2895f9c4d0f0326c2e33dc5a235a5b246ca5ce5d1aa5b` |

## Negative and coherence checks

- Candidate packages cannot create themselves, edit an existing version, transfer an old approval,
  activate after failed evaluation, or reactivate a suspended/deprecated version.
- Catalog validation compares canonical index bytes and digest with the active pointers and validates
  the package lifecycle hash chain.
- Routing rejects incomplete plans, plan-digest mismatches, non-active packages, changed pointers,
  uncovered work units, redundant skills, conflicts, incompatible frameworks, and ungranted package
  permissions.
- Contribution events require matching skill attribution and a prior selection in the same session;
  framework stages require a prior framework selection.
- Review findings require a prior recommendation, and an upheld recommendation requires a prior
  finding. Recommendation and owner-decision authority remain separate.
- Profile invocation grants no context, write, decision, promotion, governance, external-action, or
  persistent-memory authority.
- All Phase 1 crash recovery, concurrency, canonicalization, policy, protected-path, and projection
  tests and all Phase 2 lifecycle/context tests remain green.

## Known limits and next decision

Phase 3 intentionally uses deterministic rules and synthetic package contents. It does not provide
real/personal profiles or skills, model execution, semantic-review model execution, persistent-agent
memory, platform adapters, personal-data ingestion, migration, connectors, scheduling, a GUI, or the
complete decision memo/case journal/current-status projection set assigned to Phase 4.

The owner approved the interaction-first design and ADR-0008 and separately authorized P3A on
2026-09-03. Review this evidence together with `docs/PHASE-3A-EVIDENCE.md`; Phase 4 remains
unauthorized until the combined Phase 3/P3A evidence is approved and P4 receives separate explicit
authorization.
