# Vault Next Phase 5 Evidence

Status: Owner approved
Evidence date: 2026-09-04
Scope: Exact roadmap P5 scope, synthetic fixtures only

## Verdict

The technical P5 gate passes. Vault Next now creates fixed, hash-bound semantic-review packets,
keeps reviewers tool-less and non-authoritative, persists immutable result attempts separately from
the reviewer, and prevents required-review finalization until an exact pass or explicit owner waiver.
Synthetic evaluation runs and baselines are immutable and baseline establishment/change requires an
explicit reviewed-change record.

The owner approved this evidence on 2026-09-04. That approval does not authorize P5A, P7, or any
personal-content operation.

## Authorized boundary observed

- The repository owner approved Phase 4 evidence and authorized the roadmap's exact synthetic-only
  P5 scope on 2026-09-04.
- All cases, recommendations, findings, reviewers, rubrics, outcomes, evaluation checks, and
  expected results are invented.
- No protected legacy source or rollback backup was read or changed.
- No model call, prompt execution, remote service, connector, adapter, scheduler, background worker,
  personal profile/content, migration, or external transmission was used.
- The governance draft remains inactive. P5A, P6, and later phases were not started.

## Delivered behavior

| P5 deliverable | Evidence |
|---|---|
| Fixed review packet | Versioned packet binds case/session, exact target hash, full source watermark, rubric, sensitivity disposition, and explicit no-tool/no-write/no-decision/no-approval policy |
| Exact target review | Supports recommendation event, immutable artifact-version content hash, and checkpoint event targets; a changed target does not reuse clearance |
| Tool-less reviewer | Reviewer interface is a pure packet-in/result-out boundary; the coordinator, never the reviewer, records completion |
| Findings and finalization | High findings block the session and deny owner decision/closure while review is unresolved; low-level review data carries exact source event references and remediation |
| Outage/retry | Unavailable review is a structured non-pass; draft history remains valid and retry creates a separate immutable result attempt against the same target hash |
| Waiver | Only an owner-attributed, explicit confirmation tied to a finding result and target hash clears that result |
| Sensitivity | A packet containing any sensitivity above `none` withholds substantive content and returns a non-pass rather than leaking material |
| Evaluation/replay | Immutable synthetic regression run records routing, event-invariant, projection, and reviewer-rubric check digests; baseline writes require a reviewed-change record and owner confirmation |
| Redaction protocol | [Candidate protocol](REDACTION-PROTOCOL-v1.md) is deliberately inactive and requires its own owner/source/purpose authorization before use |

## Acceptance results

| Gate | Result | Structured evidence |
|---|---|---|
| AT-016 | Pass for P5 | High synthetic coherence finding is source-referenced, blocks the session, and denies final owner decision while leaving draft capture intact |
| AT-017 | Pass for P5 | Reviewer unavailability records `unavailable`, never pass; retry creates attempt 2 for the identical target hash and can clear the review gate |
| P5 authority invariant | Pass | Review packet policy fixes tools, writes, approval, and decision authority to `false`; reviewer receives no repository/runtime interface |
| Exact-version invariant | Pass | Packet/result/completion/waiver all bind the target SHA-256; stale or packet-external references are rejected |
| Baseline-control invariant | Pass | Unreviewed baseline establishment/change is rejected with `REVIEW_BASELINE_CHANGE_UNREVIEWED` |
| Synthetic end-to-end replay | Pass | Replays the P4 synthetic question-through-outcome case, then adds a separate reviewed recommendation-through-explicit-decision journey |

## Verification record

The compliant workspace runtime was Python `3.12.14`; Vault Next reports tool version `0.4.0`.

```text
format-check: pass
lint: pass
typecheck/schema-load: pass
full test discovery: 68 passed
acceptance discovery: 46 passed (12 Phase 1, 8 Phase 2, 10 Phase 3, 5 Phase 3A, 6 Phase 4, 5 Phase 5)
```

The independent P5 fixture validates with zero findings:

| Evidence value | SHA-256 or stable value |
|---|---|
| Semantic fixture | `d241ef1d1dba8f3829aaf0f3508fae5896be0ab453c1aa87a29b9951333293a9` |
| Operational fixture (canonical empty list) | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Review target | `a01736181c67384bffeb8f135bc24e030a45dea04b893a641b6d93895dc2cc93` |
| Review result | `752f66982e710882fb8d8c4910b269e23469d80427f93b8ff02e55b425b60b3a` |
| Evaluation run | `21d519a29839c41a315aa20180ebf54d352e6a247cd5e08d5b1669fab22b0922` |
| Evaluation baseline | `81e6cb565723bf462ac3a31cdb9b8001db0e562266d20522dff79d8887affc50` |
| Semantic event count | `63` |
| Operational action count | `0` |
| Projection count | `7` |

## Known limits and next decision

P5 supplies a deterministic interface and synthetic reviewer fixtures. It does not run a model or
claim model-level semantic judgment. It does not activate the redaction protocol, inspect
personal material, create real profiles, migrate content, connect services, schedule follow-up, or
perform external actions.

The owner approved the P5 evidence and separately approved Redaction Protocol v1 as inactive
governance only on 2026-09-04. P5A and P7 remain unauthorized. The protocol supplies no permission
to access personal or legacy content; a completed, exact P7 pilot authorization must be approved
before any source access begins.
