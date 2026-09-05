# Vault Next Phase 4 Evidence

Status: Owner approved; P5 subsequently authorized
Evidence date: 2026-09-04
Scope: Exact roadmap P4 scope, synthetic fixtures only

## Verdict

The technical P4 gate passes. Vault Next now renders deterministic, provenance-labelled Markdown
decision memos, case journals, working-artifact histories, and current-work views from canonical
events. Generated files are explicitly non-authoritative, content-hash-bound, cleanly rebuildable,
and quarantined if local edits differ from the canonical rebuild.

No view creates a decision, work commitment, artifact acceptance, promotion, or external action.
The new owner-only `outcome.assessed` record makes later result/process evaluation explicit while
preserving the historical owner decision unchanged.

The repository owner approved this evidence on 2026-09-04. P5 then received its own separate
exact-scope authorization; this evidence does not authorize any later phase.

## Authorized boundary observed

- The repository owner approved the combined Phase 3/P3A evidence and this roadmap's exact
  synthetic-only P4 scope on 2026-09-04.
- All cases, questions, decisions, outcomes, artifacts, owner statements, tasks, evidence, and
  expected results are invented.
- No protected legacy source or rollback backup was read or changed.
- No personal profile, personal content, migration, model call, platform adapter, connector,
  scheduler, background worker, external service, or transmission was used.
- The governance draft remains inactive. P5 was separately authorized later and is evidenced in
  `docs/PHASE-5-EVIDENCE.md`.

## Delivered behavior

| P4 deliverable | Evidence |
|---|---|
| Decision memo | Original question, frame/change history, evidence/limits, assumptions/alternatives, recommendation history, preserved owner-decision history and current disposition, later outcome assessment, and source watermark |
| Case journal | Chronological, actor-attributed event table plus interaction journey, checkpoint/owner-input visibility, and correction markers |
| Artifact history | Immutable version lineage, parent/hash/change comparison, feedback disposition, review state, and exact accepted-version identification |
| Current-work/today view | Due/review items, proposed versus owner-committed work, blockers, active cases/sessions, and accepted artifacts awaiting a next step |
| Outcome separation | Owner-only `outcome.assessed` record separates result quality from process quality, prediction assessment, competing explanation, confidence, maturity, and evidence |
| Integrity | Generated header carries source IDs, source watermark, generator/schema version, do-not-edit flag, and self-excluding digest; validator rebuilds every Markdown projection |
| Tamper handling | Rebuild detects modified generated Markdown, quarantines the prior bytes, and restores the canonical rendering without changing semantic history |

## Acceptance results

| Gate | Result | Structured evidence |
|---|---|---|
| AT-006 | Pass for P4 | Decision memo carries material synthetic decision records, attribution, source event IDs, and full source watermark |
| AT-008 | Pass for P4 | Memo distinguishes decision revision/current state without changing the original decision record |
| AT-010 | Pass for P4 | Case journal renders correction event/provenance while original event bytes remain unchanged |
| AT-018 | Pass for P4 | Markdown tampering fails validation; canonical rebuild quarantines the edit and restores the generated view |
| AT-019 | Pass for P4 regression | Markdown projectors read semantic events only; operational records remain separate and the fixture has zero operations |
| AT-025 | Pass for P4 | Owner outcome assessment reports mixed result quality and strong process quality separately, with competing explanation, confidence, maturity, and registered synthetic evidence |
| AT-032 projection portion | Pass for P4 | Artifact history renders exact version/hash acceptance, feedback disposition, and immutable lineage/comparison |
| AT-033 projection portion | Pass for P4 | Today view separates proposals from owner commitments, exposes provenance/watermark, and creates no event |

## Verification record

The compliant workspace runtime was Python `3.12.14`; Vault Next reports tool version `0.4.0`.

```text
make verify PYTHON=python3

format-check: pass
lint: pass
typecheck/schema-load: pass
full test discovery: 63 passed
acceptance discovery: 41 passed (12 Phase 1, 8 Phase 2, 10 Phase 3, 5 Phase 3A, 6 Phase 4)
```

The deterministic P4 fixture is replayed by its acceptance test. It reconstructs the P3A synthetic
journey, resumes it under a fresh explicit decision session, records a decision revision and a
separate owner outcome assessment linked to registered synthetic evidence, rebuilds older session
traces, then writes four Markdown views.

| Evidence value | SHA-256 or stable value |
|---|---|
| Semantic fixture | `2196ad97cbb4b2d115a990311d1f68d0d9b4667057272be729b11ea29fd58442` |
| Operational fixture (canonical empty list) | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Decision memo | `fbab529a92bf9f13160129bf0467bf823e5f2314130bc5cd841423ba832ea827` |
| Case journal | `88fac9d7da2325a3f9f203ea182498dd902dfaf454594de7448ee8f2d2d65c94` |
| Artifact history | `fc5ff29c0ea7decd30181a19f8809e7c923d56e5dbb245100d5b2f44696897f5` |
| Current-work view | `40964b7b7d0e36ec1946f3aa42fc08a3496d82429e375db9f4a756774427e961` |
| Semantic event count | `52` |
| Operational action count | `0` |
| Projection count | `7` |

An independent fixture validation reports zero findings.

## Known limits and next decision

P4 is a generated-view layer over local synthetic state. It does not implement model-based semantic
review, evaluation workflow, redaction protocol, real/personal profiles or content, migration,
adapters, external task/calendar synchronization, reminders, connectors, scheduling, background
operation, or any external action.

The Markdown views intentionally summarize canonical artifact metadata rather than embed artifact
bytes. Their purpose is reviewable lineage and state, not an alternate mutable artifact store.

The P4 evidence was approved on 2026-09-04. The next decision is whether to approve the separately
authorized P5 evidence; P5A remains unauthorized.
