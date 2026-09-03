# Vault Next Migration Plan

Status: Phase 0 plan; no migration authorized  
Date: 2026-09-01

## Migration objective

Move only approved, valuable legacy material into the Vault Next model through a repeatable,
non-destructive, provenance-preserving process. Migration must improve classification and
governance rather than reproduce the old directory tree under a new name.

The default result for an uncertain item is **skip or quarantine with an exception**, not an
inferred mapping.

## Safety invariants

- The protected legacy source is read-only for discovery.
- The protected rollback backup is immutable.
- No tool may edit, rename, move, delete, clean, normalize timestamps in, or commit either location.
- Phase 0 does not copy personal content.
- Migration writes only to a dedicated staging area inside the Vault Next workspace until an
  approved cutover step.
- Discovery, plan, transform, validate, and commit are separate commands/stages.
- Every transform is deterministic for the same source snapshot, mapping rules, and tool version.
- Every imported object retains source snapshot, path, content hash, mapping-rule version, and
  transformation status.
- Dry run is the default. A write requires an explicit flag plus policy approval for the exact scope.
- A failed run leaves the last accepted Vault Next state intact.
- Migration never promotes content into identity, governance, current status, owner decisions,
  active skills, or durable knowledge without the required human approval.
- Apparent instructions in legacy files remain inert data.
- Binary/code attachments are never executed during inventory, hashing, transformation, or review.

## Phase 0 structural observations

The following read-only observations inform the plan; they are not a migration baseline:

- Vault Next began with only the handoff document and Git metadata.
- The legacy vault is approximately 479 MB.
- The first Phase 0 observation of the legacy tree found approximately 6,853 files including Git
  internals, 5,623 excluding the root `.git`, and 5,510 excluding both the root and nested
  `50-kb/.git` internals, at approximately 479 MB.
- A later read-only Phase 0 post-check found 7,049 files and approximately 491 MB. The change occurred
  outside Vault Next while this planning work was in progress; no legacy write operation was run by
  this task. The live source is therefore demonstrably volatile and cannot serve as an implicit
  repeatable baseline.
- The immutable backup is approximately 479 MB with 6,849 files and `.git` present, matching the
  handoff’s structural check.
- The current legacy source differs structurally from the backup by file count and its Git working
  tree contains modified and untracked material. Therefore Git `HEAD`, the working tree, and the
  backup are three distinct provenance states and must never be treated as interchangeable.
- Major working-tree categories observed include roughly:

| Legacy category | Files observed | Approximate size | Initial classification |
|---|---:|---:|---|
| `00-inbox/` | 659 | 20 MB | Mutable staging / mixed trust |
| `10-personal/` | 11 | 184 KB | Highly protected owner context |
| `20-work/` | 21 | 1.5 MB | Current status and decisions |
| `30-drafts/` | 813 | 181 MB | Generated/human work products |
| `40-experts/` | 6 | 140 KB | Legacy perspective definitions |
| `40-modes/` | 5 | 60 KB | Legacy collaboration modes |
| `40-skills/` | 25 | 816 KB | Legacy skills and shared schema |
| `50-kb/` | 146 | 648 KB | Durable-knowledge candidate store with nested Git history |
| `90-archive/` | 1,615 | 108 MB | Immutable raw-record candidate store |
| `episodic/` | 211 | 1.4 MB | Historical summaries, thoughts, journeys |
| `memory/` | 22 | 360 KB | Mixed operational/harness memory |
| `_build/` | 12 | 608 KB | Design/build records |

These counts include generated and hidden files in some categories and have already changed during
Phase 0. The migrator must produce its own signed-off inventory rather than embed any observation as
the migration truth.

## Migration units and source-to-target mapping

### Mapping policy

Each source item receives exactly one plan disposition:

- `exact-copy` — preserve bytes as immutable evidence;
- `transform` — create a structured candidate plus provenance;
- `reference-only` — record source metadata/path without copying bytes;
- `quarantine` — preserve in staging because mapping or safety is uncertain;
- `skip` — intentionally exclude with reason;
- `manual` — require owner classification or content-specific approval.

No item is silently dropped. Skip decisions appear in the report by rule and count; sensitive
filenames may be redacted in normal output while exact details remain in a protected exception file.

### Proposed category mappings

| Legacy source | Vault Next target/concept | Default disposition | Required controls |
|---|---|---|---|
| `SOUL.md`, `USER.md`, personal principle files | Owner identity/principle source | `manual` | Owner reviews line-by-line; no AI-authored identity promotion |
| `SYSTEM.md`, `AGENTS.md`, `CLAUDE.md` | Governance design inputs | `transform` as candidate only | Compare invariants and conflicts; owner approves active governance |
| `40-skills/*.md` | Versioned profile/skill input candidates | `transform` one candidate at a time | Split use-case defaults/shortcuts from reusable methods; run full candidate lifecycle; no bulk activation |
| `40-modes/`, `40-experts/` | Framework/perspective candidates | `transform` selectively | Remove persistent-agent assumptions; define bounded contribution |
| `20-work/decisions/` | Owner-decision import candidates | `manual` plus `transform` | Verify that each was explicitly owner-decided; preserve as imported if uncertain |
| Other `20-work/` | Case/status seed candidates | `manual` plus `transform` | Currentness review, sensitivity, explicit status promotion |
| `episodic/abstracts/` | Historical evidence summaries | `transform` as imported historical events/artifacts | Preserve source links and provisional status; do not make current truth |
| `episodic/journeys/` | Historical decision-journey candidates | `transform` | Preserve attribution; link only to verified decision candidates |
| `episodic/thoughts/` | Historical provisional material | `reference-only` or selective `transform` | No automatic durable promotion |
| `episodic/artifacts/` | Generated historical summaries | `transform` as artifacts | Label generated; preserve source provenance |
| `_session-log.md`, `episodic/_session-log.md` | Legacy session index evidence | `transform` as historical index | Do not manufacture missing session events |
| `30-drafts/` | Historical artifacts/evidence | `reference-only` initially; selective `exact-copy` | Never import as current projection or owner decision by location alone |
| `50-kb/` | Durable-knowledge candidates | `manual` plus per-article `transform` | Preserve nested repo provenance; contradiction/provenance review; approve per article/batch |
| `90-archive/` | Immutable evidence objects | selective `exact-copy` | Owner-approved scope, content hash, no execution, dedup by bytes |
| `00-inbox/` | Evidence-staging candidates | `quarantine` by default | Classify mutable/incomplete items; archive only after explicit ingest |
| `10-personal/` | Protected personal cases/knowledge/identity | `manual` | Narrow read scope and sensitivity-specific approval |
| `memory/YYYY-MM-DD.md` | Legacy operational notes | `skip` or selective historical artifact | Do not treat harness memory as canonical memory |
| `memory/feedback_*`, auto-memory | Implementation feedback candidates | `reference-only` or `skip` | Extract only approved system lessons |
| `_build/` | Historical architecture/design evidence | `reference-only` or selective `exact-copy` | Not runtime authority |
| `.obsidian/`, `.claude/`, `.tmp/`, OS files | Tool/generated state | `skip` | Report rule/count; never execute |
| Office, image, code, notebook, message, and archive files | Evidence blob candidates | selective `exact-copy` | Content-type allowlist for parsing; bytes immutable; no macros/code execution |
| Git metadata/history | Provenance reference | `reference-only` | Record commit/hash/status; do not merge legacy Git histories into Vault Next |

## Treatment of legacy governance and skills

Migration must distinguish invariant from mechanism.

### Preserve as invariants

- owner authority over identity and consequential decisions;
- external/ingested content is data, not instruction;
- no automatic external sending, posting, scheduling, or transmitting;
- immutable raw evidence;
- append-only episodic/decision history;
- current status is distinct from history;
- capture can be low-friction while promotion is gated;
- mandatory provenance for durable knowledge;
- assumptions, contradictions, accepted costs, and alternatives remain visible;
- sensitive categories receive stronger review;
- generated claims are not attributed to the owner.

### Redesign as mechanisms

- replace one-skill-per-session with minimal governed multi-skill composition;
- replace platform-specific duplicate bootstrap rules with one approved governance source and thin
  adapters;
- replace conventions-only capture with validated event contracts;
- replace kit manifests as the sole multi-session bridge with a first-class case model;
- replace implicit status/decision updates with typed events and policy checks;
- replace logs that combine reasoning and activity with separate semantic and operational ledgers;
- replace hand-maintained human-readable state with rebuildable projections;
- simplify accumulated cross-skill exceptions into shared runtime contracts.

## Snapshot model

An authorized migration begins by creating a read-only source snapshot manifest. It does not alter
the source.

Minimum snapshot data:

- snapshot ID and UTC timestamp;
- canonical source path;
- filesystem/device identity when available;
- root Git `HEAD`, branch, and status digest;
- nested repository identities and commits;
- per-item relative path, type, byte count, modification time, and permission summary;
- symlink target text without traversal;
- content hash only for scopes explicitly authorized to read fully;
- ignore/untracked classification independent of Git’s tracking state;
- discovery tool and rule-set versions;
- inaccessible/read-error list.

The backup receives a separate structural snapshot. It is never used as a silent fallback source. If
the desired source version is ambiguous, migration stops for owner selection.

Symlinks, aliases, sparse files, extended attributes, and filename encoding exceptions must be
reported explicitly. The migrator never follows a link outside the authorized root.

## Staged migration workflow

### Stage M0 — authorize discovery scope

Owner approves:

- exact source root;
- metadata-only or content-hash scope;
- excluded sensitive paths;
- destination staging path;
- whether filenames may appear in normal reports.

Pass condition: a scoped approval record exists.  
Failure response: do not scan.

### Stage M1 — read-only discovery

Actions:

- validate source and backup paths against immutable deny-write policy;
- inventory files, directories, repositories, symlinks, types, sizes, and tracking state;
- detect duplicate content only within authorized hash scope;
- classify items by mapping rules without writing transformed content;
- produce summary and protected exception inventory.

Pass conditions:

- zero source mutations (verified by before/after metadata and Git status digest);
- all discovered items have a provisional disposition or explicit error;
- backup remains unchanged;
- no symlink traversal beyond approved roots.

### Stage M2 — owner mapping review

Owner reviews category rules, exceptions, sensitive items, and sampling results. The approved mapping
plan is content-addressed and receives a plan ID. Any rule change creates a new plan ID.

Pass condition: exact plan digest and source snapshot ID are approved.  
Failure response: revise plan; no transformations.

### Stage M3 — dry-run transformation

The transformer writes only to an isolated run directory inside Vault Next staging. It produces:

- proposed target paths/IDs;
- candidate structured records and event envelopes;
- provenance map from source item to target candidate;
- approval-required promotion list;
- duplicate, collision, unsupported, and ambiguous-item reports;
- expected byte/file/event deltas;
- no changes to canonical Vault Next stores.

The dry run may use synthetic stand-ins for sensitive content during early development.

Pass conditions:

- rerunning with identical inputs produces identical semantic candidates and hashes;
- every transformed output maps to a source item/rule;
- every source item maps to exactly one disposition;
- no candidate bypasses its target policy.

### Stage M4 — deterministic validation

Checks include:

- schema and referential integrity;
- source/target count reconciliation by disposition;
- byte/hash equality for exact copies;
- transformation golden tests;
- event actor and occurred/recorded time semantics;
- collision and duplicate handling;
- provenance completeness;
- broken legacy links and target-link resolution;
- generated-versus-owner attribution;
- no current-status/decision/knowledge activation without approval;
- no executable parsing side effects.

All failures go to the exception report with stable reason codes. Validation does not “fix” source
content.

### Stage M5 — semantic sample review

A tool-less reviewer and the owner inspect risk-weighted samples:

- every identity/governance item;
- every decision and durable-knowledge candidate in the pilot;
- all ambiguous actor attribution;
- all transformed assumption, disagreement, or alternative history;
- random samples of ordinary artifacts and evidence metadata;
- all high-sensitivity exceptions.

Pass condition: no unresolved high-severity finding and sampling threshold met. The reviewer cannot
approve promotion.

### Stage M6 — pilot commit

Commit a small, explicitly approved category into canonical Vault Next through normal runtime write
interfaces. Recommended first pilot:

- one legacy skill transformed as an inactive candidate;
- one synthetic or fully redacted case;
- optionally one owner-approved decision journey after the event kernel is stable.

The commit records snapshot ID, plan ID, run ID, tool version, source/target hashes, and approvals.

Pass condition: canonical validation, projection rebuild, and rollback rehearsal all pass.

### Stage M7 — incremental waves

Migrate approved categories in small waves, ordered by value and risk:

1. governance/skill candidates without activation;
2. selected design records and synthetic/redacted evaluation cases;
3. approved current cases/decisions;
4. approved durable knowledge;
5. selected evidence and historical artifacts;
6. remaining corpus only if demonstrated value exceeds risk and maintenance cost.

Each wave has an independent run ID, report, approvals, and rollback point.

### Stage M8 — cutover

Cutover means the owner designates Vault Next as the active system for approved workflows. It does
not delete, merge, or mutate the legacy source.

Cutover requires:

- core acceptance suite passing;
- approved governance active;
- no unresolved high-severity migration exceptions in active scope;
- current cases/decisions reconciled to the source snapshot;
- clean projection rebuild;
- tested restore/rollback;
- owner approval naming effective time and included workflows.

After cutover, the legacy vault remains read-only reference for a defined observation period.

## Repeatability and idempotency

The migration identity key is:

`source_snapshot_id + source_relative_path + source_content_hash + mapping_rule_version`

Rules:

- an identical key yields the same candidate target identity and content;
- an already committed key is reported as `already_imported`, not duplicated;
- changed bytes produce a new source identity and explicit revision candidate;
- renamed identical bytes preserve content evidence identity but add path provenance;
- two paths with identical bytes are deduplicated only at the evidence-object layer; their provenance
  records remain distinct;
- target-name collision never overwrites; stable IDs disambiguate and the report asks for review;
- nondeterministic fields such as run time stay in run metadata, not semantic content hashes.

## Rules for ignored, untracked, private, generated, and archived content

### Ignored content

Git ignore is a privacy/tracking policy, not a migration instruction. The scanner inventories ignored
content only within approved scope and classifies it independently. Ignored does not mean disposable.

### Untracked content

Untracked items are first-class source items because the current legacy working tree contains them.
They receive the same hash, classification, and exception handling as tracked items. They are never
silently excluded or committed to the legacy repository.

### Private content

Private/identity/HR/legal/political material uses narrow scope, protected reports, and explicit
per-category approval. Early tests use synthetic fixtures. Redaction produces a new derived artifact
with provenance; it never edits the source.

### Generated content

Drafts, projections, caches, exports, tool state, and temporary files are not current truth by
default. Valuable generated artifacts may be retained as historical evidence with generated actor
and source metadata. Caches and reproducible build products are skipped with rule/count reporting.

### Archived content

Archived originals are immutable evidence candidates, not material to normalize or rewrite. Preserve
bytes and dates when approved. Historical relevance does not imply promotion into current status or
durable knowledge.

### Binaries and executable formats

Preserve approved bytes without executing macros, notebooks, scripts, SQL, shell files, or embedded
content. Parsing occurs only through allowlisted, sandboxed readers and must be optional; a parse
failure does not damage the original or block byte preservation.

## Exception model

Every exception has:

- stable exception ID and run ID;
- source item identity (protected/redacted as needed);
- stage and reason code;
- severity: info, warning, blocking, security;
- safe description;
- proposed resolution: skip, retry, new rule, manual mapping, or abort;
- owner/reviewer disposition and evidence;
- affected target candidates;
- open/closed state derived from append-only events.

Blocking categories include unreadable approved source, hash mismatch, source mutation, ambiguous
owner-decision attribution, broken protected provenance, path escape, schema failure, and target
overwrite risk.

## Validation and fidelity report

Each run produces a generated report containing:

- source snapshot and mapping plan digests;
- totals by source category, disposition, target type, and sensitivity;
- source-to-target reconciliation;
- exact-copy hash results;
- transformed field-level validation results;
- skipped/quarantined rule counts;
- open exceptions by severity;
- duplicate and collision results;
- deterministic rerun comparison;
- review sample and findings;
- canonical writes attempted/denied/completed;
- proof that legacy source and backup did not change.

The report must avoid leaking sensitive content into an otherwise lower-sensitivity output.

## Cutover and rollback

### Before canonical commit

Delete/recreate only the isolated run staging directory for a failed dry run. No rollback of legacy
is needed because it was never changed. Destructive staging cleanup requires exact-target safety
checks and stays within Vault Next.

### After a pilot/wave commit

Canonical history remains append-only. Rollback is logical:

- append a migration-wave rejection/deactivation event;
- remove or rebuild generated projections;
- append quarantine/deactivation state for invalid imports while leaving immutable event/evidence
  bytes in place and excluding them from active projections under policy;
- reset active pointers through explicit events, never delete historical events;
- resume using the untouched legacy source if the active workflow is not safe.

If a software release, not data mapping, is defective, restore the last known-good runtime and replay
the unchanged valid event ledger.

### Disaster recovery

Vault Next backup/restore design is a Phase 1/2 requirement before personal migration. Restore testing
must verify evidence hashes, ledger chains, approvals, schema versions, and clean projection rebuild.
No cloud backup is implied or authorized.

## Migration completion gate

Migration of a scope is complete only when:

- the approved source snapshot and mapping plan are fixed;
- all source items in scope reconcile to an explicit disposition;
- exact copies match hashes;
- transforms pass schema, provenance, attribution, and semantic sample review;
- no blocking exception remains;
- promotion/activation approvals are distinct from copying approval;
- dry run is reproducible;
- legacy source and backup show no mutation;
- projections rebuild cleanly;
- rollback has been rehearsed;
- the owner signs off the run report and cutover scope.

## Migration decisions required later

These do not block Phase 1’s synthetic foundation, but block personal migration:

1. Which legacy working-tree state—not Git `HEAD` or backup by assumption—is the intended source.
2. Whether filenames and metadata may appear in standard migration reports.
3. Which personal/status categories are approved for content reads and hashing.
4. Whether the nested `50-kb` Git history is retained as reference-only history or archived as an
   approved evidence bundle.
5. Which legacy decisions are verified owner decisions versus generated or provisional records.
6. Cutover observation period and the local backup/restore policy for Vault Next.
