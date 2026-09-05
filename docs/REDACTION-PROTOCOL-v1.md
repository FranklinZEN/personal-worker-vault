# Redaction Protocol v1 — Candidate, Not Active

Status: Candidate only; no historical case is authorized for entry
Date: 2026-09-04

This document is a P5 design artefact, not an approval to read, copy, transform, or import personal
or legacy material. The protected legacy source and rollback backup remain out of scope.

## Required procedure before any future redacted case

1. The owner names the exact source item, purpose, receiving environment, and permitted reviewers.
2. A read-only copy is created only under separately approved scope; source paths and contents are
   never sent to a model or external service by default.
3. Remove or replace direct identifiers, contact details, employer/client/project identifiers,
   credentials, file paths, dates that create re-identification risk, quoted communications, and
   unique narrative combinations. Retain only the minimum material needed for the stated purpose.
4. Record a redaction manifest containing source fingerprint, transformations, removed categories,
   residual sensitivity, reviewer access limit, and output fingerprint. The manifest must not embed
   the original content.
5. A designated owner review confirms the redacted output cannot reasonably reconstruct the source
   in its intended context. Uncertainty means withhold the item.
6. Treat approved redacted material as immutable test input, never as a transferred owner decision,
   active work commitment, artifact acceptance, or permission grant.
7. Store the approved redacted fixture separately from source material; preserve provenance and a
   rollback/deactivation path.

## Hard stops

- No automatic redaction or batch processing.
- No reviewer/model receives personal or non-`none` sensitivity content under the P5 implementation.
- No historical case is imported, activated, or projected from this document alone.
- A new scope approval is required for every initial redacted pilot and before any wider migration.

## Approval required

This protocol must receive explicit owner approval, together with a separate exact-source and
exact-purpose authorization, before it can be used. Until then it is an inactive candidate.
