# ADR-0005: Use checked-in schemas with a strict standard-library validator

- Status: Accepted for Phase 1 implementation
- Date: 2026-09-01
- Decision owner: Phase 1 architecture under the approved roadmap
- Scope: Phase 1 record validation and dependencies

## Context

Phase 1 needs versioned, inspectable schemas and deterministic error codes. The approved scope must
run locally without an external service, and the workspace currently has no third-party validation
package installed.

## Decision

Check JSON Schema documents into `schemas/v1`. Execute the Phase 1 subset through a small internal
validator that supports only the keywords used by those schemas and rejects unknown keywords when a
schema is loaded. Semantic validation—actor authority, references, approval binding, path policy, and
chain integrity—remains in explicit domain validators after structural validation.

Use no runtime dependency in Phase 1. The supported interpreter is Python 3.12 or newer. The schema
loader, keyword coverage, stable issue ordering, and negative cases are directly tested.

## Consequences

- The schema files remain the structural source of truth without a package download.
- The internal validator is deliberately small and is not presented as a general JSON Schema
  implementation.
- Adding an unsupported schema feature fails closed and requires an ADR or implementation change.
- A mature pinned validator may replace the subset implementation later after fixture replay proves
  identical acceptance behavior.
