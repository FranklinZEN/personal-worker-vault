# ADR-0004: Use restricted canonical JSON and locked monthly JSONL ledgers

- Status: Accepted for Phase 1 implementation
- Date: 2026-09-01
- Decision owner: Phase 1 architecture under the approved roadmap
- Scope: Canonical serialization, hashing, partitioning, append, locking, and recovery

## Context

Canonical events and operational records must hash identically on supported machines, survive an
interrupted append, and expose a valid prefix without silently accepting a damaged tail.

## Decision

Use UTF-8 JSON with sorted object keys, compact separators, JSON booleans/null, and no floating-point
numbers. Values requiring decimal precision are stored as schema-constrained strings. Strings retain
their Unicode code points and JSON escaping is deterministic. A trailing newline is record framing
and is excluded from the record hash.

Store semantic and operational records as one canonical JSON object per line in monthly UTC
partitions. Each partition begins with `GENESIS` and has its own SHA-256 chain. The record hash covers
the complete record except its own final hash field, including the previous-record hash.

Writers use one lock file at each ledger root with an exclusive POSIX advisory lock. Under the lock
they validate the current tail, finalize the candidate hashes, stage and fsync the candidate, append it with one
operating-system write, fsync the partition, and re-read the appended bytes. A failed verification is
reported as corruption; it is never reported as success.

Recovery runs under the same lock, identifies the longest valid byte prefix, writes the entire
invalid suffix to a content-addressed quarantine artifact, and truncates only after the quarantine
write is durable. It never changes bytes in the valid prefix.

## Consequences

- Phase 1 supports local macOS/POSIX execution; cross-platform locking is deferred.
- Hashes are deterministic because canonical records disallow ambiguous floating-point encodings.
- Monthly partitions bound validation and recovery work while retaining a simple file format.
- A hostile machine owner can rewrite the ledger and hashes; the chain is tamper-evident, not a
  signature or remote attestation mechanism.
