"""Synthetic evaluation runs and explicit baseline-change controls for Phase 5."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from vault_next.canonical import canonical_bytes, canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.paths import RuntimePaths
from vault_next.records import SCHEMA_VERSION, SchemaRegistry, aware_utc_now, timestamp


@dataclass(frozen=True)
class EvaluationRun:
    """One deterministic replay report, suitable for an immutable baseline."""

    record: dict[str, Any]
    sha256: str


class EvaluationRegistry:
    """Store synthetic regression reports and reject baseline updates without reviewed evidence."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
    ) -> None:
        self.paths = paths
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock

    def run(
        self,
        suite: dict[str, Any],
        checks: dict[str, Callable[[], Any]],
    ) -> EvaluationRun:
        """Run named deterministic checks and write an immutable, content-addressed report."""

        suite_id = str(suite["suite_id"])
        suite_version = str(suite["suite_version"])
        suite_sha256 = canonical_sha256(suite)
        results = []
        for check_id, check in sorted(checks.items()):
            detail = check()
            passed = bool(detail["passed"]) if isinstance(detail, dict) else bool(detail)
            results.append(
                {
                    "check_id": check_id,
                    "passed": passed,
                    "detail_sha256": canonical_sha256(detail),
                }
            )
        record = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.ids.new("evaluation_run"),
            "suite_id": suite_id,
            "suite_version": suite_version,
            "suite_sha256": suite_sha256,
            "run_at": timestamp(self.clock()),
            "checks": results,
            "run_sha256": "0" * 64,
        }
        record["run_sha256"] = canonical_sha256(record)
        self.schemas.require("evaluation-run", record)
        digest = canonical_sha256(record)
        self._write_immutable(self.paths.evaluation_root / "runs" / f"{record['run_id']}.json", record)
        return EvaluationRun(record, digest)

    def establish_or_change_baseline(
        self,
        run: EvaluationRun,
        *,
        reviewed_change_record_sha256: str | None,
        owner_id: str = "owner",
        explicit_confirmation: bool = False,
    ) -> dict[str, Any]:
        """Create a baseline only with an explicit owner-confirmed reviewed change record."""

        if not explicit_confirmation or reviewed_change_record_sha256 is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.REVIEW_BASELINE_CHANGE_UNREVIEWED,
                        "$baseline",
                        "baseline creation/change requires an explicit reviewed change record",
                    )
                ]
            )
        baseline = {
            "schema_version": SCHEMA_VERSION,
            "baseline_id": self.ids.new("review"),
            "suite_id": run.record["suite_id"],
            "suite_sha256": run.record["suite_sha256"],
            "run_sha256": run.sha256,
            "reviewed_change_record_sha256": reviewed_change_record_sha256,
            "owner_id": owner_id,
            "explicit_confirmation": True,
            "established_at": timestamp(self.clock()),
            "baseline_sha256": "0" * 64,
        }
        baseline["baseline_sha256"] = canonical_sha256(baseline)
        self.schemas.require("evaluation-baseline", baseline)
        self._write_immutable(
            self.paths.evaluation_root / "baselines" / f"{baseline['baseline_id']}.json", baseline
        )
        return baseline

    def _write_immutable(self, path: Path, value: dict[str, Any]) -> None:
        path = self.paths.ensure_runtime_write_target(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = canonical_bytes(value) + b"\n"
        if path.exists():
            if path.read_bytes() == content:
                return
            raise ValidationError(
                [Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), "immutable evaluation record differs")]
            )
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        try:
            temporary.write_bytes(content)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
