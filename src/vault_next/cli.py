"""Small local CLI for the Phase 1 safety kernel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from vault_next.fixtures import (
    run_synthetic_phase2,
    run_synthetic_phase3,
    run_synthetic_phase3a,
    run_synthetic_session,
)
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry
from vault_next.validator import KernelValidator


def _default_schema_root() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "v1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault-next")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--schema-root", type=Path, default=_default_schema_root())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("synthetic-run", help="run the synthetic Phase 1 vertical slice")
    commands.add_parser("synthetic-phase2-run", help="run the synthetic Phase 2 continuity proof")
    commands.add_parser("synthetic-phase3-run", help="run the synthetic Phase 3 routing proof")
    commands.add_parser("synthetic-phase3a-run", help="run the synthetic P3A interaction proof")
    commands.add_parser("validate", help="validate semantic and operational ledgers")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "synthetic-run":
        result = run_synthetic_session(args.root, args.schema_root)
        print(json.dumps(result.to_record(), indent=2, sort_keys=True))
        return 0
    if args.command == "synthetic-phase2-run":
        result = run_synthetic_phase2(args.root, args.schema_root)
        print(json.dumps(result.to_record(), indent=2, sort_keys=True))
        return 0
    if args.command == "synthetic-phase3-run":
        result = run_synthetic_phase3(args.root, args.schema_root)
        print(json.dumps(result.to_record(), indent=2, sort_keys=True))
        return 0
    if args.command == "synthetic-phase3a-run":
        result = run_synthetic_phase3a(args.root, args.schema_root)
        print(json.dumps(result.to_record(), indent=2, sort_keys=True))
        return 0

    paths = RuntimePaths(args.root)
    schemas = SchemaRegistry(args.schema_root)
    if args.command == "validate":
        report = KernelValidator(paths, schemas).validate()
        print(json.dumps(report.to_record(), indent=2, sort_keys=True))
        return 0 if report.passed else 1
    raise AssertionError("unreachable")
