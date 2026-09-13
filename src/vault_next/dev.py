"""Dependency-free local development checks for the Phase 1 repository."""

from __future__ import annotations

import argparse
import ast
import compileall
import sys
from pathlib import Path
from typing import Sequence

from vault_next.records import SchemaRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _python_files() -> list[Path]:
    return sorted((PROJECT_ROOT / "src").rglob("*.py")) + sorted(
        (PROJECT_ROOT / "tests").rglob("*.py")
    )


def format_files(*, check: bool) -> int:
    """Normalize deterministic whitespace or report files needing normalization."""

    changed: list[Path] = []
    for path in _python_files():
        original = path.read_text(encoding="utf-8")
        normalized = "\n".join(line.rstrip() for line in original.splitlines()) + "\n"
        if normalized != original:
            changed.append(path)
            if not check:
                path.write_text(normalized, encoding="utf-8")
    if changed:
        for path in changed:
            print(f"format: {path.relative_to(PROJECT_ROOT)}")
        return 1 if check else 0
    return 0


def lint_files() -> int:
    """Run small deterministic source checks without a downloaded linter."""

    findings: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            findings.append(f"{path}:{exc.lineno}: syntax error: {exc.msg}")
            continue
        for number, line in enumerate(source.splitlines(), start=1):
            if "\t" in line:
                findings.append(f"{path}:{number}: tab character")
            if len(line) > 120:
                findings.append(f"{path}:{number}: line exceeds 120 characters")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                findings.append(f"{path}:{node.lineno}: wildcard import")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec"}:
                    findings.append(f"{path}:{node.lineno}: dynamic execution is forbidden")
    for finding in findings:
        print(finding)
    return 1 if findings else 0


def typecheck_files() -> int:
    """Compile sources and require annotations on public module-level functions."""

    ok = compileall.compile_dir(PROJECT_ROOT / "src", quiet=1)
    ok = compileall.compile_dir(PROJECT_ROOT / "tests", quiet=1) and ok
    findings: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            if node.returns is None:
                findings.append(f"{path}:{node.lineno}: public function lacks return annotation")
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            for argument in arguments:
                if argument.arg not in {"self", "cls"} and argument.annotation is None:
                    findings.append(
                        f"{path}:{node.lineno}: argument {argument.arg} lacks annotation"
                    )
    schema_registry = SchemaRegistry(PROJECT_ROOT / "schemas" / "v1")
    for schema_root in sorted((PROJECT_ROOT / "schemas").glob("v[0-9]*")):
        schema_version = f"{schema_root.name.removeprefix('v')}.0"
        for schema_path in sorted(schema_root.rglob("*.schema.json")):
            name = str(schema_path.relative_to(schema_root)).removesuffix(".schema.json")
            schema_registry.get(name, schema_version=schema_version)
    for finding in findings:
        print(finding)
    return 1 if findings or not ok else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m vault_next.dev")
    commands = parser.add_subparsers(dest="command", required=True)
    format_command = commands.add_parser("format")
    format_command.add_argument("--check", action="store_true")
    commands.add_parser("lint")
    commands.add_parser("typecheck")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "format":
        return format_files(check=args.check)
    if args.command == "lint":
        return lint_files()
    if args.command == "typecheck":
        return typecheck_files()
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
