"""Read-only Git publication-boundary verification for local runtime material."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from vault_next.errors import ErrorCode, Issue, ValidationError


RUNTIME_STORE_EXAMPLES = (
    "data/events/semantic/invented-event.jsonl",
    "data/audit/operations/invented-operation.jsonl",
    "data/staging/invented-stage.json",
    "data/evidence/objects/invented-evidence.bin",
    "data/packages/lifecycle/invented-package.json",
    "data/evaluations/invented-evaluation.json",
    "data/reviews/packets/invented-packet.json",
    "data/artifacts/objects/invented-artifact.bin",
    "data/projections/invented-projection.md",
    "data/quarantine/invented-tail.bin",
    "data/indexes/invented-index.sqlite",
    "data/caches/invented-cache.bin",
    "data/reports/invented-owner-report.bin",
    "data/backups/invented-backup.bin",
)


def publication_issues(repository_root: Path) -> tuple[Issue, ...]:
    """Return all normal-path Git publication boundary failures without mutating Git state."""

    root = repository_root.resolve()
    issues: list[Issue] = []
    ignore_file = root / ".gitignore"
    try:
        ignore_text = ignore_file.read_text(encoding="utf-8")
    except OSError:
        issues.append(Issue(ErrorCode.PUBLICATION_BOUNDARY_VIOLATION, str(ignore_file), "missing .gitignore"))
        return tuple(issues)
    if "/data/" not in ignore_text.splitlines():
        issues.append(
            Issue(
                ErrorCode.PUBLICATION_BOUNDARY_VIOLATION,
                str(ignore_file),
                "private runtime root /data/ is not ignored",
            )
        )
    for relative_path in RUNTIME_STORE_EXAMPLES:
        result = _git(root, "check-ignore", "--quiet", "--", relative_path)
        if result.returncode != 0:
            issues.append(
                Issue(
                    ErrorCode.PUBLICATION_BOUNDARY_VIOLATION,
                    relative_path,
                    "private runtime example is not ignored",
                )
            )
    tracked = _nul_paths(_git(root, "ls-files", "--cached", "-z", "--", "data").stdout)
    for path in tracked:
        issues.append(
            Issue(ErrorCode.PUBLICATION_BOUNDARY_VIOLATION, path, "private runtime path is tracked")
        )
    staged = _nul_paths(_git(root, "diff", "--cached", "--name-only", "-z").stdout)
    for path in staged:
        if path == "data" or path.startswith("data/"):
            issues.append(
                Issue(ErrorCode.PUBLICATION_BOUNDARY_VIOLATION, path, "private runtime path is staged")
            )
    return tuple(sorted(set(issues)))


def require_publication_boundary(repository_root: Path) -> None:
    """Raise the stable validation error used by verification and release checks."""

    issues = publication_issues(repository_root)
    if issues:
        raise ValidationError(issues)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only publication boundary check from a repository root."""

    parser = argparse.ArgumentParser(prog="python -m vault_next.publication")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    issues = publication_issues(args.root)
    for issue in issues:
        print(f"{issue.code}@{issue.path}: {issue.message}")
    return 1 if issues else 0


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        capture_output=True,
    )


def _nul_paths(raw: bytes) -> tuple[str, ...]:
    return tuple(value.decode("utf-8") for value in raw.split(b"\0") if value)


if __name__ == "__main__":
    sys.exit(main())
