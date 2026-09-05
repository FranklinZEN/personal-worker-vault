"""Runtime path layout and immutable legacy-boundary enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vault_next.errors import ErrorCode, Issue, ValidationError

DEFAULT_PROTECTED_ROOTS = (Path.home() / "vault", Path.home() / "vault copy")


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class RuntimePaths:
    """Resolved local runtime paths with deny-write legacy roots."""

    root: Path
    protected_roots: tuple[Path, ...] = DEFAULT_PROTECTED_ROOTS

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", self.root.resolve())
        object.__setattr__(
            self,
            "protected_roots",
            tuple(path.resolve() for path in self.protected_roots),
        )

    @property
    def semantic_root(self) -> Path:
        return self.root / "data" / "events" / "semantic"

    @property
    def audit_root(self) -> Path:
        return self.root / "data" / "audit" / "operations"

    @property
    def staging_root(self) -> Path:
        return self.root / "data" / "staging"

    @property
    def evidence_root(self) -> Path:
        return self.root / "data" / "evidence"

    @property
    def package_root(self) -> Path:
        return self.root / "data" / "packages"

    @property
    def evaluation_root(self) -> Path:
        return self.root / "data" / "evaluations"

    @property
    def review_root(self) -> Path:
        """Immutable local review packets, results, and owner waivers."""

        return self.root / "data" / "reviews"

    @property
    def artifact_root(self) -> Path:
        return self.root / "data" / "artifacts"

    @property
    def projection_root(self) -> Path:
        return self.root / "data" / "projections"

    @property
    def quarantine_root(self) -> Path:
        return self.root / "data" / "quarantine"

    def ensure_runtime_write_target(self, target: Path) -> Path:
        """Resolve and authorize a write beneath the runtime root."""

        resolved = target.resolve()
        issues: list[Issue] = []
        for protected in self.protected_roots:
            if _contains(protected, resolved):
                issues.append(
                    Issue(
                        ErrorCode.PROTECTED_PATH_WRITE_DENIED,
                        "$target",
                        f"write target is beneath protected root: {protected}",
                    )
                )
        if not _contains(self.root, resolved):
            issues.append(
                Issue(
                    ErrorCode.PATH_OUTSIDE_RUNTIME_ROOT,
                    "$target",
                    f"write target is outside runtime root: {self.root}",
                )
            )
        if issues:
            raise ValidationError(issues)
        return resolved

    def initialize(self) -> None:
        """Create only authorized Vault Next runtime directories."""

        for path in (
            self.semantic_root,
            self.audit_root,
            self.staging_root,
            self.evidence_root,
            self.package_root,
            self.evaluation_root,
            self.review_root,
            self.artifact_root,
            self.projection_root,
            self.quarantine_root,
        ):
            self.ensure_runtime_write_target(path).mkdir(parents=True, exist_ok=True)
