"""Fail-closed POSIX I/O primitives for the synthetic migration laboratory.

The admission object is a trusted in-process test-harness capability.  It deliberately is not a
sandbox, owner authentication mechanism, or public arbitrary-path admission API.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import stat
from tempfile import TemporaryDirectory
from typing import Callable, Iterator

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.paths import RuntimePaths


SYNTHETIC_MARKER = ".vault-next-synthetic-migration-fixture.json"
MARKER_KIND = "vault-next-synthetic-migration-fixture"
MARKER_CONTRACT_VERSION = "1.0"
_ADMISSION_FACTORY_TOKEN = object()


@dataclass(frozen=True)
class _Identity:
    device: int
    inode: int


class SyntheticSourceAdmission:
    """Opaque fixture admission made only by :class:`SyntheticFixtureWorkspace`."""

    __slots__ = (
        "_marker_bytes",
        "_root",
        "_root_identity",
        "_runtime_identity",
        "_token",
    )

    def __init__(
        self,
        *,
        marker_bytes: bytes,
        root: Path,
        root_identity: _Identity,
        runtime_identity: _Identity,
        token: object,
    ) -> None:
        self._marker_bytes = marker_bytes
        self._root = root
        self._root_identity = root_identity
        self._runtime_identity = runtime_identity
        self._token = token


class SyntheticFixtureWorkspace:
    """Create one disposable, disjoint source/backup/runtime fixture workspace.

    Tests may add hostile invented source entries after creation.  Only the source directory
    identity and marker created here receive an admission; no method admits an arbitrary path.
    """

    def __init__(self) -> None:
        self._temporary = TemporaryDirectory(prefix="vault-next-s1a-fixture-")
        base = Path(self._temporary.name)
        self.source = base / "source"
        self.backup = base / "backup"
        self.runtime = base / "runtime"
        for path in (self.source, self.backup, self.runtime):
            path.mkdir()
        marker = {
            "contract_version": MARKER_CONTRACT_VERSION,
            "fixture_id": f"fixture_sha256_{secrets.token_hex(32)}",
            "kind": MARKER_KIND,
        }
        marker_bytes = canonical_bytes(marker) + b"\n"
        (self.source / SYNTHETIC_MARKER).write_bytes(marker_bytes)
        self.admission = SyntheticSourceAdmission(
            marker_bytes=marker_bytes,
            root=self.source,
            root_identity=_identity_from_path(self.source),
            runtime_identity=_identity_from_path(self.runtime),
            token=_ADMISSION_FACTORY_TOKEN,
        )

    def close(self) -> None:
        self._temporary.cleanup()


class AdmittedSource:
    """One safely opened admitted source root and descriptor-relative reads."""

    def __init__(self, root_fd: int, observer: Callable[[str], None] | None) -> None:
        self._root_fd = root_fd
        self._observer = observer

    def close(self) -> None:
        os.close(self._root_fd)

    def walk(self) -> tuple[list[dict[str, object]], list[str]]:
        items: list[dict[str, object]] = []
        repositories: list[str] = []
        self._walk_directory(self._root_fd, (), items, repositories)
        return items, repositories

    def read_regular(self, relative_path: str) -> bytes:
        parts = _normal_relative_parts(relative_path)
        directory_fds: list[int] = []
        current_fd = self._root_fd
        try:
            for part in parts[:-1]:
                child_fd = _open_directory_at(
                    current_fd, part, ErrorCode.MIGRATION_SOURCE_REPLACED, "$source"
                )
                directory_fds.append(child_fd)
                current_fd = child_fd
            if self._observer is not None:
                self._observer(relative_path)
            return _read_regular_at(
                current_fd,
                parts[-1],
                ErrorCode.MIGRATION_SOURCE_REPLACED,
                "$source",
                require_single_link=True,
            )
        finally:
            for directory_fd in reversed(directory_fds):
                os.close(directory_fd)

    def _walk_directory(
        self,
        directory_fd: int,
        components: tuple[str, ...],
        items: list[dict[str, object]],
        repositories: list[str],
    ) -> None:
        for name in sorted(os.listdir(directory_fd)):
            if not components and name == SYNTHETIC_MARKER:
                continue
            relative = "/".join((*components, name))
            if not _is_normal_relative_path(relative):
                items.append(_inaccessible_item(relative, "UNSUPPORTED_PATH"))
                continue
            try:
                entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                items.append(_inaccessible_item(relative, "READ_ERROR"))
                continue
            mode = entry_stat.st_mode
            if stat.S_ISLNK(mode):
                try:
                    target = os.readlink(name, dir_fd=directory_fd)
                except OSError:
                    items.append(_inaccessible_item(relative, "READ_ERROR"))
                    continue
                target_bytes = os.fsencode(target)
                items.append(
                    {
                        "byte_count": len(target_bytes),
                        "content_sha256": sha256_hex(target_bytes),
                        "kind": "symlink",
                        "relative_path": relative,
                        "symlink_inside_source": _lexically_inside_source(components, target),
                    }
                )
                continue
            if stat.S_ISDIR(mode):
                items.append(
                    {
                        "byte_count": 0,
                        "content_sha256": None,
                        "kind": "directory",
                        "relative_path": relative,
                    }
                )
                if name == ".git":
                    repositories.append("/".join(components) or ".")
                    continue
                if self._observer is not None:
                    self._observer(relative)
                child_fd = _open_directory_at(
                    directory_fd, name, ErrorCode.MIGRATION_SOURCE_REPLACED, "$source"
                )
                try:
                    self._walk_directory(child_fd, (*components, name), items, repositories)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(mode):
                items.append(_inaccessible_item(relative, "UNSUPPORTED_SPECIAL_FILE"))
                continue
            if entry_stat.st_nlink != 1:
                items.append(_inaccessible_item(relative, "UNSUPPORTED_HARD_LINK"))
                continue
            if self._observer is not None:
                self._observer(relative)
            content = _read_regular_at(
                directory_fd,
                name,
                ErrorCode.MIGRATION_SOURCE_REPLACED,
                "$source",
                expected_identity=_identity(entry_stat),
                require_single_link=True,
            )
            items.append(
                {
                    "byte_count": len(content),
                    "content_sha256": sha256_hex(content),
                    "is_binary": b"\x00" in content,
                    "kind": "file",
                    "relative_path": relative,
                }
            )


class StagingArea:
    """Pinned runtime staging root with descriptor-relative immutable publication."""

    def __init__(self, paths: RuntimePaths) -> None:
        _require_safe_io()
        self._runtime_path = paths.root
        self._runtime_identity = _identity_from_path(paths.root)
        with self._open_staging_root() as staging_fd:
            self._staging_identity = _identity(os.fstat(staging_fd))

    @contextmanager
    def open_run(self, run_id: str, *, create: bool) -> Iterator["StagingRun"]:
        if not _is_run_id(run_id):
            _raise(ErrorCode.MIGRATION_RUN_INVALID, "$run_id", "run identifier is malformed")
        with self._open_staging_root() as staging_fd:
            migrations_fd = _ensure_directory_at(staging_fd, "migrations") if create else _open_directory_at(
                staging_fd, "migrations", ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging"
            )
            try:
                if create:
                    try:
                        os.mkdir(run_id, 0o700, dir_fd=migrations_fd)
                    except FileExistsError:
                        pass
                run_fd = _open_directory_at(
                    migrations_fd, run_id, ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging"
                )
                try:
                    yield StagingRun(run_fd)
                finally:
                    os.close(run_fd)
            finally:
                os.close(migrations_fd)

    @contextmanager
    def _open_staging_root(self) -> Iterator[int]:
        runtime_fd = _open_directory_path(
            self._runtime_path, ErrorCode.MIGRATION_STAGING_TAMPERED, "$runtime"
        )
        try:
            if _identity(os.fstat(runtime_fd)) != self._runtime_identity:
                _raise(ErrorCode.MIGRATION_STAGING_TAMPERED, "$runtime", "runtime root identity changed")
            data_fd = _open_directory_at(
                runtime_fd, "data", ErrorCode.MIGRATION_STAGING_TAMPERED, "$runtime/data"
            )
            try:
                staging_fd = _open_directory_at(
                    data_fd, "staging", ErrorCode.MIGRATION_STAGING_TAMPERED, "$runtime/data/staging"
                )
                try:
                    if (
                        hasattr(self, "_staging_identity")
                        and _identity(os.fstat(staging_fd)) != self._staging_identity
                    ):
                        _raise(ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging", "staging root identity changed")
                    yield staging_fd
                finally:
                    os.close(staging_fd)
            finally:
                os.close(data_fd)
        finally:
            os.close(runtime_fd)


class StagingRun:
    """An open run directory; names are fixed one-component implementation names."""

    def __init__(self, directory_fd: int) -> None:
        self._directory_fd = directory_fd

    def read(self, name: str, *, missing_code: ErrorCode) -> bytes:
        _require_plain_name(name)
        return _read_regular_at(
            self._directory_fd,
            name,
            ErrorCode.MIGRATION_STAGING_TAMPERED,
            "$staging",
            missing_code=missing_code,
            require_single_link=True,
        )

    def exists(self, name: str) -> bool:
        _require_plain_name(name)
        return _read_optional_regular_at(self._directory_fd, name) is not None

    def write_immutable(self, name: str, content: bytes) -> None:
        _require_plain_name(name)
        _write_immutable_at(self._directory_fd, name, content)

    @contextmanager
    def copies(self) -> Iterator[int]:
        copies_fd = _ensure_directory_at(self._directory_fd, "copies")
        try:
            yield copies_fd
        finally:
            os.close(copies_fd)

    def read_copy(self, name: str) -> bytes:
        _require_plain_name(name)
        copies_fd = _open_directory_at(
            self._directory_fd, "copies", ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging/copies"
        )
        try:
            return _read_regular_at(
                copies_fd,
                name,
                ErrorCode.MIGRATION_STAGING_TAMPERED,
                "$staging/copies",
                require_single_link=True,
            )
        finally:
            os.close(copies_fd)

    def write_copy_immutable(self, name: str, content: bytes) -> None:
        _require_plain_name(name)
        with self.copies() as copies_fd:
            _write_immutable_at(copies_fd, name, content)


@contextmanager
def open_admitted_source(
    admission: object,
    runtime_root: Path,
    observer: Callable[[str], None] | None = None,
) -> Iterator[AdmittedSource]:
    """Open the exact admitted root and exact marker without following links."""

    _require_safe_io()
    if not isinstance(admission, SyntheticSourceAdmission):
        _raise(
            ErrorCode.MIGRATION_ADMISSION_REQUIRED,
            "$admission",
            "source access requires a trusted synthetic fixture admission",
        )
    if admission._token is not _ADMISSION_FACTORY_TOKEN:
        _raise(ErrorCode.MIGRATION_ADMISSION_INVALID, "$admission", "admission was not factory-issued")
    if _identity_from_path(runtime_root) != admission._runtime_identity:
        _raise(ErrorCode.MIGRATION_ADMISSION_INVALID, "$admission", "admission belongs to another workspace")
    root_fd = _open_directory_path(
        admission._root, ErrorCode.MIGRATION_SOURCE_REPLACED, "$source_root"
    )
    try:
        if _identity(os.fstat(root_fd)) != admission._root_identity:
            _raise(ErrorCode.MIGRATION_SOURCE_REPLACED, "$source_root", "admitted root identity changed")
        marker = _read_regular_at(
            root_fd,
            SYNTHETIC_MARKER,
            ErrorCode.MIGRATION_FIXTURE_MARKER_INVALID,
            "$marker",
            require_single_link=True,
        )
        if marker != admission._marker_bytes or not _valid_marker(marker):
            _raise(ErrorCode.MIGRATION_FIXTURE_MARKER_INVALID, "$marker", "fixture marker binding is invalid")
        source = AdmittedSource(root_fd, observer)
        root_fd = -1
        try:
            yield source
        finally:
            source.close()
    finally:
        if root_fd != -1:
            os.close(root_fd)


def run_staging_path(paths: RuntimePaths, run_id: str) -> Path:
    """Return only the derived, non-authoritative display path for a verified run id."""

    if not _is_run_id(run_id):
        _raise(ErrorCode.MIGRATION_RUN_INVALID, "$run_id", "run identifier is malformed")
    return paths.staging_root / "migrations" / run_id


def canonical_json_bytes(value: object) -> bytes:
    return canonical_bytes(value) + b"\n"


def parse_canonical_json(content: bytes, *, path: str, code: ErrorCode) -> dict[str, object]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _raise(code, path, "staged JSON is not valid")
    if not isinstance(value, dict) or canonical_json_bytes(value) != content:
        _raise(code, path, "staged JSON is not canonical")
    return value


def _identity(stat_result: os.stat_result) -> _Identity:
    return _Identity(stat_result.st_dev, stat_result.st_ino)


def _identity_from_path(path: Path) -> _Identity:
    _require_safe_io()
    fd = _open_directory_path(path, ErrorCode.MIGRATION_IO_UNSUPPORTED, "$runtime")
    try:
        return _identity(os.fstat(fd))
    finally:
        os.close(fd)


def _require_safe_io() -> None:
    required = (
        os.name == "posix",
        getattr(os, "O_NOFOLLOW", 0) != 0,
        getattr(os, "O_DIRECTORY", 0) != 0,
        os.open in os.supports_dir_fd,
        os.stat in os.supports_dir_fd,
        os.readlink in os.supports_dir_fd,
        os.link in os.supports_dir_fd,
    )
    if not all(required):
        _raise(
            ErrorCode.MIGRATION_IO_UNSUPPORTED,
            "$io",
            "descriptor-relative no-follow operations are unavailable",
        )


def _open_directory_path(path: Path, code: ErrorCode, issue_path: str) -> int:
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        _raise(code, issue_path, "directory open failed safely")
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        _raise(code, issue_path, "expected directory")
    return fd


def _open_directory_at(parent_fd: int, name: str, code: ErrorCode, issue_path: str) -> int:
    _require_plain_name(name)
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError:
        _raise(code, issue_path, "descriptor-relative directory open failed safely")
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        _raise(code, issue_path, "expected directory")
    return fd


def _ensure_directory_at(parent_fd: int, name: str) -> int:
    _require_plain_name(name)
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError:
        _raise(ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging", "staging directory creation failed")
    return _open_directory_at(parent_fd, name, ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging")


def _read_regular_at(
    parent_fd: int,
    name: str,
    code: ErrorCode,
    issue_path: str,
    *,
    expected_identity: _Identity | None = None,
    missing_code: ErrorCode | None = None,
    require_single_link: bool,
) -> bytes:
    _require_plain_name(name)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        _raise(missing_code or code, issue_path, "required file is absent")
    except OSError:
        _raise(code, issue_path, "descriptor-relative file open failed safely")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            _raise(code, issue_path, "expected regular file")
        if require_single_link and before.st_nlink != 1:
            _raise(code, issue_path, "multiply linked file is not accepted")
        if expected_identity is not None and _identity(before) != expected_identity:
            _raise(code, issue_path, "file identity changed")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        content = b"".join(chunks)
        after = os.fstat(fd)
        if _identity(after) != _identity(before) or after.st_size != len(content):
            _raise(code, issue_path, "file changed while being read")
        return content
    finally:
        os.close(fd)


def _read_optional_regular_at(parent_fd: int, name: str) -> bytes | None:
    _require_plain_name(name)
    try:
        return _read_regular_at(
            parent_fd,
            name,
            ErrorCode.MIGRATION_STAGING_TAMPERED,
            "$staging",
            require_single_link=True,
        )
    except ValidationError as exc:
        if any(issue.code == ErrorCode.MIGRATION_STAGING_TAMPERED for issue in exc.issues):
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
        raise


def _write_immutable_at(parent_fd: int, name: str, content: bytes) -> None:
    existing = _read_optional_regular_at(parent_fd, name)
    if existing is not None:
        if existing != content:
            _raise(ErrorCode.MIGRATION_STAGING_COLLISION, "$staging", "immutable output conflicts")
        return
    temporary = f".{name}.tmp-{secrets.token_hex(16)}"
    fd = -1
    temporary_identity: _Identity | None = None
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        temporary_identity = _identity(os.fstat(fd))
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _read_optional_regular_at(parent_fd, name)
            if existing != content:
                _raise(ErrorCode.MIGRATION_STAGING_COLLISION, "$staging", "immutable output conflicts")
        except OSError:
            _raise(ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging", "immutable publication failed safely")
    finally:
        if fd != -1:
            os.close(fd)
        if temporary_identity is not None:
            _unlink_if_owned(parent_fd, temporary, temporary_identity)


def _unlink_if_owned(parent_fd: int, name: str, expected_identity: _Identity) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        return
    if _identity(current) == expected_identity and stat.S_ISREG(current.st_mode):
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            return


def _valid_marker(content: bytes) -> bool:
    try:
        marker = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(marker, dict) or canonical_json_bytes(marker) != content:
        return False
    if set(marker) != {"contract_version", "fixture_id", "kind"}:
        return False
    fixture_id = marker["fixture_id"]
    return (
        marker["contract_version"] == MARKER_CONTRACT_VERSION
        and marker["kind"] == MARKER_KIND
        and isinstance(fixture_id, str)
        and fixture_id.startswith("fixture_sha256_")
        and len(fixture_id) == len("fixture_sha256_") + 64
        and all(character in "0123456789abcdef" for character in fixture_id.removeprefix("fixture_sha256_"))
    )


def _normal_relative_parts(path: str) -> tuple[str, ...]:
    if not _is_normal_relative_path(path):
        _raise(ErrorCode.MIGRATION_PATH_INVALID, "$relative_path", "source relative path is invalid")
    return tuple(path.split("/"))


def _is_normal_relative_path(path: str) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    return all(component not in {"", ".", ".."} for component in path.split("/"))


def _lexically_inside_source(parent_components: tuple[str, ...], target: str) -> bool:
    if target.startswith("/") or "\x00" in target:
        return False
    components = list(parent_components)
    for component in target.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            if not components:
                return False
            components.pop()
        else:
            components.append(component)
    return True


def _inaccessible_item(relative_path: str, error: str) -> dict[str, object]:
    return {
        "byte_count": 0,
        "content_sha256": None,
        "error": error,
        "kind": "inaccessible",
        "relative_path": relative_path,
    }


def _is_run_id(value: str) -> bool:
    prefix = "migration_run_sha256_"
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and len(value) == len(prefix) + 64
        and all(character in "0123456789abcdef" for character in value.removeprefix(prefix))
    )


def _require_plain_name(name: str) -> None:
    if not isinstance(name, str) or not name or "/" in name or "\\" in name or "\x00" in name or name in {".", ".."}:
        _raise(ErrorCode.MIGRATION_STAGING_TAMPERED, "$staging", "unsafe staging entry name")


def _raise(code: ErrorCode, path: str, message: str) -> None:
    raise ValidationError([Issue(code, path, message)])
