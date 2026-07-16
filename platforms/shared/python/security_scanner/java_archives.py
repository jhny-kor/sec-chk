from __future__ import annotations

import fnmatch
import hashlib
import stat
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath


ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")
MAX_COMPRESSION_RATIO = 1_000


@dataclass(frozen=True, slots=True)
class ArchiveLocation:
    outer_path: Path
    nested_path: str = ""

    def display(self) -> str:
        return str(self.outer_path) if not self.nested_path else f"{self.outer_path}!/{self.nested_path}"


@dataclass(frozen=True, slots=True)
class ArchiveArtifact:
    location: ArchiveLocation
    filename: str
    archive_type: str
    sha256: str
    size: int
    modified_at: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class ArchiveScan:
    artifacts: tuple[ArchiveArtifact, ...]
    warnings: tuple[str, ...]

    def __iter__(self):
        return iter(self.artifacts)


def scan_archives(
    target: Path,
    *,
    excludes: tuple[str, ...] = (),
    max_depth: int | None = None,
    max_entries: int | None = None,
    max_uncompressed_bytes: int | None = None,
) -> ArchiveScan:
    root = target.expanduser().resolve()
    if not root.is_dir() and not root.is_file():
        raise ValueError(f"Java scan target does not exist: {target}")
    if any(limit is not None and limit < 1 for limit in (max_depth, max_entries, max_uncompressed_bytes)):
        raise ValueError("archive limits must be positive")

    artifacts: list[ArchiveArtifact] = []
    warnings: list[str] = []
    paths = (root,) if root.is_file() else tuple(sorted(root.rglob("*")))
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        relative = path.name if root.is_file() else path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in excludes):
            continue
        try:
            payload = path.read_bytes()
            modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        except OSError as exc:
            warnings.append(f"Could not read archive {path}: {exc}")
            continue
        _walk_archive(
            ArchiveArtifact(
                location=ArchiveLocation(path),
                filename=path.name,
                archive_type=path.suffix.lower().lstrip("."),
                sha256=_sha256(payload),
                size=len(payload),
                modified_at=modified_at,
                payload=payload,
            ),
            max_depth=max_depth,
            max_entries=max_entries,
            max_uncompressed_bytes=max_uncompressed_bytes,
            artifacts=artifacts,
            warnings=warnings,
        )
    return ArchiveScan(tuple(artifacts), tuple(warnings))


def _walk_archive(
    artifact: ArchiveArtifact,
    *,
    max_depth: int | None,
    max_entries: int | None,
    max_uncompressed_bytes: int | None,
    artifacts: list[ArchiveArtifact],
    warnings: list[str],
) -> None:
    artifacts.append(artifact)
    if artifact.archive_type not in {"jar", "war", "ear"}:
        return
    try:
        with zipfile.ZipFile(BytesIO(artifact.payload)) as archive:
            if max_entries is not None and len(archive.infolist()) > max_entries:
                warnings.append(f"Archive entry limit exceeded: {artifact.location.display()}")
                return
            total_size = 0
            for member in archive.infolist():
                if _unsafe_member(member):
                    warnings.append(f"unsafe ZIP path skipped: {artifact.location.display()}!/{member.filename}")
                    continue
                if member.is_dir() or _is_zip_symlink(member):
                    if _is_zip_symlink(member):
                        warnings.append(f"ZIP symlink skipped: {artifact.location.display()}!/{member.filename}")
                    continue
                total_size += member.file_size
                if max_uncompressed_bytes is not None and total_size > max_uncompressed_bytes:
                    warnings.append(f"Archive uncompressed-size limit exceeded: {artifact.location.display()}")
                    break
                if member.compress_size and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO:
                    warnings.append(f"Suspicious ZIP compression ratio: {artifact.location.display()}!/{member.filename}")
                if not _is_java_archive_name(member.filename):
                    continue
                depth = artifact.location.nested_path.count("!/") + (2 if artifact.location.nested_path else 1)
                if max_depth is not None and depth > max_depth:
                    warnings.append(f"Maximum nested archive depth reached: {artifact.location.display()}!/{member.filename}")
                    continue
                if member.flag_bits & 0x1:
                    warnings.append(f"Encrypted ZIP entry skipped: {artifact.location.display()}!/{member.filename}")
                    continue
                try:
                    payload = archive.read(member)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    warnings.append(f"Could not read nested archive {artifact.location.display()}!/{member.filename}: {exc}")
                    continue
                nested_location = ArchiveLocation(
                    artifact.location.outer_path,
                    f"{artifact.location.nested_path}!/{member.filename}".lstrip("!/"),
                )
                nested = ArchiveArtifact(
                    location=nested_location,
                    filename=Path(member.filename).name,
                    archive_type=Path(member.filename).suffix.lower().lstrip("."),
                    sha256=_sha256(payload),
                    size=len(payload),
                    modified_at=artifact.modified_at,
                    payload=payload,
                )
                _walk_archive(
                    nested,
                    max_depth=max_depth,
                    max_entries=max_entries,
                    max_uncompressed_bytes=max_uncompressed_bytes,
                    artifacts=artifacts,
                    warnings=warnings,
                )
    except (OSError, zipfile.BadZipFile, EOFError) as exc:
        warnings.append(f"Corrupt ZIP skipped: {artifact.location.display()}: {exc}")


def _is_java_archive_name(name: str) -> bool:
    return Path(name).suffix.lower() in ARCHIVE_SUFFIXES


def _unsafe_member(member: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(member.filename)
    return path.is_absolute() or ".." in path.parts or "\x00" in member.filename


def _is_zip_symlink(member: zipfile.ZipInfo) -> bool:
    mode = (member.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
