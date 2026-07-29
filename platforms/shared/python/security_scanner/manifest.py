from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class ManifestFile:
    path: str
    sha256: str
    size: int
    modified_at: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "modified_at": self.modified_at,
        }


@dataclass(frozen=True, slots=True)
class DeploymentManifest:
    target: str
    generated_at: str
    files: tuple[ManifestFile, ...]

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "files": [item.to_json() for item in self.files],
        }


@dataclass(frozen=True, slots=True)
class ManifestComparison:
    baseline: str
    target: str
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    unchanged: tuple[str, ...]

    @property
    def summary(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "unchanged": len(self.unchanged),
        }

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "baseline": self.baseline,
            "target": self.target,
            "summary": self.summary,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
            "unchanged": list(self.unchanged),
        }


def create_manifest(target: Path) -> DeploymentManifest:
    if not target.exists():
        raise FileNotFoundError(target)
    files = tuple(_manifest_file(path, target) for path in _iter_files(target))
    return DeploymentManifest(
        target=str(target),
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        files=files,
    )


def load_manifest(path: Path) -> DeploymentManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Manifest must be a JSON object")
    files = payload.get("files")
    if not isinstance(files, list):
        raise ValueError("Manifest must include a files list")
    return DeploymentManifest(
        target=str(payload.get("target", "")),
        generated_at=str(payload.get("generated_at", "")),
        files=tuple(_parse_file(item) for item in files),
    )


def compare_manifest_to_target(baseline: DeploymentManifest, target: Path) -> ManifestComparison:
    current = create_manifest(target)
    baseline_files = {item.path: item for item in baseline.files}
    current_files = {item.path: item for item in current.files}
    baseline_paths = set(baseline_files)
    current_paths = set(current_files)
    shared_paths = baseline_paths & current_paths
    changed = tuple(sorted(path for path in shared_paths if baseline_files[path].sha256 != current_files[path].sha256))
    unchanged = tuple(sorted(path for path in shared_paths if baseline_files[path].sha256 == current_files[path].sha256))
    return ManifestComparison(
        baseline=baseline.target,
        target=str(target),
        added=tuple(sorted(current_paths - baseline_paths)),
        removed=tuple(sorted(baseline_paths - current_paths)),
        changed=changed,
        unchanged=unchanged,
    )


def render_manifest_json(manifest: DeploymentManifest) -> str:
    return json.dumps(manifest.to_json(), indent=2, ensure_ascii=False)


def render_manifest_compare_json(comparison: ManifestComparison) -> str:
    return json.dumps(comparison.to_json(), indent=2, ensure_ascii=False)


def _iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs.sort()
        for name in sorted(files):
            path = Path(root) / name
            if path.is_file():
                yield path


def _manifest_file(path: Path, root: Path) -> ManifestFile:
    stat = path.stat()
    return ManifestFile(
        path=_relative_path(path, root),
        sha256=_sha256(path),
        size=stat.st_size,
        modified_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def _relative_path(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    return path.relative_to(root).as_posix()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_file(item: JsonValue) -> ManifestFile:
    if not isinstance(item, dict):
        raise ValueError("Manifest file entries must be JSON objects")
    return ManifestFile(
        path=str(item.get("path", "")),
        sha256=str(item.get("sha256", "")),
        size=int(item.get("size", 0)),
        modified_at=str(item.get("modified_at", "")),
    )
