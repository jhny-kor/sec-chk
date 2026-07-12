from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_MARKERS = {
    ".git": "git",
    "Cargo.toml": "rust",
    "Dockerfile": "docker",
    "Package.swift": "swift",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "go.mod": "go",
    "package.json": "node",
    "pom.xml": "maven",
    "pyproject.toml": "python",
    "requirements.txt": "python",
}

PROJECT_SUFFIX_MARKERS = {
    ".code-workspace": "workspace",
    ".sln": "dotnet",
    ".xcodeproj": "xcode",
    ".xcworkspace": "xcode",
}

DISCOVERY_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".mypy_cache",
    ".next",
    ".omx",
    ".playwright-cli",
    ".pytest_cache",
    ".terraform",
    ".venv",
    "DerivedData",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "output",
    "reports",
    "target",
    "venv",
}


@dataclass(frozen=True)
class DiscoveredProject:
    name: str
    path: Path
    markers: tuple[str, ...]
    ecosystems: tuple[str, ...]


def discover_projects(root: Path, max_depth: int | None = None, include_root: bool = False) -> tuple[DiscoveredProject, ...]:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return ()

    projects: list[DiscoveredProject] = []
    _visit(root, root, 0, max_depth, include_root, projects)
    return tuple(projects)


def _visit(
    root: Path,
    current: Path,
    depth: int,
    max_depth: int | None,
    include_root: bool,
    projects: list[DiscoveredProject],
) -> None:
    project = _project_from_path(root, current)
    if project and (include_root or depth > 0):
        projects.append(project)
        return

    if max_depth is not None and depth >= max_depth:
        return

    try:
        children = sorted(current.iterdir(), key=lambda path: path.name.lower())
    except OSError:
        return

    for child in children:
        if not child.is_dir() or child.is_symlink() or child.name in DISCOVERY_EXCLUDE_DIRS:
            continue
        _visit(root, child, depth + 1, max_depth, include_root, projects)


def _project_from_path(root: Path, path: Path) -> DiscoveredProject | None:
    markers: list[str] = []
    ecosystems: set[str] = set()

    try:
        children = tuple(path.iterdir())
    except OSError:
        return None

    names = {child.name: child for child in children}
    for marker, ecosystem in PROJECT_MARKERS.items():
        if marker in names:
            markers.append(marker)
            ecosystems.add(ecosystem)

    for child in children:
        ecosystem = PROJECT_SUFFIX_MARKERS.get(child.suffix)
        if ecosystem:
            markers.append(child.name)
            ecosystems.add(ecosystem)

    if not markers:
        return None

    try:
        relative = path.relative_to(root)
        name = str(relative) if str(relative) != "." else path.name
    except ValueError:
        name = path.name

    return DiscoveredProject(
        name=name,
        path=path,
        markers=tuple(sorted(markers)),
        ecosystems=tuple(sorted(ecosystems)),
    )
