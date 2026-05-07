from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .checks.common import find_line_containing, read_text_lines
from .models import DependencyComponent, TargetConfig


PYTHON_EXACT_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9][^\s;#]*)")
NODE_RANGE_PREFIXES = ("^", "~", ">", "<", "=", "*")


def components_from_file(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    if path.name == "package-lock.json":
        return _components_from_package_lock(path, target)
    if path.name == "package.json":
        return _components_from_package_json(path, target)
    if path.name in {"requirements.txt", "requirements.in"} or path.name.endswith("-requirements.txt"):
        return _components_from_requirements(path, target)
    if path.name == "pyproject.toml":
        return _components_from_pyproject(path, target)
    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        return _components_from_dockerfile(path, target)
    return []


def unique_components(components: list[DependencyComponent] | tuple[DependencyComponent, ...]) -> tuple[DependencyComponent, ...]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[DependencyComponent] = []
    for component in components:
        key = component.key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(component)
    return tuple(sorted(unique, key=lambda item: (item.target, item.ecosystem.lower(), item.name.lower(), item.version)))


def queryable_osv_components(components: list[DependencyComponent] | tuple[DependencyComponent, ...]) -> tuple[DependencyComponent, ...]:
    supported_ecosystems = {"npm", "PyPI"}
    return tuple(
        component
        for component in unique_components(components)
        if component.ecosystem in supported_ecosystems and _is_exact_version(component.version)
    )


def component_payload(component: DependencyComponent) -> dict[str, object]:
    return {
        "name": component.name,
        "ecosystem": component.ecosystem,
        "version": component.version,
        "purl": component.purl,
        "target": component.target,
        "path": str(component.path),
        "line": component.line,
        "scope": component.scope,
        "source": component.source,
        "osv_queryable": bool(queryable_osv_components((component,))),
    }


def _components_from_package_json(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return []

    components: list[DependencyComponent] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        scope = "excluded" if section == "devDependencies" else "required"
        for name, version in deps.items():
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version.strip(),
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"'),
                    scope=scope,
                    source=section,
                )
            )
    return components


def _components_from_package_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return []

    components: list[DependencyComponent] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, package_data in packages.items():
            if not package_path or not isinstance(package_data, dict):
                continue
            version = package_data.get("version")
            if not isinstance(version, str) or not version:
                continue
            name = package_data.get("name")
            if not isinstance(name, str) or not name:
                name = _name_from_node_modules_path(str(package_path))
            if not name:
                continue
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"') or find_line_containing(lines, f'"{package_path}"'),
                    source="package-lock",
                )
            )

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _collect_lock_dependencies(dependencies, path, target, lines, components)
    return components


def _collect_lock_dependencies(
    dependencies: dict[str, Any],
    path: Path,
    target: TargetConfig,
    lines: list[str],
    components: list[DependencyComponent],
) -> None:
    for name, payload in dependencies.items():
        if not isinstance(name, str) or not isinstance(payload, dict):
            continue
        version = payload.get("version")
        if isinstance(version, str) and version:
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"'),
                    source="package-lock",
                )
            )
        nested = payload.get("dependencies")
        if isinstance(nested, dict):
            _collect_lock_dependencies(nested, path, target, lines, components)


def _components_from_requirements(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue
        match = PYTHON_EXACT_RE.match(line)
        if not match:
            continue
        name = _normalize_python_name(match.group(1))
        version = match.group(2).strip()
        components.append(
            _component(
                name=name,
                ecosystem="PyPI",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source=path.name,
            )
        )
    return components


def _components_from_pyproject(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ provides tomllib
        return []
    try:
        data = tomllib.loads("\n".join(lines))
    except tomllib.TOMLDecodeError:
        return []

    components: list[DependencyComponent] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        for item in _dependency_strings(project.get("dependencies")):
            _append_python_requirement_component(components, item, path, target, lines, "project.dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, values in optional.items():
                for item in _dependency_strings(values):
                    _append_python_requirement_component(components, item, path, target, lines, f"project.optional-dependencies.{group}", "excluded")

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies", {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                if name.lower() == "python":
                    continue
                if isinstance(version, str):
                    components.append(
                        _component(
                            name=_normalize_python_name(name),
                            ecosystem="PyPI",
                            version=version.strip(),
                            path=path,
                            target=target,
                            line=find_line_containing(lines, name),
                            source="tool.poetry.dependencies",
                        )
                    )
    return components


def _components_from_dockerfile(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    components: list[DependencyComponent] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.upper().startswith("FROM "):
            continue
        image = line.split(maxsplit=1)[1].split(" AS ", maxsplit=1)[0].strip()
        if "@" in image:
            name, version = image.split("@", maxsplit=1)
        elif ":" in image and "/" not in image.rsplit(":", maxsplit=1)[1]:
            name, version = image.rsplit(":", maxsplit=1)
        else:
            name, version = image, "latest"
        components.append(
            _component(
                name=name,
                ecosystem="Docker",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source="Dockerfile",
            )
        )
    return components


def _append_python_requirement_component(
    components: list[DependencyComponent],
    requirement: str,
    path: Path,
    target: TargetConfig,
    lines: list[str],
    source: str,
    scope: str = "required",
) -> None:
    match = PYTHON_EXACT_RE.match(requirement)
    if not match:
        return
    name = _normalize_python_name(match.group(1))
    components.append(
        _component(
            name=name,
            ecosystem="PyPI",
            version=match.group(2).strip(),
            path=path,
            target=target,
            line=find_line_containing(lines, requirement) or find_line_containing(lines, name),
            scope=scope,
            source=source,
        )
    )


def _dependency_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _component(
    *,
    name: str,
    ecosystem: str,
    version: str,
    path: Path,
    target: TargetConfig,
    line: int | None = None,
    scope: str = "required",
    source: str = "",
) -> DependencyComponent:
    normalized_name = _normalize_component_name(name, ecosystem)
    normalized_version = version.strip()
    return DependencyComponent(
        name=normalized_name,
        ecosystem=ecosystem,
        version=normalized_version,
        path=path,
        target=target.name,
        line=line,
        scope=scope,
        source=source,
        purl=_purl(ecosystem, normalized_name, normalized_version),
    )


def _name_from_node_modules_path(value: str) -> str:
    marker = "node_modules/"
    if marker not in value:
        return ""
    tail = value.rsplit(marker, maxsplit=1)[1]
    parts = tail.split("/")
    if len(parts) >= 2 and parts[0].startswith("@"):
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else ""


def _normalize_component_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return _normalize_python_name(name)
    return name.strip()


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _is_exact_version(version: str) -> bool:
    cleaned = version.strip()
    if not cleaned or cleaned.startswith(NODE_RANGE_PREFIXES):
        return False
    return not any(token in cleaned for token in ("*", "||", " - ", "x", "X"))


def _purl(ecosystem: str, name: str, version: str) -> str:
    purl_type = {
        "npm": "npm",
        "PyPI": "pypi",
        "Docker": "docker",
    }.get(ecosystem, ecosystem.lower())
    quoted_name = quote(name, safe="/")
    quoted_version = quote(version, safe="")
    return f"pkg:{purl_type}/{quoted_name}@{quoted_version}" if quoted_version else f"pkg:{purl_type}/{quoted_name}"
