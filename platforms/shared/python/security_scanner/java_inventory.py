from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, replace
from io import BytesIO
from typing import Iterable
from urllib.parse import quote

from .java_archives import ArchiveArtifact, ArchiveScan


@dataclass(frozen=True, slots=True)
class JavaComponent:
    group: str
    name: str
    version: str
    purl: str
    sha256: str
    size: int
    archive_type: str
    modified_at: str
    locations: tuple[str, ...]
    identification_source: str
    identity_status: str
    manual_review_required: bool

    def payload(self) -> dict[str, object]:
        return {
            "group": self.group,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "sha256": self.sha256,
            "size": self.size,
            "archive_type": self.archive_type,
            "modified_at": self.modified_at,
            "locations": list(self.locations),
            "identification_source": self.identification_source,
            "identity_status": self.identity_status,
            "manual_review_required": self.manual_review_required,
        }


def inventory_components(artifacts: ArchiveScan | Iterable[ArchiveArtifact]) -> tuple[JavaComponent, ...]:
    candidates = artifacts.artifacts if isinstance(artifacts, ArchiveScan) else tuple(artifacts)
    by_sha: dict[str, JavaComponent] = {}
    for artifact in candidates:
        component = identify_archive(artifact)
        existing = by_sha.get(component.sha256)
        if existing is None:
            by_sha[component.sha256] = component
            continue
        locations = tuple(dict.fromkeys((*existing.locations, *component.locations)))
        by_sha[component.sha256] = replace(existing, locations=locations)
    return tuple(sorted(by_sha.values(), key=lambda item: (item.name.lower(), item.version, item.sha256)))


def identify_archive(artifact: ArchiveArtifact) -> JavaComponent:
    group = ""
    name = artifact.filename
    version = ""
    source = "filename-unresolved"
    status = "unresolved"
    try:
        with zipfile.ZipFile(BytesIO(artifact.payload)) as archive:
            names = sorted(name for name in archive.namelist() if not name.endswith("/"))
            properties = next((name for name in names if _is_pom_properties(name)), None)
            if properties:
                values = _properties(archive.read(properties).decode("utf-8", errors="replace"))
                group, name, version = _coordinates(values)
                if group and name and version:
                    source, status = "pom.properties", "resolved"
            if status == "unresolved":
                pom = next((entry for entry in names if _is_pom_xml(entry)), None)
                if pom:
                    group, name, version = _pom_xml_coordinates(archive.read(pom))
                    if group and name and version:
                        source, status = "pom.xml", "resolved"
            if status == "unresolved":
                manifest = next((entry for entry in names if entry.upper() == "META-INF/MANIFEST.MF"), None)
                if manifest:
                    values = _properties(archive.read(manifest).decode("utf-8", errors="replace"))
                    name = values.get("Implementation-Title") or values.get("Bundle-SymbolicName") or artifact.filename
                    version = values.get("Implementation-Version") or values.get("Bundle-Version") or ""
                    if name != artifact.filename or version:
                        source, status = "manifest", "partial"
    except (OSError, zipfile.BadZipFile, UnicodeError, ET.ParseError):
        source = "filename-unresolved"

    purl = _maven_purl(group, name, version) if status == "resolved" else ""
    return JavaComponent(
        group=group,
        name=name,
        version=version,
        purl=purl,
        sha256=artifact.sha256,
        size=artifact.size,
        archive_type=artifact.archive_type,
        modified_at=artifact.modified_at,
        locations=(artifact.location.display(),),
        identification_source=source,
        identity_status=status,
        manual_review_required=status != "resolved",
    )


def _is_pom_properties(name: str) -> bool:
    return name.startswith("META-INF/maven/") and name.endswith("/pom.properties")


def _is_pom_xml(name: str) -> bool:
    return name.startswith("META-INF/maven/") and name.endswith("/pom.xml")


def _properties(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        line = pending + line
        pending = ""
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        match = re.match(r"([^:=\s]+)\s*[:=]\s*(.*)$", stripped)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def _coordinates(values: dict[str, str]) -> tuple[str, str, str]:
    return values.get("groupId", ""), values.get("artifactId", ""), values.get("version", "")


def _pom_xml_coordinates(payload: bytes) -> tuple[str, str, str]:
    root = ET.fromstring(payload)
    values: dict[str, str] = {}
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name in {"groupId", "artifactId", "version"} and element.text:
            values.setdefault(local_name, element.text.strip())
    return _coordinates(values)


def _maven_purl(group: str, name: str, version: str) -> str:
    return f"pkg:maven/{quote(group, safe='.')}/{quote(name, safe='.-_')}@{quote(version, safe='.-_+')}"
