from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class DataSource:
    path: str
    sha256: str
    status: str
    metadata: dict[str, object]

    def payload(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "status": self.status, **self.metadata}


@dataclass(frozen=True, slots=True)
class OfflineVulnerabilityData:
    nvd: dict[str, dict[str, object]]
    cisa_kev: dict[str, dict[str, object]]
    knvd: dict[str, tuple[dict[str, object], ...]]
    knvd_manual_review: tuple[dict[str, object], ...]
    sources: tuple[DataSource, ...]
    data_as_of: str
    warnings: tuple[str, ...]
    fatal: bool


def load_offline_data(
    nvd_source: Path | None,
    cisa_source: Path | None,
    knvd_source: Path | None,
    cve_ids: Iterable[str],
) -> OfflineVulnerabilityData:
    requested = {value.upper() for value in cve_ids}
    warnings: list[str] = []
    sources: list[DataSource] = []
    nvd, nvd_info, nvd_dates, nvd_fatal = _load_nvd(nvd_source, requested, warnings)
    sources.append(nvd_info)
    kev, kev_info, kev_dates, kev_fatal = _load_kev(cisa_source, requested, warnings)
    sources.append(kev_info)
    knvd, knvd_manual_review, knvd_info, knvd_dates, knvd_fatal = _load_knvd(knvd_source, requested, warnings)
    sources.append(knvd_info)
    dates = sorted(value for value in (*nvd_dates, *kev_dates, *knvd_dates) if value)
    return OfflineVulnerabilityData(
        nvd=nvd,
        cisa_kev=kev,
        knvd=knvd,
        knvd_manual_review=knvd_manual_review,
        sources=tuple(sources),
        data_as_of=dates[-1] if dates else "unknown",
        warnings=tuple(warnings),
        fatal=nvd_fatal or kev_fatal or knvd_fatal,
    )


def _load_nvd(
    source: Path | None,
    requested: set[str],
    warnings: list[str],
) -> tuple[dict[str, dict[str, object]], DataSource, tuple[str, ...], bool]:
    if source is None:
        return {}, _not_provided("nvd"), (), False
    files = _source_files(source, (".json", ".json.gz"))
    if not files:
        warnings.append(f"NVD data source contains no JSON files: {source}")
        return {}, _source_info(source, "invalid", {"name": "nvd"}), (), True
    records: dict[str, dict[str, object]] = {}
    dates: list[str] = []
    try:
        for path in files:
            payload = _read_json(path)
            dates.extend(_date_values(payload, ("lastModifiedDate", "lastModified")))
            vulnerabilities = payload.get("vulnerabilities", payload.get("CVE_Items", []))
            if not isinstance(vulnerabilities, list):
                continue
            for entry in vulnerabilities:
                cve = entry.get("cve") if isinstance(entry, dict) and isinstance(entry.get("cve"), dict) else entry
                if not isinstance(cve, dict):
                    continue
                metadata = cve.get("CVE_data_meta")
                legacy_id = metadata.get("ID", "") if isinstance(metadata, dict) else ""
                cve_id = str(cve.get("id", legacy_id)).upper()
                if cve_id in requested:
                    records[cve_id] = cve
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, ValueError) as exc:
        warnings.append(f"Could not load NVD data {source}: {exc}")
        return records, _source_info(source, "invalid", {"name": "nvd"}), tuple(dates), True
    return records, _source_info(source, "loaded", {"name": "nvd"}), tuple(dates), False


def _load_kev(
    source: Path | None,
    requested: set[str],
    warnings: list[str],
) -> tuple[dict[str, dict[str, object]], DataSource, tuple[str, ...], bool]:
    if source is None:
        return {}, _not_provided("cisa_kev"), (), False
    try:
        payload = _read_json(source)
        values = payload.get("vulnerabilities", [])
        records = {
            str(entry.get("cveID", "")).upper(): entry
            for entry in values
            if isinstance(entry, dict) and str(entry.get("cveID", "")).upper() in requested
        } if isinstance(values, list) else {}
        dates = _date_values(payload, ("dateReleased", "catalogVersion"))
        metadata = {"name": "cisa_kev", "catalog_version": payload.get("catalogVersion", ""), "date_released": payload.get("dateReleased", "")}
        return records, _source_info(source, "loaded", metadata), dates, False
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, ValueError) as exc:
        warnings.append(f"Could not load CISA KEV data {source}: {exc}")
        return {}, _source_info(source, "invalid", {"name": "cisa_kev"}), (), True


def _load_knvd(
    source: Path | None,
    requested: set[str],
    warnings: list[str],
) -> tuple[dict[str, tuple[dict[str, object], ...]], tuple[dict[str, object], ...], DataSource, tuple[str, ...], bool]:
    if source is None:
        return {}, (), _not_provided("knvd"), (), False
    try:
        payload = _read_json(source)
        notices = payload.get("notices", [])
        records: dict[str, list[dict[str, object]]] = {}
        manual_review: list[dict[str, object]] = []
        if isinstance(notices, list):
            for notice in notices:
                if not isinstance(notice, dict):
                    continue
                cve_ids = notice.get("cve_ids")
                if not isinstance(cve_ids, list) or not cve_ids:
                    manual_review.append(notice)
                    continue
                for cve_id in cve_ids:
                    normalized = str(cve_id).upper()
                    if normalized in requested:
                        records.setdefault(normalized, []).append(notice)
        dates = _date_values(payload, ("generated_at",))
        return {key: tuple(value) for key, value in records.items()}, tuple(manual_review), _source_info(source, "loaded", {"name": "knvd", "generated_at": payload.get("generated_at", "")}), dates, False
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, ValueError) as exc:
        warnings.append(f"Could not load KNVD data {source}: {exc}")
        return {}, (), _source_info(source, "invalid", {"name": "knvd"}), (), True


def _read_json(path: Path) -> dict[str, object]:
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return payload


def _source_files(source: Path, suffixes: tuple[str, ...]) -> tuple[Path, ...]:
    if source.is_file():
        return (source,) if source.name.lower().endswith(suffixes) else ()
    if source.is_dir():
        return tuple(sorted(path for path in source.rglob("*") if path.is_file() and path.name.lower().endswith(suffixes)))
    return ()


def _source_info(source: Path, status: str, metadata: dict[str, object] | None = None) -> DataSource:
    details = dict(metadata or {})
    details["files"] = _source_file_digests(source)
    return DataSource(str(source), _hash_source(source), status, details)


def _not_provided(name: str) -> DataSource:
    return DataSource("", "", "not_provided", {"name": name})


def _hash_source(source: Path) -> str:
    digest = hashlib.sha256()
    if source.is_file():
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    if source.is_dir():
        for path in sorted(path for path in source.rglob("*") if path.is_file()):
            digest.update(str(path.relative_to(source)).encode("utf-8"))
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _source_file_digests(source: Path) -> list[dict[str, str]]:
    paths = (source,) if source.is_file() else tuple(sorted(path for path in source.rglob("*") if path.is_file())) if source.is_dir() else ()
    records: list[dict[str, str]] = []
    for path in paths:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        records.append({"path": str(path), "sha256": digest.hexdigest()})
    return records


def _date_values(payload: dict[str, object], names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(value for name in names if isinstance(value := payload.get(name), str) and value)
