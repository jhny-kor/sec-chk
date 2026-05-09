from __future__ import annotations

import argparse
import gzip
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from shutil import copyfileobj

from .config import ConfigError, expand_path, load_config
from .models import CATEGORIES, SEVERITIES, ReportConfig, ScannerConfig, TargetConfig
from .reporting import filter_by_min_severity, render_report, write_report
from .scanner import SecurityScanner

ARCHIVE_SUFFIXES = (
    ".zip",
    ".jar",
    ".war",
    ".ear",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tbz",
    ".tbz2",
    ".tar.bz2",
    ".txz",
    ".tar.xz",
    ".gz",
)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list-categories":
        for category in CATEGORIES:
            print(category)
        return 0

    if args.command == "discover":
        from .discovery import discover_projects

        target = expand_path(args.target, Path.cwd())
        for project in discover_projects(target, args.depth):
            markers = ", ".join(project.markers)
            ecosystems = ", ".join(project.ecosystems)
            print(f"{project.name}\t{project.path}\t{ecosystems}\t{markers}")
        return 0

    if args.command == "serve":
        from .server import serve_dashboard

        return serve_dashboard(args.host, args.port, args.language)

    if args.command == "app":
        from .app import run_app

        try:
            return run_app(args.host, args.port, args.language, open_browser=not args.no_browser)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"App error: {exc}", file=sys.stderr)
            return 2

    if args.command in {None, "scan"}:
        try:
            with _build_scan_config_context(args) as config:
                scanner = SecurityScanner(config)
                findings = scanner.scan()
                filtered_findings = filter_by_min_severity(findings, config.report.min_severity)
                effective_targets = scanner.effective_targets or config.targets
                target_names = tuple(target.name for target in effective_targets)
                target_paths = {target.name: str(target.path) for target in effective_targets}
                content = render_report(
                    filtered_findings,
                    config.report.format,
                    target_names=target_names,
                    target_paths=target_paths,
                    language=config.report.language,
                    components=scanner.components,
                )
                write_report(content, config.report.output)

                for warning in scanner.warnings:
                    print(f"warning: {warning}", file=sys.stderr)

                print(
                    f"Scanned {len(target_names)} target(s); "
                    f"{len(filtered_findings)} finding(s) at or above {config.report.min_severity}.",
                    file=sys.stderr,
                )
                if args.fail_on and _has_failure(filtered_findings, args.fail_on):
                    return 1
        except ConfigError as exc:
            print(f"Config error: {exc}", file=sys.stderr)
            return 2
        return 0

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local-security-scan",
        description="Read-only local project security scanner.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan configured local project folders")
    scan.add_argument("--config", type=Path, help="JSON config file")
    scan.add_argument(
        "--target",
        action="append",
        help="target folder, file, or supported archive; can be passed multiple times",
    )
    scan.add_argument(
        "--category",
        action="append",
        choices=CATEGORIES,
        help="category to run; can be passed multiple times",
    )
    scan.add_argument("--format", choices=("markdown", "json", "html", "sarif", "cyclonedx"), help="report format")
    scan.add_argument("--output", type=Path, help="report output path")
    scan.add_argument("--language", choices=("en", "ko"), help="report display language")
    scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    scan.add_argument("--max-file-size", type=int, help="maximum file size to scan in bytes")
    scan.add_argument("--discover-projects", action="store_true", help="discover project roots under target folders")
    scan.add_argument("--discovery-depth", type=int, help="maximum discovery depth below each target")
    scan.add_argument("--enable-osv", action="store_true", help="query OSV.dev for exact-version dependency vulnerabilities")

    discover = subparsers.add_parser("discover", help="list project roots under a folder")
    discover.add_argument("--target", default=".", help="folder to inspect")
    discover.add_argument("--depth", type=int, default=2, help="maximum folder depth")

    serve = subparsers.add_parser("serve", help="run the local dashboard server")
    serve.add_argument("--host", default="127.0.0.1", help="host interface to bind")
    serve.add_argument("--port", type=int, default=8765, help="port to bind")
    serve.add_argument("--language", choices=("en", "ko"), default="ko", help="initial dashboard language")

    app = subparsers.add_parser("app", help="run the dashboard like a local desktop app")
    app.add_argument("--host", default="127.0.0.1", help="host interface to bind")
    app.add_argument("--port", type=int, default=8765, help="first port to try")
    app.add_argument("--language", choices=("en", "ko"), default="ko", help="initial dashboard language")
    app.add_argument("--no-browser", action="store_true", help="do not open the default browser automatically")

    subparsers.add_parser("list-categories", help="show available check categories")
    return parser


@contextmanager
def _build_scan_config_context(args: argparse.Namespace):
    with tempfile.TemporaryDirectory(prefix="sec-chk-inputs-") as temp_dir:
        yield _build_scan_config(args, archive_extract_root=Path(temp_dir))


def _build_scan_config(args: argparse.Namespace, *, archive_extract_root: Path | None = None) -> ScannerConfig:
    if args.config:
        config = load_config(args.config)
    elif args.target:
        config = _config_from_cli(args, archive_extract_root=archive_extract_root)
    elif Path("scanner_config.json").exists():
        config = load_config(Path("scanner_config.json"))
    elif Path("scanner_config.example.json").exists():
        config = load_config(Path("scanner_config.example.json"))
    else:
        config = _config_from_cli(args, archive_extract_root=archive_extract_root)

    return _apply_overrides(config, args, archive_extract_root=archive_extract_root)


def _config_from_cli(args: argparse.Namespace, *, archive_extract_root: Path | None = None) -> ScannerConfig:
    target_values = args.target or ["."]
    categories = tuple(args.category or CATEGORIES)
    base_dir = Path.cwd()
    targets = tuple(
        TargetConfig(
            name=Path(target).expanduser().name or target,
            path=_prepare_input_target(expand_path(target, base_dir), archive_extract_root),
            categories=categories,
            max_file_size_bytes=args.max_file_size or 524288,
            discover_projects=bool(args.discover_projects),
            discovery_depth=args.discovery_depth if args.discovery_depth is not None else 2,
        )
        for target in target_values
    )
    report = ReportConfig(
        format=args.format or "markdown",
        output=args.output.resolve() if args.output else None,
        min_severity=args.min_severity or "low",
        language=args.language or "en",
    )
    return ScannerConfig(targets=targets, report=report, enable_osv=bool(args.enable_osv))


def _apply_overrides(
    config: ScannerConfig,
    args: argparse.Namespace,
    *,
    archive_extract_root: Path | None = None,
) -> ScannerConfig:
    targets = config.targets
    if args.target:
        cli_config = _config_from_cli(args, archive_extract_root=archive_extract_root)
        targets = cli_config.targets
    elif args.category or args.max_file_size or args.discover_projects or args.discovery_depth is not None:
        targets = tuple(
            TargetConfig(
                name=target.name,
                path=target.path,
                categories=tuple(args.category) if args.category else target.categories,
                exclude_globs=target.exclude_globs,
                max_file_size_bytes=args.max_file_size or target.max_file_size_bytes,
                discover_projects=True if args.discover_projects else target.discover_projects,
                discovery_depth=args.discovery_depth if args.discovery_depth is not None else target.discovery_depth,
            )
            for target in config.targets
        )

    report = ReportConfig(
        format=args.format or config.report.format,
        output=args.output.resolve() if args.output else config.report.output,
        min_severity=args.min_severity or config.report.min_severity,
        language=args.language or config.report.language,
    )
    return ScannerConfig(targets=targets, report=report, enable_osv=bool(args.enable_osv) or config.enable_osv)


def _prepare_input_target(path: Path, archive_extract_root: Path | None) -> Path:
    if not path.exists() or not path.is_file() or not _looks_like_archive(path):
        return path
    if archive_extract_root is None:
        raise ConfigError("Archive input requires a temporary extraction directory")

    target_dir = archive_extract_root / _archive_target_name(path)
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        if zipfile.is_zipfile(path):
            _extract_zip(path, target_dir)
            return target_dir
        if tarfile.is_tarfile(path):
            _extract_tar(path, target_dir)
            return target_dir
        if path.suffix.lower() == ".gz":
            _extract_gzip(path, target_dir)
            return target_dir
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        raise ConfigError(f"Could not extract archive target {path}: {exc}") from exc

    raise ConfigError(f"Unsupported archive format: {path}")


def _looks_like_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _archive_target_name(path: Path) -> str:
    safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in path.name)
    return f"{safe_name}.extracted"


def _safe_destination(root: Path, member_name: str) -> Path:
    destination = (root / member_name).resolve()
    root_resolved = root.resolve()
    if destination != root_resolved and root_resolved not in destination.parents:
        raise ConfigError(f"Archive contains unsafe path: {member_name}")
    return destination


def _extract_zip(path: Path, target_dir: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            destination = _safe_destination(target_dir, member.filename)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, destination.open("wb") as output:
                copyfileobj(source, output)


def _extract_tar(path: Path, target_dir: Path) -> None:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            destination = _safe_destination(target_dir, member.name)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with source, destination.open("wb") as output:
                copyfileobj(source, output)


def _extract_gzip(path: Path, target_dir: Path) -> None:
    output_name = path.name[:-3] if path.name.lower().endswith(".gz") else f"{path.name}.out"
    destination = _safe_destination(target_dir, output_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "rb") as source, destination.open("wb") as output:
        copyfileobj(source, output)


def _has_failure(findings, fail_on: str) -> bool:
    from .models import SEVERITY_RANK

    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)
