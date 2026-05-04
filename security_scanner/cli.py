from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ConfigError, config_from_dict, expand_path, load_config
from .models import CATEGORIES, SEVERITIES, ReportConfig, ScannerConfig, TargetConfig
from .reporting import filter_by_min_severity, render_report, write_report
from .scanner import SecurityScanner


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

    if args.command in {None, "scan"}:
        try:
            config = _build_scan_config(args)
        except ConfigError as exc:
            print(f"Config error: {exc}", file=sys.stderr)
            return 2

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
    scan.add_argument("--target", action="append", help="target path; can be passed multiple times")
    scan.add_argument(
        "--category",
        action="append",
        choices=CATEGORIES,
        help="category to run; can be passed multiple times",
    )
    scan.add_argument("--format", choices=("markdown", "json", "html", "sarif"), help="report format")
    scan.add_argument("--output", type=Path, help="report output path")
    scan.add_argument("--language", choices=("en", "ko"), help="report display language")
    scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    scan.add_argument("--max-file-size", type=int, help="maximum file size to scan in bytes")
    scan.add_argument("--discover-projects", action="store_true", help="discover project roots under target folders")
    scan.add_argument("--discovery-depth", type=int, help="maximum discovery depth below each target")

    discover = subparsers.add_parser("discover", help="list project roots under a folder")
    discover.add_argument("--target", default=".", help="folder to inspect")
    discover.add_argument("--depth", type=int, default=2, help="maximum folder depth")

    serve = subparsers.add_parser("serve", help="run the local dashboard server")
    serve.add_argument("--host", default="127.0.0.1", help="host interface to bind")
    serve.add_argument("--port", type=int, default=8765, help="port to bind")
    serve.add_argument("--language", choices=("en", "ko"), default="ko", help="initial dashboard language")

    subparsers.add_parser("list-categories", help="show available check categories")
    return parser


def _build_scan_config(args: argparse.Namespace) -> ScannerConfig:
    if args.config:
        config = load_config(args.config)
    elif args.target:
        config = _config_from_cli(args)
    elif Path("scanner_config.json").exists():
        config = load_config(Path("scanner_config.json"))
    elif Path("scanner_config.example.json").exists():
        config = load_config(Path("scanner_config.example.json"))
    else:
        config = _config_from_cli(args)

    return _apply_overrides(config, args)


def _config_from_cli(args: argparse.Namespace) -> ScannerConfig:
    target_values = args.target or ["."]
    categories = tuple(args.category or CATEGORIES)
    base_dir = Path.cwd()
    targets = tuple(
        TargetConfig(
            name=Path(target).expanduser().name or target,
            path=expand_path(target, base_dir),
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
    return ScannerConfig(targets=targets, report=report)


def _apply_overrides(config: ScannerConfig, args: argparse.Namespace) -> ScannerConfig:
    targets = config.targets
    if args.target:
        cli_config = _config_from_cli(args)
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
    return ScannerConfig(targets=targets, report=report)


def _has_failure(findings, fail_on: str) -> bool:
    from .models import SEVERITY_RANK

    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)
