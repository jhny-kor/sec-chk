from __future__ import annotations

import argparse
import gzip
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from shutil import copyfileobj

from .config import ConfigError, expand_path, load_config
from .models import CATEGORIES, DEFAULT_CATEGORIES, SEVERITIES, ReportConfig, ScannerConfig, TargetConfig
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

    if args.command == "init-security":
        from .toolkit import write_security_template_files

        try:
            target = expand_path(args.target, Path.cwd())
            if args.dry_run:
                from .toolkit import security_template_files

                for relative_path in security_template_files(args.project_name or target.name):
                    print(target / relative_path)
                return 0
            results = write_security_template_files(target, project_name=args.project_name, force=bool(args.force))
        except (OSError, ValueError) as exc:
            print(f"Template error: {exc}", file=sys.stderr)
            return 2
        for result in results:
            print(f"{result.status}\t{result.path}")
        return 0

    if args.command == "install-hook":
        from .toolkit import install_pre_commit_hook

        try:
            result = install_pre_commit_hook(expand_path(args.target, Path.cwd()), fail_on=args.fail_on, force=bool(args.force))
        except (OSError, ValueError) as exc:
            print(f"Hook install error: {exc}", file=sys.stderr)
            return 2
        print(f"{result.status}\t{result.path}")
        return 0

    if args.command in {"repo-security-checklist", "ssdf-plan", "secure-by-design-plan", "sigstore-plan"}:
        from .toolkit import (
            render_release_signing_plan,
            render_repository_security_checklist,
            render_secure_by_design_plan,
            render_ssdf_workflow_plan,
        )

        project_name = args.project_name or Path(args.target).expanduser().name or "KODA Project"
        if args.command == "repo-security-checklist":
            content = render_repository_security_checklist(project_name)
        elif args.command == "ssdf-plan":
            content = render_ssdf_workflow_plan(project_name)
        elif args.command == "secure-by-design-plan":
            content = render_secure_by_design_plan(project_name)
        else:
            content = render_release_signing_plan(project_name, artifact_path=args.artifact)
        write_report(content, expand_path(str(args.output), Path.cwd()) if args.output else None)
        return 0

    if args.command == "zap-command":
        from .integrations import zap_baseline_command

        try:
            print(zap_baseline_command(args.url, output_dir=args.output_dir, minutes=args.minutes))
        except ValueError as exc:
            print(f"ZAP command error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "zap-run":
        from .dast import render_zap_findings_json, run_zap_baseline

        try:
            result = run_zap_baseline(
                args.url,
                output_dir=expand_path(args.output_dir, Path.cwd()),
                minutes=args.minutes,
                dry_run=args.dry_run,
                timeout_seconds=args.timeout,
            )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(f"ZAP run error: {exc}", file=sys.stderr)
            return 2
        if args.dry_run:
            print(result.command)
            return 0
        findings_path = result.output_dir / "koda-zap-findings.json"
        findings_path.write_text(render_zap_findings_json(result.findings), encoding="utf-8")
        print(
            json_dumps(
                {
                    "exit_code": result.exit_code,
                    "output_dir": str(result.output_dir),
                    "finding_count": len(result.findings),
                    "findings": str(findings_path),
                    "command": result.command,
                }
            )
        )
        if result.exit_code not in {0, 1, 2}:
            return result.exit_code
        if args.fail_on_alerts and result.findings:
            return 1
        return 0

    if args.command == "evidence-checklist":
        from .evidence import write_evidence_checklist

        output = expand_path(args.output, Path.cwd())
        try:
            write_evidence_checklist(
                output,
                project_name=args.project_name or Path(args.target).expanduser().name or "project",
                language=args.language,
                json_format=args.format == "json",
            )
        except OSError as exc:
            print(f"Evidence checklist error: {exc}", file=sys.stderr)
            return 2
        print(output)
        return 0

    if args.command == "diff-reports":
        from .diffing import diff_reports, render_diff_json, render_diff_markdown

        try:
            diff = diff_reports(expand_path(args.baseline, Path.cwd()), expand_path(args.current, Path.cwd()))
            content = render_diff_json(diff) if args.format == "json" else render_diff_markdown(diff, language=args.language)
            write_report(content, expand_path(str(args.output), Path.cwd()) if args.output else None)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"Diff report error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "release-package":
        from .release import build_release_security_package

        try:
            manifest = build_release_security_package(
                target=expand_path(args.target, Path.cwd()),
                output_dir=expand_path(args.output_dir, Path.cwd()),
                project_name=args.project_name,
                language=args.language,
                enable_vuln_intel=args.enable_vuln_intel,
            )
        except (OSError, ValueError) as exc:
            print(f"Release package error: {exc}", file=sys.stderr)
            return 2
        print(json_dumps(manifest))
        return 0

    if args.command == "dependency-track-command":
        from .integrations import dependency_track_upload_command

        try:
            print(
                dependency_track_upload_command(
                    server_url=args.server_url,
                    project_name=args.project_name,
                    project_version=args.project_version,
                    sbom_path=args.sbom,
                    api_key_env=args.api_key_env,
                    auto_create=args.auto_create,
                )
            )
        except ValueError as exc:
            print(f"Dependency-Track command error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "upload-sbom":
        from .integrations import api_key_from_env, upload_sbom_to_dependency_track

        try:
            api_key = args.api_key or api_key_from_env(args.api_key_env)
            payload = upload_sbom_to_dependency_track(
                server_url=args.server_url,
                api_key=api_key,
                project_name=args.project_name,
                project_version=args.project_version,
                sbom_path=expand_path(args.sbom, Path.cwd()),
                auto_create=args.auto_create,
            )
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"Dependency-Track upload error: {exc}", file=sys.stderr)
            return 2
        print(json_dumps(payload))
        return 0

    if args.command == "host-scan":
        report = ReportConfig(
            format=args.format or "markdown",
            output=expand_path(str(args.output), Path.cwd()) if args.output else None,
            min_severity=args.min_severity or "info",
            language=args.language or "en",
        )
        target = TargetConfig(name="host", path=Path.cwd(), categories=("host",))
        config = ScannerConfig(
            targets=(target,),
            report=report,
            enable_host_inventory=args.inventory or args.check_cve,
            enable_host_eol=args.eol,
            enable_host_cve=args.check_cve,
            nvd_api_key=os.environ.get(args.nvd_api_key_env) if args.nvd_api_key_env else None,
        )
        scanner = SecurityScanner(config)
        findings = scanner.scan()
        filtered_findings = filter_by_min_severity(findings, config.report.min_severity)
        content = render_report(
            filtered_findings,
            config.report.format,
            target_names=("host",),
            language=config.report.language,
        )
        write_report(content, config.report.output)
        for warning in scanner.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(
            f"Host scan: {len(filtered_findings)} finding(s) at or above {config.report.min_severity}.",
            file=sys.stderr,
        )
        if args.fail_on and _has_failure(filtered_findings, args.fail_on):
            return 1
        return 0

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
    scan.add_argument("--format", choices=("markdown", "json", "html", "sarif", "cyclonedx", "cyclonedx-vex"), help="report format")
    scan.add_argument("--output", type=Path, help="report output path")
    scan.add_argument("--language", choices=("en", "ko"), help="report display language")
    scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    scan.add_argument("--max-file-size", type=int, help="maximum file size to scan in bytes")
    scan.add_argument("--discover-projects", action="store_true", help="discover project roots under target folders")
    scan.add_argument("--discovery-depth", type=int, help="maximum discovery depth below each target")
    scan.add_argument("--enable-osv", action="store_true", help="query OSV.dev for exact-version dependency vulnerabilities")
    scan.add_argument(
        "--enable-vuln-intel",
        action="store_true",
        help="enrich OSV CVEs with CISA KEV and FIRST EPSS exploit intelligence; implies --enable-osv",
    )

    host_scan = subparsers.add_parser("host-scan", help="check this computer's security posture (host/endpoint)")
    host_scan.add_argument("--format", choices=("markdown", "json", "html", "sarif"), help="report format")
    host_scan.add_argument("--output", type=Path, help="report output path")
    host_scan.add_argument("--language", choices=("en", "ko"), help="report display language")
    host_scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include (default info)")
    host_scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    host_scan.add_argument("--inventory", action="store_true", help="collect installed application inventory")
    host_scan.add_argument("--eol", action="store_true", help="check OS end-of-life status via endoflife.date (network)")
    host_scan.add_argument(
        "--check-cve",
        action="store_true",
        help="look up installed-app CVEs via NVD (network, rate-limited, implies --inventory)",
    )
    host_scan.add_argument(
        "--nvd-api-key-env",
        help="environment variable holding an NVD API key (raises NVD rate limits)",
    )

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

    init_security = subparsers.add_parser("init-security", help="write preventive security templates into a project")
    init_security.add_argument("--target", default=".", help="project folder to initialize")
    init_security.add_argument("--project-name", default="", help="project name to include in templates")
    init_security.add_argument("--force", action="store_true", help="overwrite existing template files")
    init_security.add_argument("--dry-run", action="store_true", help="print files that would be created")

    install_hook = subparsers.add_parser("install-hook", help="install a KODA pre-commit security gate into a Git repository")
    install_hook.add_argument("--target", default=".", help="Git repository folder")
    install_hook.add_argument("--fail-on", choices=SEVERITIES, default="high", help="block commits at or above this severity")
    install_hook.add_argument("--force", action="store_true", help="overwrite an existing pre-commit hook")

    repo_security = subparsers.add_parser("repo-security-checklist", help="write a GitHub repository security settings checklist")
    repo_security.add_argument("--target", default=".", help="project folder name used for the checklist")
    repo_security.add_argument("--project-name", default="", help="project name")
    repo_security.add_argument("--output", type=Path, help="checklist output path")

    ssdf_plan = subparsers.add_parser("ssdf-plan", help="write a NIST SSDF workflow plan")
    ssdf_plan.add_argument("--target", default=".", help="project folder name used for the plan")
    ssdf_plan.add_argument("--project-name", default="", help="project name")
    ssdf_plan.add_argument("--output", type=Path, help="plan output path")

    secure_by_design = subparsers.add_parser("secure-by-design-plan", help="write a CISA Secure by Design prevention plan")
    secure_by_design.add_argument("--target", default=".", help="project folder name used for the plan")
    secure_by_design.add_argument("--project-name", default="", help="project name")
    secure_by_design.add_argument("--output", type=Path, help="plan output path")

    sigstore_plan = subparsers.add_parser("sigstore-plan", help="write a SLSA/Sigstore release signing plan")
    sigstore_plan.add_argument("--target", default=".", help="project folder name used for the plan")
    sigstore_plan.add_argument("--project-name", default="", help="project name")
    sigstore_plan.add_argument("--artifact", default="dist/app.tar.gz", help="artifact path to reference in commands")
    sigstore_plan.add_argument("--output", type=Path, help="plan output path")

    zap_command = subparsers.add_parser("zap-command", help="print an OWASP ZAP baseline Docker command")
    zap_command.add_argument("--url", required=True, help="authorized http(s) URL to check")
    zap_command.add_argument("--output-dir", default="reports/zap", help="folder for ZAP reports")
    zap_command.add_argument("--minutes", type=int, default=1, help="spider duration in minutes")

    zap_run = subparsers.add_parser("zap-run", help="run OWASP ZAP baseline against an authorized URL")
    zap_run.add_argument("--url", required=True, help="authorized http(s) URL to check")
    zap_run.add_argument("--output-dir", default="reports/zap", help="folder for ZAP reports")
    zap_run.add_argument("--minutes", type=int, default=1, help="spider duration in minutes")
    zap_run.add_argument("--timeout", type=int, default=900, help="maximum runtime in seconds")
    zap_run.add_argument("--dry-run", action="store_true", help="print the Docker command without running ZAP")
    zap_run.add_argument("--fail-on-alerts", action="store_true", help="exit 1 when ZAP reports any finding")

    evidence = subparsers.add_parser("evidence-checklist", help="write a manual evidence checklist for standards that require evidence review")
    evidence.add_argument("--target", default=".", help="project folder name used for the checklist")
    evidence.add_argument("--project-name", default="", help="project name to include in the checklist")
    evidence.add_argument("--output", default="manual-evidence-checklist.md", help="checklist output path")
    evidence.add_argument("--language", choices=("en", "ko"), default="ko", help="checklist language")
    evidence.add_argument("--format", choices=("markdown", "json"), default="markdown", help="checklist format")

    diff_reports = subparsers.add_parser("diff-reports", help="compare two JSON scan reports")
    diff_reports.add_argument("--baseline", required=True, help="older JSON scan report")
    diff_reports.add_argument("--current", required=True, help="newer JSON scan report")
    diff_reports.add_argument("--output", type=Path, help="diff report output path")
    diff_reports.add_argument("--format", choices=("markdown", "json"), default="markdown", help="diff report format")
    diff_reports.add_argument("--language", choices=("en", "ko"), default="ko", help="diff report language")

    release_package = subparsers.add_parser("release-package", help="create a release security package with SBOM, VEX, checklist, findings, and checksums")
    release_package.add_argument("--target", default=".", help="project folder to package")
    release_package.add_argument("--output-dir", default="KODA-release-security-package", help="output folder")
    release_package.add_argument("--project-name", default="", help="project name")
    release_package.add_argument("--language", choices=("en", "ko"), default="ko", help="package language")
    release_package.add_argument("--enable-vuln-intel", action="store_true", help="query OSV/CVE and KEV/EPSS while building package")

    dependency_track_command = subparsers.add_parser("dependency-track-command", help="print a Dependency-Track SBOM upload curl command")
    dependency_track_command.add_argument("--server-url", required=True, help="Dependency-Track backend URL")
    dependency_track_command.add_argument("--project-name", required=True, help="Dependency-Track project name")
    dependency_track_command.add_argument("--project-version", default="main", help="Dependency-Track project version")
    dependency_track_command.add_argument("--sbom", default="reports/sbom.cdx.json", help="CycloneDX SBOM path")
    dependency_track_command.add_argument("--api-key-env", default="DEPENDENCY_TRACK_API_KEY", help="environment variable used in the generated command")
    dependency_track_command.add_argument("--auto-create", action=argparse.BooleanOptionalAction, default=True, help="allow project auto-creation")

    upload_sbom = subparsers.add_parser("upload-sbom", help="upload a CycloneDX SBOM to Dependency-Track")
    upload_sbom.add_argument("--server-url", required=True, help="Dependency-Track backend URL")
    upload_sbom.add_argument("--project-name", required=True, help="Dependency-Track project name")
    upload_sbom.add_argument("--project-version", default="main", help="Dependency-Track project version")
    upload_sbom.add_argument("--sbom", required=True, help="CycloneDX SBOM path")
    upload_sbom.add_argument("--api-key", default="", help="Dependency-Track API key; prefer --api-key-env for shell history safety")
    upload_sbom.add_argument("--api-key-env", default="DEPENDENCY_TRACK_API_KEY", help="environment variable containing the API key")
    upload_sbom.add_argument("--auto-create", action=argparse.BooleanOptionalAction, default=True, help="allow project auto-creation")

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
    categories = tuple(args.category or DEFAULT_CATEGORIES)
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
    enable_vuln_intel = bool(getattr(args, "enable_vuln_intel", False))
    return ScannerConfig(targets=targets, report=report, enable_osv=bool(args.enable_osv) or enable_vuln_intel, enable_vuln_intel=enable_vuln_intel)


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
    enable_vuln_intel = bool(getattr(args, "enable_vuln_intel", False)) or config.enable_vuln_intel
    return ScannerConfig(
        targets=targets,
        report=report,
        enable_osv=bool(args.enable_osv) or config.enable_osv or enable_vuln_intel,
        enable_vuln_intel=enable_vuln_intel,
    )


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


def json_dumps(payload: object) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)
