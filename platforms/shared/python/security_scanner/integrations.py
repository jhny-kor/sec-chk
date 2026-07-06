from __future__ import annotations

import json
import os
import re
import shlex
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def zap_baseline_command(target_url: str, *, output_dir: str = "reports/zap", minutes: int = 1) -> str:
    _require_http_url(target_url, label="target URL")
    if minutes <= 0:
        raise ValueError("minutes must be positive")
    output_path = output_dir.rstrip("/") or "reports/zap"
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", output_path):
        raise ValueError("output_dir may only contain letters, numbers, slash, dot, dash, and underscore")
    mount_path = output_path if output_path.startswith("/") else f"$PWD/{output_path}"
    return " ".join(
        [
            "mkdir",
            "-p",
            shlex.quote(output_path),
            "&&",
            "docker",
            "run",
            "--rm",
            "-t",
            "-v",
            f'"{mount_path}:/zap/wrk:rw"',
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t",
            shlex.quote(target_url),
            "-m",
            str(minutes),
            "-r",
            "zap-baseline.html",
            "-w",
            "zap-baseline.md",
            "-J",
            "zap-baseline.json",
        ]
    )


def dependency_track_upload_command(
    *,
    server_url: str,
    project_name: str,
    project_version: str,
    sbom_path: str,
    api_key_env: str = "DEPENDENCY_TRACK_API_KEY",
    auto_create: bool = True,
) -> str:
    endpoint = _dependency_track_bom_endpoint(server_url)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api_key_env):
        raise ValueError("api_key_env must be a valid environment variable name")
    return " ".join(
        [
            "curl",
            "-X",
            "POST",
            shlex.quote(endpoint),
            "-H",
            f'"X-Api-Key: ${{{api_key_env}}}"',
            "-F",
            shlex.quote(f"autoCreate={str(auto_create).lower()}"),
            "-F",
            shlex.quote(f"projectName={project_name}"),
            "-F",
            shlex.quote(f"projectVersion={project_version}"),
            "-F",
            shlex.quote(f"bom=@{sbom_path}"),
        ]
    )


def upload_sbom_to_dependency_track(
    *,
    server_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    sbom_path: Path,
    auto_create: bool = True,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    if not api_key.strip():
        raise ValueError("Dependency-Track API key is required")
    if not project_name.strip():
        raise ValueError("project_name is required")
    if not project_version.strip():
        raise ValueError("project_version is required")
    if not sbom_path.exists() or not sbom_path.is_file():
        raise ValueError(f"SBOM file does not exist: {sbom_path}")

    endpoint = _dependency_track_bom_endpoint(server_url)
    boundary = f"----KODAFormBoundary{uuid.uuid4().hex}"
    body = _multipart_body(
        boundary,
        fields={
            "autoCreate": str(auto_create).lower(),
            "projectName": project_name,
            "projectVersion": project_version,
        },
        file_field="bom",
        file_path=sbom_path,
    )
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Api-Key": api_key,
            "User-Agent": "sec-chk-local-security-scanner",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            text = response.read().decode("utf-8", errors="replace")
            if not text.strip():
                return {"status": response.status, "body": ""}
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"body": text}
            if isinstance(payload, dict):
                payload.setdefault("status", response.status)
                return payload
            return {"status": response.status, "body": payload}
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Dependency-Track upload failed ({exc.code}): {details}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Dependency-Track upload failed: {exc}") from exc


def api_key_from_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"Environment variable is not set: {name}")
    return value


def _dependency_track_bom_endpoint(server_url: str) -> str:
    parsed = _require_http_url(server_url, label="Dependency-Track server URL")
    base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    if base.endswith("/api/v1/bom"):
        return base
    if base.endswith("/api"):
        return f"{base}/v1/bom"
    if base.endswith("/api/v1"):
        return f"{base}/bom"
    return f"{base}/api/v1/bom"


def _require_http_url(value: str, *, label: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{label} must be an http(s) URL")
    return parsed


def _multipart_body(boundary: str, *, fields: dict[str, str], file_field: str, file_path: Path) -> bytes:
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode("utf-8"),
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'.encode("utf-8"),
            b"Content-Type: application/json\r\n\r\n",
            file_path.read_bytes(),
            b"\r\n",
            f"--{boundary}--\r\n".encode("utf-8"),
        ]
    )
    return b"".join(chunks)
