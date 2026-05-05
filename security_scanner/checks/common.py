from __future__ import annotations

import os
from pathlib import Path


TEXT_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cfg",
    ".cs",
    ".conf",
    ".config",
    ".cpp",
    ".css",
    ".cxx",
    ".env",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".m",
    ".md",
    ".php",
    ".plist",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}

TEXT_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".npmrc",
    "Dockerfile",
    "Makefile",
    "requirements.txt",
}


def is_text_candidate(path: Path) -> bool:
    if path.name in TEXT_FILENAMES:
        return True
    if path.name.startswith(".env."):
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def read_text_lines(path: Path, max_size: int) -> list[str] | None:
    try:
        if path.stat().st_size > max_size:
            return None
        with path.open("rb") as handle:
            data = handle.read()
    except OSError:
        return None

    if b"\x00" in data[:4096]:
        return None

    text = data.decode("utf-8", errors="replace")
    return text.splitlines()


def find_line_containing(lines: list[str], needle: str) -> int | None:
    for index, line in enumerate(lines, start=1):
        if needle in line:
            return index
    return None


def normalized_relpath(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return str(rel).replace(os.sep, "/")
