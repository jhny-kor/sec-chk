from __future__ import annotations

import os
from functools import lru_cache
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
    ".hcl",
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
    ".tf",
    ".tfvars",
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
    ".gitignore",
    ".htaccess",
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
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size > max_size:
        return None
    return _read_text_lines_cached(str(path), max_size, stat.st_mtime_ns, stat.st_size)


def clear_read_text_cache() -> None:
    _read_text_lines_cached.cache_clear()


@lru_cache(maxsize=4096)
def _read_text_lines_cached(path_value: str, max_size: int, mtime_ns: int, size: int) -> list[str] | None:
    del mtime_ns
    try:
        if size > max_size:
            return None
        with Path(path_value).open("rb") as handle:
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
