"""Extract useful context from a source-code repository."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    "target",
    "coverage",
}

DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
}

CONFIGURATION_FILES = {
    ".env",
    ".env.example",
    ".env.sample",
    "config.yaml",
    "config.yml",
    "config.json",
    "application.yaml",
    "application.yml",
    "application.properties",
    "settings.py",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yaml",
    "compose.yml",
}

FRAMEWORK_HINTS = {
    "fastapi": ["fastapi"],
    "django": ["django"],
    "flask": ["flask"],
    "next.js": ["next.config.js", "next.config.ts", "next.config.mjs"],
    "react": ["react"],
    "express": ["express"],
    "spring": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "streamlit": ["streamlit"],
}


def _safe_read_text(path: Path, max_chars: int = 20_000) -> str | None:
    """Read a text file safely, limiting its size."""

    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            return file.read(max_chars)
    except (OSError, PermissionError):
        return None


def _relative_path(path: Path, root: Path) -> str:
    """Return a normalized repository-relative path."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def scan_repository(
    repository_path: str | Path,
    max_files: int = 5000,
    max_file_size_bytes: int = 1_000_000,
    excluded_dirs: set[str] | None = None,
) -> dict[str, Any]:
    """Scan a repository and return structured metadata.

    This function only reads files and directory names.
    It does not execute project code.
    """

    root = Path(repository_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(
            f"Repository path does not exist: {root}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Repository path is not a directory: {root}"
        )

    excluded = set(DEFAULT_EXCLUDED_DIRS)

    if excluded_dirs:
        excluded.update(excluded_dirs)

    all_files: list[Path] = []
    skipped_large_files: list[str] = []

    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in excluded
        )

        current_path = Path(current_root)

        for filename in sorted(filenames):
            path = current_path / filename

            try:
                if path.stat().st_size > max_file_size_bytes:
                    skipped_large_files.append(
                        _relative_path(path, root)
                    )
                    continue
            except OSError:
                continue

            all_files.append(path)

            if len(all_files) >= max_files:
                break

        if len(all_files) >= max_files:
            break

    file_paths = [
        _relative_path(path, root)
        for path in all_files
    ]

    dependency_files = [
        path
        for path in file_paths
        if Path(path).name.lower() in DEPENDENCY_FILES
    ]

    configuration_files = [
        path
        for path in file_paths
        if Path(path).name.lower() in CONFIGURATION_FILES
        or Path(path).name.lower().startswith(".env.")
    ]

    source_extensions = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".rs",
        ".cpp",
        ".c",
        ".cs",
        ".rb",
        ".php",
    }

    source_files = [
        path
        for path in file_paths
        if Path(path).suffix.lower() in source_extensions
    ]

    framework_hints: list[str] = []

    lower_paths = {Path(path).name.lower() for path in file_paths}

    for framework, hints in FRAMEWORK_HINTS.items():
        if any(
            hint.lower() in lower_paths
            or any(
                hint.lower() in path.lower()
                for path in dependency_files
            )
            for hint in hints
        ):
            framework_hints.append(framework)

    return {
        "repository_path": str(root),
        "file_count": len(file_paths),
        "files": file_paths,
        "source_files": source_files,
        "dependency_files": dependency_files,
        "configuration_files": configuration_files,
        "framework_hints": sorted(set(framework_hints)),
        "skipped_large_files": skipped_large_files,
        "scan_limits": {
            "max_files": max_files,
            "max_file_size_bytes": max_file_size_bytes,
        },
    }


def get_relevant_files(
    repository_context: dict[str, Any],
    keywords: list[str] | None = None,
    limit: int = 20,
) -> list[str]:
    """Select repository files relevant to investigation keywords."""

    files = repository_context.get("files", [])

    if not isinstance(files, list):
        return []

    if not keywords:
        return files[:limit]

    normalized_keywords = [
        keyword.lower()
        for keyword in keywords
        if keyword
    ]

    scored_files: list[tuple[int, str]] = []

    for file_path in files:
        path_lower = str(file_path).lower()

        score = sum(
            1
            for keyword in normalized_keywords
            if keyword in path_lower
        )

        if score:
            scored_files.append((score, str(file_path)))

    scored_files.sort(
        key=lambda item: (-item[0], item[1])
    )

    return [
        file_path
        for _, file_path in scored_files[:limit]
    ]


def extract_repository_context(
    repository_path: str | Path,
    keywords: list[str] | None = None,
) -> dict[str, Any]:
    """Build repository context for downstream detection."""

    context = scan_repository(repository_path)

    context["relevant_files"] = get_relevant_files(
        context,
        keywords=keywords,
    )

    return context


def read_repository_file(
    repository_path: str | Path,
    relative_path: str,
    max_chars: int = 20_000,
) -> str | None:
    """Read a repository file using a validated relative path.

    Rejects paths that escape the repository root.
    """

    root = Path(repository_path).expanduser().resolve()
    target = (root / relative_path).resolve()

    try:
        target.relative_to(root)
    except ValueError:
        raise ValueError(
            "Requested file is outside the repository root."
        )

    if not target.is_file():
        return None

    return _safe_read_text(target, max_chars=max_chars)


def summarize_dependency_file(
    repository_path: str | Path,
    relative_path: str,
) -> dict[str, Any]:
    """Read a dependency file and return basic metadata."""

    content = read_repository_file(
        repository_path,
        relative_path,
    )

    if content is None:
        return {
            "path": relative_path,
            "available": False,
        }

    return {
        "path": relative_path,
        "available": True,
        "content_preview": content,
        "character_count": len(content),
    }


def save_repository_context(
    context: dict[str, Any],
    output_path: str | Path,
) -> None:
    """Save repository metadata as JSON."""

    destination = Path(output_path)
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with destination.open("w", encoding="utf-8") as file:
        json.dump(
            context,
            file,
            indent=2,
            ensure_ascii=False,
        )