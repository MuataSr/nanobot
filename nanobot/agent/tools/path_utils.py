"""Shared path helpers for workspace-scoped tools."""

from pathlib import Path, PurePath

from nanobot.config.paths import get_media_dir
from nanobot.security.workspace_policy import (
    is_path_within,
    resolve_allowed_path,
)

# Glob patterns for sensitive system files (SSH keys, credentials, etc.).
SENSITIVE_PATTERNS: list[str] = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/ssh/*",
    "/etc/gshadow",
    "/root/.ssh/*",
    "/home/*/.ssh/*",
    "*.pem",
    "*.key",
]


def is_sensitive_path(resolved_path: Path) -> bool:
    """Return True if *resolved_path* matches any SENSITIVE_PATTERNS entry."""
    pure = PurePath(resolved_path)
    return any(pure.match(pat) for pat in SENSITIVE_PATTERNS)


def is_under(path: Path, directory: Path) -> bool:
    """Return True when path resolves under directory."""
    return is_path_within(path, directory)


def resolve_workspace_path(
    path: str,
    workspace: Path | None = None,
    allowed_dir: Path | None = None,
    extra_allowed_dirs: list[Path] | None = None,
    extra_allowed_files: list[Path] | None = None,
    include_media_dir: bool = True,
) -> Path:
    """Resolve path against workspace and enforce allowed directory containment."""
    media_roots = [get_media_dir()] if include_media_dir else []
    extra_roots = [*media_roots, *(extra_allowed_dirs or [])] if allowed_dir else None
    return resolve_allowed_path(
        path,
        workspace=workspace,
        allowed_root=allowed_dir,
        extra_allowed_roots=extra_roots,
        extra_allowed_files=extra_allowed_files,
    )
