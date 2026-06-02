"""JSONL audit logger for governance decisions.

Append-only log with:
- SHA256 hash of tool input (never raw commands — could contain secrets)
- One JSON line per governance decision
- Auto-rotation at configurable size (default 10MB)
- Zero dependencies beyond stdlib
"""

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger


# Default audit log location
_DEFAULT_AUDIT_PATH = Path.home() / ".nanobot" / "audit.jsonl"


def _iso_now() -> str:
    """UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_input(data: Any) -> str:
    """SHA256 hash of arbitrary data for audit logging.

    We hash rather than log raw input because tool arguments can contain
    secrets, passwords, API keys, etc.
    """
    raw = json.dumps(data, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only JSONL audit logger with auto-rotation.

    Usage:
        auditor = AuditLogger()
        auditor.log(tool="exec", action="deny", risk="critical",
                     rule="bash/rm-root", reason="Blocked...",
                     input_hash="sha256:abc123")

    Output format (one line per entry):
        {"ts":"2026-05-17T13:28:00+00:00","tool":"exec","action":"deny",
         "risk":"critical","rule":"bash/rm-root","reason":"Blocked...",
         "input_hash":"sha256:abc123"}
    """

    def __init__(
        self,
        path: str | Path | None = None,
        enabled: bool = True,
        max_size_mb: float = 10.0,
    ) -> None:
        self._path = Path(path) if path else _DEFAULT_AUDIT_PATH
        self._enabled = enabled
        self._max_bytes = int(max_size_mb * 1024 * 1024)
        self._write_count = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def path(self) -> Path:
        return self._path

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def log(
        self,
        tool: str,
        action: str,
        risk: str,
        rule: str,
        reason: str,
        input_hash: str,
    ) -> None:
        """Write a single audit entry."""
        if not self._enabled:
            return

        self._rotate_if_needed()

        entry = {
            "ts": _iso_now(),
            "tool": tool,
            "action": action,
            "risk": risk,
            "rule": rule,
            "reason": reason,
            "input_hash": input_hash,
        }

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._write_count += 1
        except OSError as exc:
            # Audit logging failure must NOT break the agent
            logger.warning("Audit log write failed: {}", exc)

    def log_decision(self, decision: Any) -> None:
        """Log a GovernanceDecision object directly."""
        self.log(
            tool=decision.tool_name,
            action=decision.action.value,
            risk=decision.risk_level.value,
            rule=decision.rule_id,
            reason=decision.reason,
            input_hash=decision.input_hash,
        )

    def _rotate_if_needed(self) -> None:
        """Rotate the audit log if it exceeds max_size_mb."""
        if not self._path.exists():
            return
        try:
            size = self._path.stat().st_size
        except OSError:
            return

        if size < self._max_bytes:
            return

        # Rotate: audit.jsonl → audit.jsonl.1 (overwrite previous rotated)
        rotated = self._path.with_suffix(".jsonl.1")
        try:
            self._path.replace(rotated)
            logger.info("Audit log rotated: {} → {}", self._path, rotated)
        except OSError as exc:
            logger.warning("Audit log rotation failed: {}", exc)

    def read_tail(self, n: int = 20) -> list[dict[str, Any]]:
        """Read the last *n* audit entries (for debugging/preflight)."""
        if not self._path.exists():
            return []
        try:
            lines = self._path.read_text(encoding="utf-8").strip().split("\n")
            entries = []
            for line in lines[-n:]:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return entries
        except OSError:
            return []

    @property
    def entry_count(self) -> int:
        """Count entries in the current log file."""
        if not self._path.exists():
            return 0
        try:
            return sum(
                1 for line in self._path.read_text(encoding="utf-8").split("\n")
                if line.strip()
            )
        except OSError:
            return 0

    def stats(self) -> dict[str, Any]:
        """Return audit log statistics."""
        return {
            "enabled": self._enabled,
            "path": str(self._path),
            "entries": self.entry_count,
            "writes_this_session": self._write_count,
            "max_size_mb": self._max_bytes / (1024 * 1024),
        }
