"""Constitution loader and pydantic models.

Loads a constitution.yaml file (or returns safe defaults) and exposes
a typed Constitution object that the governance engine uses for
permission decisions.

Auto-discovery order:
  1. Explicit path from config.json (hooks.config.governance.constitution_path)
  2. constitution.yaml in workspace root
  3. ~/.nanobot/constitution.yaml (global)
  4. Built-in defaults (no file needed — zero behavior change)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Pydantic models for constitution.yaml structure
# ---------------------------------------------------------------------------

class IdentityBoundary(BaseModel):
    """A single identity boundary declaration."""

    rule: str
    enforcement: Literal["prompt", "hook", "both"] = "hook"
    reason: str = ""


class IdentityConfig(BaseModel):
    """Agent identity section."""

    name: str = "nanobot"
    boundaries: list[str] = Field(default_factory=lambda: [
        "Only modify files within workspace",
        "Never expose secrets or API keys",
        "Ask before destructive operations",
    ])


class ToolPermission(BaseModel):
    """Per-tool permission configuration."""

    policy: Literal["open", "restricted", "locked"] = "restricted"
    deny_patterns: list[str] = Field(default_factory=list)
    allow_patterns: list[str] = Field(default_factory=list)
    deny_paths: list[str] = Field(default_factory=list)
    ask_paths: list[str] = Field(default_factory=list)


class DefaultPermissions(BaseModel):
    """Default permission settings."""

    unknown_tool: Literal["ask", "allow", "deny"] = "ask"
    on_error: Literal["deny", "allow"] = "deny"  # fail-closed


class RiskThresholds(BaseModel):
    """Risk level → action mapping."""

    low: Literal["allow", "ask", "deny"] = "allow"
    medium: Literal["allow", "ask", "deny"] = "allow"
    high: Literal["allow", "ask", "deny"] = "deny"
    critical: Literal["allow", "ask", "deny"] = "deny"


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    enabled: bool = True
    output: str = ""  # empty = default location (~/.nanobot/audit.jsonl)
    max_size_mb: float = 10.0


class Constitution(BaseModel):
    """Root constitution model.

    Validates the entire constitution.yaml structure.  Use
    ``Constitution.load()`` for auto-discovery or
    ``Constitution.default()`` for safe built-in defaults.
    """

    version: str = "1.0"
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    permissions: dict[str, ToolPermission] = Field(default_factory=dict)
    defaults: DefaultPermissions = Field(default_factory=DefaultPermissions)
    risk: RiskThresholds = Field(default_factory=RiskThresholds)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    # Source tracking (not in YAML — set during load)
    _source_path: str | None = None

    @property
    def source_path(self) -> str | None:
        return self._source_path

    @property
    def tool_count(self) -> int:
        """Number of tools with explicit permission overrides."""
        return len(self.permissions)

    @property
    def rule_count(self) -> int:
        """Total number of deny/allow patterns + deny/ask paths."""
        count = 0
        for tool_perm in self.permissions.values():
            count += (
                len(tool_perm.deny_patterns)
                + len(tool_perm.allow_patterns)
                + len(tool_perm.deny_paths)
                + len(tool_perm.ask_paths)
            )
        return count

    def get_tool_permission(self, tool_name: str) -> ToolPermission:
        """Get permission config for a tool, falling back to defaults."""
        # Normalize tool names
        normalized = tool_name.lower().replace("-", "_")
        # Check both original and normalized
        if tool_name in self.permissions:
            return self.permissions[tool_name]
        if normalized in self.permissions:
            return self.permissions[normalized]
        # Default policy for known tools
        defaults: dict[str, ToolPermission] = {
            "exec": ToolPermission(policy="restricted"),
            "shell": ToolPermission(policy="restricted"),
            "edit_file": ToolPermission(policy="restricted"),
            "write_file": ToolPermission(policy="restricted"),
            "read_file": ToolPermission(policy="open"),
        }
        return defaults.get(tool_name, ToolPermission(policy="restricted"))

    def risk_action(self, risk_level: str) -> str:
        """Map a risk level string to its configured action."""
        mapping = {
            "low": self.risk.low,
            "medium": self.risk.medium,
            "high": self.risk.high,
            "critical": self.risk.critical,
        }
        return mapping.get(risk_level, "deny")

    # -----------------------------------------------------------------------
    # Factory methods
    # -----------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> Constitution:
        """Load constitution from YAML, with auto-discovery.

        If *path* is provided, load from that file.
        Otherwise, search in order:
          1. constitution.yaml in CWD
          2. ~/.nanobot/constitution.yaml
        If nothing found, return built-in defaults.
        """
        if path is not None:
            p = Path(path).expanduser().resolve()
            if p.is_file():
                return cls._from_file(p)
            logger.warning("Constitution file not found: {} — using defaults", p)
            return cls.default()

        # Auto-discovery
        candidates = [
            Path.cwd() / "constitution.yaml",
            Path.home() / ".nanobot" / "constitution.yaml",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return cls._from_file(candidate)

        logger.debug("No constitution.yaml found — using built-in defaults")
        return cls.default()

    @classmethod
    def _from_file(cls, path: Path) -> Constitution:
        """Parse and validate a constitution YAML file."""
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
            if not isinstance(data, dict):
                logger.warning(
                    "Constitution YAML is not a mapping (got {}) — using defaults",
                    type(data).__name__,
                )
                return cls.default()
            constitution = cls.model_validate(data)
            constitution._source_path = str(path)
            logger.info(
                "Constitution loaded from {} ({} tools, {} rules)",
                path,
                constitution.tool_count,
                constitution.rule_count,
            )
            return constitution
        except (OSError, yaml.YAMLError, ValueError) as exc:
            logger.error("Failed to load constitution from {}: {} — using defaults", path, exc)
            return cls.default()
        except Exception as exc:
            logger.exception("Unexpected error loading constitution from {}", path)
            raise

    @classmethod
    def default(cls) -> Constitution:
        """Return safe built-in defaults (no file needed)."""
        return cls(
            version="1.0",
            identity=IdentityConfig(),
            defaults=DefaultPermissions(),  # unknown_tool=ask, on_error=deny
            risk=RiskThresholds(),  # critical/high=deny, medium/low=allow
            audit=AuditConfig(enabled=True),
        )

    def summary(self) -> dict[str, Any]:
        """Return a human-readable summary for preflight reporting."""
        return {
            "version": self.version,
            "source": self._source_path or "built-in defaults",
            "identity_name": self.identity.name,
            "identity_boundaries": len(self.identity.boundaries),
            "tool_overrides": self.tool_count,
            "total_rules": self.rule_count,
            "risk_thresholds": {
                "critical": self.risk.critical,
                "high": self.risk.high,
                "medium": self.risk.medium,
                "low": self.risk.low,
            },
            "defaults": {
                "unknown_tool": self.defaults.unknown_tool,
                "on_error": self.defaults.on_error,
            },
            "audit_enabled": self.audit.enabled,
        }
