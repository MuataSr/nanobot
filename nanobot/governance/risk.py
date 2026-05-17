"""Risk classifier for governance decisions.

Takes a tool name + arguments, classifies the risk level in <5ms using
pre-compiled regex patterns from risk_rules.py.  Returns a
GovernanceDecision with the action the permission engine should take.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nanobot.governance.risk_rules import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    RULES,
)


class RiskLevel(str, Enum):
    """Risk severity levels."""

    LOW = LOW
    MEDIUM = MEDIUM
    HIGH = HIGH
    CRITICAL = CRITICAL


class GovernanceAction(str, Enum):
    """Actions the permission engine can take."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(slots=True)
class GovernanceDecision:
    """Result of a governance risk classification + permission check."""

    action: GovernanceAction
    risk_level: RiskLevel
    rule_id: str
    reason: str
    tool_name: str
    input_hash: str  # SHA256 of input for audit (never raw input)
    timestamp: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == GovernanceAction.DENY


def _tool_family(tool_name: str) -> list[str]:
    """Map a nanobot tool name to one or more rule families.

    Returns a list because some tools (like exec) need checking against
    multiple families.

    Unknown tools get a default classification that at least checks
    for secrets and protects nanobot internals — no tool should ever
    pass through with zero risk scrutiny.
    """
    mapping: dict[str, list[str]] = {
        "exec": ["bash", "secrets", "nanobot_protect"],
        "shell": ["bash", "secrets", "nanobot_protect"],
        "edit_file": ["file_write", "secrets", "nanobot_protect"],
        "write_file": ["file_write", "secrets", "nanobot_protect"],
        "read_file": ["sensitive_read", "secrets"],
    }
    return mapping.get(tool_name, ["secrets", "nanobot_protect"])


def _extract_target_path(arguments: dict[str, Any]) -> str:
    """Best-effort extraction of the file path from tool arguments."""
    for key in ("path", "file_path", "filename", "working_dir", "dest"):
        val = arguments.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


class RiskClassifier:
    """Classify tool calls by risk level using pre-compiled patterns.

    All patterns are compiled at import time in risk_rules.py so each
    classify() call is just regex matching — no compilation overhead.
    """

    def __init__(self, extra_rules: dict[str, dict[str, list]] | None = None) -> None:
        # Merge any user-provided rules on top of built-ins
        self._rules: dict[str, dict[str, list]] = {}
        for family, levels in RULES.items():
            self._rules[family] = dict(levels)
        if extra_rules:
            for family, levels in extra_rules.items():
                if family not in self._rules:
                    self._rules[family] = {}
                for level, patterns in levels.items():
                    if level not in self._rules[family]:
                        self._rules[family][level] = []
                    self._rules[family][level].extend(patterns)

    def classify(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[RiskLevel, str, str]:
        """Classify a tool call.

        Returns (risk_level, rule_id, reason).

        If no patterns match, returns (LOW, "", "no matching risk rule").
        """
        families = _tool_family(tool_name)
        if not families:
            return RiskLevel.LOW, "", "no rules for tool"

        # For bash/exec, check the command text
        command_text = ""
        if tool_name in ("exec", "shell"):
            command_text = arguments.get("command", "")
            if not isinstance(command_text, str):
                command_text = str(command_text)

        # For file tools, check the path
        target_path = _extract_target_path(arguments)

        # Also build a combined content string for secret detection
        content_str = command_text + " " + " ".join(
            str(v) for v in arguments.values() if isinstance(v, str)
        )

        # Check families in priority order: critical → high → medium → low
        for risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
            for family in families:
                level_rules = self._rules.get(family, {}).get(risk_level.value, [])
                for pattern, rule_id, reason in level_rules:
                    # Bash patterns check against the command text
                    if family in ("bash", "nanobot_protect"):
                        text = command_text or content_str
                        if text and pattern.search(text):
                            return risk_level, rule_id, reason
                    # File write patterns check against the target path
                    elif family == "file_write":
                        if target_path and pattern.search(target_path):
                            return risk_level, rule_id, reason
                    # Secret patterns check against all content
                    elif family == "secrets":
                        if content_str and pattern.search(content_str):
                            return risk_level, rule_id, reason
                    # Sensitive read patterns check against the target path
                    elif family == "sensitive_read":
                        if target_path and pattern.search(target_path):
                            return risk_level, rule_id, reason

        return RiskLevel.LOW, "", "no matching risk rule"
