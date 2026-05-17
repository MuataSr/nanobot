"""Permission engine for governance decisions.

8-level priority chain that takes a RiskClassifier result + Constitution
configuration and produces a final GovernanceDecision (allow/ask/deny).

Priority order (highest wins):
  1. Constitution deny_patterns/deny_paths match → DENY (absolute)
  2. Risk level >= threshold → threshold action (deny/ask per config)
  3. Constitution allow_patterns match → ALLOW
  4. Tool policy = "locked" → DENY
  5. Tool policy = "open" → ALLOW
  6. Tool policy = "restricted" + no deny match → ALLOW
  7. Unknown tool → default action (ask/deny/allow per config)
  8. Error during evaluation → on_error action (deny per config — fail-closed)

This module is the bridge between risk.py (classification) and
constitution.py (configuration), producing the final decision that
runner.py and shell.py consume.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from nanobot.governance.audit import AuditLogger, hash_input
from nanobot.governance.constitution import Constitution, ToolPermission
from nanobot.governance.risk import (
    GovernanceAction,
    GovernanceDecision,
    RiskClassifier,
    RiskLevel,
)


class GovernanceDenied(Exception):
    """Raised when a tool call is blocked by governance.

    The runner catches this and returns the denial reason to the model
    so it knows not to retry the same command.
    """

    def __init__(self, decision: GovernanceDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


class PermissionEngine:
    """Evaluate governance decisions using constitution + risk classification.

    Usage:
        engine = PermissionEngine()  # uses default constitution
        decision = engine.check("exec", {"command": "rm -rf /"})
        if decision.blocked:
            raise GovernanceDenied(decision)
    """

    def __init__(
        self,
        constitution: Constitution | None = None,
        classifier: RiskClassifier | None = None,
        auditor: AuditLogger | None = None,
    ) -> None:
        self._constitution = constitution or Constitution.default()
        self._classifier = classifier or RiskClassifier()
        self._auditor = auditor  # None = no auditing
        self._deny_cache: dict[str, list[re.Pattern[str]]] = {}
        self._allow_cache: dict[str, list[re.Pattern[str]]] = {}
        self._deny_path_cache: dict[str, list[re.Pattern[str]]] = {}
        self._ask_path_cache: dict[str, list[re.Pattern[str]]] = {}
        self._build_pattern_caches()

    @property
    def constitution(self) -> Constitution:
        return self._constitution

    def _build_pattern_caches(self) -> None:
        """Pre-compile constitution regex patterns for fast matching."""
        for tool_name, perm in self._constitution.permissions.items():
            key = tool_name.lower().replace("-", "_")
            self._deny_cache[key] = [
                re.compile(p) for p in perm.deny_patterns
            ]
            self._allow_cache[key] = [
                re.compile(p) for p in perm.allow_patterns
            ]
            self._deny_path_cache[key] = [
                re.compile(p) for p in perm.deny_paths
            ]
            self._ask_path_cache[key] = [
                re.compile(p) for p in perm.ask_paths
            ]

    def _normalize_tool(self, tool_name: str) -> str:
        return tool_name.lower().replace("-", "_")

    def _match_patterns(
        self, text: str, patterns: list[re.Pattern[str]]
    ) -> re.Pattern[str] | None:
        """Return the first matching pattern, or None."""
        for p in patterns:
            if p.search(text):
                return p
        return None

    def _extract_text(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Extract the primary text to check for command patterns."""
        for key in ("command", "content", "text"):
            val = arguments.get(key)
            if isinstance(val, str) and val:
                return val
        return ""

    def _extract_path(self, arguments: dict[str, Any]) -> str:
        """Extract the file path from arguments."""
        for key in ("path", "file_path", "filename", "dest"):
            val = arguments.get(key)
            if isinstance(val, str) and val:
                return val
        return ""

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> GovernanceDecision:
        """Evaluate a tool call against governance rules.

        Returns a GovernanceDecision with the final action (allow/ask/deny).
        """
        input_hash = hash_input({"tool": tool_name, **arguments})
        norm_tool = self._normalize_tool(tool_name)

        try:
            decision = self._evaluate(tool_name, norm_tool, arguments, input_hash)
        except Exception as exc:
            # Priority 8: error during evaluation → fail-closed
            logger.exception("Governance evaluation error for tool={}", tool_name)
            decision = GovernanceDecision(
                action=GovernanceAction(self._constitution.defaults.on_error),
                risk_level=RiskLevel.LOW,
                rule_id="governance/error",
                reason=f"Governance evaluation failed: {exc}",
                tool_name=tool_name,
                input_hash=input_hash,
            )

        # Audit log the decision (regardless of outcome)
        if self._auditor:
            self._auditor.log_decision(decision)

        return decision

    def _evaluate(
        self,
        tool_name: str,
        norm_tool: str,
        arguments: dict[str, Any],
        input_hash: str,
    ) -> GovernanceDecision:
        """Run the 8-level priority chain."""

        text = self._extract_text(tool_name, arguments)
        path = self._extract_path(arguments)

        # Step 1: Classify risk
        risk_level, rule_id, reason = self._classifier.classify(
            tool_name, arguments
        )

        # Get tool-specific permission config
        perm = self._constitution.get_tool_permission(tool_name)

        # --- Priority 1: Constitution deny_patterns / deny_paths ---
        deny_patterns = self._deny_cache.get(norm_tool, [])
        deny_paths = self._deny_path_cache.get(norm_tool, [])

        if text and deny_patterns:
            matched = self._match_patterns(text, deny_patterns)
            if matched:
                return GovernanceDecision(
                    action=GovernanceAction.DENY,
                    risk_level=risk_level,
                    rule_id=f"constitution/deny_pattern:{matched.pattern}",
                    reason=f"Blocked by constitution deny pattern",
                    tool_name=tool_name,
                    input_hash=input_hash,
                )

        if path and deny_paths:
            matched = self._match_patterns(path, deny_paths)
            if matched:
                return GovernanceDecision(
                    action=GovernanceAction.DENY,
                    risk_level=risk_level,
                    rule_id=f"constitution/deny_path:{matched.pattern}",
                    reason=f"Blocked by constitution deny path",
                    tool_name=tool_name,
                    input_hash=input_hash,
                )

        # --- Priority 2: Risk level threshold ---
        risk_action_str = self._constitution.risk_action(risk_level.value)
        if risk_action_str == "deny":
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                risk_level=risk_level,
                rule_id=rule_id or f"risk/{risk_level.value}",
                reason=reason or f"Risk level {risk_level.value} exceeds threshold",
                tool_name=tool_name,
                input_hash=input_hash,
            )
        if risk_action_str == "ask":
            # "ask" is informational for now — log it but allow
            # Future: could pause for human approval
            pass

        # --- Priority 3: Constitution allow_patterns ---
        allow_patterns = self._allow_cache.get(norm_tool, [])
        if text and allow_patterns:
            matched = self._match_patterns(text, allow_patterns)
            if matched:
                return GovernanceDecision(
                    action=GovernanceAction.ALLOW,
                    risk_level=risk_level,
                    rule_id=f"constitution/allow_pattern:{matched.pattern}",
                    reason="Allowed by constitution allow pattern",
                    tool_name=tool_name,
                    input_hash=input_hash,
                )

        # --- Priority 4-6: Tool policy ---
        if perm.policy == "locked":
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                risk_level=risk_level,
                rule_id="policy/locked",
                reason=f"Tool {tool_name} is locked by policy",
                tool_name=tool_name,
                input_hash=input_hash,
            )

        if perm.policy == "open":
            return GovernanceDecision(
                action=GovernanceAction.ALLOW,
                risk_level=risk_level,
                rule_id=rule_id or "policy/open",
                reason=reason or "Allowed by open tool policy",
                tool_name=tool_name,
                input_hash=input_hash,
            )

        if perm.policy == "restricted":
            # Check ask_paths for informational logging
            ask_paths = self._ask_path_cache.get(norm_tool, [])
            if path and ask_paths:
                matched = self._match_patterns(path, ask_paths)
                if matched:
                    # Still allow, but tag it as "ask" for audit visibility
                    return GovernanceDecision(
                        action=GovernanceAction.ALLOW,
                        risk_level=risk_level,
                        rule_id=f"constitution/ask_path:{matched.pattern}",
                        reason=f"Sensitive path (ask) — allowed but logged",
                        tool_name=tool_name,
                        input_hash=input_hash,
                    )

            # Restricted with no deny match → allow
            return GovernanceDecision(
                action=GovernanceAction.ALLOW,
                risk_level=risk_level,
                rule_id=rule_id or "policy/restricted",
                reason=reason or "Allowed by restricted policy (no deny match)",
                tool_name=tool_name,
                input_hash=input_hash,
            )

        # --- Priority 7: Unknown tool ---
        default_action = GovernanceAction(self._constitution.defaults.unknown_tool)
        return GovernanceDecision(
            action=default_action,
            risk_level=risk_level,
            rule_id="default/unknown_tool",
            reason=f"Unknown tool {tool_name} — default action: {default_action.value}",
            tool_name=tool_name,
            input_hash=input_hash,
        )

    def summary(self) -> dict[str, Any]:
        """Return permission engine status for preflight."""
        return {
            "constitution": self._constitution.summary(),
            "audit": self._auditor.stats() if self._auditor else {"enabled": False},
        }
