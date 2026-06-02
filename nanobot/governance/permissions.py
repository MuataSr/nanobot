"""Permission engine for governance decisions.

8-level priority chain that takes a RiskClassifier result + Constitution
configuration and produces a final GovernanceDecision (allow/ask/deny).

Each priority level is an independent Rule object. The chain executes in
order; the first Rule to return a non-None GovernanceDecision wins.

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
from abc import ABC, abstractmethod
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


# ── Shared evaluation context passed through the rule chain ────────


class _EvalContext:
    """Pre-computed data shared across all rules in a single evaluation."""

    __slots__ = (
        "tool_name",
        "norm_tool",
        "arguments",
        "input_hash",
        "text",
        "path",
        "risk_level",
        "rule_id",
        "reason",
        "perm",
    )

    def __init__(
        self,
        tool_name: str,
        norm_tool: str,
        arguments: dict[str, Any],
        input_hash: str,
        text: str,
        path: str,
        risk_level: RiskLevel,
        rule_id: str,
        reason: str,
        perm: ToolPermission,
    ) -> None:
        self.tool_name = tool_name
        self.norm_tool = norm_tool
        self.arguments = arguments
        self.input_hash = input_hash
        self.text = text
        self.path = path
        self.risk_level = risk_level
        self.rule_id = rule_id
        self.reason = reason
        self.perm = perm


# ── Abstract rule base ─────────────────────────────────────────────


class Rule(ABC):
    """A single priority level in the governance evaluation chain.

    Returns a GovernanceDecision to stop the chain, or None to pass
    to the next rule.
    """

    @abstractmethod
    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        ...


# ── Concrete rules (one per priority level) ────────────────────────


class ConstitutionDenyRule(Rule):
    """Priority 1: Constitution deny_patterns / deny_paths → DENY."""

    def __init__(
        self,
        deny_cache: dict[str, list[re.Pattern[str]]],
        deny_path_cache: dict[str, list[re.Pattern[str]]],
    ) -> None:
        self._deny_cache = deny_cache
        self._deny_path_cache = deny_path_cache

    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        deny_patterns = self._deny_cache.get(ctx.norm_tool, [])
        if ctx.text and deny_patterns:
            matched = _match_patterns(ctx.text, deny_patterns)
            if matched:
                return GovernanceDecision(
                    action=GovernanceAction.DENY,
                    risk_level=ctx.risk_level,
                    rule_id=f"constitution/deny_pattern:{matched.pattern}",
                    reason="Blocked by constitution deny pattern",
                    tool_name=ctx.tool_name,
                    input_hash=ctx.input_hash,
                )

        deny_paths = self._deny_path_cache.get(ctx.norm_tool, [])
        if ctx.path and deny_paths:
            matched = _match_patterns(ctx.path, deny_paths)
            if matched:
                return GovernanceDecision(
                    action=GovernanceAction.DENY,
                    risk_level=ctx.risk_level,
                    rule_id=f"constitution/deny_path:{matched.pattern}",
                    reason="Blocked by constitution deny path",
                    tool_name=ctx.tool_name,
                    input_hash=ctx.input_hash,
                )

        return None


class RiskThresholdRule(Rule):
    """Priority 2: Risk level >= threshold → deny or ask."""

    def __init__(self, constitution: Constitution) -> None:
        self._constitution = constitution

    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        risk_action_str = self._constitution.risk_action(ctx.risk_level.value)

        if risk_action_str == "deny":
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                risk_level=ctx.risk_level,
                rule_id=ctx.rule_id or f"risk/{ctx.risk_level.value}",
                reason=ctx.reason or f"Risk level {ctx.risk_level.value} exceeds threshold",
                tool_name=ctx.tool_name,
                input_hash=ctx.input_hash,
            )

        if risk_action_str == "ask":
            return GovernanceDecision(
                action=GovernanceAction.ASK,
                risk_level=ctx.risk_level,
                rule_id=ctx.rule_id or f"risk/{ctx.risk_level.value}",
                reason=ctx.reason or f"Risk level {ctx.risk_level.value} requires confirmation",
                tool_name=ctx.tool_name,
                input_hash=ctx.input_hash,
            )

        return None


class ConstitutionAllowRule(Rule):
    """Priority 3: Constitution allow_patterns → ALLOW."""

    def __init__(
        self,
        allow_cache: dict[str, list[re.Pattern[str]]],
    ) -> None:
        self._allow_cache = allow_cache

    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        allow_patterns = self._allow_cache.get(ctx.norm_tool, [])
        if ctx.text and allow_patterns:
            matched = _match_patterns(ctx.text, allow_patterns)
            if matched:
                return GovernanceDecision(
                    action=GovernanceAction.ALLOW,
                    risk_level=ctx.risk_level,
                    rule_id=f"constitution/allow_pattern:{matched.pattern}",
                    reason="Allowed by constitution allow pattern",
                    tool_name=ctx.tool_name,
                    input_hash=ctx.input_hash,
                )
        return None


class PolicyLockedRule(Rule):
    """Priority 4: Tool policy = 'locked' → DENY."""

    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        if ctx.perm.policy == "locked":
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                risk_level=ctx.risk_level,
                rule_id="policy/locked",
                reason=f"Tool {ctx.tool_name} is locked by policy",
                tool_name=ctx.tool_name,
                input_hash=ctx.input_hash,
            )
        return None


class PolicyOpenRule(Rule):
    """Priority 5: Tool policy = 'open' → ALLOW."""

    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        if ctx.perm.policy == "open":
            return GovernanceDecision(
                action=GovernanceAction.ALLOW,
                risk_level=ctx.risk_level,
                rule_id=ctx.rule_id or "policy/open",
                reason=ctx.reason or "Allowed by open tool policy",
                tool_name=ctx.tool_name,
                input_hash=ctx.input_hash,
            )
        return None


class PolicyRestrictedRule(Rule):
    """Priority 6: Tool policy = 'restricted' → check ask_paths, then ALLOW."""

    def __init__(
        self,
        ask_path_cache: dict[str, list[re.Pattern[str]]],
    ) -> None:
        self._ask_path_cache = ask_path_cache

    def check(self, ctx: _EvalContext) -> GovernanceDecision | None:
        if ctx.perm.policy == "restricted":
            ask_paths = self._ask_path_cache.get(ctx.norm_tool, [])
            if ctx.path and ask_paths:
                matched = _match_patterns(ctx.path, ask_paths)
                if matched:
                    return GovernanceDecision(
                        action=GovernanceAction.ALLOW,
                        risk_level=ctx.risk_level,
                        rule_id=f"constitution/ask_path:{matched.pattern}",
                        reason="Sensitive path (ask) — allowed but logged",
                        tool_name=ctx.tool_name,
                        input_hash=ctx.input_hash,
                    )

            return GovernanceDecision(
                action=GovernanceAction.ALLOW,
                risk_level=ctx.risk_level,
                rule_id=ctx.rule_id or "policy/restricted",
                reason=ctx.reason or "Allowed by restricted policy (no deny match)",
                tool_name=ctx.tool_name,
                input_hash=ctx.input_hash,
            )
        return None


class UnknownToolRule(Rule):
    """Priority 7: Unknown tool → default action from constitution."""

    def __init__(self, constitution: Constitution) -> None:
        self._constitution = constitution

    def check(self, ctx: _EvalContext) -> GovernanceDecision:
        default_action = GovernanceAction(self._constitution.defaults.unknown_tool)
        return GovernanceDecision(
            action=default_action,
            risk_level=ctx.risk_level,
            rule_id="default/unknown_tool",
            reason=f"Unknown tool {ctx.tool_name} — default action: {default_action.value}",
            tool_name=ctx.tool_name,
            input_hash=ctx.input_hash,
        )


# ── Helper ─────────────────────────────────────────────────────────


def _match_patterns(
    text: str, patterns: list[re.Pattern[str]]
) -> re.Pattern[str] | None:
    """Return the first matching pattern, or None."""
    for p in patterns:
        if p.search(text):
            return p
    return None


def _extract_text(tool_name: str, arguments: dict[str, Any]) -> str:
    """Extract the primary text to check for command patterns."""
    for key in ("command", "content", "text"):
        val = arguments.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def _extract_path(arguments: dict[str, Any]) -> str:
    """Extract the file path from arguments."""
    for key in ("path", "file_path", "filename", "dest"):
        val = arguments.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


# ── Exception ──────────────────────────────────────────────────────


class GovernanceDenied(Exception):
    """Raised when a tool call is blocked by governance.

    The runner catches this and returns the denial reason to the model
    so it knows not to retry the same command.
    """

    def __init__(self, decision: GovernanceDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


# ── Engine ─────────────────────────────────────────────────────────


class PermissionEngine:
    """Evaluate governance decisions using constitution + risk classification.

    The engine builds a chain of Rule objects, each representing one priority
    level. The chain runs in order; the first rule to return a non-None
    GovernanceDecision wins.

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

        # Build pattern caches
        self._deny_cache: dict[str, list[re.Pattern[str]]] = {}
        self._allow_cache: dict[str, list[re.Pattern[str]]] = {}
        self._deny_path_cache: dict[str, list[re.Pattern[str]]] = {}
        self._ask_path_cache: dict[str, list[re.Pattern[str]]] = {}
        self._build_pattern_caches()

        # Build the rule chain (order matters!)
        self._rules: list[Rule] = [
            ConstitutionDenyRule(self._deny_cache, self._deny_path_cache),
            RiskThresholdRule(self._constitution),
            ConstitutionAllowRule(self._allow_cache),
            PolicyLockedRule(),
            PolicyOpenRule(),
            PolicyRestrictedRule(self._ask_path_cache),
            UnknownToolRule(self._constitution),
        ]

    @property
    def constitution(self) -> Constitution:
        return self._constitution

    @property
    def rules(self) -> list[Rule]:
        """Expose the rule chain for inspection/testing."""
        return list(self._rules)

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

    def _build_context(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        input_hash: str,
    ) -> _EvalContext:
        """Classify risk and assemble the shared evaluation context."""
        norm_tool = tool_name.lower().replace("-", "_")
        text = _extract_text(tool_name, arguments)
        path = _extract_path(arguments)
        risk_level, rule_id, reason = self._classifier.classify(
            tool_name, arguments
        )
        perm = self._constitution.get_tool_permission(tool_name)

        return _EvalContext(
            tool_name=tool_name,
            norm_tool=norm_tool,
            arguments=arguments,
            input_hash=input_hash,
            text=text,
            path=path,
            risk_level=risk_level,
            rule_id=rule_id,
            reason=reason,
            perm=perm,
        )

    def _evaluate(self, ctx: _EvalContext) -> GovernanceDecision:
        """Run the rule chain; first non-None result wins."""
        for rule in self._rules:
            decision = rule.check(ctx)
            if decision is not None:
                return decision

        # Should never reach here — UnknownToolRule always returns
        return GovernanceDecision(
            action=GovernanceAction.DENY,
            risk_level=ctx.risk_level,
            rule_id="governance/no_rule_matched",
            reason="No governance rule matched — fail-closed",
            tool_name=ctx.tool_name,
            input_hash=ctx.input_hash,
        )

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> GovernanceDecision:
        """Evaluate a tool call against governance rules.

        Returns a GovernanceDecision with the final action (allow/ask/deny).
        """
        input_hash = hash_input({"tool": tool_name, **arguments})

        try:
            ctx = self._build_context(tool_name, arguments, input_hash)
            decision = self._evaluate(ctx)
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

    def summary(self) -> dict[str, Any]:
        """Return permission engine status for preflight."""
        return {
            "constitution": self._constitution.summary(),
            "audit": self._auditor.stats() if self._auditor else {"enabled": False},
        }
