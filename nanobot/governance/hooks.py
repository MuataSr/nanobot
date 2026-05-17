"""GovernanceHook — config-driven tool call gate via PermissionEngine.

Registered as "governance" in the HookRegistry. Opt-in via config.json:

  "agents": {
    "defaults": {
      "hooks": {
        "enabled_hooks": ["governance"],
        "config": {
          "governance": {
            "constitution_path": "~/.nanobot/constitution.yaml"
          }
        }
      }
    }
  }

If no constitution.yaml exists, the engine uses default rules (block critical/high,
allow everything else). If governance is not in enabled_hooks, zero overhead.
"""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger

from nanobot.agent.hook import (
    AgentHook,
    ConfigurableHook,
    HookRegistry,
    ToolCallContext,
)
import yaml as _yaml  # noqa: F401 — needed for except clause

from nanobot.governance.permissions import GovernanceDenied, PermissionEngine
from nanobot.governance.constitution import Constitution
from nanobot.governance.audit import AuditLogger


@HookRegistry.register("governance")
class GovernanceHook(ConfigurableHook):
    """Gate every tool call through the governance permission engine.

    Raises GovernanceDenied inside ``before_tool_call`` to prevent the
    runner from executing the tool. The runner's error handling converts
    this into a tool result string that the model sees, so it knows not
    to retry the same dangerous command.
    """

    def __init__(self, config: dict[str, Any] | None = None, **kwargs: Any) -> None:
        super().__init__(config=config, **kwargs)
        self._reraise = True  # Governance denials must propagate

        # Build constitution from config
        constitution_path = (config or {}).get("constitution_path")
        if constitution_path:
            try:
                self._constitution = Constitution.load(constitution_path)
                logger.info("Governance: loaded constitution from {}", constitution_path)
            except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
                logger.warning("Governance: failed to load constitution from {}: {} — using defaults", constitution_path, exc)
                self._constitution = Constitution.default()
            except Exception as exc:
                logger.error("Governance: unexpected error loading constitution from {}: {!r}", constitution_path, exc)
                raise
        else:
            self._constitution = Constitution.default()

        # Build audit logger
        audit_enabled = (config or {}).get("audit_enabled", True)
        audit_path = (config or {}).get("audit_path")
        self._auditor = AuditLogger(
            path=audit_path,
            enabled=audit_enabled,
            max_size_mb=(config or {}).get("audit_max_size_mb", 10.0),
        )

        # Build permission engine
        self._engine = PermissionEngine(
            constitution=self._constitution,
            auditor=self._auditor,
        )

        logger.info(
            "Governance: active (risk_thresholds={}, audit={}, tools={})",
            {k: v for k, v in [
                ("critical", self._constitution.risk.critical),
                ("high", self._constitution.risk.high),
                ("medium", self._constitution.risk.medium),
                ("low", self._constitution.risk.low),
            ]},
            "on" if audit_enabled else "off",
            len(self._constitution.permissions),
        )

    @property
    def engine(self) -> PermissionEngine:
        """Expose engine for preflight/status checks."""
        return self._engine

    async def before_tool_call(self, tc_ctx: ToolCallContext) -> None:
        """Evaluate governance before the tool executes.

        Raises GovernanceDenied if the call is blocked.
        """
        decision = self._engine.check(tc_ctx.tool_name, tc_ctx.arguments)

        if decision.blocked:
            logger.warning(
                "Governance DENY: tool={} rule={} risk={}",
                tc_ctx.tool_name,
                decision.rule_id,
                decision.risk_level.value,
            )
            raise GovernanceDenied(decision)
        elif decision.risk_level.value in ("medium", "high"):
            logger.info(
                "Governance allow (elevated risk): tool={} risk={} rule={}",
                tc_ctx.tool_name,
                decision.risk_level.value,
                decision.rule_id,
            )
