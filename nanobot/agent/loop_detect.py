"""Loop detection hook — catches agents repeating identical tool-call patterns.

Tracks two patterns across iterations:

1. **Identical signatures** — same tool names + same arguments.  At
   ``warn_at`` repeats the agent receives an in-context nudge; at ``halt_at``
   a stronger message steers the model toward a final text response.

2. **Same-tool hammering** — the *same single tool* called consecutively
   regardless of arguments.  Catches agents that vary search queries slightly
   each call to evade the identical-signature check.  Governed by
   ``same_tool_warn_at`` and ``same_tool_halt_at``.

No modifications to the runner are required — the hook works entirely
through the existing ``before_execute_tools`` and ``after_iteration`` hook
points.

Usage::

    from nanobot.agent.loop_detect import LoopDetectHook
    hook = LoopDetectHook(warn_at=3, halt_at=5)
    # Pass to AgentRunner or add to a CompositeHook.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from loguru import logger

from nanobot.agent.hook import AgentHook, AgentHookContext
from nanobot.providers.base import ToolCallRequest


# ── Signature helpers ─────────────────────────────────────────────────

def _canonical_signature(calls: list[ToolCallRequest]) -> str:
    """Deterministic fingerprint for a batch of tool calls.

    Sorts by tool name, strips volatile metadata, and hashes the
    normalised JSON.
    """
    if not calls:
        return "__empty__"

    buckets: dict[str, list[dict[str, Any]]] = {}
    for tc in calls:
        clean_args = {
            k: v for k, v in tc.arguments.items()
            if k not in ("tool_call_id",)
        }
        buckets.setdefault(tc.name, []).append(clean_args)

    payload: list[tuple[str, list[dict[str, Any]]]] = sorted(buckets.items())
    for idx, (name, args_list) in enumerate(payload):
        payload[idx] = (name, sorted(args_list, key=lambda a: json.dumps(a, sort_keys=True)))

    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Messages ──────────────────────────────────────────────────────────

_WARN_MESSAGE = (
    "⚠️ Loop detected — you have made the same set of tool calls "
    "{count} times in a row with no progress. "
    "Stop repeating these calls and try a fundamentally different approach."
)

_HALT_MESSAGE = (
    "🛑 Loop halt — the same tool calls have been repeated {count} times. "
    "The current strategy is NOT working. "
    "Do NOT call any more tools. Respond directly to the user with what "
    "you have so far, or ask them for guidance."
)

_SAME_TOOL_WARN_MESSAGE = (
    "⚠️ Tool hammering detected — you have called '{tool}' {count} times "
    "in a row. Stop calling this tool and work with the results you have, "
    "or try a fundamentally different approach."
)

_SAME_TOOL_HALT_MESSAGE = (
    "🛑 Tool hammering halt — '{tool}' has been called {count} consecutive "
    "times. Do NOT call any more tools. Respond directly to the user with "
    "what you have, or ask them for guidance."
)


# ── Hook ──────────────────────────────────────────────────────────────

class LoopDetectHook(AgentHook):
    """Inject recovery guidance when the agent repeats identical tool calls.

    Parameters
    ----------
    warn_at:
        Consecutive identical signatures before a warning is injected.
        Default ``3``.
    halt_at:
        Consecutive identical signatures before a halt message is injected
        that explicitly tells the model to stop calling tools.
        Default ``5``.  Must be greater than *warn_at*.
    same_tool_warn_at:
        Consecutive calls of the *same single tool* (any args) before
        a warning.  Default ``4``.
    same_tool_halt_at:
        Consecutive calls of the *same single tool* before a halt message.
        Default ``6``.  Must be greater than *same_tool_warn_at*.
    """

    __slots__ = (
        "_warn_at", "_halt_at", "_last_sig", "_count", "_halted",
        "_same_tool_warn", "_same_tool_halt", "_last_tool_name",
        "_same_tool_count", "_same_tool_halted",
    )

    def __init__(self, *, warn_at: int = 3, halt_at: int = 5,
                 same_tool_warn_at: int = 4, same_tool_halt_at: int = 6) -> None:
        super().__init__()
        if halt_at <= warn_at:
            raise ValueError(f"halt_at ({halt_at}) must be > warn_at ({warn_at})")
        if same_tool_halt_at <= same_tool_warn_at:
            raise ValueError(
                f"same_tool_halt_at ({same_tool_halt_at}) must be > "
                f"same_tool_warn_at ({same_tool_warn_at})"
            )
        self._warn_at = warn_at
        self._halt_at = halt_at
        self._last_sig: str | None = None
        self._count: int = 0
        self._halted: bool = False
        self._same_tool_warn = same_tool_warn_at
        self._same_tool_halt = same_tool_halt_at
        self._last_tool_name: str | None = None
        self._same_tool_count: int = 0
        self._same_tool_halted: bool = False

    # ── Hook points ───────────────────────────────────────────────

    async def before_execute_tools(self, context: AgentHookContext) -> None:
        sig = _canonical_signature(context.tool_calls)
        if sig == self._last_sig:
            self._count += 1
        else:
            self._last_sig = sig
            self._count = 1

        if self._count == self._warn_at:
            logger.warning(
                "LoopDetect: consecutive repeats={} for session",
                self._count,
            )
            self._inject(context, _WARN_MESSAGE.format(count=self._count))

        elif self._count >= self._halt_at and not self._halted:
            logger.warning(
                "LoopDetect: consecutive repeats={}, injecting HALT",
                self._count,
            )
            self._inject(context, _HALT_MESSAGE.format(count=self._count))
            self._halted = True

        # ── Same-tool hammering detection ───────────────────────────
        tool_names = {tc.name for tc in context.tool_calls}
        if len(tool_names) == 1:
            tool_name = next(iter(tool_names))
            if tool_name == self._last_tool_name:
                self._same_tool_count += 1
            else:
                self._last_tool_name = tool_name
                self._same_tool_count = 1

            if self._same_tool_count == self._same_tool_warn and not self._same_tool_halted:
                logger.warning(
                    "LoopDetect: same-tool hammering: '%s' x%s",
                    tool_name, self._same_tool_count,
                )
                self._inject(
                    context,
                    _SAME_TOOL_WARN_MESSAGE.format(
                        tool=tool_name, count=self._same_tool_count,
                    ),
                )

            elif self._same_tool_count >= self._same_tool_halt and not self._same_tool_halted:
                logger.warning(
                    "LoopDetect: same-tool halt: '%s' x%s",
                    tool_name, self._same_tool_count,
                )
                self._inject(
                    context,
                    _SAME_TOOL_HALT_MESSAGE.format(
                        tool=tool_name, count=self._same_tool_count,
                    ),
                )
                self._same_tool_halted = True
        else:
            # Multiple different tools = not hammering, reset
            self._last_tool_name = None
            self._same_tool_count = 0

    async def after_iteration(self, context: AgentHookContext) -> None:
        # Reset on successful progress (iteration ended with tool results
        # being appended, meaning the next iteration will proceed normally).
        # We only keep the halt flags set once triggered.
        if self._halted:
            return
        if self._same_tool_halted:
            return

    # ── Internal ──────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all loop state.  Call between independent sessions."""
        self._last_sig = None
        self._count = 0
        self._halted = False
        self._last_tool_name = None
        self._same_tool_count = 0
        self._same_tool_halted = False

    @staticmethod
    def _inject(context: AgentHookContext, text: str) -> None:
        """Append a user-level nudge to the message list."""
        context.messages.append({
            "role": "user",
            "content": f"[Loop Detection] {text}",
        })
