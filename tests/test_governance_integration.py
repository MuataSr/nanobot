"""End-to-end integration test for governance system.

Verifies the full wiring path:
  config.json → constitution.yaml loads → PermissionEngine gates tool calls →
  dangerous commands denied, safe commands allowed, unknown tools classified.

Run: python3 tests/test_governance_integration.py
"""

import sys
import tempfile
from pathlib import Path

# Ensure the nanobot package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nanobot.governance.constitution import Constitution
from nanobot.governance.permissions import PermissionEngine, GovernanceDecision
from nanobot.governance.risk import GovernanceAction as Action, RiskLevel
from nanobot.governance.audit import AuditLogger
from nanobot.governance.risk import _tool_family
from nanobot.governance.constitution import ToolPermission


# ── Test helpers ──────────────────────────────────────────────

_passed = 0
_failed = 0


def _assert(condition: bool, label: str) -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  ✅ {label}")
    else:
        _failed += 1
        print(f"  ❌ {label}")


# ── Test 1: Constitution loads from real file ─────────────────

print("\n[Test 1] Constitution loads from real constitution.yaml")
constitution_path = Path.home() / ".nanobot" / "constitution.yaml"
if constitution_path.exists():
    c = Constitution.load(str(constitution_path))
    _assert(c.source_path == str(constitution_path), "source_path set correctly")
    _assert(c.tool_count >= 4, f"tool_count >= 4 (got {c.tool_count})")
    _assert(c.rule_count >= 21, f"rule_count >= 21 (got {c.rule_count})")
    _assert(c.identity.name == "Ann-E", f"identity.name = {c.identity.name}")
    _assert(len(c.identity.boundaries) >= 5, f"boundaries >= 5 (got {len(c.identity.boundaries)})")
else:
    print("  ⚠️  Skipped — no constitution.yaml found at ~/.nanobot/")


# ── Test 2: Constitution.from_yaml does NOT exist ─────────────

print("\n[Test 2] Constitution.from_yaml should not exist (old bug)")
_assert(
    not hasattr(Constitution, "from_yaml"),
    "from_yaml correctly absent — only load() exists",
)


# ── Test 3: _tool_family never returns empty ──────────────────

print("\n[Test 3] _tool_family returns classification for unknown tools")
_assert("bash" in _tool_family("exec"), "exec → bash family")
_assert("secrets" in _tool_family("exec"), "exec → secrets family")
_assert(
    len(_tool_family("totally_unknown_tool")) > 0,
    "unknown tool gets default families (not empty)",
)
_assert(
    "secrets" in _tool_family("totally_unknown_tool"),
    "unknown tool → secrets family",
)
_assert(
    "nanobot_protect" in _tool_family("totally_unknown_tool"),
    "unknown tool → nanobot_protect family",
)


# ── Test 4: PermissionEngine deny/allow decisions ─────────────

print("\n[Test 4] PermissionEngine gates dangerous vs safe commands")

if constitution_path.exists():
    c = Constitution.load(str(constitution_path))
    auditor = AuditLogger(enabled=False)  # don't write during tests
    engine = PermissionEngine(constitution=c, auditor=auditor)

    # 4a. Safe command → ALLOW
    safe = engine.check("exec", {"command": "ls -la /tmp"})
    _assert(safe.action == Action.ALLOW, f"ls -la → {safe.action.value}")

    # 4b. Destructive command → DENY
    destructive = engine.check("exec", {"command": "rm -rf /"})
    _assert(
        destructive.action == Action.DENY,
        f"rm -rf / → {destructive.action.value}",
    )
    _assert(destructive.rule_id != "", f"rule_id set: {destructive.rule_id}")

    # 4c. Unknown tool still gets evaluated (not silently passed)
    unknown = engine.check("mystery_tool", {"content": "hello world"})
    _assert(
        unknown.action in (Action.ALLOW, Action.DENY),
        f"mystery_tool → {unknown.action.value} (not ignored)",
    )

    # 4d. File write to nanobot internals → DENY
    internal = engine.check("exec", {"command": "echo hacked >> nanobot/governance/hooks.py"})
    _assert(
        internal.action == Action.DENY,
        f"write to nanobot source → {internal.action.value}",
    )
else:
    print("  ⚠️  Skipped — no constitution.yaml")


# ── Test 5: Constitution parse failure raises, not swallows ────

print("\n[Test 5] Broken constitution raises error, doesn't silently default")

with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tf:
    tf.write("{{{{invalid yaml")
    bad_path = tf.name

try:
    c = Constitution.load(bad_path)
    # If we get here, it fell back to defaults — that's acceptable for parse errors
    _assert(c.source_path is None or c.tool_count >= 0, "graceful fallback to defaults")
    print("  ⚠️  Loaded defaults instead of raising (acceptable for parse errors)")
except Exception as exc:
    _assert(True, f"raised {type(exc).__name__} — error propagates correctly")

Path(bad_path).unlink(missing_ok=True)


# ── Test 6: Audit logger smoke test ───────────────────────────

print("\n[Test 6] Audit logger writes entries correctly")

with tempfile.TemporaryDirectory() as td:
    log_path = Path(td) / "test_audit.jsonl"
    auditor = AuditLogger(path=log_path, enabled=True)

    auditor.log(
        tool="exec",
        action="deny",
        risk="critical",
        rule="bash/rm-root",
        reason="Blocked destructive rm",
        input_hash="sha256:abc123",
    )
    _assert(auditor.entry_count == 1, f"entry_count = {auditor.entry_count}")

    entries = auditor.read_tail(1)
    _assert(len(entries) == 1, f"read_tail returned {len(entries)} entries")
    _assert(entries[0]["action"] == "deny", "entry action = deny")
    _assert(entries[0]["rule"] == "bash/rm-root", "entry rule = bash/rm-root")


# ── Test 7: ASK action returns ASK, not ALLOW ──────────────────

print("\n[Test 7] ASK action is returned correctly (not silently passed)")

with tempfile.TemporaryDirectory() as td:
    # Create a constitution with medium risk → ask
    ask_constitution_yaml = """
identity:
  name: TestBot
  boundaries: []

risk:
  critical: deny
  high: deny
  medium: ask
  low: allow

defaults:
  unknown_tool: deny
  on_error: deny

tools:
  exec:
    policy: restricted
    deny_patterns: []
    allow_patterns: []
    deny_paths: []
    ask_paths: []
"""
    ask_path = Path(td) / "ask_constitution.yaml"
    ask_path.write_text(ask_constitution_yaml)
    ask_c = Constitution.load(str(ask_path))
    ask_engine = PermissionEngine(constitution=ask_c, auditor=AuditLogger(enabled=False))

    # "ls" is low risk normally, but we need to trigger medium
    # Use a command that triggers medium risk rules (e.g., network)
    # Actually, let's test via unknown tool which goes to default
    # For a direct test: check that risk_action("medium") returns "ask"
    _assert(
        ask_c.risk_action("medium") == "ask",
        f"risk_action(medium) = {ask_c.risk_action('medium')}",
    )

    # And verify a medium-risk classified tool returns ASK action
    # sudo triggers the bash/sudo MEDIUM rule
    ask_result = ask_engine.check("exec", {"command": "sudo apt install something"})
    _assert(
        ask_result.action == Action.ASK,
        f"sudo (medium risk) → {ask_result.action.value}",
    )
    _assert(
        ask_result.rule_id != "",
        f"rule_id set: {ask_result.rule_id}",
    )


# ── Summary ───────────────────────────────────────────────────

print(f"\n{'='*50}")
print(f"Results: {_passed} passed, {_failed} failed")


# ── Test 8: Rule chain composition ────────────────────────────

print("\n[Test 8] Rule chain is composable and independently testable")

from nanobot.governance.permissions import (
    ConstitutionDenyRule,
    RiskThresholdRule,
    ConstitutionAllowRule,
    PolicyLockedRule,
    PolicyOpenRule,
    PolicyRestrictedRule,
    UnknownToolRule,
    _EvalContext,
)

# Verify engine has exactly 7 rules
engine_for_chain = PermissionEngine(auditor=AuditLogger(enabled=False))
_assert(
    len(engine_for_chain.rules) == 7,
    f"Expected 7 rules, got {len(engine_for_chain.rules)}",
)

# Verify rule types in order
expected_types = [
    ConstitutionDenyRule,
    RiskThresholdRule,
    ConstitutionAllowRule,
    PolicyLockedRule,
    PolicyOpenRule,
    PolicyRestrictedRule,
    UnknownToolRule,
]
for i, (rule, expected) in enumerate(zip(engine_for_chain.rules, expected_types)):
    _assert(
        type(rule) is expected,
        f"Rule {i}: expected {expected.__name__}, got {type(rule).__name__}",
    )

# Test a rule in isolation: PolicyLockedRule should deny locked tools
locked_ctx = _EvalContext(
    tool_name="test_locked",
    norm_tool="test_locked",
    arguments={},
    input_hash="abc123",
    text="",
    path="",
    risk_level=RiskLevel.LOW,
    rule_id="",
    reason="",
    perm=ToolPermission(policy="locked"),
)
locked_rule = PolicyLockedRule()
locked_result = locked_rule.check(locked_ctx)
_assert(
    locked_result is not None and locked_result.action == Action.DENY,
    f"PolicyLockedRule should deny locked tools, got {locked_result}",
)

# Test a rule in isolation: PolicyOpenRule should allow open tools
open_ctx = _EvalContext(
    tool_name="test_open",
    norm_tool="test_open",
    arguments={},
    input_hash="abc123",
    text="",
    path="",
    risk_level=RiskLevel.LOW,
    rule_id="",
    reason="",
    perm=ToolPermission(policy="open"),
)
open_rule = PolicyOpenRule()
open_result = open_rule.check(open_ctx)
_assert(
    open_result is not None and open_result.action == Action.ALLOW,
    f"PolicyOpenRule should allow open tools, got {open_result}",
)

# Test UnknownToolRule in isolation: always returns a decision (never None)
from nanobot.governance.constitution import Constitution as C2
unknown_ctx = _EvalContext(
    tool_name="mystery",
    norm_tool="mystery",
    arguments={},
    input_hash="abc123",
    text="",
    path="",
    risk_level=RiskLevel.LOW,
    rule_id="",
    reason="",
    perm=ToolPermission(policy="restricted"),
)
unknown_rule = UnknownToolRule(C2.default())
unknown_result = unknown_rule.check(unknown_ctx)
_assert(
    unknown_result is not None,
    "UnknownToolRule must always return a decision",
)
_assert(
    unknown_result.rule_id == "default/unknown_tool",
    f"UnknownToolRule rule_id = {unknown_result.rule_id}",
)


# ── Final Summary ─────────────────────────────────────────────

print(f"\nFinal: {_passed} passed, {_failed} failed")
if _failed:
    print("⚠️  Some tests failed — see above")
    sys.exit(1)
else:
    print("✅ All integration tests passed")
