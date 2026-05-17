# Governance System

nanobot includes an **opt-in governance layer** that inspects tool calls before execution, classifies risk, and blocks or allows each call based on a configurable constitution.

## Quick Start

**1. Create a constitution file**

Copy the template to your workspace or `~/.nanobot/`:

```bash
cp nanobot/templates/constitution.yaml ~/.nanobot/constitution.yaml
```

Edit to match your security posture. No file = safe built-in defaults with zero overhead.

**2. Enable the governance hook**

In your `config.json`:

```json
{
  "hooks": {
    "enabled_hooks": ["governance"],
    "config": {
      "governance": {
        "constitution_path": "constitution.yaml"
      }
    }
  }
}
```

That's it. The agent will now check every tool call against the constitution.

## Architecture

```
Tool call requested
        │
        ▼
GovernanceHook.before_tool_call()
        │
        ├─ PermissionEngine.check(tool, args)
        │       │
        │       ├─ Constitution: per-tool policy (open/restricted/locked)
        │       ├─ RiskClassifier: ~36 curated regex patterns
        │       │     organized by (tool_family, risk_level)
        │       └─ Returns: GovernanceDecision (allow/ask/deny)
        │
        ├─ AuditLogger.log(decision)
        │     append-only JSONL, auto-rotation at 10MB
        │
        └─ If DENY → GovernanceDenied exception
              → caught in runner.py
              → model sees: "Blocked by governance policy: ..."
              → adapts and chooses different approach
```

## Modules

| Module | Purpose |
|--------|---------|
| `governance/constitution.py` | Pydantic models + YAML loader with auto-discovery |
| `governance/permissions.py` | PermissionEngine — combines constitution + risk classifier |
| `governance/risk.py` | RiskClassifier — classifies tool calls by risk level (<5ms) |
| `governance/risk_rules.py` | ~36 pre-compiled regex patterns across 5 tool families |
| `governance/audit.py` | JSONL audit logger with SHA256 input hashing + auto-rotation |
| `governance/hooks.py` | GovernanceHook — wires governance into the AgentHook system |

## Risk Classification

The risk classifier uses pre-compiled regex patterns organized by **tool family** and **risk level**:

**Tool families:**
- `bash` — exec/shell command patterns
- `file_write` — file path patterns for write operations
- `secrets` — credential/API key patterns in content
- `sensitive_read` — file path patterns for read operations
- `nanobot_protect` — prevents agents from tampering with own history/state

**Risk levels:**
- **Critical** — `rm -rf /`, fork bombs, `mkfs`, AWS key exfiltration
- **High** — pipe-to-sh, force-push main, destructive `dd`, SSH key writes
- **Medium** — `sudo`, package install/remove, firewall changes, `systemctl`
- **Low** — everything else (no matching pattern)

**Default threshold mapping:**
- Critical → `deny`
- High → `deny`
- Medium → `allow`
- Low → `allow`

## Constitution Structure

```yaml
version: "1.0"

identity:
  name: my-agent
  boundaries:
    - "Only modify files within workspace"
    - "Never expose secrets"

permissions:
  exec:
    policy: restricted          # open | restricted | locked
    deny_patterns: [...]        # command substrings to block
    allow_patterns: [...]       # command substrings to always allow
    deny_paths: [...]           # file paths to block
    ask_paths: [...]            # file paths that require confirmation
  edit_file:
    policy: restricted
    deny_paths: ["/etc/shadow"]

defaults:
  unknown_tool: ask             # ask | allow | deny
  on_error: deny                # fail-closed

risk:
  critical: deny
  high: deny
  medium: allow
  low: allow

audit:
  enabled: true
  output: ""                    # empty = ~/.nanobot/audit.jsonl
  max_size_mb: 10.0
```

## Auto-Discovery Order

The constitution loader searches in this order:

1. Explicit path from `config.json` (`hooks.config.governance.constitution_path`)
2. `constitution.yaml` in workspace root (CWD)
3. `~/.nanobot/constitution.yaml` (global)
4. Built-in defaults (no file needed)

## Audit Log

Every governance decision is logged to `~/.nanobot/audit.jsonl` (one JSON line per entry):

```json
{
  "ts": "2026-05-17T13:28:00+00:00",
  "tool": "exec",
  "action": "deny",
  "risk": "critical",
  "rule": "bash/rm-root",
  "reason": "Blocked catastrophic root filesystem deletion",
  "input_hash": "sha256:abc123..."
}
```

**Key design decisions:**
- Tool input is **SHA256-hashed** — raw commands (which may contain secrets) are never written to disk
- Auto-rotates at `max_size_mb` (default 10MB): `audit.jsonl` → `audit.jsonl.1`
- Audit failure does **not** break the agent — writes are best-effort

## Per-Tool Policy

| Policy | Behavior |
|--------|----------|
| `open` | Tool always allowed. No governance check, no audit entry. |
| `restricted` | Checked against deny patterns + risk classifier. |
| `locked` | Always denied unless the call matches an `allow_patterns` entry. |

## Extending Risk Rules

Add custom rules via the constitution's `extra_rules` config, or create a PR adding patterns to `risk_rules.py`. Each rule is a tuple of `(compiled_regex, rule_id, reason_string)`.

Guidelines for new rules:
- Must be **specific** — false positives erode trust
- Must include a **clear reason** — the model uses this to adapt
- Must be **testable** — include test cases in `tests/test_governance.py`
- Organized by `(tool_family, risk_level)` for O(1) lookup

## Performance

- Risk classification: **<5ms** per tool call (pre-compiled regex, no network)
- Zero overhead when governance hook is disabled
- Audit logging: async append, does not block tool execution
- Constitution loaded once at startup, cached in memory

## Design Philosophy

- **Opt-in**: No governance without explicit `enabled_hooks: ["governance"]`
- **Fail-closed**: Errors during classification default to `deny`
- **Model-friendly denials**: Blocked calls return a message the model can use to adapt, not a crash
- **Audit-first**: Every decision is logged with SHA256 input hash
- **Self-protecting**: Agents cannot tamper with their own history/state files
