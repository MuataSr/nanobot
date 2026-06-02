"""Built-in risk classification patterns.

Curated from AutoHarness's 79 patterns down to ~36 that matter for
single-machine Linux agents.  Organized by (tool_family, risk_level)
so the classifier can do a single dict lookup for the tool family
then iterate the short pattern list.

Each entry: (compiled_regex, human_rule_id, reason_string)
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# ---------------------------------------------------------------------------
# Bash / exec patterns
# ---------------------------------------------------------------------------
BASH_CRITICAL: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\brm\s+-[rf]{1,2}\s+/(?!\w)"),
        "bash/rm-root",
        "Blocked catastrophic root filesystem deletion",
    ),
    (
        re.compile(r"\brm\s+-[rf]{1,2}\s+(?:~|\$HOME)\b"),
        "bash/rm-home",
        "Blocked catastrophic home directory deletion",
    ),
    (
        re.compile(r"\bmkfs\b"),
        "bash/mkfs",
        "Blocked filesystem formatting command",
    ),
    (
        re.compile(r"\bdd\s+if=.*\bof=/dev/"),
        "bash/dd-device",
        "Blocked raw device write via dd",
    ),
    (
        re.compile(r":\(\)\s*\{.*\};\s*:"),
        "bash/fork-bomb",
        "Blocked fork bomb pattern",
    ),
    (
        re.compile(r"\bchmod\s+-R\s+777\s+/"),
        "bash/chmod-root-777",
        "Blocked recursive world-writable on root",
    ),
    (
        re.compile(r">\s*/dev/sd"),
        "bash/redirect-disk",
        "Blocked direct write to disk device",
    ),
    (
        re.compile(r"\b(mkfs|diskpart)\b"),
        "bash/disk-ops",
        "Blocked destructive disk operation",
    ),
]

BASH_HIGH: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b"),
        "bash/pipe-remote-exec",
        "Blocked piped remote script execution",
    ),
    (
        re.compile(r"\bgit\s+push\s+.*--force.*\b(?:main|master)\b"),
        "bash/git-force-main",
        "Blocked force-push to main/master branch",
    ),
    (
        re.compile(r"\bgit\s+reset\s+--hard"),
        "bash/git-reset-hard",
        "Blocked hard git reset (uncommitted work loss)",
    ),
    (
        re.compile(r"\b(shutdown|reboot|poweroff)\b"),
        "bash/system-power",
        "Blocked system power command",
    ),
    (
        re.compile(r"\bdd\s+\S+.*\bof=\S+"),
        "bash/dd-output",
        "Blocked destructive dd output",
    ),
    (
        re.compile(r"\brm\s+-[rf]{1,2}\b"),
        "bash/rm-rf",
        "Destructive recursive force deletion",
    ),
    (
        re.compile(r"\bformat\s+(?:[A-Z]:|/dev/)"),
        "bash/format-drive",
        "Blocked drive formatting",
    ),
    (
        re.compile(r"\bsystemctl\s+(?:stop|disable|mask)\s+.*(?:ssh|nanobot|network)"),
        "bash/systemctl-critical-service",
        "Blocked stopping critical system service",
    ),
]

BASH_MEDIUM: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\bsudo\b"),
        "bash/sudo",
        "Privileged command execution (sudo)",
    ),
    (
        re.compile(r"\b(?:apt|yum|dnf|pacman)\s+install\b"),
        "bash/pkg-install",
        "Package installation changes system state",
    ),
    (
        re.compile(r"\b(?:apt|yum|dnf|pacman)\s+remove\b"),
        "bash/pkg-remove",
        "Package removal changes system state",
    ),
    (
        re.compile(r"\b(?:iptables|ufw|firewall-cmd)\b"),
        "bash/firewall",
        "Firewall modification changes network policy",
    ),
    (
        re.compile(r"\bsystemctl\b"),
        "bash/systemctl",
        "Service management changes system state",
    ),
    (
        re.compile(r"\bcrontab\b"),
        "bash/crontab",
        "Cron modification changes scheduled tasks",
    ),
]

# ---------------------------------------------------------------------------
# File-write patterns (applied to the path being written)
# ---------------------------------------------------------------------------
FILE_WRITE_CRITICAL: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"^/etc/(?:shadow|passwd|sudoers|ssh/sshd_config)"),
        "file/system-credential",
        "Blocked write to system credential file",
    ),
    (
        re.compile(r"^/boot/"),
        "file/boot-partition",
        "Blocked write to boot partition",
    ),
    (
        re.compile(r"\.ssh/authorized_keys$"),
        "file/ssh-keys",
        "Blocked write to SSH authorized keys",
    ),
    (
        re.compile(r"^/usr/lib/"),
        "file/system-lib",
        "Blocked write to system library directory",
    ),
]

FILE_WRITE_HIGH: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"/\.(?:bashrc|profile|zshrc|bash_profile|bash_logout)$"),
        "file/shell-config",
        "Blocked write to shell configuration file",
    ),
    (
        re.compile(r"\.env[\w.-]*$"),
        "file/env-file",
        "Blocked write to environment/secrets file",
    ),
    (
        re.compile(r"(?:credentials|secrets?|tokens?)\.(?:json|yaml|yml|conf)$"),
        "file/credential-file",
        "Blocked write to credential store",
    ),
    (
        re.compile(r"\.pem$|\.key$"),
        "file/private-key",
        "Blocked write to private key file",
    ),
]

# ---------------------------------------------------------------------------
# Secret detection patterns (applied to tool input content)
# ---------------------------------------------------------------------------
SECRETS_CRITICAL: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "secrets/aws-access-key",
        "AWS access key detected in command content",
    ),
    (
        re.compile(r"\b(?:sk-|sk-)[a-zA-Z0-9]{20,}\b"),
        "secrets/api-token",
        "API token detected in command content",
    ),
    (
        re.compile(r"\bghp_[a-zA-Z0-9]{20,}\b"),
        "secrets/github-token",
        "GitHub personal access token detected",
    ),
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "secrets/private-key",
        "Private key material detected in content",
    ),
    (
        re.compile(r"\bpassword\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
        "secrets/plaintext-password",
        "Plaintext password assignment detected",
    ),
    (
        re.compile(r"\b(?:secret|token|api_key)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
        "secrets/credential-assignment",
        "Credential assignment detected in content",
    ),
]

# ---------------------------------------------------------------------------
# Sensitive read patterns (paths that should warn/ask before reading)
# ---------------------------------------------------------------------------
SENSITIVE_READ: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\.ssh/(?:id_rsa|id_ed25519|id_ecdsa)$"),
        "read/ssh-private-key",
        "Reading SSH private key",
    ),
    (
        re.compile(r"\.env[\w.-]*$"),
        "read/env-file",
        "Reading environment/secrets file",
    ),
    (
        re.compile(r"\.pem$"),
        "read/pem-file",
        "Reading PEM certificate/key file",
    ),
    (
        re.compile(r"(?:credentials|secrets?|tokens?)\.(?:json|yaml|yml|conf)$"),
        "read/credential-file",
        "Reading credential store file",
    ),
]

# ---------------------------------------------------------------------------
# Nanobot self-protection patterns
# ---------------------------------------------------------------------------
NANOBOT_PROTECT: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r">>?\s*\S*(?:history\.jsonl|\.dream_cursor)"),
        "nanobot/history-write",
        "Blocked direct write to nanobot history files",
    ),
    (
        re.compile(r"\btee\b[^|;&<>]*(?:history\.jsonl|\.dream_cursor)"),
        "nanobot/history-tee",
        "Blocked tee to nanobot history files",
    ),
    (
        re.compile(
            r"\b(?:cp|mv)\b(?:\s+[^\s|;&<>]+)+\s+\S*(?:history\.jsonl|\.dream_cursor)"
        ),
        "nanobot/history-cp-mv",
        "Blocked copy/move targeting nanobot history files",
    ),
    (
        re.compile(r"\bdd\b[^|;&<>]*\bof=\S*(?:history\.jsonl|\.dream_cursor)"),
        "nanobot/history-dd",
        "Blocked dd write to nanobot history files",
    ),
    (
        re.compile(r"\bsed\s+-i[^|;&<>]*(?:history\.jsonl|\.dream_cursor)"),
        "nanobot/history-sed",
        "Blocked in-place edit of nanobot history files",
    ),
    # Protect nanobot source code from tampering
    (
        re.compile(
            r"(?:>>|>|\btee\b|\bcat\b[^|]*>>?)[^|;&<>]*"
            r"(?:nanobot/governance|nanobot/hooks|nanobot/soul|nanobot/config)"
        ),
        "nanobot/source-write",
        "Blocked write to nanobot governance/source files",
    ),
    (
        re.compile(
            r"\b(?:cp|mv)\b[^|;&<>]*"
            r"(?:nanobot/governance|nanobot/hooks)"
        ),
        "nanobot/source-cp-mv",
        "Blocked copy/move targeting nanobot source files",
    ),
]

# ---------------------------------------------------------------------------
# Index: tool_family → {risk_level → pattern_list}
# ---------------------------------------------------------------------------
RULES: dict[str, dict[str, list[tuple[re.Pattern[str], str, str]]]] = {
    "bash": {
        CRITICAL: BASH_CRITICAL,
        HIGH: BASH_HIGH,
        MEDIUM: BASH_MEDIUM,
    },
    "file_write": {
        CRITICAL: FILE_WRITE_CRITICAL,
        HIGH: FILE_WRITE_HIGH,
    },
    "secrets": {
        CRITICAL: SECRETS_CRITICAL,
    },
    "sensitive_read": {
        HIGH: SENSITIVE_READ,
    },
    "nanobot_protect": {
        CRITICAL: NANOBOT_PROTECT,
    },
}
