#!/usr/bin/env python3
"""Antigravity 2.0 PreToolUse Hook for Verifiable Software Factory."""

import json
import os
import re
import sys

SECRET_PATHS = [
    r"(^|/)\.factory-state/.*\.key\.json$",
    r"\.(pem|key|p12)$",
    r"^/opt/antigravity/tokens/",
]

HIGH_TRUST_PATHS = [
    r"(^|/)policy/opa/",
    r"(^|/)factory/internal/attestation/gatekeeper\.go$",
    r"(^|/)factory/internal/governance/tpi\.go$",
    r"(^|/)\.agents/hooks",
]

SAFE_CMDS = (
    "make build",
    "go test ",
    "go vet ",
    "git status",
    "git diff",
    "git log",
    "./bin/factory ",
)


def emit(decision: str, reason: str = "") -> None:
    out = {"decision": decision}
    if reason:
        out["reason"] = reason
    sys.stdout.write(json.dumps(out) + "\n")
    sys.exit(0)


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        emit("force_ask", "Factory hook failed to parse stdin JSON")

    tc = data.get("toolCall") or {}
    name = tc.get("name", "")
    args = tc.get("args") or {}

    if name in ("view_file", "write_to_file", "replace_file_content", "multi_replace_file_content"):
        path = (args.get("TargetFile") or args.get("AbsolutePath") or "").replace("\\", "/")
        for pat in SECRET_PATHS:
            if re.search(pat, path):
                emit("deny", f"Factory zero-trust policy blocked access to key/secret path: {os.path.basename(path)}")
        if name != "view_file":
            for pat in HIGH_TRUST_PATHS:
                if re.search(pat, path):
                    emit("force_ask", f"Editing critical security gate requires explicit human confirmation: {path}")
        emit("allow")

    if name == "run_command":
        cmd = (args.get("CommandLine") or "").strip()
        if re.search(r"\bgit\s+push\b[^\n]*(--force|-f\b)|\brm\s+-[a-zA-Z]*rf\s+(/(\*|\s|$)|~|\.\.)", cmd):
            emit("deny", "Destructive command blocked by factory zero-trust hook")
        if re.search(r"\bgit\s+push\b", cmd):
            emit("force_ask", "Pushing factory changes requires explicit human confirmation")
        if not re.search(r"[;&|`$<>]", cmd):
            for p in SAFE_CMDS:
                if cmd == p.strip() or cmd.startswith(p):
                    emit("auto_approve", f"Routine factory build/verify command auto-approved: {p.strip()}")
        emit("allow")

    emit("allow")


if __name__ == "__main__":
    main()
