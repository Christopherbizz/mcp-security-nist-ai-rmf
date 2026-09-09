#!/usr/bin/env python3
"""
mcp_audit.py — Static security auditor for MCP server configurations and
tool manifests, with findings mapped to the NIST AI Risk Management
Framework (AI RMF 1.0) functions: Govern, Map, Measure, Manage.

See ../FRAMEWORK.md for the full risk-to-framework mapping this tool
implements a subset of, and ../README.md for usage examples.

Pure standard library — no third-party runtime dependencies.

Usage:
    python mcp_audit.py --config path/to/mcp_config.json
    python mcp_audit.py --manifest path/to/tools_manifest.json
    python mcp_audit.py --config a.json --manifest b.json --format json --fail-on HIGH
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    rmf_function: str
    rmf_category: str
    title: str
    detail: str
    remediation: str
    location: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "rmf_function": self.rmf_function,
            "rmf_category": self.rmf_category,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "location": self.location,
        }


# ---------------------------------------------------------------------------
# Known-tool baseline for typosquat/shadowing detection. Deliberately small —
# extend this list with your organization's actually-approved tool names.
# ---------------------------------------------------------------------------
KNOWN_TOOL_NAMES = [
    "read_file", "write_file", "list_directory", "search_files",
    "execute_command", "http_request", "query_database",
]

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),            # OpenAI/Anthropic/Stripe-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),                 # AWS access key ID
    re.compile(r"ghp_[A-Za-z0-9]{36}"),              # GitHub PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),     # Slack token
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9/_\-+=]{12,}"),
]

DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"\brm\s+-rf\b"),
    re.compile(r"\bsudo\b"),
    re.compile(r"curl[^|]*\|\s*(sh|bash)\b"),
    re.compile(r"wget[^|]*\|\s*(sh|bash)\b"),
    re.compile(r"\bchmod\s+777\b"),
    re.compile(r"\beval\b"),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (all |any )?(previous|prior|above) instructions"),
    re.compile(r"(?i)system\s*:\s*you (are|must|should)"),
    re.compile(r"(?i)disregard (the|your) (system|previous) prompt"),
    re.compile(r"(?i)do not (tell|inform|mention) the user"),
    re.compile(r"(?i)always include the full contents of"),
]


def sev_at_least(sev: Severity, floor: Severity) -> bool:
    return sev.value >= floor.value


# ---------------------------------------------------------------------------
# Checks against an MCP client config (Claude Desktop-style "mcpServers" map)
# ---------------------------------------------------------------------------

def check_server_config(config: dict, source: str) -> list[Finding]:
    findings: list[Finding] = []
    servers = config.get("mcpServers", {})

    for name, spec in servers.items():
        loc = f"{source}::mcpServers.{name}"
        command = spec.get("command", "")
        args = spec.get("args", [])
        env = spec.get("env", {})
        full_cmdline = " ".join([str(command)] + [str(a) for a in args])

        # --- MANAGE: hardcoded credentials ---
        for key, value in env.items():
            value_str = str(value)
            if any(p.search(value_str) for p in SECRET_PATTERNS):
                findings.append(Finding(
                    rule_id="CRED-001",
                    severity=Severity.HIGH,
                    rmf_function="MANAGE",
                    rmf_category="Risk treatment, monitoring, and documentation",
                    title="Likely hardcoded credential in server environment configuration",
                    detail=f"Environment variable '{key}' for server '{name}' appears to contain a live secret value rather than a reference.",
                    remediation="Store the credential in the OS keychain / a secrets manager and inject it at runtime, rather than embedding the literal value in this config file.",
                    location=loc,
                ))

        # --- MEASURE: dangerous command patterns (local server compromise) ---
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            if pattern.search(full_cmdline):
                findings.append(Finding(
                    rule_id="EXEC-001",
                    severity=Severity.HIGH,
                    rmf_function="MEASURE",
                    rmf_category="Evaluation for trustworthy characteristics (safety)",
                    title="Potentially dangerous command pattern in server launch configuration",
                    detail=f"Server '{name}' launch command matches a high-risk pattern: '{pattern.pattern}'.",
                    remediation="Review the exact command before approving. Run local MCP servers sandboxed (container, restricted user, minimal filesystem/network access) rather than with full host privileges.",
                    location=loc,
                ))

        # --- MAP: supply chain / unpinned versions ---
        if command in ("npx", "uvx", "pipx"):
            joined_args = " ".join(str(a) for a in args)
            if not re.search(r"@\d+\.\d+", joined_args):
                findings.append(Finding(
                    rule_id="SUPPLY-001",
                    severity=Severity.MEDIUM,
                    rmf_function="MAP",
                    rmf_category="Risks mapped for third-party components",
                    title="MCP server package is not version-pinned",
                    detail=f"Server '{name}' is launched via '{command}' without a pinned version, so the code that actually runs can change between runs without review (a 'rug pull').",
                    remediation="Pin an exact version (e.g. package@1.4.2) and update deliberately, reviewing the diff/changelog, rather than always pulling the latest published release.",
                    location=loc,
                ))

        # --- MEASURE: plaintext HTTP for non-loopback endpoints ---
        for arg in args:
            if isinstance(arg, str) and arg.startswith("http://") and "localhost" not in arg and "127.0.0.1" not in arg:
                findings.append(Finding(
                    rule_id="TRANSPORT-001",
                    severity=Severity.HIGH,
                    rmf_function="MEASURE",
                    rmf_category="Evaluation for trustworthy characteristics (security)",
                    title="Non-loopback plaintext HTTP endpoint configured",
                    detail=f"Server '{name}' references a plaintext HTTP URL to a non-local host: {arg}",
                    remediation="Use HTTPS for any non-loopback MCP transport endpoint to protect tokens and payloads in transit.",
                    location=loc,
                ))

        # --- GOVERN: no recorded source/publisher metadata ---
        if "_source" not in spec and "_publisher" not in spec:
            findings.append(Finding(
                rule_id="GOV-001",
                severity=Severity.LOW,
                rmf_function="GOVERN",
                rmf_category="Third-party and supply chain risk policy",
                title="No recorded source/publisher metadata for this server",
                detail=f"Server '{name}' has no organizational metadata (approval owner, source repo, review date) attached in this config.",
                remediation="Maintain an internal registry mapping each approved MCP server to its source, reviewer, and approval date — don't rely on the runtime config file as the system of record for approval.",
                location=loc,
            ))

    return findings


# ---------------------------------------------------------------------------
# Checks against an MCP tool manifest (list of tool definitions with
# name / description / inputSchema, as returned by a tools/list call)
# ---------------------------------------------------------------------------

def check_tool_manifest(manifest: dict, source: str) -> list[Finding]:
    findings: list[Finding] = []
    tools = manifest.get("tools", [])
    seen_names: list[str] = []

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        description = tool.get("description", "") or ""
        input_schema = tool.get("inputSchema", {}) or {}
        loc = f"{source}::tools.{name}"

        # --- MAP: tool poisoning via description ---
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(description):
                findings.append(Finding(
                    rule_id="POISON-001",
                    severity=Severity.HIGH,
                    rmf_function="MAP",
                    rmf_category="Impacts characterized (integrity of model behavior)",
                    title="Tool description contains a suspected embedded instruction",
                    detail=f"Tool '{name}' description matches a known prompt-injection pattern: '{pattern.pattern}'.",
                    remediation="Treat this tool as untrusted pending manual review. Legitimate tool descriptions document behavior for the model/user — they should never contain imperative instructions directed at the model itself.",
                    location=loc,
                ))

        # --- MEASURE: overly permissive schema ---
        if input_schema.get("type") == "object" and input_schema.get("additionalProperties", True) is not False:
            findings.append(Finding(
                rule_id="SCHEMA-001",
                severity=Severity.MEDIUM,
                rmf_function="MEASURE",
                rmf_category="Evaluation for trustworthy characteristics (robustness)",
                title="Tool input schema does not restrict additional properties",
                detail=f"Tool '{name}' input schema does not set 'additionalProperties: false', allowing arbitrary extra fields to be passed through.",
                remediation="Set additionalProperties: false on tool input schemas so unexpected fields are rejected rather than silently accepted.",
                location=loc,
            ))

        # --- MAP: typosquat / tool shadowing detection ---
        for known in KNOWN_TOOL_NAMES:
            if name != known:
                similarity = difflib.SequenceMatcher(None, name.lower(), known.lower()).ratio()
                if similarity > 0.82:
                    findings.append(Finding(
                        rule_id="SHADOW-001",
                        severity=Severity.MEDIUM,
                        rmf_function="MAP",
                        rmf_category="Impacts characterized (deception/impersonation risk)",
                        title="Tool name is suspiciously similar to a known/approved tool name",
                        detail=f"Tool '{name}' is {similarity:.0%} similar to known tool '{known}' — possible typosquat or shadowing attempt.",
                        remediation="Confirm this is an intentionally distinct tool, not an impersonation of an already-trusted one. Reject or rename if it's meant to look like an existing tool.",
                        location=loc,
                    ))

        # --- GOVERN: duplicate tool names (ambiguous resolution / shadowing) ---
        if name in seen_names:
            findings.append(Finding(
                rule_id="SHADOW-002",
                severity=Severity.MEDIUM,
                rmf_function="GOVERN",
                rmf_category="Policies for transparent, effective processes",
                title="Duplicate tool name declared more than once in this manifest",
                detail=f"Tool name '{name}' appears more than once — the client/model may not deterministically resolve which implementation is invoked.",
                remediation="Ensure tool names are unique across all connected servers, or namespace them (e.g. server-prefixed) to prevent ambiguity or deliberate shadowing.",
                location=loc,
            ))
        seen_names.append(name)

    return findings


def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("No findings. 0 issues detected.")
        return

    by_function: dict[str, list[Finding]] = {}
    for f in findings:
        by_function.setdefault(f.rmf_function, []).append(f)

    findings_sorted = sorted(findings, key=lambda f: -f.severity.value)

    print(f"{'SEVERITY':<8} {'RULE':<12} {'RMF':<9} TITLE")
    print("-" * 90)
    for f in findings_sorted:
        print(f"{f.severity.name:<8} {f.rule_id:<12} {f.rmf_function:<9} {f.title}")
        print(f"         location: {f.location}")
        print(f"         detail:   {f.detail}")
        print(f"         fix:      {f.remediation}")
        print()

    print("Summary by NIST AI RMF function:")
    for func in ["GOVERN", "MAP", "MEASURE", "MANAGE"]:
        count = len(by_function.get(func, []))
        if count:
            print(f"  {func:<8} {count} finding(s)")

    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)
    print(f"\nTotal: {len(findings)} finding(s) ({high} HIGH, {medium} MEDIUM, {low} LOW)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Static security auditor for MCP configs/manifests, mapped to the NIST AI RMF."
    )
    parser.add_argument("--config", help="Path to an MCP client config JSON (mcpServers map)")
    parser.add_argument("--manifest", help="Path to an MCP tools manifest JSON (tools/list-shaped)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument(
        "--fail-on", choices=["HIGH", "MEDIUM", "LOW", "INFO", "NONE"], default="HIGH",
        help="Exit non-zero if any finding at or above this severity is present (default: HIGH)",
    )
    args = parser.parse_args()

    if not args.config and not args.manifest:
        parser.error("Provide at least one of --config or --manifest")

    findings: list[Finding] = []

    if args.config:
        findings.extend(check_server_config(load_json(args.config), args.config))

    if args.manifest:
        findings.extend(check_tool_manifest(load_json(args.manifest), args.manifest))

    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print_report(findings)

    if args.fail_on != "NONE":
        floor = Severity[args.fail_on]
        if any(sev_at_least(f.severity, floor) for f in findings):
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
