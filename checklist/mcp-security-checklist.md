# MCP Security Checklist

Operational checklist derived from [`FRAMEWORK.md`](../FRAMEWORK.md), organized by NIST AI RMF function. Intended to be run through before approving a new MCP server, and re-run on any update to an already-approved one.

## GOVERN

- [ ] The server has a recorded owner/approver, source repository, and approval date in an internal registry (not just the runtime config file)
- [ ] The server has been categorized by blast radius (read-only/local, read-only/network, write/local, write/network, financial/irreversible)
- [ ] A policy exists defining which tool categories require human-in-the-loop approval at call time
- [ ] Third-party MCP server risk has a named owner, equivalent to how third-party library risk is owned

## MAP

- [ ] Every tool description and parameter schema has been read in full by a human reviewer — not skimmed, not auto-approved
- [ ] Tool descriptions have been checked for embedded imperative instructions directed at the model ("ignore previous instructions," "system:," etc.)
- [ ] New tool names have been checked against already-trusted tool names for suspicious similarity (typosquatting)
- [ ] Locally-invoked packages are pinned to an exact version, not `@latest` or unpinned
- [ ] Any OAuth scopes requested are the minimum needed, not an omnibus/wildcard grant

## MEASURE

- [ ] Tool input schemas set `additionalProperties: false`
- [ ] All remote transport endpoints use HTTPS — no plaintext HTTP to a non-loopback host
- [ ] The server does not accept tokens that weren't explicitly issued for it (no token passthrough)
- [ ] Local server launch commands have been inspected for dangerous patterns (`sudo`, `rm -rf`, `curl | sh`, `chmod 777`, `eval`)
- [ ] `tool/mcp_audit.py` has been run against the server's config and/or tool manifest with zero HIGH-severity findings

## MANAGE

- [ ] No credentials are hardcoded in plaintext in any server configuration file
- [ ] Credentials are sourced from OS-native secure storage or a secrets manager, and use short-lived tokens where possible
- [ ] Every tool invocation is logged with full parameters, calling identity, and timestamp, feeding a SIEM or equivalent
- [ ] Logs are checked to confirm secrets are redacted before they reach the audit sink
- [ ] CI is configured to fail (not just warn) on HIGH-severity findings from the audit tool
- [ ] Already-approved servers are re-scanned periodically, not only at initial approval
