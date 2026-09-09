# MCP Security Framework — NIST AI RMF Aligned

A security framework for Model Context Protocol (MCP) deployments, mapped to the four functions of the [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) (Govern, Map, Measure, Manage) — plus a working static-analysis tool that enforces a subset of it in CI.

MCP is a fast-moving, genuinely new attack surface: a tool's description can carry instructions a model treats as trustworthy, an approved server can be swapped out post-approval, and a proxy between client and third-party API can become a confused deputy. This repo treats securing an MCP deployment as a governed process, not a one-time checklist.

## What's here

```
.
├── FRAMEWORK.md                        # The core deliverable: MCP threat model
│                                          mapped to NIST AI RMF functions, plus
│                                          a reference architecture
├── checklist/
│   └── mcp-security-checklist.md          # Operational checklist derived from FRAMEWORK.md
├── tool/
│   ├── mcp_audit.py                         # Static auditor — zero runtime dependencies
│   ├── requirements.txt                      # pytest, for tests/ only
│   └── tests/
│       └── test_mcp_audit.py                  # 13 tests covering every rule
├── examples/                              # Fixtures used by tests and CI
│   ├── good-server-config.json
│   ├── risky-server-config.json
│   ├── tool-manifest-good.json
│   └── tool-manifest-risky.json
└── .github/workflows/ci.yml            # Runs tests, then self-audits the fixtures
```

Start with [`FRAMEWORK.md`](FRAMEWORK.md) — that's the actual content. This README covers how to run the tool.

## The audit tool

`tool/mcp_audit.py` statically scans two kinds of MCP artifacts:

- **A client config** (the `mcpServers` map used by Claude Desktop and similar clients) — checking for hardcoded credentials, dangerous launch commands, unpinned package versions, plaintext HTTP endpoints, and missing governance metadata.
- **A tool manifest** (a `tools/list`-shaped JSON document) — checking tool descriptions for embedded prompt-injection patterns, overly permissive input schemas, and typosquatted/duplicate tool names.

Every finding is tagged with the specific NIST AI RMF function it corresponds to (see [`FRAMEWORK.md`](FRAMEWORK.md) for the full rationale behind each rule).

### Usage

```bash
cd tool
python mcp_audit.py --config path/to/mcp_config.json
python mcp_audit.py --manifest path/to/tools_manifest.json
python mcp_audit.py --config a.json --manifest b.json --format json --fail-on MEDIUM
```

Try it against the bundled examples:

```bash
# Clean — exits 0
python mcp_audit.py --config ../examples/good-server-config.json --manifest ../examples/tool-manifest-good.json

# Flags 14 findings across all four RMF functions — exits 1
python mcp_audit.py --config ../examples/risky-server-config.json --manifest ../examples/tool-manifest-risky.json
```

`--fail-on` (default `HIGH`) controls the exit-code threshold, so this can gate a CI pipeline the same way `tfsec`/`Checkov` gate the Terraform repos in this portfolio: a HIGH-severity finding fails the build, not just a warning in the log.

### Running the tests

```bash
pip install -r tool/requirements.txt
python -m pytest tool/tests/ -v
```

13 tests, one per rule, covering both the "should fire" and "should not false-positive" cases.

## CI

`.github/workflows/ci.yml` runs the test suite, then runs the tool against both bundled examples as a live regression check: the good example must pass cleanly, and the risky example must be flagged — if either assumption breaks, the build fails. This is the same self-verifying pattern used for `tfsec`/`Checkov` elsewhere in this portfolio, applied to a hand-rolled scanner instead of an off-the-shelf one.

## Scope and limitations

This is a static analyzer working from configuration and manifest files alone — it cannot detect a server behaving maliciously only at runtime (e.g., a tool description that's benign but a return value that carries an indirect prompt injection, or a "rug pull" that swaps behavior after the version check passes). It's one layer of the defense described in `FRAMEWORK.md`'s reference architecture, not a replacement for runtime monitoring, sandboxing, or human review of high-risk tool calls. The `KNOWN_TOOL_NAMES` list and regex-based detection patterns are also intentionally small starting points meant to be extended with an organization's actual approved-tool inventory and observed attack patterns, not a complete, static ruleset.

## References

See [`FRAMEWORK.md`](FRAMEWORK.md#references) for full citations — primarily the official [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices), the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), and the [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework).
