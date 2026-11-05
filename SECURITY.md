# Security

Report vulnerabilities through the repository's private security-advisory
channel. Do not include live tokens, OAuth codes/verifiers, receipts, or private
issue content in a report.

The primary boundaries are:

- one explicit profile per CLI remote operation, binding instance, account, OAuth
  topology, credential generation, executor, and exact project allowlist;
- OS secret-store credentials that never enter argv, environment, JSON, logs,
  receipts, profiles, or repository files;
- fixed-origin requests with redirects disabled and bounded response bodies;
- in the portable and macOS identity editions, a six-tool Remote MCP read
  allowlist plus host enforcement or a read-only YouTrack identity;
- inert handling of all YouTrack-provided content;
- network-free mutation planning, trusted user-presence approval, receipt
  binding, one mutation attempt, and bounded reconciliation.

The documented Remote MCP tool catalog is internally inconsistent: it calls
predefined tools read-only while listing `create_issue`, `update_issue`,
`add_issue_comment`, `manage_issue_tags`, `link_issues`, `create_article`,
`update_article`, and `log_work`. Never treat an unfiltered `/mcp` endpoint as
read-only. In the standard edition, MCP write tools are permitted and act with
the connector account's own rights, outside the CLI's profile binding, allowlist,
plan and reconciliation.

Tests must use fake credentials and local servers. They must never call a live
YouTrack instance or the real OS secret store. If a mutation response becomes
ambiguous, do not replay it; reconcile by receipt and require operator resolution
when evidence is inconclusive.
