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

## Secret store (`core/secretstore`)

The store keeps one secret per (service, account) pair in the operating
system's credential store and never falls back to a file. What each platform
relies on:

| OS | Store | What the protection rests on |
| --- | --- | --- |
| macOS | login keychain, Security.framework | the keychain's access control list, which names the code-signing identity of the program that created the item; the keychain lock; the user's session |
| Windows | Credential Manager, per-user, local-machine persistence | the user's logon session and DPAPI protection of the credential; a secret is split over a manifest and numbered chunks |
| Linux | Secret Service provider (for example gnome-keyring) on the session bus | the provider's own lock and unlock; the session bus socket being owned by the user; no bus is launched |

Limits to state plainly:

- Another program running as the same user can pre-create an item or a target
  name, or delete and rewrite one, before this program does. The store reads
  back what is there under the name; it does not prove who wrote it. Treat a
  credential as hostile input until it has been used and checked.
- The store gives no integrity guarantee. It does not sign or authenticate
  what it keeps, so a same-user program that can write to the store can replace
  a secret with its own, and the caller cannot tell from the store alone.
- Secret bytes are zeroed in Go memory on a best-effort basis only. The
  platform libraries copy them into buffers this module cannot zero.
- Core dumps can contain secrets; callers should adopt `DisableCoreDumps`.

Tests must use fake credentials and local servers. They must never call a live
YouTrack instance or the user's own OS secret store. Untagged tests use an
in-memory fake. The tagged integration tests run the real backends only against
a scratch keychain, a throwaway Credential Manager prefix or a private session
bus, in CI or on a developer machine that opted in. If a mutation response becomes
ambiguous, do not replay it; reconcile by receipt and require operator resolution
when evidence is inconclusive.
