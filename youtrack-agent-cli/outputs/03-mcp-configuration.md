# Recommended read-oriented YouTrack Remote MCP configuration

Status: Proposed; examples only, not installed

## Baseline server-side tool allowlist

Use one canonical URL per named profile:

```text
https://<instance>/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true
```

Allowed tools:

| Tool | Purpose | Skill restriction |
|---|---|---|
| `get_current_user` | Verify authenticated identity | Required at first use and after reauthentication |
| `search_issues` | Bounded issue discovery | Limit 10 by default, 50 max; use project scope when known |
| `get_issue` | Exact issue read | Exact ID plus explicit profile required |
| `get_issue_comments` | Bounded comments for one exact issue | Limit 20 by default, 50 max |
| `get_project` | Exact project metadata | No project enumeration |
| `get_issue_fields_schema` | Resolve immutable field/value IDs and types before a write plan | Use only for the selected allowlisted project; bind schema hash into the plan |

Do not include `find_projects` in the baseline. It may be added to a separate discovery profile with a hard bound when users genuinely need cross-project discovery. Likewise, keep `search_articles`/`get_article`, groups, and users outside the baseline and add them only in purpose-specific read profiles.

Never use bare `/mcp` or `ignoreTools=` for a read-oriented connection. The official tool catalog includes mutations, while `tools=` is a positive list returned by `tools/list`. JetBrains describes it as a discovery/quota-control filter and does not state that a direct hidden `tools/call` is rejected. Therefore strict read-only also requires a host runtime allowlist or a YouTrack identity without write permissions. See [Remote MCP Server](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html).

Keep the query-string order stable. Codex derives parts of its OAuth callback identity from the full server URL, including path and query string, so changing the tool order can change the callback identity. Register the exact callback URL printed by the client. See [OpenAI MCP OAuth client registration and callbacks](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

## Naming convention

```text
youtrack_<instance-alias>_<account-alias>_ro
```

Examples:

- `youtrack_acme_alice_ro`
- `youtrack_acme_releasebot_ro`
- `youtrack_jetbrains_public_alice_ro`

The name is a label, not the security identity. Persist and verify the normalized service origin and expected YouTrack account ID/login separately.

## Codex example

Codex supports remote MCP URLs, OAuth, bearer-token environment-variable references, `enabled_tools`, and per-server approval policy. See [OpenAI MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

```toml
[mcp_servers.youtrack_acme_alice_ro]
url = "https://acme.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true"
auth = "oauth"
enabled_tools = [
  "get_current_user",
  "search_issues",
  "get_issue",
  "get_issue_comments",
  "get_project",
  "get_issue_fields_schema",
]
default_tools_approval_mode = "prompt"
required = false
```

Setup sequence after the operator approves implementation:

1. Add the full canonical URL under a unique server name.
2. If automatic CIMD registration is enabled in YouTrack and supported by the client, complete browser OAuth. Otherwise, have the YouTrack administrator preregister a public OAuth client and register the exact callback displayed by `codex mcp add`.
3. Run the interactive login.
4. Inspect the discovered tools and call `get_current_user`.
5. In a non-production test profile, attempt a direct protocol-level call to hidden `update_issue` with a syntactically valid but guaranteed nonexistent target. Require an unknown/forbidden-tool rejection before domain validation. A not-found/validation response means the hidden tool was callable and fails the test. Never use a real target or run this against production.
6. Record only the expected account ID/login in the local non-secret profile; do not record tokens.

For a permanent-token fallback, use `bearer_token_env_var` only if the execution environment can inject the value securely and avoid dumps. The guarded CLI should prefer direct Keychain retrieval instead. Never put a token in TOML.

## Claude Code example

Claude Code supports remote HTTP MCP servers and browser OAuth. Its project `.mcp.json` requires explicit `type: "http"`; user-scoped configuration is preferable for account-specific connections. See [Claude Code MCP](https://code.claude.com/docs/en/mcp).

```json
{
  "mcpServers": {
    "youtrack_acme_alice_ro": {
      "type": "http",
      "url": "https://acme.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true"
    }
  }
}
```

Authenticate interactively from `/mcp`. Do not commit account-specific headers or tokens. Claude Code documents prompt-injection risk for MCP servers that fetch external content; the skill's untrusted-content rules remain mandatory even for this official server.

Optional permission rules may auto-approve the six exact read tools after the profile is verified. They are convenience, not the read-only boundary. Claude Code permission rules use canonical names such as `mcp__<server>__<tool>`; broad deny rules take precedence over narrow allows and therefore cannot implement allowlist exceptions. For strict read-only in Claude Code, prefer a YouTrack identity whose permissions cannot mutate. See [Claude Code permissions](https://code.claude.com/docs/en/permissions).

## OAuth profile policy

YouTrack 2026.2 supports administrator-managed OAuth clients, Authorization Code with PKCE, preregistered MCP clients, and optional CIMD automatic registration. CIMD automatic registration is disabled by default. YouTrack does not support OAuth Dynamic Client Registration for MCP clients. See [YouTrack OAuth 2.0 Authorization](https://www.jetbrains.com/help/youtrack/devportal/OAuth-authorization-in-youtrack.html).

Recommended policy:

- Prefer Authorization Code + PKCE.
- Register separate OAuth clients for Codex and Claude Code because their callback and credential-storage behavior can differ.
- Prefer public clients with PKCE for local tools; do not distribute one confidential client secret in a shared skill.
- Use confidential clients only when a trusted host can protect the secret.
- Require exact registered loopback redirect URIs/patterns supported by YouTrack and the client.
- Verify `state`, PKCE verifier, issuer/metadata where the client supports it, and the returned user identity.
- Store refresh tokens in the client's secure credential store; for `youtrack-agent-cli`, use the OS secret-store adapter.
- Keep permanent tokens as an explicitly configured fallback, stored in the OS secret store and scoped to YouTrack.

### Endpoint topology for YouTrack Server

Do not collapse every URL into one origin. A profile pins these values independently:

```text
youtrack_service_url
mcp_url
rest_base
oauth_issuer
oauth_authorization_endpoint
oauth_token_endpoint
allowed_redirect_origins
```

For YouTrack Cloud and Server with built-in Hub, these are predictably related. A Server installation can use an external Hub service on another origin, which is legitimate only when the profile explicitly pins that issuer and its endpoints. “Same-origin only” applies separately within each service boundary; it must not silently reject a configured external Hub or accept an unconfigured one. See [YouTrack OAuth endpoints](https://www.jetbrains.com/help/youtrack/devportal/OAuth-authorization-in-youtrack.html#endpoints).

## Multiple instances and accounts

Every connection name maps to exactly one expected `(origin, user)` pair. Before returning any business data, the skill reports:

```text
profile: youtrack_acme_alice_ro
instance: https://acme.youtrack.cloud
account: alice@example.com
```

If multiple profiles exist and the user did not select one, do not query every instance. Ask for the profile after showing a non-secret list.

Same-instance multiple accounts require a compatibility test because clients can key OAuth credentials by endpoint. Required acceptance test:

1. Configure two differently named entries with the same canonical endpoint.
2. Authenticate them as different users.
3. Restart the client.
4. Call `get_current_user` through each entry.
5. Confirm identities remain distinct.

If the test fails, use separate client configuration roots/sessions or separate secure bearer-token contexts. Do not rotate one shared credential behind two profile names.

## Install/startup validator and drift checks

These checks belong to an installer/compatibility validator and host configuration gate, not to the instruction-only skill. Fail the profile closed unless all checks pass:

1. URL schemes are HTTPS and MCP/REST/OAuth endpoints match their separately pinned profile values.
2. Redirects remain within the pinned service or explicitly pinned external-Hub boundary.
3. `tools/list` returns exactly the six allowed tool names.
4. No `customToolPackages` parameter is present.
5. `get_current_user` matches expected account identity.
6. A bounded `search_issues` test honors its limit and does not auto-page.
7. An exact `get_issue` call does not trigger any secondary URL fetch or instruction execution.
8. A protocol-level negative call to a hidden mutation is rejected, or strict read-only is instead supplied by the host runtime allowlist/read-only YouTrack identity.

Any mismatch produces a diagnostic that names the profile and non-secret origin but does not include tokens, authorization headers, or full returned content.

## Read-only assurance levels

Do not give every configuration the same label:

- **Discovery-constrained:** `tools=` hides all but the six names from normal discovery.
- **Host-constrained:** the agent host also enforces the same runtime allowlist.
- **Permission-constrained:** the authenticated YouTrack identity has no mutation permissions.
- **Strict read-only:** host or permission enforcement blocks hidden direct calls, and the compatibility negative test passes for the deployed versions.

Defense in depth is:

```text
YouTrack endpoint tools= discovery allowlist
        + client runtime allowlist where supported
        + read-only YouTrack identity where possible
        + negative hidden-call compatibility test
        + installer discovery exact-set check
        + skill routing rule against MCP writes
        + user/account identity check
```

If any layer reports a mutating tool, the connection is misconfigured and must not be used. The skill can refuse a dangerous visible tool; it is not the component that proves raw discovery or hidden-call behavior.

## Data-minimization limit

`search_issues` is naturally bounded and returns basic information, but YouTrack documents `get_issue` as returning a fixed detailed structure rather than accepting a caller-selected `fields` projection. The skill can minimize what it displays, not necessarily what MCP retrieves. Deployments that require retrieval-level field minimization should use a narrow REST read helper with explicit `fields`, after a separate design decision, instead of claiming that `get_issue` is field-minimal.
