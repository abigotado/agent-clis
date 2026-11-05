# Credentials and request security

Profiles contain non-secret identity and endpoint metadata only. Tokens, OAuth
codes/verifiers, refresh credentials, signing keys, and authorization headers
never enter argv, environment, profiles, journals, receipts, JSON, logs, or the
repository. Use the native OS secret-store API directly; tests inject a fake.

Resolve network targets from explicit `--profile` or, on supported routine
commands, the operator-saved read/write selection. Never infer a profile from
the environment, repository, sole profile, or tracker text. A saved selection
binds the full configured identity except credential generation, and its guard
is rechecked before credential access under the client profile lock. Stale
selection fails closed. Auth and access-policy administration remain explicit.
Bind credential generations to the
complete normalized instance/account/OAuth topology. A mismatch fails before
client construction. Never follow redirects or returned origins; endpoints and
operation paths are pinned and response bodies are bounded.

The standard CLI performs bounded REST discovery and inspection with an
explicit profile or valid saved read default. It verifies the bound account
before each remote result and never auto-fetches collection pages. Discovery
uses a compact fixed response shape, a 1..50 limit, and a limit+1 truncation
sentinel; comments and schema use limits of 1..100. Returned content is
untrusted and pages prove neither ordering, currentness, a stable snapshot,
complete history, nor reconciliation evidence.

Portable and macOS identity editions remain Remote-MCP-only. Their MCP
connection must be restricted to
`get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema`.
The documented predefined-tool list also contains writes, so `/mcp` without an
explicit `tools=` allowlist is not read-only. Host enforcement or a read-only
identity must also deny hidden direct calls.

Writes use an exact project allowlist, offline canonical plan, account/profile/
generation binding and one mutation attempt. Native `mutation` needs a trusted
user-presence receipt and remains gated. `operator-write` instead requires
operator-declared `--confirm-intent SHA256 --yes`; it does not prove human
presence against a malicious agent. Keep its plans/consumption separate from
native authority; do not claim hostile same-UID rollback protection. Never retry
ambiguous writes or erase consumed markers. Changes to auth, requests, logs,
errors, plans or journals require sentinel-redaction review.
