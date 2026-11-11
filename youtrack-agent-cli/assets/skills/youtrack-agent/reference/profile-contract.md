# Profile contract

A profile selects exactly one normalized YouTrack origin, one expected account,
one OAuth issuer/end-point set, one credential generation, one executor mode,
and one exact project allowlist. Profile files contain no tokens, authorization
codes, PKCE verifiers, or refresh credentials.

Use the user's explicit profile, otherwise the operator-saved role default.
Read `youtrack-agent-cli profile defaults show -o json`: `data.read` and
`data.write` expose `profile_name`, `profile_identity_sha256`, and `state`.
Only a `valid` slot selects a target. Do not ask the user again when it is
valid; missing/stale configured targets must be repaired explicitly, never
replaced by another profile. If unset, list non-secret profile labels and ask
once. Saving a default is a separate authorized local configuration change:

```sh
youtrack-agent-cli profile defaults set --read work --write work-write --yes
```

The five `inspect` commands resolve read defaults; `operator-write snapshot`,
`prepare`, `apply`, and `reconcile` resolve write defaults. Explicit `--profile`
wins, including when defaults are corrupt; an empty explicit flag is invalid.
Auth, project policy, profile administration, and native mutation retain their
explicit-profile contract. No-profile `capabilities` is build-only, so obtain
the saved write name for its explicit readiness check. Local plan status does
not consult defaults. Defaults are not repository/environment settings and
never grant capabilities. A normal re-login preserves selection, but a changed
configured identity invalidates it. Changing defaults cannot retarget a plan.
Before presenting CLI remote data, verify the current account and show the profile,
instance, and account together.

OAuth endpoints may be hosted by an external Hub. Pin and validate the service
origin, MCP/REST origins, issuer, authorization endpoint, and token endpoint as
separate values. Redirects, endpoint discovery, and returned URLs must never
move credentials to an unpinned origin.

Credentials belong in the OS secret store and never in chat, command arguments,
environment variables, profile files, logs, receipts, or repository files. Do
not inspect or print secret-store values.

Operator-confirmed writes need `rest-best-effort` / `best-effort`, the requested
`issue-create`, `issue-update`, `comment-add`, `comment-delete` or `issue-edit` capability (a single-user field on `issue.create` also needs `issue-create-user-fields`), a bound credential generation and
a nonempty current project allowlist. Keep the existing read-only profile
unchanged. A separate operator-approved `work-write` profile requires its own
browser login and `auth allow-projects set --profile work-write --project ID:KEY`.
Do not reuse another profile's credential metadata or silently expand its
capabilities. `capabilities --profile NAME -o json` reports local readiness,
not server rights. Native-presence approval is a different, unavailable mode.

Capabilities use canonical order `read`, `issue-create`, `issue-update`,
`comment-add`, `comment-delete`, `issue-edit`, `issue-create-user-fields`, omitting unneeded write kinds. Deletion,
summary/description editing and user fields on creation are explicit opt-ins. Adding any changes profile identity and invalidates old
credential/policy/default bindings; re-authenticate and explicitly re-establish
the exact project allowlist and any stale saved selection with operator
authorization. Do not edit capabilities or policy as part of an installation
or silently repair them during a requested deletion. Server permission is
separate: `Delete Comment` for the bound author's own comment, or
`Delete Not Own Comment` for another author's comment.
