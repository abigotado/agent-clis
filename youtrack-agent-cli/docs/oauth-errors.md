# OAuth token error recovery

The standard macOS CLI reports OAuth token failures in the v1 JSON error
envelope. The seven code, exit, and recovery rows are generated from the
runtime catalog in the [machine contract](contract.md#oauth-token-errors-standard-macos-cli-planned-v020);
that table is the canonical reference. This guide explains when those rows
apply. The new classifications are planned for the tagged `v0.2.0` Formula:
an untagged source checkout reports `devel`, and a merged source change alone
does not reach Homebrew until a release tag is pinned by a merged tap update.
`hint` is actionable prose, not a stable category ID; machine consumers must
branch on `error.code` and exit instead of matching its wording.

Before the planned `v0.2.0` classification, authorization-code token-exchange
failures used `OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5. The six new
authorization-code categories are a deliberate machine-recovery change while
the JSON envelope shape remains `v:1`. That statement does not describe the
old handling of *local post-refresh* failures, which crossed other error
translation paths.

These OAuth errors do not include `error.retry_after`. For
`OAUTH_TOKEN_ENDPOINT_UNAVAILABLE`, the caller applies its own bounded backoff
before starting a fresh login; the CLI does not forward the server's
`Retry-After` header or authorize replay of the old token request.

Cancellation or deadline expiry detected before either token request is attempted
keeps the normal `CANCELED` or `TIMEOUT` recovery. Once an attempt begins, the
client cannot prove whether the server consumed it. An interrupted authorization-
code exchange therefore requires a fresh login, without retrying its token POST.
An HTTP 200 response with a body-read failure is also non-retryable: the server
may already have consumed the authorization code, regardless of the local read
error. The CLI exposes only a fixed error category and HTTP 200, never the
underlying read error.
Likewise, a malformed or oversized HTTP 200 response—or an unexpected 1xx or
non-200 2xx response—does not prove the authorization code remains usable.
`OAUTH_TOKEN_RESPONSE_INVALID` always requires a fresh interactive login and
new code after checking compatibility; it never authorizes replaying the old
token POST, even if the client configuration is changed.

After a refresh attempt, all failures collapse to the legacy non-retryable
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5 recovery, including DNS and TLS failures
that may in fact have occurred before dispatch and local failure after a
successful refresh response. Before refresh-local normalization, direct error
translation after a successful refresh could report different machine results:

| Local post-refresh failure | Earlier direct translation | Planned `v0.2.0` |
| --- | --- | --- |
| Profile/credential binding rejection | `CREDENTIAL_BINDING_MISMATCH` / 5 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |
| Invalid refreshed-token validation | `USAGE` / 2 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |
| Keychain interaction denied | `KEYCHAIN_INTERACTION_REQUIRED` / 5 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |
| Keychain ACL migration required | `CONFIRMATION_REQUIRED` / 7 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |
| Keychain ACL migration canceled | `CONFIRMATION_REQUIRED` / 7 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |
| Keychain status failure or unknown local store error | `INTERNAL` / 1 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |
| Save canceled or deadline exceeded | `CANCELED` or `TIMEOUT` / 6 | `OAUTH_TOKEN_EXCHANGE_FAILED` / 5 |

These local cases do not get new stable `error.code` values in `v0.2.0`;
the hint supplies only case-specific repair prose. A local binding rejection
happens before Save,
so the old credential remains unchanged. A Save failure leaves the persisted
credential state unknown. This intentionally coarse
classification preserves the published refresh contract until a durable
cross-process fence can establish safe retry semantics. Refresh-token rotation
makes a lost or malformed response ambiguous:
the server may have consumed the old token even when this CLI cannot save the
new one. This release does not have a durable cross-process refresh fence.
The CLI does not repeat refresh within the same invocation. A failed token
request leaves the old credential in place. A later auth-dependent invocation, including
`auth status --check` or an authenticated read, may automatically send that
old refresh token again. Agents must avoid further auth-dependent commands
after a failed refresh and direct the operator to a fresh interactive login.
If the old credential remains present, the operator must explicitly approve
its replacement (`auth login --profile NAME --yes`); agents must not add
`--yes` automatically. The CLI's machine hints never prescribe an unattended
confirmation flag.

After a successful refresh response, local failures have fixed, actionable
diagnostics while retaining the same auth/5 code. A binding mismatch directs
the operator to inspect the local profile/credential binding; invalid token
validation directs them to local token validation and OAuth client
configuration. Other pre-Save validation failures direct them to inspect the
local binding check. None of these paths called Save, so the old credential
remains. Save failures keep persistence *uncertain*: the public hint identifies
one fixed local repair area—interactive Keychain access, an operator-approved
ACL migration, canceled Keychain authorization, an interrupted or timed-out
save, Keychain availability and permissions, or an unclassified local store
failure—without exposing the raw error or OSStatus. In every case the agent
stops auth-dependent commands and refresh retries. Only after the local issue
is addressed should an operator start a fresh interactive login and explicitly
approve replacement if required.

A future refresh-recovery change must first add a durable fence and test it
across separate CLI invocations.

Only fixed categories and numeric HTTP statuses are exposed. Server response
bodies, OAuth codes, PKCE verifiers, tokens, URLs returned by the server, and
raw transport errors never appear in the public error.
