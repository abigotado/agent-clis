# ADR-001: Split YouTrack agent access into a constrained Remote MCP read plane and a guarded local control plane with pluggable executors

- Status: Accepted for the fail-closed first slice
- Date: 2026-09-01
- Decision owner: Operator
- Applies to: YouTrack Cloud/Server 2026.2, Codex, Claude Code
- Update: the standard edition now permits YouTrack MCP write tools beside the CLI; the read-only editions keep the six-tool allowlist.

## Context

The integration must safely support multiple YouTrack instances and accounts, provide one installable skill for more than one agent host, keep routine reads ergonomic, and make mutations deliberate and recoverable.

YouTrack 2026.2 provides three relevant official extension surfaces:

- A remote MCP endpoint at `https://<instance>/mcp`, authenticated as a YouTrack user. Requests run with that user's permissions. The endpoint accepts a positive `tools=` filter and supports OAuth or permanent tokens. See [Remote MCP Server](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html).
- The public REST API at `<YouTrack-Service-URL>/api`, with explicit field selection and pagination. See [REST API URL and Endpoints](https://www.jetbrains.com/help/youtrack/devportal/api-url-and-endpoints.html), [Fields Syntax](https://www.jetbrains.com/help/youtrack/devportal/api-fields-syntax.html), and [Pagination](https://www.jetbrains.com/help/youtrack/devportal/api-concept-pagination.html).
- Custom MCP tools delivered inside a YouTrack app. They require Low-level Admin to upload, are available globally rather than attached to one project, and run with the current user's access. See [Custom MCP Tools](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html).

YouTrack 2026.2 also lets administrators manage OAuth clients. JetBrains recommends Authorization Code with PKCE for new applications when possible; OAuth tokens act on behalf of the authorizing user and do not exceed that user's permissions. See [OAuth 2.0 Authorization](https://www.jetbrains.com/help/youtrack/devportal/OAuth-authorization-in-youtrack.html) and [Authorization Code](https://www.jetbrains.com/help/youtrack/devportal/Authorization-Code.html).

### Safety-significant documentation conflict

The [Custom MCP Tools](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html) page states: predefined tools are read-only. The [Remote MCP Server](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html) page says the server can read and update issues and lists predefined mutations:

- `create_issue`
- `create_draft_issue`
- `update_issue`
- `change_issue_assignee`
- `add_issue_comment`
- `manage_issue_tags`
- `link_issues`
- `create_article`
- `update_article`
- `log_work`

The conflict cannot be safely resolved by assuming the broader read-only statement is authoritative. The exposed tool surface is what matters. Therefore the bare `/mcp` endpoint and `ignoreTools=` configurations fail the read-only requirement.

## Decision drivers

- Fail closed when YouTrack adds or changes predefined tools.
- Make the selected instance and account visible on every operation.
- Keep searches bounded and prefer exact reads after discovering an issue ID.
- Treat issue descriptions, comments, articles, usernames, and links as untrusted data.
- Keep secrets out of skill files, repositories, command lines, logs, and long-lived environment variables.
- Enforce a project allowlist for writes independently of the model and independently of YouTrack UI wording.
- Make dry-run possible without any network access.
- Ensure a single confirmation cannot authorize a different payload, profile, project, or later replay.
- Never blindly retry a mutation after a timeout or connection loss.
- Keep the shared skill portable across Codex and Claude Code.

## Decision

### 1. Remote MCP is the read plane, with layered enforcement

Each connection represents one named `(instance, account, access-mode)` profile, for example `youtrack_acme_alice_ro`. Its URL contains a positive allowlist:

```text
https://acme.youtrack.cloud/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true
```

JetBrains documents `tools=` as controlling which names are returned by `tools/list`; it does not explicitly promise that a direct `tools/call` for a hidden tool is rejected. Therefore `tools=` is a mandatory discovery allowlist, not by itself an authorization boundary. The install/compatibility validator must negatively test a hidden mutating call such as `update_issue` in non-production, using a syntactically valid but guaranteed nonexistent target so the test cannot mutate. Only a protocol-level unknown/forbidden-tool result passes; a domain validation/not-found response proves that the hidden tool was callable. The test must pass before a write-capable identity is accepted as “strict read-only”.

The host must pin the same names again when it supports a runtime allowlist. The preferred final boundary is a dedicated YouTrack identity/role with no mutation permissions. Where neither a verified host runtime allowlist nor a read-only identity is available, the profile is only “model-visible read-only”, not a strict read-only security boundary, and this limitation must be shown to the operator.

On connection, a validator verifies that the discovered tool set is exactly the expected set and that `get_current_user` matches the profile's expected identity. The instruction-only skill can refuse visible dangerous tools but cannot itself inspect raw `tools/list` on every host; surface validation belongs to installation and startup configuration gates.

The `ignoreTools=` parameter is not used: a denylist would expose future tools by default.

Remote MCP remains preferred for routine reads. When MCP comments are
unavailable, the standard CLI permits one exact-issue comments page with an
explicit profile, limit 1..100 and nonnegative offset. Bound-account verification
precedes one bounded comments page from the fixed GET endpoint with a limit+1
truncation sentinel; no additional pages are auto-fetched. This untrusted page
proves neither ordering, currentness, a stable
snapshot, complete history, nor reconciliation evidence. The portable and macOS
identity editions remain MCP-only, and the six-tool discovery and hidden-call
boundaries above are unchanged.

### 2. A local CLI is the guarded-write control plane; execution is pluggable

The recommended common component is a dedicated `youtrack-agent-cli`, not direct REST calls authored by the model and not predefined MCP mutation tools. The CLI exposes only enumerated operations and applies policy before any executor:

- explicit profile on every command;
- separately pinned YouTrack service URL, MCP URL, REST base, OAuth issuer/endpoints, and expected account identity;
- project IDs and keys allowlisted per profile;
- OAuth Authorization Code with PKCE by default, permanent token only as a fallback;
- refresh/permanent tokens in an OS secret store (macOS Keychain first adapter), never in profile files;
- pinned HTTPS boundaries for YouTrack and OAuth, allowing a cross-origin external Hub only when explicitly configured, with an explicit self-hosted CA policy when needed;
- deterministic, network-free plan generation;
- a short-lived confirmation receipt bound to the complete normalized intent and precondition, minted through a channel the agent cannot approve for itself;
- a helper-owned fixed-active cross-process authority coordinator shared with
  every approval-registry commit: durable `in_flight`, one exact-request permit, one
  send/outcome, durable close, and no restart/retry after permit, proven by
  exact two-party barrier schedules through enrollment and close/delete faults;
  registry acquisition binds a pre-read canonical intent. LaunchAgent lifecycle
  and process-local executor guards are not cross-process security boundaries.
  Only the uninterrupted owner closes after irrevocable capability quiescence;
  an unclosed lease quarantines all later authority even after restart/reboot.
  Already-closed cleanup uses the exact persistent reference and cannot delete
  a replacement active item;
- setup-first activation-smoke and post-grant plans whose stage token/context
  authorizes only one exact-artifact revision-1 enrollment from a proved empty
  disposable inventory, whose retained registry snapshot binds every later
  observation/index/set, and whose final observations prove terminal state and
  replay denial;
- external trusted-supervisor destruction of each disposable host after
  evidence export and before the successor activation-grant/publication
  signature, bound by disposal evidence. Live `stage_cleanup`, ACK-recovery,
  and helper-produced empty-inventory cleanup proofs are deferred;
- case-final assertion evaluation: operation observations carry no assertion
  IDs and only the runner's ordered post-transcript final observation can pass
  a case;
- a descriptor-bound embedded-helper profile expiry checked strictly at Gate,
  publication, installation, peer authentication, confirmation, permit, and
  registry proposal/final signing, registry commit, and final pre-send, with
  just-before/equality/after/between-check vectors at every boundary;
- at most one mutating HTTP request per intent;
- method-specific read reconciliation after success or an ambiguous transport result;
- no automatic replay of an ambiguous intent.

The future machine surface adds only `mutation authority status` and trusted-
UI `mutation authority recover`, with no plan ID or force-clear option. JSON v1
is retained, but exits 10..13 deliberately distinguish wait, trusted recovery,
artifact replacement, and reconfirmation; corruption/operator escalation uses
existing exit 1. Journal v2 is a prerequisite; only v1 `prepared` migrates and
every other valid v1 state is quarantined, not guessed.

Two executors are supported architecturally:

- **REST executor:** smallest deployable option and suitable for a controlled pilot. For create, the allowlisted project ID is in the mutation payload. For update/comment/link/work operations, however, the exact issue can move projects between the CLI's preflight GET and POST. The reviewed REST documentation does not establish a general conditional-write/version primitive, so project allowlisting is best-effort for these operations. This residual risk requires explicit operator acceptance.
- **Custom MCP executor inside a YouTrack app:** required when project allowlisting, receipt verification, nonce consumption, and mutation must be enforced atomically server-side. JetBrains documents that requests applying issue changes are processed in a single database transaction; it is a design inference, to be validated on a test instance, that a custom MCP action can perform the policy check and mutation in that one transaction. See [Transactions](https://www.jetbrains.com/help/youtrack/devportal/workflow-transactions.html) and [Custom MCP Tools](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html).

The local planner/approver remains mandatory with either executor because only it can provide a network-free plan, OS-protected human approval, and agent-provider-neutral profile/secret handling.

### 3. One portable skill routes between the planes

The common `youtrack-agent` skill contains no credentials and grants no authority. It:

- requires explicit profile selection;
- performs bounded discovery through the read-only Remote MCP connection;
- permits the standard CLI's bounded exact-comments fallback when MCP comments
  are unavailable; the portable and macOS identity editions remain MCP-only;
- switches to exact issue reads as soon as an ID is known;
- treats returned content as quoted evidence, not instructions;
- refuses all exposed MCP mutations even if a misconfigured server advertises them;
- uses the CLI receipt workflow for writes only after explicit user intent.

The canonical skill folder uses the common Agent Skills layout. Codex officially discovers local skills under `.agents/skills` or `$HOME/.agents/skills` and follows symlinks; Claude Code discovers them under `.claude/skills` or `~/.claude/skills` and also follows symlinks. See [OpenAI: Build skills](https://learn.chatgpt.com/docs/build-skills) and [Claude Code: Extend Claude with skills](https://code.claude.com/docs/en/skills).

### 4. Custom MCP write tools are optional for the pilot, but required for strict atomic project policy

A YouTrack app is the stronger executor when an organization requires a strict project boundary across concurrent issue moves. It may be deferred from an initial REST pilot because:

- installation requires Low-level Admin;
- tools become available globally across projects;
- the model-facing tool call reaches the server before a local network-free dry-run can act as a boundary;
- standard MCP annotations are hints, not a portable human-attestation mechanism;
- app rollout, versioning, and audit must be repeated for every instance;
- a custom app cannot solve local multi-profile secret management.

If pursued, custom write tools must still require an externally minted, single-use confirmation receipt and an internal project allowlist, consume the nonce in the same transaction, and reject any target whose current project ID/key is not allowed. Merely setting `destructiveHint` or relying on a client prompt is insufficient.

## Profile identity model

The stable profile key is not an instance nickname alone. It is:

```text
profile_id = local-name
youtrack_service_url = normalized HTTPS URL + service path
mcp_url = pinned Remote MCP URL
rest_base = pinned <service URL>/api
oauth_issuer = pinned Hub issuer (may be a different origin)
oauth_authorization_endpoint = pinned endpoint derived from issuer metadata
oauth_token_endpoint = pinned endpoint derived from issuer metadata
account_id = immutable YouTrack user/database ID where available
expected_login = human-checkable login/email
mode = ro | guarded-write
allowed_projects = [{id, key}]
```

No profile is silently selected when more than one exists. An issue like `ABC-123` is not assumed to identify an instance. The user must name the profile, or the agent must present a non-mutating choice and wait.

For same-instance, multi-account MCP connections, hosts may key OAuth state by endpoint rather than solely by local server name. The implementation must test this behavior. Until verified, simultaneous same-endpoint accounts use separate client configuration roots or separate securely supplied token contexts; they must never be emulated by silently replacing credentials under one profile.

## Alternatives considered

| Option | Advantages | Rejected/limited because |
|---|---|---|
| Bare official Remote MCP for reads and writes | Lowest implementation cost | Published tool surface includes mutations; no project allowlist, offline plan, portable receipt, or ambiguous-outcome policy |
| Remote MCP with `ignoreTools=` | Simple denylist | Fails open when new tools appear |
| Remote MCP with positive `tools=` for reads | Official, low friction, OAuth-capable | Accepted only as the read plane |
| Direct model-authored REST/curl | Flexible and official API | Credentials, payload validation, retries, and confirmation are too easy to mishandle |
| Third-party YouTrack CLI | Fast start | Not a trusted foundation without source, dependency, release, and credential-handling audit |
| JetBrains repository-local helper | Useful precedent | Not an independently supported YouTrack product CLI or stable cross-project contract |
| Custom MCP app for writes | Atomic server-side policy is possible; central enforcement | Requires admin/global rollout and still needs an external portable human-attestation channel |
| Own guarded REST CLI | Strong local planning, secrets, receipt, and portability | Accepted as common control plane; REST execution has documented TOCTOU residual risk |
| Local planner + custom MCP executor | Offline/human controls plus atomic server policy | Recommended strict target; highest implementation and deployment cost |

JetBrains support stated in 2026 that there was no official standalone YouTrack CLI; the official app tooling is for app/workflow package management, not general issue operations. See [JT-94681](https://youtrack.jetbrains.com/projects/JT/issues/JT-94681/Is-there-any-official-cli-rest-api-for-youtrack-itself) and [Using an External Code Editor](https://www.jetbrains.com/help/youtrack/devportal/js-workflow-external-editor.html).

## Consequences

### Positive

- The everyday read path uses the official supported Remote MCP integration.
- Future mutating tools remain absent from normal discovery because the server-side filter is a positive list; strict enforcement still depends on the host runtime or user permissions until the negative direct-call test establishes stronger server behavior.
- The skill stays provider-neutral and does not encode secrets or one vendor's permission extension.
- Guarded writes have a stable protocol that can be independently tested and audited.
- Ambiguous outcomes stop rather than multiplying side effects.

### Costs and residual risks

- Two planes must be configured and supported.
- OAuth behavior for two accounts on the same instance needs a compatibility spike per client.
- Local confirmation proves local human interaction, not organizational approval; stronger organizations may require SSO-backed approval or a server-side policy service.
- Some create/comment reconciliations are weaker without a preallocated plan marker or dedicated custom field.
- A normal pseudo-terminal prompt is not proof of human presence when the agent host can inject terminal input. The macOS write MVP therefore needs a trusted approval UI and a Keychain/Secure Enclave signing operation protected by LocalAuthentication (or an equivalent out-of-band approval channel); without it, writes remain disabled.
- User permissions remain an upper bound but are not sufficient as a lower-level safety policy; the local project allowlist must remain enforced.
- REST executors cannot strictly close the issue-move race for update/comment operations without a server conditional-write primitive. Strict deployments need the custom MCP executor or must remain limited to operations whose target project is part of the mutation itself.

## Revisit conditions

Revisit this ADR if JetBrains:

- resolves the predefined-tool documentation conflict and provides a server-enforced read-only mode;
- adds per-connection project allowlists or mutation approval receipts;
- publishes a supported general-purpose CLI with equivalent safety properties;
- adds idempotency keys or conditional write primitives to the REST API; or
- gives custom MCP tools a portable, server-verifiable human-confirmation mechanism.
