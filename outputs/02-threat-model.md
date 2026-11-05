# Threat model: multi-instance YouTrack agent integration

Status: Accepted for the fail-closed Gate 1A design; native and remote-write
gates are not passed
Method: asset/trust-boundary analysis with STRIDE-style threat enumeration
Update: the standard edition now permits YouTrack MCP write tools beside the CLI. Residual risk: such calls act with the connector account's own rights, outside the CLI's profile binding, project allowlist, frozen plan and reconciliation; the read-only editions are unchanged.

## Security objectives

1. A read request reaches only the explicitly selected instance and expected account.
2. Routine MCP sessions expose no mutating YouTrack tools, and strict profiles additionally block hidden direct calls through host runtime policy or read-only YouTrack permissions.
3. Search and collection reads are bounded in count and fields.
4. YouTrack content cannot grant authority, redirect credentials, or cause tool execution.
5. A write reaches only an allowlisted project and exactly the payload a human confirmed.
6. A mutation is sent at most once for one confirmed intent.
7. A timeout or dropped response never causes a blind retry.
8. Long-lived credentials do not appear in files, command lines, logs, model context, or generated receipts.

## Assets

- OAuth refresh tokens, access tokens, permanent-token fallbacks, and OAuth client secrets.
- YouTrack issues, comments, articles, links, tags, work items, users, and project metadata.
- Profile bindings between local name, instance origin, account ID/login, and allowed project IDs/keys.
- Helper-private Secure Enclave signing keys, append-only approval registry,
  exact artifact-descriptor digest, receipt nonce journal, and audit records.
- Developer ID identity, nested helper provisioning profile, signed/notarized
  bundle, pinned offline Ed25519 authorization root, detached descriptor,
  Gate tokens/evidence sets, provisional production authorization,
  activation-smoke evidence, production activation grant, and publication
  envelope.
- User trust: the meaning of a confirmation and the expectation that a dry-run has no network side effect.

## Trust boundaries

| Boundary | Data crossing it | Required posture |
|---|---|---|
| Agent model ↔ host tool runtime | Tool name, arguments, returned content | Runtime enforcement; never rely on prompt compliance alone |
| Host ↔ YouTrack Remote MCP | OAuth/token, tool discovery, issue content | HTTPS, pinned MCP URL, `tools=` discovery allowlist, host runtime allowlist/read-only identity, identity check |
| Skill ↔ local CLI | Explicit profile, normalized operation payload | Strict schema; stdin/file descriptor for bodies, not shell interpolation |
| CLI ↔ OS secret store | Refresh/permanent tokens | Secret-store APIs; values never returned to the agent |
| CLI ↔ native approval helper | Canonical display bytes, fresh challenge, descriptor and authorization-context digests, bounded registry read, signed receipt | Connection-bound audit token, Developer ID Team/bundle baseline plus offline-root-authorized exact Apple code identities, peer digest agreement, bounded framed protocol, timeout, no caller-selected endpoint |
| Release/Gate authority ↔ CLI/helper | Detached descriptor, per-architecture runner tokens/evidence sets, provisional authorization, activation-smoke plan/evidence, production activation grant | Pinned Ed25519 root and domains; private key offline; exact canonical bytes; two complete fresh-session Gate passes and activation smoke on every declared architecture; no in-band rollover |
| Trusted Gate host/runner ↔ offline release operator | Test execution, transcripts, evidence index | Clean/reverted dedicated host, signed reviewed runner, operator-supervised run, complete evidence review; content addressing detects later tampering but is not proof of honest execution |
| Native helper ↔ private data-protection Keychain/Secure Enclave | Generation-specific private key, immutable registry transitions, and apply-authority lease/permit/closed records | Helper-only provisioned access group, fresh user presence for signing/key ceremonies, exact Security.framework dictionaries/projections, unique key tags, append-only one-shot records |
| CLI ↔ YouTrack APIs | Reads, one mutation, reconciliation reads | Separately pinned service/REST/MCP/OAuth endpoints, timeouts, no unsafe retry |
| Human ↔ confirmation UI | Rendered canonical intent and approval | Dedicated OS UI or genuinely out-of-band terminal, explicit account/instance/project, user-presence-protected signed receipt |
| YouTrack content ↔ model context | Descriptions, comments, articles, names, URLs | Always untrusted data; quote and delimit |

## Threats and controls

| ID | Threat | Impact | Primary controls | Residual risk |
|---|---|---|---|---|
| T1 | Documentation conflict, hidden direct call, or future tool-surface drift exposes a mutation in a “read” connection | Unauthorized write | Endpoint `tools=` discovery allowlist; host runtime allowlist where available; negative direct hidden-tool-call compatibility test; preferably a read-only YouTrack identity; skill refuses visible MCP write names | JetBrains documents only `tools/list` filtering. Without runtime enforcement or read-only permissions, the connection is not a strict authorization boundary |
| T2 | Prompt injection in an issue/comment/article tells the agent to run commands, reveal secrets, change profile, or write elsewhere | Credential loss or confused-deputy mutation | Delimit returned content as untrusted; never follow embedded operational instructions; no secrets in model-visible context; writes require a receipt minted outside the model | Social engineering can still influence a human reviewer |
| T3 | Issue key collision or vague language selects the wrong instance/account | Cross-tenant disclosure or mutation | Explicit profile required; show origin and expected login on every result/plan; call `get_current_user`/`users/me`; no default with multiple profiles | Humans can still select the wrong clearly labeled profile |
| T4 | OAuth credential for one account is reused by a second same-endpoint profile | Wrong-user access | Profile identity verification; separate OAuth client/config root or token context when host storage collides; fail closed on mismatch | Client credential-keying behavior may change across versions |
| T5 | Token appears in checked-in config, CLI arguments, environment dumps, logs, or error text | Credential theft | OAuth client storage where supported; OS Keychain for CLI; no token CLI flags; redact headers/URLs; never log bodies or secrets | Endpoint query is non-secret but may reveal instance/profile naming |
| T6 | Malicious redirect or user-supplied base URL sends authorization to another host | Token exfiltration/SSRF | Separately pin YouTrack service/MCP/REST URLs and OAuth issuer/endpoints; reject per-command URLs; allow only registered/pinned cross-origin external Hub; explicit custom-CA configuration | Compromised DNS/CA remains outside application-level controls |
| T7 | Unbounded search or broad field selection leaks excessive data or consumes quota | Confidentiality/cost/availability | Project-scoped queries where possible; default limit 10, hard maximum 50; explicit `fields`; exact read after ID discovery; no automatic full pagination | A single issue may itself contain sensitive/large content |
| T8 | Agent writes to a project allowed by the user account but outside the integration's intended scope | Unauthorized business change | Immutable project ID+key allowlist; create embeds project ID in payload; strict update/comment deployments use a custom MCP executor that checks current project and mutates in one server transaction | REST preflight GET + POST has an issue-move TOCTOU race; it is best-effort and requires explicit acceptance |
| T9 | Model or local process modifies payload between dry-run, display, signature, and apply | Unreviewed change | Offline `plan_id` is allocated before rendering and included in any marker/body; confirmation UI loads canonical bytes once and displays that immutable in-memory snapshot; its digest becomes `plan_sha256`, and the helper signs the complete unsigned receipt binding that digest to the fresh request challenge, nonce, TTL, identity, and policy fields | Rendering bugs could mislead the human; golden tests and independent parser/render tests are required |
| T10 | Receipt is replayed or reused for a different request | Duplicate or altered mutation | Fresh 32-byte challenge whose SHA-256 is signed in the receipt; constant-time response binding; short TTL; one-time nonce journal; exact intent hash; atomically mark in-flight before network; consumed/ambiguous terminal states | Local journal rollback from backups could re-enable a nonce; server-side marker helps detect it |
| T11 | State changes after planning but before apply | Lost update or invalid transition | Exact preflight read; compare expected state/version fingerprint; abort on mismatch; never silently re-plan | YouTrack REST documentation reviewed here does not establish a general conditional-write primitive |
| T12 | Connection drops after YouTrack commits but before response | Duplicate mutation if retried | Exactly one mutating request; mark outcome ambiguous; perform bounded read reconciliation; never auto-retry | Comments REST documents no author/time filter or ordering guarantee; without a verified tail algorithm or marker-backed activity query, comment/create outcomes can remain unresolved |
| T13 | HTTP library retries POST automatically | Duplicate mutation | Disable automatic retries for mutation methods at every layer; tests with forced timeout/reset | Infrastructure outside the CLI could still retry if misconfigured |
| T14 | Custom MCP app is assumed project-scoped but is globally available | Organization-wide unexpected exposure | Do not install unless the operator selects the strict executor; require internal project allowlist, explicit `customToolPackages=`, non-production validation, and independent review | All users can discover the package when explicitly requested, subject to their permissions |
| T15 | MCP annotations such as `readOnlyHint`/`destructiveHint` are treated as enforcement | Writes without reliable approval | Treat annotations as metadata only; enforce at endpoint, client runtime, CLI, and receipt validator | Host UI may present misleading labels |
| T16 | Third-party CLI or dependency is compromised | Credential theft or arbitrary mutation | Do not adopt without source/dependency/release audit; minimize CLI dependencies; signed releases/SBOM later | Own implementation still has supply-chain dependencies |
| T17 | Confirmation is minted by the agent rather than a human | Approval bypass | A normal PTY is explicitly insufficient when the agent can inject input; use dedicated trusted UI plus Keychain/Secure Enclave key access protected by LocalAuthentication, or an out-of-band approval service; no noninteractive override | A user can still approve without reading; the UI must render instance/account/project/diff before the OS presence check |
| T18 | Reconciliation search itself is broad or fooled by similar content | False success/failure | Exact target reads first; bounded time window, author, project, receipt ID, and content hash; return `ambiguous` unless unique | Marker-free create reconciliation can remain inconclusive |
| T19 | A same-user process replaces, races, or speaks directly to the helper endpoint | Approval or registry confused deputy | Both peers authenticate the connection audit token against Developer ID requirements and the offline-root-authorized exact `kSecCodeInfoUnique` / `kSecCodeInfoCdHashes` set; fixed bounded protocol; descriptor-digest agreement; CLI cannot select an endpoint; helper-private Keychain group; fresh trusted UI and user presence for authority transitions | The same user can interfere with local IPC and deny service; availability is fail-closed, not guaranteed |
| T20 | Concurrent helpers, crash recovery, or malformed/forked registry state loses a rotation/revocation update | Wrong approval key or revived authority | Immutable deterministic revision accounts; one `SecItemAdd` contender per next revision; predecessor hashes; complete bounded gap-free enumeration; exact post-add read and one-read ambiguous reconciliation; no update/delete/retry | A complete older Keychain-ledger snapshot is internally valid and cannot be detected without an external high-water mark, whether the current or an older binary reads it |
| T21 | An older legitimately Developer-ID-signed matched CLI/helper pair satisfies publisher identity and accesses the stable Keychain group | Newer policy is bypassed by side-loaded old code | First release has no production predecessor; the provisional authorization and activation grant pin the exact first-release code identities and capability; mixed or rebuilt peers fail; Gate tests a never-shipped old-build fixture; Cask refuses downgrade; a second write-capable build is prohibited until key, registry, credential, stale-token, and authorization-root rollover is solved | Restoring the complete identical first-release artifact together with its valid authority sidecars remains allowed; complete Keychain rollback is still outside the claim |
| T22 | Rotation creates duplicate-tagged or orphaned Secure Enclave keys | Ambiguous key selection or stale signing authority | Fresh random key ID and unique tag for every generation attempt; registry binds tag/SPKI/fingerprint; only committed active tag may sign; bounded enumeration, non-authoritative retention, and no key reuse | Orphaned and retired keys count toward the 64-key cap and can deny future rotation; ordinary cleanup remains unavailable until a separately reviewed authority protocol exists |
| T23 | A same-Team/ID/build rebuild reuses another artifact's Gate evidence | Untested code gains confirmation or write authority | Offline-root-signed descriptor binds every architecture's Apple code identities; both peers validate self and audit-token peer; two complete per-architecture Gate evidence sets, provisional authorization, smoke evidence set, and activation grant all bind the same descriptor | Compromise of the offline root can mint authority and requires an out-of-band incident/rollover design |
| T24 | A valid Gate-only token leaks or is replayed as production authority | Failed candidate runs outside the disposable Gate host | E1/E2 tokens use distinct domains, exact Gate-runner code identity, capability, expiry, and fresh session nonce; production peers reject Gate domains; failed candidates and tokens are quarantined | The clean Gate host, signed runner, and supervising operator are trusted release inputs. A compromised runner/OS can fabricate test evidence and may induce the offline operator to authorize a bad artifact; content hashes do not prove honest execution |
| T25 | A sidecar is swapped, symlinked, truncated, or parsed differently by CLI/helper | Peers authorize different code/policy | Fixed archive/install paths; bounded no-follow regular-file reads; strict canonical re-encode; pinned-root signatures; authenticated agreement on descriptor and authorization-context digests; immutable registry and receipts bind those digests | Same-user deletion can deny service; availability remains fail-closed |
| T26 | Recovery is selected while the current approval key is still usable or its failure is only transient/canceled | Attacker or confused operator replaces the approval root without continuity | Recovery requires a valid gap-free ledger and either already-disabled state or one exact active-tag lookup returning `errSecItemNotFound`; a returned key triggers a domain-separated continuity probe and forbids recovery, while every cancel/auth/transient/unknown result fails closed; final signature binds the recovery-evidence digest | A compromised Keychain/Security.framework can lie about item absence and is outside the local helper threat boundary |
| T27 | A post-Gate capability becomes reusable before its mandatory production-path smoke succeeds, or a smoke receipt is replayed after activation | Untested or failed code gains production confirmation/write authority | Post-E2 authorization is provisional and denies ordinary use; a fresh per-architecture smoke token authorizes only its content-addressed deny-only workflow; the journal persists a stage-tagged descriptor/provisional/token/context set and terminalizes any hard-denied attempt as non-reconcilable `activation_smoke_consumed`; smoke receipts remain context-ineligible and are destroyed with the disposable environment; only a later root-signed activation grant over the complete smoke evidence set enables production | The offline operator and pinned root remain trusted to review and sign the correct evidence set |
| T28 | Authority sidecars are replaced or revoked after a request becomes in-flight | Reconciliation cannot prove what capability authorized an ambiguous write | The journal atomically retains the exact canonical descriptor, signed provisional authorization, signed activation grant, derived final context, receipt, SPKI, and all digests before dispatch; read-only reconciliation rebuilds and verifies that historical root-signature/hash chain without requiring it to remain active | Same-user deletion or rollback of the complete journal can still deny or confuse local audit availability; it never authorizes a retry |
| T29 | Provisional smoke passes but the later activation-grant parser, final-context derivation, or production wiring is defective | Capability or context bugs appear only after publication | After the grant is signed, every declared architecture loads the exact provisional/grant pair and exercises ordinary commands with final-context schema-v3 receipts under a separate deny-only runner token; the publication envelope binds the complete evidence set | The grant is cryptographically usable during this bounded pre-publication window; the disposable Gate host and supervising operator are trusted to quarantine every failed candidate, token, and grant |
| T30 | Concurrent apply/registry commits, same-user helpers in alternate bootstrap namespaces, owner pause/crash, or active cleanup ABA | Stale authority sends or cleanup removes a newer lease | Unique fixed-active Keychain add is the cross-process mutex; local executor and SMAppService are lifecycle/local serialization only. Original uninterrupted owner irrevocably quiesces all capabilities before normal close. Non-owner unclosed state quarantines with no journal CAS, close synthesis, or deletion. Already-closed cleanup deletes only its exact persistent reference, so stale A deletion preserves replacement B | Same-user launchctl/bootstrap control is in scope. OS/Keychain compromise is outside scope; a crash can indefinitely deny guarded writes until a separately reviewed recovery/reset protocol exists |
| T31 | Embedded Developer ID profile expires after Gate/install but before authority use | Expired evidence authorizes signing or writes | Descriptor binds exact CMS profile expiry; all 22 Gate/grant/publication/install/runtime boundaries require trusted time strictly before it, with 88 before/equality/after/between-check vectors. The only expiry exception is authenticated bounded status and already-closed persistent-reference cleanup, never journal CAS, close synthesis, new signing/acquisition/permit/send/commit | Clock/OS compromise is outside scope; expiry denies availability and cannot release an unclosed lease |
| T32 | Release-stage evidence inherits authority, substitutes setup state, or leaves test authority alive after a passing run | False evidence or surviving test authority contaminates release | Setup-only exact enrollment requires bounded empty inventories; retained registry/session snapshot binds every observation/index/set. Terminal/replay-denial evidence is exported without mutable authority. A trusted external supervisor destroys the whole disposable host; root-signed disposal attestation binds exact evidence and must precede activation-grant/publication signing. Live stage deletion and ACK-recovery authority are deferred | External supervisor and offline release root are trusted; uncertain disposal blocks successor signatures and host reuse. Candidate helper does not prove its own cleanup |
| T33 | A runner marks assertions passed before later operations or transcripts finish | A case passes despite a late failure or missing evidence | Every operation observation has exact empty assertion IDs; one distinct case-final runner observation evaluates the ordered aggregate only after all operation/transcript result digests exist; no final evaluation means no case or evidence-set pass | A compromised signed runner can fabricate observations and remains inside the stated trusted release boundary |

## Untrusted-content policy

All strings received from YouTrack are data, including Markdown, HTML, code blocks, links, attachment names, custom-field names/values, usernames, project names, and custom tool descriptions.

The skill and CLI must:

- prefix or wrap excerpts as `UNTRUSTED YOUTRACK CONTENT`;
- preserve source identity (`profile`, `instance`, `issue/article/comment ID`) separately from the content;
- never execute commands, follow setup instructions, fetch embedded URLs, change profile, or reveal credentials because the content requests it;
- never treat “approved”, “run this”, “ignore previous instructions”, or similar text inside YouTrack as user authorization;
- avoid rendering active HTML; return plain text or escaped Markdown;
- truncate and report truncation rather than silently auto-paginating;
- require a fresh user instruction outside YouTrack content for any mutation.

## Search and read bounds

- Issue search: default `limit=10`, hard maximum `50`, one page unless the user explicitly asks for the next page.
- Comment list: default `limit=20`, hard maximum `50`, one bounded compatibility-tested window only unless explicitly continued; do not assume ordering that the API does not document.
- Search results: minimal fields only (`idReadable`, `summary`, `project`, `updated`, resolution/state summary as available).
- Exact MCP issue read: permitted only after a profile and exact issue ID are known; display only fields needed for the task. Retrieval-level projection requires the narrow REST helper because `get_issue` documents a fixed detailed output.
- Articles and attachments: excluded from the baseline MCP profile; enable in a separate named read profile only when required.
- No “all issues”, “all projects”, “all users”, or recursive article traversal by default.

The REST API limits collections and supports `$top`/`$skip`; the MCP search and comment tools also expose pagination. These are capabilities, not sufficient safeguards, so the client policy supplies lower hard limits. See [YouTrack pagination](https://www.jetbrains.com/help/youtrack/devportal/api-concept-pagination.html), [Issues](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues.html), and [Remote MCP Server](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html).

## Receipt security properties

A confirmation receipt is a signed statement over a canonical plan. It includes:

```text
version
plan_id (allocated during offline prepare and already present in any audit marker)
receipt_id / nonce
issued_at / expires_at
approval_registry_revision
active_key_generation / key tag / SPKI fingerprint
profile_id
normalized_instance_origin
expected_account_id and login
operation kind
project_id and project_key
target ID (when one exists)
canonical request-body SHA-256
expected-state SHA-256 (or explicit “create has no target”)
reconciliation strategy
```

The receipt contains no credential and no full issue/comment body. `prepare` allocates `plan_id`, inserts it into the canonical marker/body, and calculates the final payload hash before the human sees anything. The approval UI loads the canonical bytes once and renders that immutable snapshot; it must not re-read a mutable plan file after display. The separately signed native helper first verifies the offline-root-authorized exact artifact and current event-sourced registry, then stores `SHA256(displayed_bytes)` as `plan_sha256`. It uses the active generation-specific Secure Enclave key to sign the deterministic unsigned receipt containing that digest, the exact current registry revision and active key identity, SHA-256 of the fresh IPC challenge, nonce, TTL, profile/account/project, policy, request, and precondition bindings. Confirmation-response acceptance checks the outstanding challenge, artifact descriptor, and exact helper-registry revision before the receipt is journaled. Apply requires that same descriptor, revision, key, and authorized capability to remain current and active; retained keys verify historical audit/reconciliation evidence only. Any registry transition invalidates a confirmed receipt for apply. Confirmation expires quickly (recommended 5 minutes), is single use, and is atomically marked `in_flight` before the network mutation. The signing operation requires fresh LocalAuthentication-backed user presence; merely reading a generic Keychain password from an agent-invoked process is not sufficient attestation.

## Ambiguous-outcome state machine

```text
prepared -> confirmed -> in_flight -> applied -> reconciled
                              |           |
                              |           `-> reconciliation_failed
                              `-> ambiguous -> reconciled | operator_resolution_required
```

There is no transition from `ambiguous` back to `confirmed`. A retry is a new intent, requiring an operator decision after reconciliation.

## Out of scope for this threat model

- Compromise of the YouTrack server, OAuth authorization server, or agent provider.
- Organization-wide data classification and retention policy.
- Approval delegation, four-eyes approval, and centralized compliance workflows.
- Attachment upload/download and arbitrary article writes in the MVP.
- OS kernel, Secure Enclave, Keychain service, Apple code-signing/notarization,
  Developer ID account, or administrator/root compromise.
- Detection or cryptographic prevention of an interactive operator,
  administrator, backup/restore mechanism, or compromised Keychain service
  replacing the approval ledger with any older complete snapshot, with either
  the current or an older validly signed release; the first release has no
  external monotonic high-water service.
- Execution of a hypothetical older matched write-capable CLI/helper pair. No
  such production predecessor exists for the first release, and publishing a
  second write-capable build is blocked until a reviewed rollover design makes
  this case in scope.
