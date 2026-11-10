# MVP command and tool surface

Status: Accepted; fail-closed first-slice surface implemented

Current mutation boundary: only offline `prepare`, local `export`, and local
`status` are enabled. `confirm`, `apply`, and `reconcile` fail closed. Native
authority commands, permits, and the future workflow below are unimplemented.

## Remote MCP read surface

The MVP exposes exactly these official tools through each read profile:

```text
get_current_user
search_issues
get_issue
get_issue_comments
get_project
get_issue_fields_schema
```

No custom MCP tool and no predefined mutation tool is part of the MVP.

## `youtrack-agent-cli` principles

- It is not a general REST client and has no arbitrary method/path command.
- It accepts structured JSON over stdin or an explicitly named file, never large bodies as shell arguments.
- Every network operation requires `--profile`; there is no mutable global “current profile”.
- Machine output is versioned JSON on stdout; diagnostics go to stderr with secrets redacted.
- Exit codes distinguish policy denial, precondition failure, transport ambiguity, and reconciliation failure.
- Mutation HTTP retries are disabled.

## Profile and authentication commands

```text
youtrack-agent-cli profile list
youtrack-agent-cli profile show --profile <name>
youtrack-agent-cli profile validate --profile <name> --offline
youtrack-agent-cli profile add --from <non-secret-profile.json>
youtrack-agent-cli auth login --profile <name>
youtrack-agent-cli auth status --profile <name>
youtrack-agent-cli auth whoami --profile <name>
youtrack-agent-cli auth logout --profile <name>
```

`profile add` writes only non-secret configuration. `auth login` uses Authorization Code + PKCE where supported and writes refresh/permanent tokens only to the OS secret store. No command returns token material.

## Read helpers used by the write protocol

Routine agent reads prefer Remote MCP. The standard CLI also provides a bounded
exact-comments fallback when MCP comments are unavailable, alongside narrow REST
reads for policy and future reconciliation:

```text
youtrack-agent-cli inspect issue --profile <name> --id <ID>
youtrack-agent-cli inspect comments --profile <name> --id <issue-ID> --limit 10 --offset 0 -o json
youtrack-agent-cli inspect project --profile <name> --project <ID-or-key>
youtrack-agent-cli inspect schema --profile <name> --project <ID-or-key> --limit <1-100> --offset <n>
youtrack-agent-cli mutation status --plan-id <YTAP-ID>
```

Comments inspection requires an explicit limit in 1..100 and nonnegative offset.
Bound-account verification precedes one bounded comments page from the fixed
GET endpoint with a limit+1 truncation sentinel; never auto-fetch additional
pages. The returned untrusted page proves
neither ordering, currentness, a stable snapshot, complete history, nor
reconciliation evidence. The portable and macOS identity editions remain MCP-only.

There is no unbounded CLI search in the initial surface. A bounded internal search primitive exists only for reconciliation. For comments, the documented collection has `$top`/`$skip` but no author/time filter or ordering guarantee, so the CLI must not claim that such filters are server-enforced. Future reconciliation may use a preflight `commentsCount` plus a compatibility-tested bounded window; without a proven ordering/window algorithm or an activity endpoint, the result remains `operator_resolution_required`.

## Mutation protocol commands

```text
youtrack-agent-cli mutation prepare \
  --offline \
  --profile <name> \
  --kind <operation> \
  --project <immutable-ID:key> \
  --request-stdin \
  --expected-state <snapshot-or-hash> \
  --schema-sha256 <digest> \
  --out <plan.json>

youtrack-agent-cli mutation confirm \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation apply \
  --profile <name> \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation reconcile \
  --profile <name> \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation status \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation export \
  --plan-id <YTAP-ID> \
  --out <new-plan.json>
```

The implemented first slice enables only `prepare`, `export`, and `status`. `confirm`,
`apply`, and `reconcile` are present as stable fail-closed commands while Gate
1A and the executor compatibility gate remain open.

The future native-authority slice adds exactly these local commands:

```text
youtrack-agent-cli --profile <name> mutation authority status
youtrack-agent-cli --profile <name> mutation authority recover
```

Both require explicit `--profile`. They accept only text/JSON output (including
the retained `--json` alias), timeout, and verbose inherited flags; they reject
`--yes`, `--dry-run`, `--fields`, raw output, plan/lease/force selectors,
positional/stdin input, and environment overrides. Authority status is
bounded/read-only; recovery requires trusted UI and may delete only an exact
already-closed active item by its persistent reference. It has no YouTrack
network capability. An unclosed item is quarantined with exit 1 and no local
mutation; restart, reboot, expiry, or UI cannot clear it. Remote reconciliation
while quarantined only reads and reports, without journal CAS. Their exact
JSON v1 data plus required invocation `meta`, errors, and proposed exit-code
mapping (including 11/12) are specified in the registry
protocol and are not implemented by the current command tree.
They require journal record v2. Only a valid v1 `prepared` record migrates;
every other v1 state, including `failed_before_mutation`, is retained unchanged
and quarantined.

### `prepare --offline`

Guarantees zero DNS, socket, browser, or OAuth activity. It:

- loads only the non-secret profile and supplied snapshot/hash;
- validates operation schema and project allowlist;
- allocates `plan_id` and inserts it into the final audit marker/body before hashing;
- canonicalizes the request;
- calculates hashes;
- renders a human plan;
- chooses a reconciliation strategy;
- writes an unsigned plan.

It cannot claim that credentials, permissions, or current server state are valid.

### Future `confirm` — disabled

Launches a trusted approval UI that loads canonical plan bytes once and displays that immutable in-memory snapshot. Before accepting bytes, both peers must validate the offline-root-authorized exact Apple code identities and agree on the artifact-descriptor digest and exact authorization-context digest. Only after OS-verified user presence, the helper stores the displayed-byte SHA-256 in `plan_sha256` and signs the deterministic unsigned receipt that binds that digest to SHA-256 of the fresh IPC challenge, receipt ID, nonce, TTL, exact approval-registry revision, authorization context, active key generation/fingerprint, account, project, schema, request, and preconditions. It must not re-read a mutable plan file after display. A normal pseudo-terminal prompt is not sufficient when the agent host can inject input. The macOS MVP should bind the signing key to Keychain/Secure Enclave access control and LocalAuthentication, or use a genuinely out-of-band approval service. There is no `--yes`, environment override, piped stdin approval, or model-callable noninteractive mode. If no trustworthy presence adapter is available, `confirm` fails closed and guarded writes remain disabled.

### Future `apply` — disabled

Must satisfy the complete [native authority constraints](../docs/gate1a-registry-protocol.md), including receipt TTL and final send fences. After bounded read-only coordinator integrity/capacity classification, and before registry-ledger reads, apply contends with every registry commit on the unique fixed-active Keychain account. Protected active/closed records bind the exact receipt digest and bounded history rejects reuse under a new lease, including a null-permit burn; journal CAS is not authority. The uninterrupted owner enters `in_flight`, obtains one exact-request permit, sends once, records the outcome, irrevocably quiesces all capabilities, and adds durable normal close. Unclosed authority remains quarantined without journal CAS, including after reboot. The last owner reaching 256 permits or closes must close and retain its valid closed active item as the capacity sentinel. Status reports `capacity_exhausted` with action `stop` and exit 0; acquire/recover returns `AUTHORITY_CAPACITY_EXHAUSTED` with existing exit 1 and never deletes the sentinel. Capacity introduces no number beyond the coordinator's proposed exits 10..13 and existing codes; the current runtime remains at 0..9. See the [state table](08-implementation-decision.md#complete-state-table) for outcomes and expiry; all these requirements remain unimplemented.

### Future `reconcile` — disabled

Never mutates YouTrack. It re-runs method-specific bounded evidence checks; only eligible already-closed records may transition to `reconciled`, `resolved_not_applied`, or `operator_resolution_required`. Explicit local operator resolution may record `resolved_applied` or `resolved_not_applied`. Quarantined records allow reports only, without journal CAS. Historical validation retains the receipt and its complete authority branch without making either current authority; see the [state contract](08-implementation-decision.md#complete-state-table) and [native constraints](../docs/gate1a-registry-protocol.md).

## MVP operation kinds

### Stage A — recommended first release

| Kind | REST mutation | Preconditions | Reconciliation |
|---|---|---|---|
| `issue.create` | REST `POST /api/issues` or custom executor | Allowlisted project ID+key is part of payload; required fields resolved to IDs/types; schema hash; plan marker | Exact returned ID on normal success; on ambiguity, bounded project/author/time/marker/content-hash search |
| `issue.update` | REST `POST /api/issues/{issueID}` or custom executor | Exact issue; field/value IDs and schema hash; expected touched-state hashes | Exact issue read; compare touched fields and receipt/audit evidence; REST mode carries issue-move TOCTOU risk |
| `comment.add` | REST `POST /api/issues/{issueID}/comments` or custom executor | Exact issue; explicit visibility; plan marker | Exact comment ID on normal success; ambiguous REST result is conclusive only with a tested bounded retrieval algorithm |

The official API documents create/update issue and add-comment operations, explicit response `fields`, and per-operation permissions. See [Issues](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues.html), [Operations with Specific Issue](https://www.jetbrains.com/help/youtrack/devportal/operations-api-issues.html), and [Issue Comments](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues-issueID-comments.html).

### Stage B — after Stage A is proven

| Kind | Why deferred |
|---|---|
| `tags.change` | Bundle/name ambiguity and add/remove semantics need dedicated preconditions |
| `issues.link` | Link direction/type and duplicate-link reconciliation need focused tests |
| `work.log` | Time-zone, work type, attributes, and payroll/reporting impact |
| `assignee.change` | Can be represented through `issue.update`, but merits a clearer human plan |

### Not in the initial guarded-write MVP

- Article create/update.
- Attachment upload/delete.
- Issue/comment delete.
- Project/user/group administration.
- Arbitrary workflow commands.
- Silent notification suppression.
- Bulk mutations.

## Request schemas

Illustrative schema shapes, not implementation code:

```json
{
  "kind": "issue.update",
  "profile": "youtrack_acme_alice_write",
  "issue": "APP-123",
  "project": { "id": "0-12", "key": "APP" },
  "set": {
    "summary": "New summary",
    "customFields": [
      {
        "fieldId": "92-3",
        "displayName": "State",
        "type": "StateIssueCustomField",
        "valueId": "69-2",
        "displayValue": "In Progress"
      }
    ]
  },
  "expected": {
    "summarySha256": "...",
    "customFieldsSha256": "...",
    "schemaSha256": "..."
  },
  "planId": "YTAP-...",
  "notifications": "normal"
}
```

Visibility is explicit for create/comment operations. Omission means the CLI refuses when the operation could accidentally broaden visibility; it does not infer visibility from surrounding chat or issue text.

## Receipt marker policy

Reliable create/comment reconciliation benefits from a stable marker. Recommended order:

1. Dedicated organization-configured custom field or app-owned property, if available later.
2. A short visible audit footer such as `Agent plan: YTAP-<plan_id>` when the operator approves this policy.
3. Marker-free matching only when explicitly configured, with the understanding that an ambiguous timeout may require manual inspection and cannot be safely retried.

`plan_id` is allocated during offline prepare, so the marker is already in the canonical body shown to the human and covered by the receipt signature. Do not add or change a marker after confirmation. Do not assume Markdown comments are invisible or preserved in a canonical form without an instance compatibility test.

## One-shot and reconciliation rules

- Preflight GETs and postflight GETs are allowed; “one-shot” means exactly one mutating request.
- `failed_before_mutation` requires the uninterrupted owner, proof that no durable permit exists, and valid durable close. After permit, verified success is applied and every other result is ambiguous, even a definitive rejection or known zero bytes sent. Later eligible closed reconciliation may establish `resolved_not_applied`.
- A success response containing the created/updated entity is followed by exact verification.
- Timeout, connection reset, invalid/truncated response, or proxy 5xx after send is `ambiguous`. A crash without a valid durable close quarantines the unchanged journal, regardless of apparent permit absence. Only an uninterrupted owner can prove and close `failed_before_mutation`; no uncertainty authorizes replay.
- The CLI never resends the mutation for the same receipt.
- For an eligible already-closed record, a unique reconciliation match changes state to `reconciled`; zero/multiple plausible matches require operator resolution, are not proof of non-application, and never authorize an automatic fresh plan. While quarantined, both results are reports only and never change the journal or release authority.

## Versioned machine response

```json
{
  "schemaVersion": 1,
  "profile": "youtrack_acme_alice_write",
  "instance": "https://acme.youtrack.cloud",
  "account": { "id": "1-2", "login": "alice" },
  "receiptId": "YTAR-...",
  "operation": "issue.update",
  "target": "APP-123",
  "mutationAttempts": 1,
  "state": "reconciled",
  "evidence": { "issueId": "APP-123", "touchedFieldsMatch": true }
}
```

Error responses use the same envelope and never include authorization headers, OAuth codes/verifiers, tokens, full request bodies, or full untrusted server responses.

## Deferred custom MCP equivalent

If a YouTrack app executor is approved, its smallest coherent surface would be:

```text
<prefix>_get_write_policy          # read-only
<prefix>_preview_mutation          # read-only server validation, not the offline dry-run
<prefix>_apply_confirmed_mutation  # verifies an externally minted receipt, then one mutation
<prefix>_reconcile_mutation        # read-only
```

This does not replace the local/offline planner or human approval channel: a server-side preview is already a network operation, and a model-accessible pair of “preview then apply” tools does not prove human confirmation. The custom app becomes the strict executor only if it verifies the same external receipt/schema hashes, checks the issue's current project, consumes the nonce, and applies the mutation in one YouTrack transaction. JetBrains documents transaction atomicity for requests that apply issue changes; verifying this behavior for a custom MCP action is an implementation compatibility gate, not an assumption. See [Transactions](https://www.jetbrains.com/help/youtrack/devportal/workflow-transactions.html).
