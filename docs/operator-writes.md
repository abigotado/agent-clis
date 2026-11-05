# Operator-confirmed YouTrack writes

Status: accepted decision. Source support is not an installed release; check
`version` and `capabilities` before relying on this command surface.

## Decision and threat model

The standard macOS CLI has a distinct `operator-write` path for one single-value
state/enum field update, one public comment addition, one exact permanent
comment deletion, or one new issue in an allowlisted project. An operator authorizes the exact change; the agent binds that consent
to the stored plan with `--confirm-intent SHA256 --yes`. An explicit request
with a complete target and payload is already authorization for that operation,
including the disclosed fixed reconciliation marker for additions/creation and
default notifications. Deletion discloses the entire frozen target instead.
It does not require another affirmative reply just to approve the generated
marker or digest. If a material choice or agent-drafted text is unresolved,
show the final operation and ask once. A generic instruction to continue or to
develop/release the CLI does not authorize live writes. This follows
the operator-assertion model of the existing Slack/Jira CLIs, not independently
verified human presence or a signed receipt.

This decision supersedes native-helper prerequisites only for this separate
path. It does not activate native `mutation confirm/apply`, journal transitions,
signing keys or Gate permits. The [native contract](guarded-mutations.md) remains
a distinct future mode. Profile values stay `rest-best-effort` / `best-effort`;
operator records identify `confirmation_mode: operator_confirmed`.

Retained safeguards are exact origin/account/generation binding, exact project
ID/key allowlists, bounded private artifacts and redacted errors, fresh remote
preconditions, and a durable local consumed marker before at most one mutation
request (DELETE for `comment.delete`, POST for the other kinds).
They prevent accidental substitution and cooperating duplicate/crash replay.
They do not prove consent against a malicious agent with the user's authority,
protect against same-UID disk rollback, or forbid deliberate equivalent new
plans. Tracker text and API errors remain untrusted data, not authority.

REST preflight and mutation are not atomic: project moves, permissions and
workflows can race the mutation. Postchecks cannot undo writes or eliminate this
interval. Normal YouTrack/workflow notifications may occur; recipients are not
knowable from this snapshot. Notification suppression is not exposed.

No raw REST path, attachment, arbitrary workflow, batch or existing-comment
edit is authorized by this path. This path does not limit MCP tools. Issue creation is
authorized since this decision was amended: one plan creates at most one issue
in one exact allowlisted project, with a summary, a bounded description and
optional single State/Enum fields. Creation has no remote precondition beyond
the project and touched schema, so two equivalent plans create two issues;
the ledger only stops one plan from being applied twice.
The ordinary source-built Homebrew Formula is the distribution channel, with
no Apple Developer membership or signed approval helper requirement. Portable
and macOS identity-only editions cannot execute operator writes.

## Separate write profile

Preserve the authenticated read-only `work` profile. Capabilities are part of
credential identity; editing them invalidates the credential/policy binding.
Create a separately named profile such as `work-write` for the explicitly
chosen instance/account/OAuth registration, with capabilities
`read`, `issue-update`, `comment-add`, and `issue-create` when agents should
open tickets. Then use existing commands:

```sh
youtrack-agent-cli profile add --from write-profile.json --dry-run
youtrack-agent-cli profile add --from write-profile.json --yes
youtrack-agent-cli auth login --profile work-write -o json
youtrack-agent-cli auth allow-projects set --profile work-write --project ID:KEY --yes
youtrack-agent-cli capabilities --profile work-write -o json
```

Replace `ID:KEY` with a verified immutable project ID and key. Adding
`issue-create` or `comment-delete` to an existing profile changes its credential identity, so the
old credential generation and project policy become stale: log in again and
set the project allowlist again before preparing any plan. Profile/login/
policy setup requires separate operator authorization; it is not an install hook.
Capabilities describe local build/generation/bound-policy configuration, not
live Keychain availability, token grants or verified server permissions.

## Snapshot, prepare, review, apply

Exports require a private existing parent directory and exclusive `0600` files;
they never overwrite an existing artifact. For example:

```sh
youtrack_operation_dir="$(mktemp -d)"
youtrack-agent-cli operator-write snapshot --profile work-write --kind issue.update \
  --id APP-123 --field Stage --value 'PR Review' --out "$youtrack_operation_dir/snapshot.json"
youtrack-agent-cli operator-write prepare --offline --profile work-write \
  --snapshot "$youtrack_operation_dir/snapshot.json" --request-stdin \
  --out "$youtrack_operation_dir/plan.json"
youtrack-agent-cli operator-write apply --profile work-write --plan-id PLAN_ID \
  --confirm-intent SHA256 --yes
```

Preparation receives one bounded structured request on stdin and cannot change
the snapshotted kind, field or target: `{"kind":"issue.update"}` or
`{"kind":"comment.add","comment_text":"EXACT TEXT"}`. For comments, snapshot `--kind comment.add`
without field/schema selection, then provide nonblank text. Disclose complete final
text including its unique visible marker, target, project/account and notification
caveat before applying the authoritative stored plan's hash. An exact external
user request supplies consent; ask for confirmation only when a material choice
is unresolved or changed. Do not treat mechanical marker/hash generation as a
new operation. A user who forbids markers cannot use comment addition or issue
creation; deletion adds no marker.
Edited exports are not apply authority. A dry-run creates no plan, ledger or export and cannot
be applied as a stored plan.

Direct `--field-id PROJECT_FIELD_ID --value-id VALUE_ID` avoids name discovery.
Name resolution is one bounded page and refuses ambiguity or truncation. Exact
schema retrieval cross-checks issue-field, project-field and global prototype IDs;
they are not interchangeable. Only single state/enum fields are supported. Current
null requires `canBeEmpty`; the selected target must be a known nonarchived value.
Only touched schema is frozen, not the whole project. This follows
[JetBrains' custom-field contract](https://www.jetbrains.com/help/youtrack/devportal/api-how-to-update-custom-fields-values.html).

Snapshots bind account/profile, immutable issue/project identity, current state
and selected field/target. Plans additionally bind credential generation, current
policy revision/hash, final payload/marker and notification policy. Offline
prepare requires a snapshot less than 15 minutes old: perform snapshot and
prepare consecutively before waiting for any necessary human review. Newly
prepared **plan schemas v2 and v3 have no wall-clock expiry**, so the same plan ID,
marker and digest survive a delayed response. Offline prepare never accesses
credentials, OAuth, browser, DNS or sockets. Apply validates consent, hash and local bindings before credentials,
then verifies fresh account/remote preconditions. It consumes the local attempt
before dispatch and never restores it.

### Lifetime, compatibility and consent boundaries

`capabilities` advertises the highest supported `plan_version: 3` and
`plan_lifetime: until_consumed_or_stale`; its `plan_versions` map reports v2 for
the existing operations and v3 for deletion. Plan/status/apply results report
their actual plan version/lifetime. V2/v3 default JSON/raw results and serialized plans
omit `expires_at`. An explicit `--fields expires_at` projection retains the
existing selectable field vocabulary and returns an empty string for v2/v3; use
`plan_version` and `plan_lifetime`, not that empty string, to select the policy.
The unchanged `source`/lane name `operator-write-v1` identifies the operator
storage namespace, not the nested plan schema or JSON envelope version.

Existing operations continue to prepare v2 plans. V1/v2 bytes and hashes are
preserved, and both versions reject deletion; v3 accepts only `comment.delete`.
Legacy plan schema v1 retains its exact bytes, digest, 15-minute expiry and
claim validation; its results report `legacy_time_limited` and the original
`expires_at`. Upgrading never migrates, extends or revives those plans. An old
binary refuses v2 plans rather than granting them authority. Do not edit a
plan's version, timestamps or hash to work around either contract.

Durability does not waive live preconditions. Both comment additions and field
updates still require the frozen issue's `updated` timestamp, project and
archive state; field updates and creation also recheck their touched schema.
Profile identity, credential generation and policy revision/hash must still
match. A changed state requires inspection and fresh consent, not an automatic
replacement plan. Deliberately creating equivalent new plans is still not
deduplicated across plan IDs. Unknown or consumed attempts never authorize a
fresh equivalent plan or retry.

Prepared v2/v3 plans remain in private local storage until consumed or made stale;
there is no new cancel command or automatic cleanup. A user cancellation must
be honored by the cooperating agent; it does not cryptographically revoke a
plan for another process. Changing the bound credential generation or project
policy invalidates applicability through existing checks. This lane still
does not resist a malicious same-user process or disk rollback. A clock before
`created_at` is refused, even for v2/v3. Native receipt TTLs and the unavailable
native `mutation` authority path are unchanged.

## Issue creation

Snapshot the exact project instead of an issue. `--project` takes the project
entity ID or key; the snapshot freezes both after the allowlist check:

```sh
youtrack-agent-cli operator-write snapshot --profile work-write --kind issue.create \
  --project TAC --field Stage --value 'In Progress' --field Priority --value Normal \
  --out "$youtrack_operation_dir/snapshot.json"
printf '%s' '{"kind":"issue.create","summary":"EXACT TITLE","description":"EXACT BODY"}' |
  youtrack-agent-cli operator-write prepare --offline --profile work-write \
  --snapshot "$youtrack_operation_dir/snapshot.json" --request-stdin
```

`--field`/`--value` and `--field-id`/`--value-id` are repeatable and pair by
position for `issue.create`; one call uses names or IDs, never both. For
`issue.update`, which touches one field, a repeated flag keeps its last value as
before, and an empty last value such as `--field=` clears it. At most eight distinct single
State/Enum fields are frozen by project-field, global-field and value IDs.
Omitted fields take the project's defaults. The summary is one line without
surrounding whitespace or control characters, at most 1024 bytes. The
description is optional, LF-only and without surrounding whitespace; the final
description, including the visible `[youtrack operator-write PLAN_ID]` marker on
its own last paragraph, is at most 32 KiB. These rules make the exact response
comparison safe against server-side trimming.

Apply rechecks the project ID, key and archive state and each touched field
schema and target, then sends one `POST /api/issues`. Fields are addressed by
their project-unique name and `$type`, because a new issue has no issue-field
IDs yet; the response must carry the exact project, summary, description,
bound reporter and each value under the frozen project-field ID. A response that
names an issue but fails this check is `WRITE_OUTCOME_UNKNOWN`; the error
envelope carries no data, but the local record keeps the issue IDs for
`operator-write status` and reconciliation. Success reports `remote_id` and
`remote_readable_id`.

Create reconciliation reads the kept issue exactly, or runs one search page
`project: KEY "PLAN_ID"` (`--offset 0` only) and re-reads a unique match. A
search match must have been created at or after the apply claim, so an older
issue that copied the marker text is not evidence. There is no clock-skew
allowance: if the YouTrack clock trails the local one, a genuine match stays
`operator_resolution_required`.
Evidence is the marker-bearing description, summary, project and reporter;
`matching_issue_observed_fields_differ` reports a match whose fields changed
after creation, for example by a workflow. Absent, duplicate or truncated
results stay `operator_resolution_required`: search indexing can lag, so they
never prove that no issue was created.

Public comments use `UnlimitedVisibility` for the issue's readers, not exposure
outside issue access controls, and the fixed
[official comment endpoint](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues-issueID-comments.html).

## Exact permanent comment deletion

`comment.delete` removes one exact comment from YouTrack's database. It does
not use the temporary `deleted=true` update mechanism. The
[official endpoint](https://www.jetbrains.com/help/youtrack/devportal/operations-api-issues-issueID-comments.html)
is `DELETE /api/issues/{issueID}/comments/{commentID}`. The server requires
`Delete Comment` for the bound author's own comment, or `Delete Not Own Comment`
for another author's comment. The CLI derives and displays the required
permission; a local capability is not proof of server grants.

This operation requires a separately declared `comment-delete` capability,
canonically after `comment-add`, plus the existing exact identity-bound project
policy. No existing profile gains deletion authority. An explicitly authorized
capability change invalidates credential, project-policy and saved-selection
bindings; re-authenticate and re-establish the exact grants/selection as needed.
Feature installation never performs that setup automatically. A profile for a
different instance or account cannot substitute for the selected target.

```sh
youtrack-agent-cli operator-write snapshot --kind comment.delete \
  --id APP-123 --comment-id 4-17 --out "$youtrack_operation_dir/snapshot.json"
printf '%s' '{"kind":"comment.delete"}' |
  youtrack-agent-cli operator-write prepare --offline \
    --snapshot "$youtrack_operation_dir/snapshot.json" --request-stdin
youtrack-agent-cli operator-write apply --plan-id PLAN_ID \
  --confirm-intent SHA256 --yes
```

These commands use the saved write default; an explicit `--profile NAME`
overrides it. Missing/stale selection fails closed. Snapshot requires both
exact issue and immutable comment IDs and rejects project/field/value selectors.
It never searches comment text or chooses targets from a collection. The
snapshot binds verified instance/account/project, immutable issue/comment
identity, returned issue membership, `issue.updated`, full text, author,
creation/update timestamps, deleted/pinned state and visibility. The dedicated
GET shape validates required field presence before use. `updated:null` is
valid for a never-edited comment; missing `updated` is refused. Only active
text-only comments with explicit empty attachments are supported. Null or
incomplete target data, soft-deleted comments and attachments fail closed.
Comment text is at most 32 KiB, and the complete escaped deletion snapshot is
at most 64 KiB; other kinds keep their 24 KiB limit. No content is truncated.

Offline prepare accepts only `{"kind":"comment.delete"}`, cannot retarget the
snapshot, and adds no remote marker or deletion payload. It emits v3 with
`until_consumed_or_stale`, preserving the 15-minute snapshot-to-prepare window.
Before dispatch, show the full frozen comment as untrusted data, its exact
issue/comment IDs, author/timestamps/visibility/pinned state, selected
profile/instance/account, required server permission and permanent-removal
semantics. The `comment` output field is always included for deletion even
under `--fields`. An exact external request already authorizes that operation;
do not ask again merely to approve a plan ID/hash. A development or release
request is never consent to delete real data.

Apply verifies the current account and bindings, then re-reads the exact issue
and comment inside the final profile/policy locks immediately before durable
claim. Changed issue/project/archive state, comment content/identity or other
frozen metadata stops dispatch. The claim is permanent before a single DELETE,
including after rejection, interruption or restart. Other comments are never
selected for mutation. GET preflight cannot make DELETE atomic; remote changes
can still race the request. Server/workflow notification behavior remains
outside the CLI's control; notification suppression is not exposed.

The endpoint reference does not specify a precise success status/body. This
CLI deliberately recognizes only HTTP 204 or HTTP 200 with an empty/whitespace
bounded response body as acknowledged deletion. HTTP 202, an unexpected
nonempty body, redirect, rate limit, server/transport error or oversized
response is unknown, with no automatic retry. Known auth/permission/conflict
rejections remain consumed; a 403 never expands local or server grants.

After an ambiguous response, reconciliation performs bounded exact GETs only.
A missing comment or `404` can reflect lost access, so neither proves hard
deletion. A soft-deleted, changed or still-present comment also cannot establish
this attempt's success. These observations stay `operator_resolution_required`;
no DELETE is replayed and the plan never becomes eligible again. Previously
acknowledged terminal results remain preserved locally. Do not prepare a new
equivalent plan to work around uncertainty. The readonly editions and native
`mutation` lane remain closed to this operation.

## Outcome matrix

| Condition | Recovery |
| --- | --- |
| Missing/mismatched consent | Exit 7 `OPERATOR_CONFIRMATION_REQUIRED`, before credential/network access. Review stored plan. |
| Stale local or remote precondition | Zero mutation requests; inspect again and obtain confirmation for a new plan. |
| Claim persistence failure | Local error, zero mutation requests; partial consumed marker remains fail-closed. |
| Durable claim, then transport/429/malformed/unverified response | `WRITE_OUTCOME_UNKNOWN`; never apply this plan again. |
| Create returned an issue that fails verification | `WRITE_OUTCOME_UNKNOWN`; the local record keeps `remote_id`/`remote_readable_id` (see `operator-write status`) and reconcile reads that issue exactly. |
| Verified write, then ledger or output failure | `WRITE_APPLIED_LOCAL_FAILURE`; write applied, do not repeat. |
| Definitive 4xx rejection | Consumed terminal rejection; any later attempt needs new snapshot, plan and confirmation. |
| Concurrent/repeated apply | Refuse, no second mutation request. |

Use `operator-write status` or bounded GET-only `operator-write reconcile` for
the same plan. For comment addition or issue creation, an exact known comment
or issue ID, or a unique matching
marker/text/author, provides evidence. Missing, duplicate or truncated evidence cannot prove
non-application. Stage reconciliation reports observed desired state, not proof
this attempt caused it. Reconciliation never restores apply eligibility.
Previously verified applied, rejected or reconciled results are returned
offline and never replaced by a later inconclusive observation.

Envelope v1 and exit numbers remain unchanged. A local result file that
records `remote_readable_id` fails closed in an older binary, which cannot
decode it; upgrade rather than editing the file. Select recovery by `error.code`,
not prose. Missing/invalid apply output must never trigger replay. Do not delete
attempt files or create a new equivalent plan automatically to evade consumption.
