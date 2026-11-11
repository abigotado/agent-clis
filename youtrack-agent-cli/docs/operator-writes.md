# Operator-confirmed YouTrack writes

Status: accepted decision. Source support is not an installed release; check
`version` and `capabilities` before relying on this command surface.

## Decision and threat model

The standard macOS CLI has a distinct `operator-write` path for one single-value
state/enum or single-user field update (set or clear), one public comment addition, one exact permanent
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
optional single State/Enum/User fields (a User field needs the separate
`issue-create-user-fields` capability). Creation has no remote precondition beyond
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
`issue-create`, `issue-create-user-fields`, `issue-link` or `comment-delete` to an existing profile changes its credential identity, so the
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
they are not interchangeable. Supported fields are single state/enum fields and
single user fields (for example Assignee). Current
null requires `canBeEmpty`; the selected state/enum target must be a known
nonarchived value. Only touched schema is frozen, not the whole project. This follows
[JetBrains' custom-field contract](https://www.jetbrains.com/help/youtrack/devportal/api-how-to-update-custom-fields-values.html).

### User fields and clearing

A single user field (`SingleUserIssueCustomField`, `UserBundle`) is set with
`--value LOGIN` (exact login, matched against the field's bundle users) or
`--value-id USER_ID`; a banned or ambiguous target is refused. `--clear-value`
(only `--kind issue.update`, exactly one `--field`/`--field-id`, never with
`--value`/`--value-id`) empties the field; it requires `canBeEmpty` and a
currently set value. `--value ""` still means "no selector", never clear. A
user value freezes only `id`, `login` and type (no name or email), and the
current holder need not still be in the bundle. The plan's `target_value` is
`null` for a clear; the key is always present. Dispatch sends `{"id":...}` for a
user and `null` for a clear.

Refusals, all exit 2 with a distinct `error.code`: `OPERATOR_FIELD_UNSUPPORTED`
(field schema the CLI cannot write; it replaces the former `USAGE` `error.code`,
exit stays 2, the hint changed),
`OPERATOR_FIELD_REQUIRED` (clear on a field that cannot be empty),
`OPERATOR_FIELD_ALREADY_EMPTY` (clear on an empty field) and
`OPERATOR_FIELD_ALREADY_SET` (target equals the current value). Do not retry
these unchanged.

Changing an assignee can notify a third party, and profiles with the
`issue-update` capability gain this authority: they previously could not touch
user fields. Review the profile's capabilities before relying on it.

Contract change: all refusals from the apply-time re-freeze of the field for
`issue.update` (for example an archived target) now report `error.code`
`OPERATOR_FIELD_STALE` with exit 9 (conflict, re-read). Cases that previously
reported `OPERATOR_FIELD_VALUE_INVALID`, `OPERATOR_BUNDLE_INVALID` or
`OPERATOR_FIELD_MAPPING_INVALID` at exit 9 changed code with the same exit;
cases that previously exited 2 moved to exit 9. A stored plan whose target
already equals the current value is now refused at apply as
`OPERATOR_FIELD_STALE` instead of sending a no-op POST. Errors from reading the issue or project
field pass through unchanged. The `inspect schema` request now also asks for
`banned` on `aggregatedUsers`; its output is unchanged.

Snapshots bind account/profile, immutable issue/project identity, current state
and selected field/target. Plans additionally bind credential generation, current
policy revision/hash, final payload/marker and notification policy. Offline
prepare requires a snapshot less than 15 minutes old: perform snapshot and
prepare consecutively before waiting for any necessary human review. Newly
prepared **plan schemas v2, v3 and v4 have no wall-clock expiry**, so the same plan ID,
marker and digest survive a delayed response. Offline prepare never accesses
credentials, OAuth, browser, DNS or sockets. Apply validates consent, hash and local bindings before credentials,
then verifies fresh account/remote preconditions. It consumes the local attempt
before dispatch and never restores it.

### Lifetime, compatibility and consent boundaries

`capabilities` advertises the highest supported `plan_version: 4` and
`plan_lifetime: until_consumed_or_stale`; its `plan_versions` map reports v4 for
`issue.update`, `issue.edit`, `issue.create` and `issue.link` (previously prepared v2 `issue.update` and `issue.create` plans are still accepted but cannot carry
user fields or a null target), v2 for comment addition, and v3 for deletion. Plan/status/apply results report
their actual plan version/lifetime. V2/v3/v4 default JSON/raw results and serialized plans
omit `expires_at`. An explicit `--fields expires_at` projection retains the
existing selectable field vocabulary and returns an empty string for v2/v3/v4; use
`plan_version` and `plan_lifetime`, not that empty string, to select the policy.
The unchanged `source`/lane name `operator-write-v1` identifies the operator
storage namespace, not the nested plan schema or JSON envelope version.

New `issue.update`, `issue.edit`, `issue.create` and `issue.link` plans are v4; comment addition continues to
prepare v2 plans. V1/v2 bytes and hashes are preserved, v2 plans remain
accepted and appliable, and both versions reject deletion; v3 accepts only
`comment.delete` and v4 only `issue.update`, `issue.edit`, `issue.create` and `issue.link`. Only v4 can encode a User field or
an explicit `null` target (clear), in an update field or in any create field; v1-v3 plans refuse both.
A v4 create plan adds no member beyond the v2 shape.
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

Prepared v2/v3/v4 plans remain in private local storage until consumed or made stale;
there is no new cancel command or automatic cleanup. A user cancellation must
be honored by the cooperating agent; it does not cryptographically revoke a
plan for another process. Changing the bound credential generation or project
policy invalidates applicability through existing checks. This lane still
does not resist a malicious same-user process or disk rollback. A clock before
`created_at` is refused, even for v2/v3/v4. Native receipt TTLs and the unavailable
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
State/Enum/User fields are frozen by project-field, global-field and value IDs,
and a clear counts toward the eight.

A single-user field such as Assignee is set by exact login (`--field Assignee
--value LOGIN`) or by user ID (`--field-id ID --value-id USER_ID`), under the same
bundle rules as `issue.update`: the user must be exactly one unbanned user in the
field bundle's `aggregatedUsers`, and only the ID, login and `User` type are
frozen. The request body is `{"name":"Assignee","$type":"SingleUserIssueCustomField","value":{"id":"USER_ID"}}`.
Setting an assignee notifies a third party.

`--clear-field NAME` and `--clear-field-id PROJECT_FIELD_ID` (repeatable, `issue.create`
only, never with `--clear-value`) leave a field empty at creation by sending
`"value": null`. The project field must allow empty values (`canBeEmpty`), else
`OPERATOR_FIELD_REQUIRED` (exit 2). They work for State, Enum and User fields; names
and IDs are never mixed in one call (`--clear-field` goes with `--field`,
`--clear-field-id` with `--field-id`) and each field is named once.

Setting or clearing a User field needs the `issue-create-user-fields` capability
in addition to `issue-create`; without it the CLI refuses with
`OPERATOR_CAPABILITY_REQUIRED` (exit 8), offline at `prepare` and again at `apply`,
before any credential or network access. State and enum set or clear needs only
`issue-create`. Adding the capability to a profile is an explicitly authorized
`profile add` change that alters the credential identity, so log in again and set the
project allowlist again.

A field the plan does not name follows the project's default value or workflow.
YouTrack may also refill a cleared field: a project default value or workflow may
assign or refill the field on create, so a cleared field can come back filled. The response must show
a named field with the exact planned value (a User with the planned ID, or an
exact JSON `null` for a clear; `{}` or an empty ID does not count). When the
issue identity matches but a named field differs, the result stays
`WRITE_OUTCOME_UNKNOWN`; `operator-write reconcile` then reads the issue and
reports `matching_issue_observed_fields_differ`. Never apply the plan again. The summary is one line without
surrounding whitespace or control characters, at most 1024 bytes. The
description is optional, LF-only and without surrounding whitespace; the final
description, including the visible `[youtrack operator-write PLAN_ID]` marker on
its own last paragraph, is at most 32 KiB. These rules make the exact response
comparison safe against server-side trimming.

Apply rechecks the project ID, key and archive state and each touched field
schema and target (a cleared field must still allow empty values), then sends one `POST /api/issues`. Fields are addressed by
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

## Editing summary and description

`issue.edit` replaces the summary, the description, or both of one exact issue
with the exact text you supply. It needs a separately declared `issue-edit`
capability, distinct from `issue-update`: no existing profile gains it. Adding
`issue-edit` to a profile is an explicitly authorized `profile add` change; like
`comment-delete` it changes the credential identity, so log in again and set the
project allowlist again before preparing a plan.

```sh
youtrack-agent-cli operator-write snapshot --kind issue.edit \
  --id APP-123 --out "$youtrack_operation_dir/snapshot.json"
printf '%s' '{"kind":"issue.edit","summary":"NEW SUMMARY","description":"NEW DESCRIPTION"}' |
  youtrack-agent-cli operator-write prepare --offline \
    --snapshot "$youtrack_operation_dir/snapshot.json" --request-stdin
youtrack-agent-cli operator-write apply --plan-id PLAN_ID \
  --confirm-intent SHA256 --yes
```

Snapshot takes only `--id` and `--out`; `--field`, `--value`, `--clear-value`,
`--project` and `--comment-id` are usage errors (exit 2). Either request member
may be omitted to leave that attribute alone. Bounds: the summary is one line,
at most 1024 bytes; the description is at most 32 KiB, LF-only and trimmed.
An explicitly present empty or null `summary` or `description` member is
refused; clearing either attribute is not supported (omit the member instead).

The snapshot freezes SHA-256 hashes of the current summary and description, not
the text. The plan holds the new text and only those hashes of the old text. If
the requested text equals the current text, prepare (including `--dry-run`)
refuses with `OPERATOR_TEXT_UNCHANGED` (exit 2); apply never raises it. Apply
re-reads the issue and refuses a changed text with `OPERATOR_ISSUE_STALE`
(exit 9), even when the new text equals the request and even when `updated` is
unchanged. A window remains between that re-check and the single POST because
YouTrack has no conditional update; a concurrent edit in it can be overwritten.
The plan is v4 and `capabilities` lists `issue.edit`.

YouTrack may normalise the stored text, so a result that differs from the
request yields `WRITE_OUTCOME_UNKNOWN`. Reconcile is read-only and, without
causal proof, never claims the write applied; it never replays. Tracker text is
untrusted data: it is shown, never interpreted. Show the operator the current
text (from `inspect issue`) as untrusted data and the exact new text before
confirming. Default output omits the old hashes; the `snapshot` and `plan`
fields show them on request.

## Linking issues

`issue.link` adds one link between two existing issues. It needs a separately
declared `issue-link` capability (canonical order: after `issue-edit` and
`issue-create-user-fields`); no
existing profile gains it, and adding it changes the credential identity, so log
in again and set the project allowlist again before preparing a plan. Both
issues' projects must be on the allowlist: a link to an issue in a project
outside it is refused. Removing links is not supported here; it stays with the
MCP connector's `link_issues`, and one operation never runs through both.

```sh
youtrack-agent-cli operator-write snapshot --kind issue.link \
  --id APP-123 --target-id OPS-7 --link-type Depend --direction "depends on" \
  --out "$youtrack_operation_dir/snapshot.json"
printf '%s' '{"kind":"issue.link"}' |
  youtrack-agent-cli operator-write prepare --offline \
    --snapshot "$youtrack_operation_dir/snapshot.json" --request-stdin
youtrack-agent-cli operator-write apply --plan-id PLAN_ID \
  --confirm-intent SHA256 --yes
```

`--id` is the source and `--target-id` the target, each an exact entity or
readable ID. Select the link type by exact, case-sensitive `--link-type NAME` or
by `--link-type-id ID`; `--direction` is the exact phrase read from the source
issue's side and must equal the type's outward phrase (`depends on`,
`duplicates`, `parent for`, `relates to`) or its inward phrase (`is required
for`, `is duplicated by`, `subtask of`), case-sensitively and never fuzzily. The
statement reads "SOURCE PHRASE TARGET". An undirected type has one phrase. A
directed type whose two phrases are identical is refused with
`OPERATOR_LINK_DIRECTION_AMBIGUOUS` (exit 2). `--field`, `--value`,
`--clear-value`, `--project` and `--comment-id` are usage errors (exit 2), and
`--target-id`, `--link-type`, `--link-type-id` and `--direction` are usage
errors with any other kind. The canonical request is `{"kind":"issue.link"}`. A known text member
(`summary`, `description`, `comment_text`) that is present but empty (`""`) or
`null` is accepted and treated as absent, as for the other kinds; a non-empty one
is refused.

Snapshot reads, in bounded single pages after verifying the account: both
issues, the link types (`GET /api/issueLinkTypes`, or the exact type by ID), the
source issue's link entries (`GET /api/issues/{id}/links`) and the issues in the
chosen entry. The link entry ID sent with the POST is taken from that listing by
type and side, never computed; a missing or duplicate entry is refused
(`OPERATOR_LINK_ENTRY_UNAVAILABLE`, exit 2). An unknown type name is exit 3 with
`did_you_mean`; a repeated type name is exit 4 with `candidates` (use
`--link-type-id`); a truncated read is exit 9 (`OPERATOR_SCHEMA_TRUNCATED` for
types, `OPERATOR_LINKS_TRUNCATED` for entries or linked issues; for the latter
swap `--id` and `--target-id` and use the reverse phrase). A link that already
exists is `OPERATOR_LINK_ALREADY_PRESENT` (exit 2, "nothing to change; do not
retry unchanged"). For an aggregation type (Subtask) whose would-be child
already has a parent, `OPERATOR_LINK_PARENT_EXISTS` (exit 2) refuses the link,
because YouTrack silently replaces the parent otherwise and the old link would
be lost. The guard is checked at snapshot and again inside the apply lock, but it
is not atomic with the POST (see the remaining race below).

Apply checks consent, digest and the two-project binding before credentials,
then re-checks everything inside the final lock, before the durable claim and
the single POST (`POST /api/issues/{source}/links/{entry}/issues`, body
`{"id":"<target database id>"}`): both issues' identity, project and archive
state, the exact link type, the same server entry ID, that the link is still
absent and that the child still has no parent. The issues' `updated`
timestamps are deliberately not compared. Any drift is `OPERATOR_ISSUE_STALE` or
`OPERATOR_LINK_STALE` (exit 9) with zero POST and the plan unconsumed. The result is verified only
when the POST echoes exactly the target's database and readable IDs and reads
then show both issues in their frozen projects and the target in the entry;
anything else is `WRITE_OUTCOME_UNKNOWN`. Removing either project from the
allowlist after prepare makes apply refuse, and makes reconcile refuse whenever
it needs remote reads. A record already applied, rejected or reconciled returns
its preserved local outcome offline
(`verified_terminal_record_preserved`) for every kind, without a policy check.

Disclose before applying: a Duplicate link may trigger a workflow that resolves
the source issue; a Subtask link sets the parent of the child; both issues'
watchers may be notified (`youtrack-default`). A concurrent identical link added
between the in-lock check and the POST leaves the end state as requested and is
recorded as applied. `capabilities` lists `issue.link`; the plan is v4.

Remaining race: the checks run in the apply lock, but YouTrack has no
conditional link add. If another actor gives the child a parent between the
in-lock probe and the POST, YouTrack silently replaces that parent with the new
Subtask link, and the CLI cannot detect it. `OPERATOR_LINK_PARENT_EXISTS` is
therefore a guard against the state observed at snapshot and apply time, not
against a concurrent reparent.

Reconcile is one GET-only, bounded page (`--limit`, `--offset`) of the entry's
issues. If the target is listed it reports `operator_resolution_required` with
evidence `desired_link_observed_without_causal_proof`: the link may have been
added by someone else. A missing or truncated observation is
`operator_resolution_required` with evidence `inconclusive`. If either issue
answers 404 or an authentication or permission refusal (deleted or no longer
readable), the evidence is `linked_issue_unavailable`, again
`operator_resolution_required`, and the record stays resolvable by the
operator; it is not an error. Reconcile never
POSTs and never restores eligibility; a moved issue is `OPERATOR_PROJECT_CHANGED`.

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
| `issue.link` precondition drift | Exit 9 `OPERATOR_ISSUE_STALE` or `OPERATOR_LINK_STALE`, zero POST, plan unconsumed; snapshot again. |
| `issue.link` target already linked or child already has a parent | Exit 2 `OPERATOR_LINK_ALREADY_PRESENT` or `OPERATOR_LINK_PARENT_EXISTS` at snapshot; nothing to apply. |

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
