# YouTrack Agent Integration — design packet

Status: **CLI direction approved; fail-closed first slice implemented locally**
Evidence cutoff: **2026-09-01**
Target baseline: **YouTrack 2026.2**, Codex, and Claude Code

Current mutation surface: offline `prepare`, local `export`, and local `status`
only. `confirm`, `apply`, and `reconcile` fail closed; the native authority
workflow described below is not implemented.

Native Gate readiness: **NOT PASSED**. The separate
[isolated-subrun ADR](../docs/gate1b-isolated-subruns.md) specifies Gate 1B unit
authorization, target lifecycle, and parent aggregation. Its inventory,
validators, and native execution still require implementation and verification;
the historical catalog is not release authority.

## Recommended decision

Adopt a split architecture:

1. Use the official YouTrack Remote MCP endpoint as the **read plane**, through a positive `tools=` discovery allowlist, a host runtime allowlist where available, and preferably a YouTrack identity whose permissions are themselves read-only. `tools=` alone is not documented as an authorization boundary.
2. Build a local `youtrack-agent-cli` as the **guarded-write control plane**. It owns profile selection, secure credential storage, network-free planning, immutable plan IDs, human confirmation receipts, and the mutation journal.
3. Package the operating policy as one provider-neutral `youtrack-agent` Agent Skill. Keep its portable core to common `SKILL.md` semantics; install the same folder into Codex and Claude Code by symlink or copy.
4. Make execution pluggable: a REST executor is acceptable only with an explicit TOCTOU residual-risk decision; a reviewed custom MCP app is required when project allowlisting must be enforced atomically in the same YouTrack transaction as the mutation.

The future local apply boundary is now fixed independently of that executor
choice: a unique fixed-active Keychain add, not launchd singleton assumptions,
serializes every registry commit across same-user helper processes
with `confirmed -> in_flight -> one exact-request permit -> one send/outcome ->
durable close`, and the descriptor-bound helper-profile expiry is checked
strictly through the final pre-send fence. The closed Gate contract adds exact
closed 23-case Gate 1A including install/migration fault cases, an 88-vector
expiry matrix, and a 26-family Gate 1B catalog expanded into isolated atomic
units with separate token-bound enrollment in both passes and deterministic schedules through
enrollment, close, active-delete ambiguity, and a
competing-acquisition ABA attempt between equality read and delete. Future
E1/E2 receipts bind a separate Gate context and retained Gate authority set,
so confirmation is testable before provisional authorization. These receipts
are rejected by every non-Gate authority path.
Activation-smoke/post-grant plans are setup-first (5/6 and 6/7 cases by
capability), bind a retained empty-inventory enrollment snapshot through all
later evidence, retain terminal/replay-denial evidence, and accept case
assertions only in a final runner observation after every transcript result.
Live release-stage deletion and ACK-ledger recovery are deferred. A trusted
external supervisor destroys each whole disposable host after evidence export;
root-bound disposal evidence must precede the activation-grant or publication-
envelope signature. No helper claims to prove the inventory empty afterwards.
Only the uninterrupted lease owner may durably close after irrevocably
quiescing every send/sign/commit capability. Non-owners quarantine an unclosed
lease indefinitely, including after restart/reboot; reconciliation is bounded
remote reading and reporting with no journal CAS. Cleanup of an already-closed
lease deletes its exact persistent reference, never the reusable account name.
Protected history burns the exact receipt digest even on a null-permit close;
journal CAS cannot restore it. At 256 permits or closes the final owner closes
and retains a valid closed active capacity sentinel. Future authority commands
retain JSON v1 and use the proposed exits 10..13 alongside existing codes;
the current runtime remains at 0..9. Capacity adds no further number: its status is
`capacity_exhausted`/`stop`/exit 0; acquisition or recovery fails with existing
exit 1 without deletion. See the [state contract](08-implementation-decision.md#complete-state-table)
and [native constraints](../docs/gate1a-registry-protocol.md). Journal v2 and prepared-only v1
migration/quarantine precede activation. These are unimplemented Gate
requirements; all writes remain disabled.

```text
Codex / Claude Code
        |
        +-- read --> named (instance, account) Remote MCP profile
        |             endpoint contains tools=<exact read allowlist>
        |
        `-- write --> shared Agent Skill --> local planner/approver
                                      --> offline immutable plan
                                      --> human-signed receipt
                                      --> REST executor (residual TOCTOU)
                                           or custom MCP executor (strict policy)
                                      --> exact/bounded reconciliation
```

## Critical documentation conflict

The official [Custom MCP Tools](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html) page says that all predefined MCP tools are read-only. The official [Remote MCP Server](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html) page simultaneously documents predefined mutating tools, including `create_issue`, `update_issue`, `add_issue_comment`, `manage_issue_tags`, `link_issues`, `create_article`, `update_article`, and `log_work` (and also `create_draft_issue` and `change_issue_assignee`).

This packet resolves the conflict conservatively: **an endpoint without an explicit positive `tools=` allowlist is not considered read-only**. However, JetBrains documents `tools=` as filtering `tools/list`, not as rejecting direct hidden `tools/call` requests. Strict read-only therefore also requires a verified host runtime allowlist or a read-only YouTrack identity. Tool annotations, names, descriptions, user prompts, and an `ignoreTools=` denylist are not security boundaries.

## Deliverables

- [ADR: split read/write architecture](01-adr.md)
- [Threat model](02-threat-model.md)
- [Recommended Remote MCP configuration](03-mcp-configuration.md)
- [Provider-neutral Agent Skill contract](04-skill-contract.md)
- [MVP command and tool surface](05-mvp-surface.md)
- [Implementation plan and decision gates](06-implementation-plan.md)
- [Evidence ledger](07-evidence.md)
- [Implementation decision and Gate 1A](08-implementation-decision.md)
- [Gate 1A approval-helper evidence report](09-gate-1a-report.md)
- [PR #7 review dispositions](10-pr7-review-resolution.md)

## Recorded operator direction

Build a dedicated CLI and Agent Skill using the same provider-neutral harness and established logic as the operator's existing Jira, Confluence, and Trello CLIs. The implementation baseline and additional YouTrack-specific gates are recorded in [Implementation decision and Gate 1A](08-implementation-decision.md).

## Remaining deployment decisions

1. Run Gate 1A with an operator-controlled Apple signing identity. Until it passes, confirmation and remote mutations remain disabled.
2. Choose the eventual executor policy: REST with explicitly accepted project-move TOCTOU residual risk, or custom MCP for atomic project-policy enforcement.
3. Supply and verify the first real instance/account/OAuth public-client profile without placing credentials in the repository.
4. Confirm whether same-instance multi-account use must be simultaneous inside one client process; otherwise named profiles already isolate accounts across invocations.
5. Decide whether every future guarded write may include a short visible preallocated plan marker for reliable reconciliation.

## Scope boundary honored

A local repository and implementation harness now exist beside this packet. No
YouTrack app or Agent Skill was installed, no live instance was contacted, no
credential was accessed, and the source was published for review without a
release, Formula, Cask, or installed package.
