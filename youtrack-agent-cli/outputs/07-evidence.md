# Evidence ledger

Retrieved: 2026-09-01
Source policy: official JetBrains, OpenAI, and Anthropic documentation or first-party issue/repository material

## JetBrains YouTrack

| Claim used in the design | Evidence |
|---|---|
| Remote MCP is available at an instance `/mcp` endpoint; requests use the authenticated user's permissions; OAuth and permanent-token connection modes are supported | [Remote MCP Server](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html) |
| Remote MCP accepts a positive `tools=` list, `ignoreTools=`, explicit `customToolPackages=`, and `enableToolOutputSchema=true` | [Remote MCP Server — Optional Parameters](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html#optional-parameters) |
| The `tools=` description speaks about names returned by `tools/list` and quota control; it does not document rejection of direct hidden `tools/call` requests | [Remote MCP Server — Optional Parameters](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html#optional-parameters) |
| The predefined catalog includes issue/article/time mutations such as create, update, comment, tags, links, and work logging | [Remote MCP Server — AI Tools](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html#ai-tools) |
| A separate official page claims all predefined MCP tools are read-only | [Custom MCP Tools](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html) |
| Custom MCP tools require Low-level Admin to upload, live in app packages, are globally available rather than project-attached, and run with the calling user's access | [Custom MCP Tools](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html) |
| Custom MCP descriptors can carry `readOnlyHint`, `destructiveHint`, `idempotentHint`, and related annotations | [Custom MCP Tools — Tool Descriptor](https://www.jetbrains.com/help/youtrack/devportal/custom-ai-tools.html#tool-descriptor) |
| Starting in 2026.2, administrators manage OAuth clients; Authorization Code + PKCE is recommended for new apps where possible; tokens act on behalf of the user | [OAuth 2.0 Authorization](https://www.jetbrains.com/help/youtrack/devportal/OAuth-authorization-in-youtrack.html) |
| YouTrack supports preregistered OAuth clients and optional CIMD automatic registration; CIMD is disabled by default; OAuth DCR is not supported for MCP clients | [OAuth 2.0 Authorization — MCP registration](https://www.jetbrains.com/help/youtrack/devportal/OAuth-authorization-in-youtrack.html#automatic-oauth-client-registration-for-mcp) |
| Public clients can use Authorization Code + PKCE without a client secret; confidential clients use client authentication | [Authorization Code](https://www.jetbrains.com/help/youtrack/devportal/Authorization-Code.html) |
| REST base URL is `<YouTrack Service URL>/api`, including installations with a service path | [REST API URL and Endpoints](https://www.jetbrains.com/help/youtrack/devportal/api-url-and-endpoints.html) |
| REST responses require explicit `fields` for useful attributes | [Fields Syntax](https://www.jetbrains.com/help/youtrack/devportal/api-fields-syntax.html) |
| REST collections support `$top`/`$skip` and are limited by default | [Pagination](https://www.jetbrains.com/help/youtrack/devportal/api-concept-pagination.html) |
| Issues support bounded query reads and creation; create requires project and summary | [Issues](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues.html) |
| A specific issue can be read or updated using an exact readable ID | [Operations with Specific Issue](https://www.jetbrains.com/help/youtrack/devportal/operations-api-issues.html) |
| `get_issue` documents a fixed detailed output; it does not document a caller-selected `fields` projection | [Remote MCP Server — `get_issue`](https://www.jetbrains.com/help/youtrack/cloud/model-context-protocol-server.html#ai-tools) |
| Issue comments support bounded list reads and add-comment POSTs; the collection parameters shown are `fields`, `$top`, and `$skip`, without documented author/time filtering or ordering guarantee | [Issue Comments](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues-issueID-comments.html) |
| Requests applying issue changes are processed atomically in one YouTrack database transaction; using this property for a custom MCP policy+mutation action remains an inference to validate | [Transactions](https://www.jetbrains.com/help/youtrack/devportal/workflow-transactions.html) |
| REST headers use Bearer authorization, JSON Accept, and JSON Content-Type for writes | [Request Headers](https://www.jetbrains.com/help/youtrack/devportal/yt-api-headers.html) |
| JetBrains support said no official standalone YouTrack CLI was available; official `youtrack-app` tooling instead manages app/workflow packages | [JT-94681](https://youtrack.jetbrains.com/projects/JT/issues/JT-94681/Is-there-any-official-cli-rest-api-for-youtrack-itself), [Using an External Code Editor](https://www.jetbrains.com/help/youtrack/devportal/js-workflow-external-editor.html) |

## OpenAI Codex

| Claim used in the design | Evidence |
|---|---|
| Codex skills are directories with `SKILL.md`, required `name`/`description`, and optional references/scripts/assets | [OpenAI: Build skills](https://learn.chatgpt.com/docs/build-skills) |
| Codex discovers repository/user skills under `.agents/skills`/`$HOME/.agents/skills` and follows symlinked skill folders | [OpenAI: Where Codex loads local skills](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills) |
| Codex remote MCP config supports URL, OAuth, bearer-token env var, `enabled_tools`, `disabled_tools`, and approval modes | [OpenAI: Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) |
| Codex supports preregistered OAuth clients and CIMD; callback identity depends on the full server URL including query string | [OpenAI: MCP OAuth client registration and callbacks](https://learn.chatgpt.com/docs/extend/mcp?surface=cli#oauth-client-registration-and-callbacks) |

## Anthropic Claude Code

| Claim used in the design | Evidence |
|---|---|
| Claude Code skills use `SKILL.md`, follow the Agent Skills open standard, support personal/project locations, and follow symlinks | [Claude Code: Extend Claude with skills](https://code.claude.com/docs/en/skills) |
| Claude Code supports remote HTTP MCP servers, browser OAuth, and explicit `type: "http"` JSON configuration | [Claude Code: Connect to tools via MCP](https://code.claude.com/docs/en/mcp) |
| Anthropic explicitly warns that MCP servers fetching external content can expose prompt-injection risk | [Claude Code MCP — Find and build MCP servers](https://code.claude.com/docs/en/mcp#find-and-build-mcp-servers) |
| Claude Code permissions are runtime-enforced; deny precedes ask and allow; MCP tool names can be matched by canonical name/glob | [Claude Code: Configure permissions](https://code.claude.com/docs/en/permissions) |
| A server-specific MCP metadata flag can force human interaction in recent Claude Code, but it is an Anthropic extension rather than a provider-neutral receipt | [Claude Code MCP — Require approval for a specific tool](https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool) |

## Evidence interpretation notes

1. The two JetBrains MCP pages conflict. The design records both rather than choosing the more permissive interpretation.
2. The `tools=` evidence establishes discovery filtering, not a server authorization guarantee. The design therefore requires a negative hidden-call test plus host runtime enforcement or read-only YouTrack permissions for strict profiles.
3. MCP annotations describe intent to the client/LLM. The reviewed documentation does not establish them as a cross-client authorization or human-attestation protocol.
4. The reviewed YouTrack REST material does not establish a general idempotency-key or conditional-write mechanism. The design therefore requires one-shot mutation plus read reconciliation and marks unresolved outcomes ambiguous. It also records the project-move TOCTOU risk for REST update/comment operations.
5. Transaction documentation supports the custom-executor direction, but atomic receipt validation, nonce consumption, current-project check, and mutation inside one custom MCP action must be proven on a non-production instance.
6. Absence of a supported standalone CLI is supported by the first-party YouTrack issue as of its 2026 answer. Repository-local JetBrains helpers may exist, but they are not treated as a published general-purpose product contract.
7. Client credential storage and same-endpoint multi-account behavior are version-sensitive. The plan treats them as compatibility tests, not settled facts.
