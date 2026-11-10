# agent-clis

Go command-line tools built to be driven by AI agents, in one repository. Every
tool is its own Go module in its own directory. There is no root module.

| Directory | Module path | Tags |
| --- | --- | --- |
| [`youtrack-agent-cli/`](https://github.com/abigotado/agent-clis/tree/main/youtrack-agent-cli) | `github.com/abigotado/agent-clis/youtrack-agent-cli` | `youtrack-agent-cli/vX.Y.Z` |

Installation and usage are in each tool's own README.

## Conventions

- Releases use tags prefixed with the module directory. This repository has no
  root `v*` tags, and a ruleset refuses them. `v0.9.1` was the last one, because
  a later root tag would change `@latest` of the frozen path below.
- The old module path `github.com/abigotado/youtrack-agent-cli` is frozen at
  `v0.9.1` and carries a deprecation notice that points here.
- `go.work` is not committed. Build each module with `GOWORK=off`.

Contribution rules are in [CONTRIBUTING.md](CONTRIBUTING.md), and the agent
rules start at [AGENTS.md](AGENTS.md). Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).
