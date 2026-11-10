# Monorepo architecture

This repository holds Go CLIs built for machine callers. There is no root
module.

- Every CLI, and later the shared `core/`, is one directory with one `go.mod`.
- CLIs never import each other. `core/` never imports a CLI.
- `go.work` is not committed. Build and test every module with `GOWORK=off`, so
  a module is checked against the versions its own `go.mod` declares.
- Release tags are prefixed with the module directory (`<cli>/vX.Y.Z`). Never
  create a root `v*` tag: `v0.9.1` was the last one, and a later one would change
  `@latest` of the frozen old module path.
- Before editing inside a CLI directory, read its `AGENTS.md`. It routes the
  rules specific to that CLI, which live in `<cli>/rules/`.
