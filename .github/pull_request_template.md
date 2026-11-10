<!--
The title becomes the commit subject on main — pull requests are squash-merged.
Write it in the imperative: "Stop auth list reading the keychain".
-->

## What changes, and why

<!-- One paragraph. The diff already shows the what; the why is what review needs. -->

## Contract impact

<!-- Exit codes, envelope fields, flag names, and output shape are a published API. -->

- [ ] Additive or none — no renamed or removed envelope field, flag, or exit code
- [ ] Breaking — described above, agreed in an issue first

## Validation

<!-- Check only what you actually ran. -->

<!-- Go commands run inside each changed module, with GOWORK=off. -->

- [ ] `gofmt -l $(git ls-files '*.go')` prints nothing
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] `go generate ./...` ran and the result is committed — or this change touches
      neither the command surface nor `internal/errx`
- [ ] `python3 .agents/scripts/sync-rules.py` and the harness tests pass — or this
      change touches neither `.agents/` nor any `<cli>/rules/`

## Checklist

- [ ] A test fails without this change
- [ ] No `.claude/` or `.codex/` files in the diff
- [ ] No API token, Authorization header, Keychain output, or credential-bearing
      trace anywhere in the diff, tests, or pasted output
