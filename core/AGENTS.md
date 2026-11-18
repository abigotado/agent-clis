# core agent rules

`core` is the shared Go module that every CLI in this repository may import. It
is a leaf: it imports no CLI module, and outside the standard library only
`golang.org/x/sys` and `github.com/godbus/dbus/v5`. The root
[`AGENTS.md`](../AGENTS.md) rules apply as well. `core/secretstore` is the only
package so far: a native secret store for the macOS Keychain, Windows
Credential Manager and the Linux Secret Service. It never falls back to a file.

## Rule router

| Surface | Required rules |
| --- | --- |
| Module layout, a new package, or a dependency | [architecture](../.agents/rules/architecture.md) |
| Any Go code | [Go style](../.agents/rules/go-style.md) |
| Any behavior change | [testing](../.agents/rules/testing.md) |
| Credentials, error text, logging, or the on-store format | [secrets](../.agents/rules/secrets.md) |
| CI, hygiene, or pushing | [quality gates](../.agents/rules/quality-gates.md) |

## Boundaries

- Error text never carries secret bytes, the service or account of a key, or
  text produced by the operating system. `Reason` is a closed set of constants.
- No backend may turn an unusable store into not found or absent. A store the
  process cannot use (the macOS keychain inside a sandbox that refuses its
  status read) is `KindUnavailable` with `ReasonKeychainUnusable`, never
  `KindNotFound`, `KindReadOnly`, or a nil error from Delete or Exists. A
  caller must never read it as a missing or expired credential or suggest
  re-authenticating.
- The exported API is pinned by `secretstore/testdata/api.golden`. A change to
  it is a deliberate edit of that file, reviewed as a public API change.
- Untagged tests never call a real OS secret store. The tagged integration
  tests (`keychainintegration`, `credmanintegration`,
  `secretserviceintegration`) use a scratch keychain, a throwaway Credential
  Manager prefix or a private bus, and never the user's own store.
- Never commit a path from a developer machine, a service host, a signing team
  identifier or a token. `.github/scripts/core-hygiene.sh` checks this.

## Gates

Run these inside this directory, with `GOWORK=off`:

```bash
export GOWORK=off
gofmt -l $(git ls-files '*.go')
for os in linux darwin windows; do GOOS=$os go vet ./...; done
go test -race ./...
CGO_ENABLED=0 go test ./...
.github/scripts/core-hygiene.sh origin/main..HEAD   # from the repository root
```

The integration tags, their environment variables and the macOS timeout are in
[`CONTRIBUTING.md`](../CONTRIBUTING.md). CI runs them on real runners.

## Never

- Add a dependency on a CLI module, or any module beyond the two above, without
  changing the dependency-closure check in CI in the same change.
- Weaken an integration test into a skip. Under a `SECRETSTORE_REQUIRE_*`
  variable a row that cannot run must fail, except a documented environmental
  limit that prints a `::notice::`.
