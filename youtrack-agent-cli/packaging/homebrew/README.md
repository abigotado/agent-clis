# Homebrew Formula inputs

`modules.json` and `homebrewcheck` are inputs to the standard source-built
Formula. They protect the complete Go dependency closure and rehearse an
offline standard-CLI build with CGO enabled. They do not publish a Formula to
the tap, validate a Formula, or establish signing, native Gate evidence, or
write readiness.

The manifest must match the complete `require` closure in `go.mod`. Each digest
is for the corresponding Go proxy `.zip`, not for a VCS or GitHub archive.
`homebrewcheck` rejects replacements and validates both `go.sum` entries before
it accepts a module.

Stage downloads with the standard Go proxy layout:

```text
<proxy-dir>/<module-path>/@v/<version>.zip
```

Then run the network-free dependency-closure and standard-CLI build rehearsal:

```bash
go run ./tools/homebrewcheck --proxy-dir <proxy-dir>
```

Add `--build` to rehearse the source build. The checker creates a disposable
source tree, derives `vendor/` and `vendor/modules.txt` from the verified proxy
zips, and builds with empty caches, `CGO_ENABLED=1`, `GOPROXY=off`,
`GOSUMDB=off`, and `GOTOOLCHAIN=local`. It does not contact YouTrack or the
Keychain.

The tap PR remains the Formula validation boundary: it must pass `brew audit`,
a source install from the pinned immutable release, and `brew test`. Passing
this checker alone does not prove that the Formula is publishable, signed, or
eligible to enable guarded writes.
