# sign-release

Signs the darwin archives of a draft release on the operator's Mac, uploads
them and publishes the release. It is the only place the Developer ID signing
key is used: CI builds and attests unsigned darwin binaries, and this tool
signs them after verifying that they are the ones CI built.

```bash
cd tools/sign-release
GOWORK=off go run . youtrack-agent-cli 0.13.0
```

The tool is its own module, and the repository has no root `go.mod`, so run it
from `tools/sign-release`. Use a clean checkout of `main`: the configuration
it embeds, including the pinned certificate, comes from that checkout. The
version has no leading `v`. The release tag is `youtrack-agent-cli/v0.13.0`. The
configuration (`config.json`) is embedded in the binary. The tool exits 0 on
success, 1 on any failure or refusal, and 2 on a wrong command line. One run
at a time holds an exclusive lock for the repository and tag (a file in
`Library/Caches/sign-release` under the account's home directory, taken from the
account database, not `$HOME`); a second run of the same
release refuses at once.

## What it does and never does

- It never executes a binary: not the downloaded one and not the signed one.
  The only programs it starts are `gh` and `/usr/bin/codesign`.
- It never handles a key file or a passphrase. `codesign` finds the identity in
  the login keychain and macOS asks you for access.
- No signing key goes to CI.
- It signs only a binary whose machodigest stream carries a `release.yaml`
  attestation for the tag's commit, and it checks that signing changed only the
  signature.
- It publishes only after every check passed and you typed the tag twice. A
  failure at any step stops the run before the one request that publishes.

The tool defends against a wrong or tampered release, not against another
process of the same account: a process running as you can read the work
directory, change the files `gh` uploads, edit `gh`'s config or take the
Keychain prompt. That is outside the threat model, as it is for the rest of
this repository. The tool narrows the window (it compares the upload files with
the verified bytes right before `gh` reads them, and checks the digests after)
but does not claim protection against such a process.

## Prerequisites

- macOS with the `Developer ID Application` identity in the login keychain.
  `cert_sha1` in `config.json` must hold the 40-hex SHA-1 of that certificate;
  the tool refuses to start while it is empty or malformed.
- `gh` logged in to `github.com` through its own stored login
  (`gh auth login`). The tool starts `gh` with a minimal environment: `PATH`,
  `TMPDIR`, `USER`, the locale, and a `HOME` taken from the account database
  (not from the `HOME` variable). `GH_TOKEN`, `GITHUB_TOKEN`, `GH_HOST`,
  `GH_REPO`, `GH_CONFIG_DIR`, `XDG_CONFIG_HOME`, proxy variables and the rest are
  ignored on purpose, so nothing in the environment can redirect a call,
  replace the login or point `gh` at another configuration. If
  `GH_CONFIG_DIR` or `XDG_CONFIG_HOME` is set, the tool prints one line saying
  it is ignored and that `gh`'s default config under the account's home is
  used. A network that needs a proxy therefore fails closed.
  `gh`'s own config file (for example `http_unix_socket`) is trusted: whoever
  can write it controls where `gh` sends its requests.
- Immutable releases enabled on the repository (a repository-wide setting).
  Published assets of an immutable release cannot be changed.
- The draft release that CI produced for the `youtrack-agent-cli/vX.Y.Z` tag:
  exactly one draft with that tag and exactly six assets (two Linux archives,
  `checksums.txt`, two darwin archives, `checksums-darwin.txt`).

## The run, in order

Progress lines go to stderr, one after each group of steps. Any mismatch is a
refusal that names the step; nothing is published after one.

1. **Checks before any command.** The configuration parses, the CLI is ready
   to sign (certificate hash set) and the version is a plain semantic version.
   The whole-run lock for the repository and tag is taken. Then the account's
   home is looked up, `gh` is located on `PATH` once and its symbolic links are
   resolved, and `gh auth status --hostname github.com` must pass.
2. **Resolve.** The release list is read; exactly one release has the tag, it
   is a draft and it carries exactly the expected assets.
3. **Download and checksum.** `checksums-darwin.txt` and both darwin archives
   are downloaded by asset ID into a new work directory (mode 0700) with size
   bounds. Both archives must match their checksum line.
4. **Tag commit.** The tag is read through the API (an annotated tag is
   followed to its commit). That commit is the one every attestation must name.
5. **Attestations.** `gh attestation verify` runs for both archives, then (after
   the archives are unpacked and checked) for both machodigest streams, with
   the repository, the `release.yaml` signer workflow, the tag as source ref,
   the commit as source digest, `--deny-self-hosted-runners` and
   `--predicate-type https://slsa.dev/provenance/v1`. The tool also compares the
   printed certificate itself: the OIDC issuer, the build signer URI (the
   workflow at the tag), the build signer digest, the build config URI (equal to
   the signer URI), a GitHub-hosted runner, the source repository URI, the
   source ref and the source commit. It binds each attestation to the bytes in
   use: the predicate type is SLSA provenance and a subject's sha256 equals the
   sha256 of the archive or stream the tool holds in memory.
6. **Unpack and parse.** Each archive holds exactly the entries in
   `archive_entries`, all plain regular files with bounded sizes. Each binary
   is a thin Mach-O of the expected CPU. Nothing is written until both pass.
7. **Immutable releases.** `repos/<repo>/immutable-releases` must answer with
   `enabled: true`. This runs before signing so that a missing setting costs no
   Keychain prompt.
8. **Sign.** For each binary, in the work directory: the stream must still
   equal the attested one, then `codesign --force --sign <sha1> --options
   runtime --timestamp --identifier <id> --requirements <requirement>` runs.
   **macOS shows one Keychain prompt per binary. Choose Allow, never Always
   Allow.**
9. **Verify.** `codesign --verify --strict -R=...` must exit 0, and
   `codesign -dvv`, `-d -r-` and `-d --entitlements -` must show the expected
   identifier, the hardened runtime flag, the team identifier, a secure
   timestamp, exactly the leaf-pinned requirement (no implicit one) and no
   entitlements. The signed binary's machodigest stream must be byte-identical
   to the attested stream: signing may change only the signature.
10. **Repackage.** New `.tar.gz` archives are written deterministically (same
    names and entries, USTAR, uid and gid 0, mtime equal to the tagged commit's
    committer date, modes 0755 for the binary and 0644 for the rest, a fixed
    gzip header) with a new `checksums-darwin.txt`.
11. **First confirmation.** Type the tag. The answer must match exactly.
12. **Upload.** The releases are listed: exactly one has the tag and it is the
    pinned release, still a draft. Each file in `signed/` is read again and must
    equal the bytes built and verified. Then `gh release upload <tag> <files>
    --clobber --repo github.com/<repo>` replaces the three darwin assets, and
    the releases are listed again with the same requirement. The release is
    read again by ID: still a draft, exactly the same asset set, the Linux assets
    untouched, and each darwin asset's `digest` equals the local sha256 (an
    asset without a `digest` is downloaded and hashed).
13. **Tag check.** The tag must still point at the attested commit.
14. **Second confirmation.** Type the tag again. Right after the answer the tag
    is checked once more, the release is read again by ID (still a draft, the
    exact asset set, the digests, the Linux asset IDs) and immutable releases
    must still be enabled.
15. **Publish.** `gh api -X PATCH repos/<repo>/releases/<id> --input -` with the
    body `{"draft":false}`. There is no `tag_name` and no `target_commitish`.
16. **Re-read.** The release is read by ID: not a draft, `immutable` is true,
    the tag is unchanged, the assets and digests are unchanged and the tag still
    points at the commit.

Each prompt takes up to three answers; a wrong one asks again, and the third
wrong answer refuses. Ctrl-C takes effect only after you press Enter, because
the tool is waiting for a line.

## The work directory

The tool prints the work directory (a new `sign-release-*` directory under
`TMPDIR`, mode 0700) and keeps it after the run. It holds the release files and
the signed binaries, and no secrets: the downloaded archives and
`checksums-darwin.txt` (the originals) at the top, one directory per
architecture with the extracted files, the machodigest streams and `signed/`
with the three uploaded files.

Keep it until the release is published and re-read successfully. After a
failure that left the draft changed it holds the originals needed to restore
the draft, so keep it until that is done. Delete it afterwards.

## Failure and recovery

- **Before the upload (steps 1 to 11).** Nothing on GitHub changed. Fix the
  cause and run again; the tool starts from the beginning in a new work
  directory.
- **After the upload, before the publish (steps 12 to 14).** The draft may now
  carry signed darwin assets that no attestation covers, and a re-run refuses
  such a draft. The error names the work directory. Restore the originals, then
  run again:

  ```bash
  gh release upload youtrack-agent-cli/v0.13.0 \
    <workdir>/youtrack-agent-cli_0.13.0_darwin_amd64.tar.gz \
    <workdir>/youtrack-agent-cli_0.13.0_darwin_arm64.tar.gz \
    <workdir>/checksums-darwin.txt \
    --clobber --repo github.com/abigotado/agent-clis
  ```

  These are the downloaded originals at the top of the work directory, not the
  files in `signed/`. If the refusal says it is not proven that the pinned
  release took the files (a second release with the tag appeared, or the pinned
  one was replaced), list the releases of the tag with their IDs and restore
  the originals on every draft that carries signed assets. `--clobber` deletes an existing asset before it uploads,
  which is acceptable only on a draft.
- **The PATCH fails.** The release may or may not be public. Read it before
  anything else: `gh api --hostname github.com repos/abigotado/agent-clis/releases/<id>`.
  If it is still a draft, restore the originals as above; if it is published,
  do not touch it. Never repeat the PATCH blindly.
- **The read after the publish fails.** The release is probably public.
  Read release `<id>` with `gh` before doing anything else.
- **A check after the publish fails.** The release is public and immutable, and
  its assets cannot be changed. Cut the next patch version and never
  re-upload.

## First run: compare the attestation output

Before the first real run, check by hand that `gh` prints what the tool
expects. Download a darwin archive of the draft and run:

```bash
gh attestation verify <archive> \
  --repo abigotado/agent-clis \
  --signer-workflow abigotado/agent-clis/.github/workflows/release.yaml \
  --source-ref refs/tags/youtrack-agent-cli/v0.13.0 \
  --source-digest <tag commit> \
  --deny-self-hosted-runners --format json --hostname github.com
```

The output is a JSON array. In every entry,
`verificationResult.signature.certificate` must show:

| Field | Value |
| --- | --- |
| `issuer` | `https://token.actions.githubusercontent.com` |
| `buildSignerURI` | `https://github.com/abigotado/agent-clis/.github/workflows/release.yaml@refs/tags/youtrack-agent-cli/v0.13.0` |
| `buildSignerDigest` | the tag commit |
| `buildConfigURI` | the same as `buildSignerURI` |
| `runnerEnvironment` | `github-hosted` |
| `sourceRepositoryURI` | `https://github.com/abigotado/agent-clis` |
| `sourceRepositoryRef` | `refs/tags/youtrack-agent-cli/v0.13.0` |
| `sourceRepositoryDigest` | the tag commit |

In every entry, `verificationResult.statement` must have
`predicateType` `https://slsa.dev/provenance/v1` and a `subject` whose
`digest.sha256` is the sha256 of the archive you verified (`shasum -a 256`).

If a field name or value differs, the tool refuses at the attestation step.
Report it. Do not change the tool or the check to get past it.

## The codesign requirement forms

The tool uses two spellings of one requirement, and codesign accepts only the
right one in each place. `<id>` is the identifier from `config.json` and
`<sha1>` the lowercase certificate hash:

- Signing takes a requirement set, with a leading `=` that marks inline text:
  `--requirements '=designated => identifier "<id>" and anchor apple generic and certificate leaf = H"<sha1>"'`
- `codesign -d -r-` prints that same set without the `=`, as one line starting
  with `designated =>`. A line starting with `# designated =>` is an implicit
  requirement and is refused.
- Verifying takes the bare expression after `-R=`. `designated =>` is a syntax
  error there:
  `-R='identifier "<id>" and anchor apple generic and certificate leaf = H"<sha1>"'`

To check a binary by hand:

```bash
codesign --verify --strict \
  -R='identifier "dev.abigotado.youtrack-agent-cli" and anchor apple generic and certificate leaf = H"<sha1>"' \
  ./youtrack-agent-cli
codesign -dvv ./youtrack-agent-cli          # Identifier, TeamIdentifier, the runtime flag, Timestamp=
codesign -d -r- ./youtrack-agent-cli        # one designated => line
codesign -d --entitlements - ./youtrack-agent-cli   # empty
```

The text checks read what a program printed, so only the first command proves
the signature and the pinned certificate; the others must agree with it.
