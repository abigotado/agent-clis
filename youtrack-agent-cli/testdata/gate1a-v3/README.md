# Schema-v3 receipt fixtures

These generated public test fixtures replace only the receipt/signing/hash and
IPC-success positives. Unchanged plans, public keys, structural DER signature,
display, request, and error fixtures remain in `../gate1a`. Historical v2 files
there are unchanged and their receipts are explicitly rejected by v3 parsers.

`revision-boundaries.json` is shared by both language suites. It pins literal
revision/generation 256 acceptance and 257 rejection independently of each
implementation's constants. It also rejects generation 257 at revision 256.
Its signed forms use the structural DER signature, not approval authority.
Tests additionally exercise generation 257 directly through key constructors,
so receipt generation/revision equality cannot mask a generation-ceiling defect.
Fixture readers select current, shared or historical paths explicitly, with no
filename-based version routing or fallback.

Run from the repository root:

```sh
go run ./testdata/gate1a-v3/generate.go
go run ./testdata/gate1a-v3/generate.go -check
```

Each output has one source-control LF excluded from the protocol bytes. The
expected registry revision is `1`, the generation is
`YTAG-00000000000000000001`, and the context digest is 64 lowercase `a` bytes.
These are comparison claims, not an authenticated authorization context.

`receipt.json` preserves the structural signature `r=1, s=2`; it is not a valid
signature over its signing bytes. `ipc-success-receipt.json` is validly signed
for the historical fixture SPKI (the P-256 generator point), using the public
test scalar `d=1` and fixed test nonce `k=2`, normalized to low-S. This deliberate
nonce reuse is strictly test-only and must never be used for any private key.
The generator is excluded from ordinary builds; no production signer or trust
root is supplied by these fixtures. IPC framing remains version 2.
