# Gate 1A cross-language fixtures

This directory preserves the historical receipt-schema-v2 spike. Its receipt,
signing and success-frame artifacts are not current approval positives: schema-v3
parsers reject those receipts. Active receipt positives and shared revision
boundaries live in [../gate1a-v3](../gate1a-v3/README.md). Tests select the directory
explicitly; there is no filename-based fallback between versions.

Each text file ends in one source-control LF. Tests remove exactly that final
LF before comparing protocol bytes or decoding hex/base64url.

- `signing.json` is the historical schema-v2 unsigned receipt encoding.
- `receipt.json` is the historical schema-v2 signed receipt encoding.
- Their `.sha256` files digest the protocol bytes without the fixture LF.
- `signature.der.hex` encodes the strict structural vector `r=1, s=2` and
  `signature.base64url` is its unpadded base64url form. It is a codec vector,
  not a signature over `signing.json`.
- The public-key X9.63 vector is the P-256 generator point. The SPKI and
  fingerprint files pin its exact protocol-v2 encodings.
- `display.hex` contains inert JSON-like untrusted content, while
  `display.escaped.txt` encodes it with the frozen byte-preserving renderer.
- `plan-*.json` are exact canonical snapshots for every supported mutation
  kind. `approval-url-corpus.json` and `plan-id-corpus.json` are shared parser
  acceptance corpora.
- `ipc-request.hex`, `ipc-success.hex`, and `ipc-error.hex` are complete
  protocol-v2 frames using challenge bytes `00..1f`. The success receipt signs
  SHA-256 of that challenge and uses the historical key-generation label `1`. It is stored
  separately as `ipc-success-receipt.json` and carries a valid low-S
  P-256 signature for the fixture SPKI and `plan-comment-add.json`, but the
  current schema-v3 decoder rejects its receipt. Request/error frames, plans,
  public keys, structural DER signatures, and display fixtures remain shared
  positives: receipt schema v3 did not change those contracts or IPC framing v2.
