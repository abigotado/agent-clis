# Isolated binding syntax vectors

This shared catalog tests only the compact canonical syntax of
`gate1b_isolated_binding_v1`. It does not establish recursive reference validity,
host isolation, authority, or a native Gate pass.

Both Go and Swift consume every positive and negative entry in `vectors.json`.
The four positive `raw` strings are exact UTF-8 bytes (no appended newline),
covering both passes and architectures. Six different repeated digest digits
make field swaps observable. `sha256` is the fixed plain SHA-256 of these bytes.

Each negative names a positive `base` and applies exactly one byte splice:
remove `delete` bytes starting at zero-based `offset`, insert the bytes decoded
from lowercase `insert_hex`, and preserve the prefix and suffix unchanged.
Its `sha256` is the fixed digest of the expanded malformed bytes. This encoding
preserves invalid UTF-8 and NULs without language-specific JSON transformations.
Consumers validate splice bounds, unique names, base existence and expanded
digests before passing each vector to the production parser.

The 136 negatives cover every field's omission, null, duplicate, reordering and
wrong types; digest grammar and lengths; schema/literal substitutions; equivalent
escaping; unknown fields; whitespace, BOM, trailing data, invalid UTF-8, empty
input, and 4,096/4,097-byte inputs. Size 4,096 remains invalid because its padding
is not canonical; this catalog does not imply every in-limit byte string is valid.
Fixed expected bytes and hashes are test fixtures, not generated runtime artifacts.
