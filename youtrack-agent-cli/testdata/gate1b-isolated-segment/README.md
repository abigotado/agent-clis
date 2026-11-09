# Isolated segment contract syntax vectors

Both Go and Swift consume all eight positive and 196 negative entries in
`vectors.json`. This is a pure canonical syntax/range catalog, not evidence of
recursive references, aggregate consistency, native execution or a Gate pass.

Positive `raw` strings are exact UTF-8 canonical bytes without a newline;
`sha256` is their fixed plain SHA-256. Both ordinal/mode pairs cover realistic
example counts, every counter at its minimum and maximum, and a deliberately
cross-count-inconsistent but domain-valid `operation_count=128` with
`observation_count=1`. That last case must parse: aggregate/closure checks belong
to later work. Four distinct repeated digest digits detect swapped fields.
`ordinal`, `mode` and the six ordered `counts` are explicit getter expectations.

Each negative names a positive `base` and applies one byte splice: remove
`delete` bytes at zero-based `offset`, insert lowercase-hex `insert_hex` bytes,
and retain the untouched prefix/suffix. Its fixed `sha256` validates the expanded
input. Both consumers check bounds, unique names, base existence and digest
before parsing. Hex preserves invalid UTF-8/NUL without reserializing JSON.

Negative cases cover all 14 fields' omission, null, duplicate, reordering and
wrong types; all six counters at zero, negative, maximum plus one, decimal,
exponent, quoted integer and massive overflow; ordinal/mode mismatch; four
digest grammars; escaping, unknown fields, sentinel diagnostics, whitespace,
BOM, trailing bytes/JSON, invalid UTF-8, empty and 4,096/4,097-byte inputs.
The 4,096-byte case is invalid because padding is not canonical, independent of
being within the byte cap. These fixtures confer no authority or runtime access.
