//go:build darwin

package main

import _ "embed"

// configJSON is the release configuration, shared with the tap workflow and the
// formula renderer. It is parsed by internal/config, which is untagged so
// Linux CI validates the same file.
//
//go:embed config.json
var configJSON []byte
