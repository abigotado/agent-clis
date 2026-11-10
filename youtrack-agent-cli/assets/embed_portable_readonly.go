//go:build portable_readonly && !macos_identity_readonly

// Package assets contains the Remote-MCP-only skill shipped by the portable
// read-only edition.
package assets

import "embed"

// FS contains only the portable read-only skill payload.
//
//go:embed all:skills/youtrack-agent-readonly
var FS embed.FS
