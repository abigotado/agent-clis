//go:build darwin && cgo && macos_identity_readonly

// Package assets contains the Remote-MCP-only skill shipped by the developer-
// only macOS identity metadata edition.
package assets

import "embed"

// FS contains only the Remote-MCP read-only skill payload.
//
//go:embed all:skills/youtrack-agent-readonly
var FS embed.FS
