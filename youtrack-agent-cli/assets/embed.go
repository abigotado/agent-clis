//go:build !portable_readonly && !macos_identity_readonly

// Package assets contains the provider-neutral Agent Skill shipped by
// youtrack-agent-cli.
package assets

import "embed"

// FS contains every skill file, including dotfiles if any are added later.
//
//go:embed all:skills
var FS embed.FS
