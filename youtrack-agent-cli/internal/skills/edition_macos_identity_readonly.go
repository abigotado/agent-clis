//go:build darwin && cgo && macos_identity_readonly

package skills

func embeddedSkillRoot() string { return "skills/youtrack-agent-readonly" }
