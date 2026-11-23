// Package usage holds the text sign-release prints when it is run without a
// supported invocation.
package usage

// Text returns the usage message, ending in a newline.
func Text() string {
	return `usage: sign-release <cli> <version>

Signs the darwin archives of a draft release, uploads them and publishes it.
Run it from tools/sign-release, its own module: GOWORK=off go run . <cli> <version>

gh must be logged in through its own stored login (gh auth login).
GH_TOKEN, GH_HOST, GITHUB_TOKEN, GH_CONFIG_DIR, XDG_CONFIG_HOME and proxy
variables are ignored on purpose: the tool starts gh with a minimal
environment and the account's own home directory, so only gh's default login
and config under that home are used.

The operator answers one Keychain prompt per binary: choose Allow, never
Always Allow. The operator also types the release tag twice, once before the
upload and once before the publish.
`
}
