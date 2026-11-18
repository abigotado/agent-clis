// Package usage holds the text sign-release prints when it is run without a
// supported invocation.
package usage

// Text returns the usage message, ending in a newline.
func Text() string {
	return "usage: sign-release <cli> <version>\n"
}
