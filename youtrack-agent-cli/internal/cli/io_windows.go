//go:build windows

package cli

import "os"

func openRegularNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
