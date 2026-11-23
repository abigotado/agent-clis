//go:build !unix

package lock

func acquire(string, string) (*Lock, error) {
	return nil, ErrUnsupported
}

// MkWorkDir is not supported without unix file modes.
func MkWorkDir(string) (string, error) {
	return "", ErrUnsupported
}
