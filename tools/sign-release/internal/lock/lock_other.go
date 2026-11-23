//go:build !unix

package lock

func acquire(string, string) (*Lock, error) {
	return nil, ErrUnsupported
}
