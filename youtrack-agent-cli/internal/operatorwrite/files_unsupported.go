//go:build !darwin && !linux

package operatorwrite

import "os"

type secureDirectory struct {
	file *os.File
	path string
}

func openDirectory(string, bool) (*secureDirectory, error)    { return nil, invalid() }
func (*secureDirectory) close() error                         { return invalid() }
func (*secureDirectory) exists(string) (bool, error)          { return false, invalid() }
func (*secureDirectory) read(string, int) ([]byte, error)     { return nil, invalid() }
func (*secureDirectory) create(string, []byte, *Store) error  { return invalid() }
func (*secureDirectory) replace(string, []byte, *Store) error { return invalid() }
