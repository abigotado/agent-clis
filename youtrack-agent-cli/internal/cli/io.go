package cli

import (
	"fmt"
	"io"
	"os"
)

const maxProfileFileBytes = 64 << 10

func readBounded(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum <= 0 {
		return nil, fmt.Errorf("invalid bounded input reader")
	}
	limited := io.LimitReader(reader, int64(maximum)+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read bounded input: %w", err)
	}
	if len(raw) > maximum {
		return nil, fmt.Errorf("input exceeds %d bytes", maximum)
	}
	return raw, nil
}

func readBoundedRegular(path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect input file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input path must be a regular non-symlink file")
	}
	if info.Size() > int64(maximum) {
		return nil, fmt.Errorf("input exceeds %d bytes", maximum)
	}
	file, err := openRegularNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened input file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("input file changed while opening")
	}
	return readBounded(file, maximum)
}
