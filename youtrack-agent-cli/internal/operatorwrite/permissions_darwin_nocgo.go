//go:build darwin && !cgo

package operatorwrite

func platformSupported() bool  { return false }
func safeACL(int, bool) bool   { return false }
func localFilesystem(int) bool { return false }
