//go:build unix

package secretstore

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/godbus/dbus/v5"
)

// sessionBusAddress returns the session bus address for the environment getenv
// reads, or "" when there is none. It never starts a bus.
//
// DBUS_SESSION_BUS_ADDRESS wins when it is set, whatever it holds: an address
// that is not unix: is refused later and does not fall back. Otherwise the
// address is the socket libdbus uses for a systemd user session,
// $XDG_RUNTIME_DIR/bus, under libdbus's own checks: the directory is an
// absolute path, and the socket is a socket itself and not a symlink to one,
// owned by the effective user euid. Any check that fails gives "", and nothing
// says which one, because the path is environment text. The window between the
// Lstat and the dial is accepted, as in libdbus: the owner check bounds the
// threat to the same user.
func sessionBusAddress(getenv func(string) string, euid int) string {
	if addr := getenv("DBUS_SESSION_BUS_ADDRESS"); addr != "" {
		return addr
	}
	dir := getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(dir) {
		return ""
	}
	path := dir + "/bus"
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(euid) {
		return ""
	}
	return "unix:path=" + dbus.EscapeBusAddressValue(path)
}
