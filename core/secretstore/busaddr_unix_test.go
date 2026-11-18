//go:build unix

package secretstore

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// shortDir returns a fresh directory whose path is short enough for a unix
// socket inside it (the limit is about 100 bytes), unlike t.TempDir, which
// embeds the test name.
func shortDir(t *testing.T, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		t.Fatalf("make a temporary directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove %s: %v", dir, err)
		}
	})
	return dir
}

// listenAt makes a real unix socket at path and keeps it until the test ends.
func listenAt(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on a unix socket: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close the listener: %v", err)
		}
	})
}

func envOf(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

// TestSessionBusAddress covers the address rule: DBUS_SESSION_BUS_ADDRESS, then
// $XDG_RUNTIME_DIR/bus under libdbus's checks. The ownership check is driven by
// the euid argument, so both of its outcomes are tested with the real owner of
// a real socket: this process.
func TestSessionBusAddress(t *testing.T) {
	euid := os.Geteuid()
	tests := []struct {
		name  string
		setup func(t *testing.T) map[string]string
		euid  int
		want  func(dir string) string // dir is XDG_RUNTIME_DIR when the setup set one
	}{
		{
			name: "address variable wins over a valid socket",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				listenAt(t, dir+"/bus")
				return map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/elsewhere", "XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(string) string { return "unix:path=/elsewhere" },
		},
		{
			name: "a non-unix address is returned for refusal and is not replaced by the socket",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				listenAt(t, dir+"/bus")
				return map[string]string{"DBUS_SESSION_BUS_ADDRESS": "tcp:host=localhost,port=1", "XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(string) string { return "tcp:host=localhost,port=1" },
		},
		{
			name: "socket owned by this user",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				listenAt(t, dir+"/bus")
				return map[string]string{"XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(dir string) string { return "unix:path=" + dir + "/bus" },
		},
		{
			name: "directory name that needs address escaping",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "s s,")
				listenAt(t, dir+"/bus")
				return map[string]string{"XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(dir string) string {
				return "unix:path=" + strings.NewReplacer(" ", "%20", ",", "%2c").Replace(dir) + "/bus"
			},
		},
		{
			name: "socket owned by another user",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				listenAt(t, dir+"/bus")
				return map[string]string{"XDG_RUNTIME_DIR": dir}
			},
			euid: euid + 1,
			want: func(string) string { return "" },
		},
		{
			name: "regular file named bus",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				if err := os.WriteFile(dir+"/bus", nil, 0o600); err != nil {
					t.Fatalf("write the file: %v", err)
				}
				return map[string]string{"XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(string) string { return "" },
		},
		{
			name: "symlink to a socket",
			setup: func(t *testing.T) map[string]string {
				target := shortDir(t, "ss")
				listenAt(t, target+"/real")
				dir := shortDir(t, "ss")
				if err := os.Symlink(target+"/real", dir+"/bus"); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return map[string]string{"XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(string) string { return "" },
		},
		{
			name: "directory named bus",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				if err := os.Mkdir(dir+"/bus", 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				return map[string]string{"XDG_RUNTIME_DIR": dir}
			},
			euid: euid,
			want: func(string) string { return "" },
		},
		{
			name: "no bus in the directory",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"XDG_RUNTIME_DIR": shortDir(t, "ss")}
			},
			euid: euid,
			want: func(string) string { return "" },
		},
		{
			name: "relative directory with a socket in it",
			setup: func(t *testing.T) map[string]string {
				dir := shortDir(t, "ss")
				listenAt(t, dir+"/bus")
				rel, err := filepath.Rel(mustGetwd(t), dir)
				if err != nil || filepath.IsAbs(rel) {
					t.Skipf("no relative path to the temporary directory: %v", err)
				}
				return map[string]string{"XDG_RUNTIME_DIR": rel}
			},
			euid: euid,
			want: func(string) string { return "" },
		},
		{
			name:  "runtime directory unset",
			setup: func(*testing.T) map[string]string { return map[string]string{} },
			euid:  euid,
			want:  func(string) string { return "" },
		},
		{
			name:  "runtime directory empty",
			setup: func(*testing.T) map[string]string { return map[string]string{"XDG_RUNTIME_DIR": ""} },
			euid:  euid,
			want:  func(string) string { return "" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := tt.setup(t)
			got := sessionBusAddress(envOf(vars), tt.euid)
			if want := tt.want(vars["XDG_RUNTIME_DIR"]); got != want {
				t.Fatalf("sessionBusAddress = %q, want %q", got, want)
			}
		})
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}

// TestSessionBusAddressFeedsOpen runs the address through openSecretService, as
// openNative does: the fallback socket is dialed, and every refusal is an
// ErrUnavailable that does not echo the path and dials nothing.
func TestSessionBusAddressFeedsOpen(t *testing.T) {
	dir := shortDir(t, "ss a")
	listenAt(t, dir+"/bus")
	regular := shortDir(t, "ss")
	if err := os.WriteFile(regular+"/bus", nil, 0o600); err != nil {
		t.Fatalf("write the file: %v", err)
	}
	euid := os.Geteuid()

	t.Run("fallback socket is dialed", func(t *testing.T) {
		f := newFakeSS()
		var got []busEndpoint
		s, err := openSecretService(t.Context(), Options{MaxSecretBytes: ssMax},
			sessionBusAddress(envOf(map[string]string{"XDG_RUNTIME_DIR": dir}), euid),
			func(ctx context.Context, endpoints []busEndpoint) (ssBus, error) {
				got = endpoints
				return f.dialer()(ctx)
			})
		if err != nil || s == nil {
			t.Fatalf("openSecretService = %v, %v", s, err)
		}
		if !slices.Equal(got, []busEndpoint{{name: dir + "/bus"}}) {
			t.Fatalf("dialed %v, want the socket under the runtime directory", got)
		}
	})

	refused := []struct {
		name string
		vars map[string]string
		euid int
	}{
		{"non-unix address with a valid socket", map[string]string{"DBUS_SESSION_BUS_ADDRESS": "tcp:host=localhost,port=1", "XDG_RUNTIME_DIR": dir}, euid},
		{"regular file", map[string]string{"XDG_RUNTIME_DIR": regular}, euid},
		{"another user's socket", map[string]string{"XDG_RUNTIME_DIR": dir}, euid + 1},
		{"relative directory", map[string]string{"XDG_RUNTIME_DIR": "run/user"}, euid},
		{"nothing set", map[string]string{}, euid},
	}
	for _, tt := range refused {
		t.Run("refused: "+tt.name, func(t *testing.T) {
			_, err := openSecretService(t.Context(), Options{MaxSecretBytes: ssMax},
				sessionBusAddress(envOf(tt.vars), tt.euid),
				func(context.Context, []busEndpoint) (ssBus, error) {
					t.Error("a refused address was dialed")
					return nil, errors.New("must not be reached")
				})
			var se *Error
			if !errors.Is(err, ErrUnavailable) || !errors.As(err, &se) || se.Op != "open" || se.Backend != "secretservice" {
				t.Fatalf("err = %v, want an open ErrUnavailable on the secretservice backend", err)
			}
			for _, secret := range []string{dir, regular, "relative", "tcp"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(se.GoString(), secret) {
					t.Fatalf("error text %q echoes environment text %q", err.Error(), secret)
				}
			}
		})
	}
}
