//go:build unix

package secretstore

import (
	"net"
	"testing"
)

// TestHelperProcessesDoNotDialTheSessionBus puts a listener where the parent's
// session bus would be, through each way Open finds one, runs the helpers that
// call Open, and requires that nothing but this test's own probe connected.
// Connections are served in arrival order, so a connection from a helper would
// be read before the probe's.
func TestHelperProcessesDoNotDialTheSessionBus(t *testing.T) {
	busDir := shortDir(t, "ss")
	ln, err := net.Listen("unix", busDir+"/bus")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close the listener: %v", err)
		}
	})

	type firstByte struct {
		b   byte
		err error
	}
	arrivals := make(chan firstByte, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // the listener was closed by the cleanup
			}
			go func() {
				defer func() {
					// The peer may already be gone; the close only frees our end.
					_ = conn.Close()
				}()
				var buf [1]byte
				_, err := conn.Read(buf[:])
				arrivals <- firstByte{b: buf[0], err: err}
			}()
		}
	}()

	tests := []struct {
		name string
		env  map[string]string
	}{
		{"address variable", map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=" + busDir + "/bus", "XDG_RUNTIME_DIR": ""}},
		{"runtime directory socket", map[string]string{"DBUS_SESSION_BUS_ADDRESS": "", "XDG_RUNTIME_DIR": busDir}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			for _, helper := range []string{"mode-conflict", "failed-first-open", "invalid-options-do-not-record"} {
				runHelperProcess(t, helper)
			}
			probe, err := net.Dial("unix", busDir+"/bus")
			if err != nil {
				t.Fatalf("dial the probe: %v", err)
			}
			if _, err := probe.Write([]byte("P")); err != nil {
				t.Fatalf("write the probe: %v", err)
			}
			if err := probe.Close(); err != nil {
				t.Fatalf("close the probe: %v", err)
			}
			select {
			case first := <-arrivals:
				if first.err != nil || first.b != 'P' {
					t.Fatalf("a helper process connected to the session bus before the probe did (first byte %#x, err %v)", first.b, first.err)
				}
			case <-t.Context().Done():
				t.Fatal("the probe never arrived")
			}
		})
	}
}
