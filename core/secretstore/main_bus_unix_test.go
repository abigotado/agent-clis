//go:build unix

package secretstore

import (
	"net"
	"testing"
	"time"
)

// TestHelperProcessesDoNotDialTheSessionBus puts a listener where the parent's
// session bus would be, through each way Open finds one, runs the helpers that
// call Open, and requires that nothing but this test's own probe connected.
// Each connection is numbered in the order Accept returned it, which is the
// order the listener queued them, and the probe must be the next number: a
// connection from a helper, silent or not, takes a number before it. The
// readers of different connections run concurrently and report in no order the
// test relies on.
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
		seq int
		b   byte
		err error
	}
	arrivals := make(chan firstByte, 16)
	go func() {
		for seq := 0; ; seq++ {
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
				arrivals <- firstByte{seq: seq, b: buf[0], err: err}
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
	for i, tt := range tests {
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
			// Every connection that arrives is read until the probe's does. One that
			// is not the probe is a helper's.
			hang := time.After(time.Minute) // only a hang reaches it
			for {
				select {
				case got := <-arrivals:
					if got.err != nil || got.b != 'P' {
						t.Fatalf("a helper process connected to the session bus (connection %d, first byte %#x, err %v)", got.seq, got.b, got.err)
					}
					// Subtest i's probe is connection i when nothing else connected,
					// including a connection that stayed silent.
					if got.seq != i {
						t.Fatalf("the probe was connection %d, want %d: a helper process connected to the session bus before it", got.seq, i)
					}
					return
				case <-hang:
					t.Fatal("the probe never arrived")
				}
			}
		})
	}
}
