//go:build linux && secretserviceintegration

package secretstore_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/abigotado/agent-clis/core/secretstore"
	"github.com/abigotado/agent-clis/core/secretstore/secretstoretest"
)

// The tests start their own dbus-daemon, with a configuration that has no
// service directory so nothing can be activated, and their own
// gnome-keyring-daemon on that bus with a throwaway HOME and XDG directories.
// They never use the DBUS_SESSION_BUS_ADDRESS of the environment they run in.

const (
	throwawayPassword = "secretstore-integration-throwaway"
	// hangGuard only stops a stuck daemon from hanging the run; nothing
	// asserts on elapsed time.
	hangGuard = 60 * time.Second
	dhName    = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

const busConfig = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`

// requireSecretService reports a missing prerequisite. CI sets
// SECRETSTORE_REQUIRE_SECRET_SERVICE=1, where it fails instead of skipping so
// a runner that lost the daemons cannot pass by testing nothing.
func requireSecretService(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if os.Getenv("SECRETSTORE_REQUIRE_SECRET_SERVICE") == "1" {
		t.Fatalf("a Secret Service is required but unusable: %v", err)
	}
	t.Skipf("no usable Secret Service: %v", err)
}

// startProcess runs cmd and kills it when the test ends.
func startProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Start(); err != nil {
		requireSecretService(t, err)
		return
	}
	t.Cleanup(func() {
		// The daemon is being torn down; a kill error means it already exited.
		_ = cmd.Process.Kill()
		_ = cmd.Wait() // reports the kill; nothing to act on
	})
}

// syncBuffer is a bytes.Buffer safe for the exec copy goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startBus starts a private session bus and returns its address.
func startBus(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("dbus-daemon")
	requireSecretService(t, err)
	dir := t.TempDir()
	config := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(config, []byte(busConfig), 0o600); err != nil {
		t.Fatalf("write bus configuration: %v", err)
	}
	cmd := exec.Command(path, "--config-file="+config, "--print-address=1", "--nofork")
	var stderr syncBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("dbus-daemon stdout: %v", err)
	}
	startProcess(t, cmd)
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()
	select {
	case addr := <-lines:
		if !strings.HasPrefix(addr, "unix:") {
			t.Fatalf("dbus-daemon printed %q, want a unix address; stderr: %s", addr, stderr.String())
		}
		return addr
	case <-time.After(hangGuard):
		t.Fatalf("dbus-daemon printed no address; stderr: %s", stderr.String())
		return ""
	}
}

// startKeyring starts gnome-keyring-daemon on the bus with its login keyring
// created and unlocked by the throwaway password, and waits until a provider
// owns the default collection.
func startKeyring(t *testing.T, addr string) {
	t.Helper()
	path, err := exec.LookPath("gnome-keyring-daemon")
	requireSecretService(t, err)
	root := t.TempDir()
	home := filepath.Join(root, "h")
	run := filepath.Join(root, "r")
	for _, dir := range []string{home, run, filepath.Join(home, "data"), filepath.Join(home, "cfg"), filepath.Join(home, "cache")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	cmd := exec.Command(path, "--foreground", "--components=secrets", "--unlock")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_RUNTIME_DIR=" + run,
		"XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_CONFIG_HOME=" + filepath.Join(home, "cfg"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"DBUS_SESSION_BUS_ADDRESS=" + addr,
	}
	cmd.Stdin = strings.NewReader(throwawayPassword + "\n")
	var output syncBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	startProcess(t, cmd)

	ctx, cancel := context.WithTimeout(t.Context(), hangGuard)
	defer cancel()
	for {
		err := secretstore.ProbeSecretServiceForTest(ctx, addr)
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("gnome-keyring-daemon did not provide the default collection: %v\n%s", err, output.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func newStore(t *testing.T, addr string, max int, mode secretstore.Interaction, plain bool, onSession func(string)) secretstore.Store {
	t.Helper()
	s, err := secretstore.NewSecretServiceStoreForTest(addr, max, mode, plain, onSession)
	if err != nil {
		t.Fatalf("NewSecretServiceStoreForTest: %v", err)
	}
	return s
}

func TestSecretServiceContract(t *testing.T) {
	addr := startBus(t)
	startKeyring(t, addr)
	for _, max := range []int{4096, secretstore.MaxSecretBytesLimit} {
		t.Run(strconv.Itoa(max), func(t *testing.T) {
			secretstoretest.Contract(t, newStore(t, addr, max, secretstore.InteractionNever, false, nil), max)
		})
	}
}

func TestSecretServiceContractPlain(t *testing.T) {
	addr := startBus(t)
	startKeyring(t, addr)
	secretstoretest.Contract(t, newStore(t, addr, 4096, secretstore.InteractionNever, true, nil), 4096)
}

func TestSecretServiceUsesDH(t *testing.T) {
	addr := startBus(t)
	startKeyring(t, addr)
	var mu sync.Mutex
	var algorithms []string
	s := newStore(t, addr, 4096, secretstore.InteractionNever, false, func(a string) {
		mu.Lock()
		defer mu.Unlock()
		algorithms = append(algorithms, a)
	})
	key := secretstore.Key{Service: "secretstore-test-dh", Account: "a"}
	t.Cleanup(func() {
		if err := s.Delete(context.WithoutCancel(t.Context()), key); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	if err := s.Save(t.Context(), key, []byte("dh-secret")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, err := s.Load(t.Context(), key); err != nil || string(got) != "dh-secret" {
		t.Fatalf("Load = %q, %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(algorithms) != 2 || algorithms[0] != dhName || algorithms[1] != dhName {
		t.Fatalf("session algorithms = %v, want two %s", algorithms, dhName)
	}
}

// lockDefaultCollection locks the default collection through a private
// connection to the test bus.
func lockDefaultCollection(t *testing.T, addr string) {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatalf("connect to the test bus: %v", err)
	}
	defer conn.Close()
	service := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	var collection dbus.ObjectPath
	if err := service.CallWithContext(t.Context(), "org.freedesktop.Secret.Service.ReadAlias", 0, "default").Store(&collection); err != nil {
		t.Fatalf("ReadAlias: %v", err)
	}
	var locked []dbus.ObjectPath
	if err := service.CallWithContext(t.Context(), "org.freedesktop.Secret.Service.Lock", 0, []dbus.ObjectPath{collection}).Store(&locked, new(dbus.ObjectPath)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if len(locked) != 1 {
		t.Fatalf("Lock locked %v, want the default collection", locked)
	}
}

func TestSecretServiceLocked(t *testing.T) {
	addr := startBus(t)
	startKeyring(t, addr)
	s := newStore(t, addr, 4096, secretstore.InteractionNever, false, nil)
	key := secretstore.Key{Service: "secretstore-test-lock", Account: "a"}
	if err := s.Save(t.Context(), key, []byte("before")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	lockDefaultCollection(t, addr)

	ctx := t.Context()
	_, err := s.Load(ctx, key)
	if !errors.Is(err, secretstore.ErrInteractionRequired) {
		t.Errorf("Load on a locked collection: %v, want ErrInteractionRequired", err)
	}
	if err := s.Save(ctx, key, []byte("after")); !errors.Is(err, secretstore.ErrInteractionRequired) {
		t.Errorf("Save on a locked collection: %v, want ErrInteractionRequired", err)
	}
	if err := s.Delete(ctx, key); !errors.Is(err, secretstore.ErrInteractionRequired) {
		t.Errorf("Delete on a locked collection: %v, want ErrInteractionRequired", err)
	}
}

func TestSecretServiceNoProvider(t *testing.T) {
	addr := startBus(t) // a bus with no provider and no way to activate one
	err := secretstore.ProbeSecretServiceForTest(t.Context(), addr)
	var se *secretstore.Error
	if !errors.Is(err, secretstore.ErrUnavailable) || !errors.As(err, &se) || se.Reason != secretstore.ReasonServiceUnknown {
		t.Fatalf("probe on a bus without a provider = %v, want ErrUnavailable with service-unknown", err)
	}
	s := newStore(t, addr, 4096, secretstore.InteractionNever, false, nil)
	key := secretstore.Key{Service: "secretstore-test-none", Account: "a"}
	if _, err := s.Load(t.Context(), key); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("Load = %v, want ErrUnavailable", err)
	}
}

// TestSecretServiceOpen goes through Open and the environment, pointing
// DBUS_SESSION_BUS_ADDRESS at the private bus for this test only.
func TestSecretServiceOpen(t *testing.T) {
	addr := startBus(t)
	startKeyring(t, addr)
	opts := secretstore.Options{MaxSecretBytes: 4096, Interaction: secretstore.InteractionNever}

	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "tcp:host=localhost,port=1")
	if _, err := secretstore.Open(t.Context(), opts); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("Open with a tcp address = %v, want ErrUnavailable", err)
	}
	// An empty address falls back to $XDG_RUNTIME_DIR/bus, so that must hold no
	// socket for the refusal to be what is tested.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	if _, err := secretstore.Open(t.Context(), opts); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("Open with an empty address = %v, want ErrUnavailable", err)
	}

	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	s, err := secretstore.Open(t.Context(), opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key := secretstore.Key{Service: "secretstore-test-open", Account: "a"}
	t.Cleanup(func() {
		if err := s.Delete(context.WithoutCancel(t.Context()), key); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	if err := s.Save(t.Context(), key, []byte("via-open")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, err := s.Load(t.Context(), key); err != nil || string(got) != "via-open" {
		t.Fatalf("Load = %q, %v", got, err)
	}
}
