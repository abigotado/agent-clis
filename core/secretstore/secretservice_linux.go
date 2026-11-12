package secretstore

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/godbus/dbus/v5"
)

// This file binds ssBus to a private godbus connection. It holds no Secret
// Service logic: secretservice.go decides what is asked and how errors
// classify.

var errMalformedSignal = errors.New("secretstore: malformed Completed signal")

// dbusConn is one private session bus connection with authentication and
// Hello done.
type dbusConn struct {
	conn *dbus.Conn
}

var _ ssBus = (*dbusConn)(nil)

// dialBus connects to the first reachable endpoint. Every connection is
// private to one operation. It dials the socket itself instead of calling
// dbus.SessionBus, which would fall back to launching a bus.
func dialBus(ctx context.Context, endpoints []busEndpoint) (ssBus, error) {
	var last error
	for _, endpoint := range endpoints {
		bus, err := dialEndpoint(ctx, endpoint)
		if err == nil {
			return bus, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errBusAddress
	}
	return nil, last
}

func dialEndpoint(ctx context.Context, endpoint busEndpoint) (*dbusConn, error) {
	name := endpoint.name
	if endpoint.abstract {
		name = "@" + name
	}
	var dialer net.Dialer
	nc, err := dialer.DialContext(ctx, "unix", name)
	if err != nil {
		return nil, err
	}
	// Authentication and Hello cannot be given a context, so a canceled
	// context expires the socket's deadline, which unblocks both.
	stop := context.AfterFunc(ctx, func() {
		// The only failure is a closed socket, which the handshake reports.
		_ = nc.SetDeadline(time.Now())
	})
	conn, err := dbus.NewConn(nc)
	if err != nil {
		stop()
		return nil, closeAfter(ctx, nc, err)
	}
	if err := conn.Auth(nil); err != nil {
		stop()
		return nil, closeAfter(ctx, conn, err)
	}
	if err := conn.Hello(); err != nil {
		stop()
		return nil, closeAfter(ctx, conn, err)
	}
	if !stop() {
		// The context ended during the handshake and the deadline fired.
		return nil, closeAfter(ctx, conn, ctx.Err())
	}
	if err := nc.SetDeadline(time.Time{}); err != nil {
		return nil, closeAfter(ctx, conn, err)
	}
	return &dbusConn{conn: conn}, nil
}

// closeAfter closes c and returns the context error if the context ended, so
// a canceled dial reports the cancellation and not the socket timeout it caused.
func closeAfter(ctx context.Context, c interface{ Close() error }, err error) error {
	// The handshake error is the one worth returning; a close error adds nothing.
	_ = c.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func (c *dbusConn) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
	call := c.conn.Object(serviceDest, path).CallWithContext(ctx, method, 0, args...)
	if call.Err != nil {
		return nil, call.Err
	}
	return call.Body, nil
}

func (c *dbusConn) close() {
	// The connection is private to the operation that is ending; a close
	// error has nothing left to affect.
	_ = c.conn.Close()
}

func (c *dbusConn) watchCompleted(ctx context.Context, prompt dbus.ObjectPath) (ssWatch, error) {
	signals := make(chan *dbus.Signal, 16)
	c.conn.Signal(signals)
	err := c.conn.AddMatchSignalContext(ctx,
		dbus.WithMatchSender(serviceDest),
		dbus.WithMatchObjectPath(prompt),
		dbus.WithMatchInterface(ifacePrompt),
		dbus.WithMatchMember("Completed"),
	)
	if err != nil {
		c.conn.RemoveSignal(signals)
		return nil, err
	}
	return &dbusWatch{conn: c.conn, prompt: prompt, signals: signals}, nil
}

// dbusWatch is a Completed subscription on a private connection. The match rule
// is not removed on stop: the connection ends with the operation.
type dbusWatch struct {
	conn    *dbus.Conn
	prompt  dbus.ObjectPath
	signals chan *dbus.Signal
}

func (w *dbusWatch) wait(ctx context.Context) (ssCompletion, error) {
	for {
		select {
		case signal, ok := <-w.signals:
			if !ok {
				return ssCompletion{}, dbus.ErrClosed
			}
			if signal.Path != w.prompt || signal.Name != ifacePrompt+".Completed" {
				continue
			}
			if len(signal.Body) != 2 {
				return ssCompletion{}, errMalformedSignal
			}
			dismissed, ok1 := signal.Body[0].(bool)
			result, ok2 := signal.Body[1].(dbus.Variant)
			if !ok1 || !ok2 {
				return ssCompletion{}, errMalformedSignal
			}
			return ssCompletion{dismissed: dismissed, result: result}, nil
		case <-ctx.Done():
			return ssCompletion{}, ctx.Err()
		}
	}
}

func (w *dbusWatch) stop() {
	w.conn.RemoveSignal(w.signals)
}
