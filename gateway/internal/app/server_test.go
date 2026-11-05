package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type observedListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *observedListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func waitFor(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestServeDrainsActiveRequest(t *testing.T)     { testShutdown(t, false, time.Second) }
func TestServeForcesCloseAfterTimeout(t *testing.T) { testShutdown(t, true, 30*time.Millisecond) }

func testShutdown(t *testing.T, force bool, timeout time.Duration) {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &observedListener{Listener: base, closed: make(chan struct{})}
	entered, release := make(chan struct{}), make(chan struct{})
	handlerCanceled := make(chan bool, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			handlerCanceled <- false
			_, _ = io.WriteString(w, "completed")
		case <-r.Context().Done():
			handlerCanceled <- true
		}
	})}
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- Serve(ctx, server, listener, timeout, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response := make(chan error, 1)
	go func() {
		resp, err := client.Get("http://" + listener.Addr().String() + "/")
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err == nil && resp.StatusCode != 200 {
				err = errors.New("unexpected response")
			}
		}
		response <- err
	}()
	waitFor(t, entered, "handler entry")
	cancel()
	waitFor(t, listener.closed, "listener closure")
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("gateway accepted a connection during shutdown")
	}
	if !force {
		select {
		case err := <-finished:
			t.Fatalf("Serve returned while request was active: %v", err)
		default:
		}
		close(release)
	}
	select {
	case canceled := <-handlerCanceled:
		if canceled != force {
			t.Fatalf("handler canceled=%v, want %v", canceled, force)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	select {
	case err := <-response:
		if force && err == nil {
			t.Fatal("forced close produced a successful response")
		}
		if !force && err != nil {
			t.Fatalf("in-flight request failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP client did not finish")
	}
	select {
	case err := <-finished:
		if force && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected shutdown deadline, got %v", err)
		}
		if !force && err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not finish")
	}
}
