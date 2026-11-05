package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

func newListener(t *testing.T) *observedListener {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &observedListener{Listener: base, closed: make(chan struct{})}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func waitFor(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func closeOnce(ch chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

func request(t *testing.T, url string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	go func() {
		response, err := client.Get(url)
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != 200 {
				err = errors.New("unexpected response status")
			}
		}
		done <- err
	}()
	return done
}

func TestServeDrainsHTTPBeforeCancelingWorkers(t *testing.T) {
	l := newListener(t)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseRequest := closeOnce(release)
	t.Cleanup(releaseRequest)
	workerCanceled, workerCleanup := make(chan struct{}), make(chan struct{})
	releaseWorker := closeOnce(workerCleanup)
	t.Cleanup(releaseWorker)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			t.Error("in-flight request canceled during drain")
			return
		}
		select {
		case <-workerCanceled:
			t.Error("worker canceled before HTTP handler completed")
		default:
		}
		_, _ = io.WriteString(w, "completed")
	})}
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- Serve(ctx, server, l, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)), func(ctx context.Context) { <-ctx.Done(); close(workerCanceled); <-workerCleanup })
	}()
	response := request(t, "http://"+l.Addr().String()+"/")
	waitFor(t, entered, "request entry")
	cancel()
	waitFor(t, l.closed, "listener closure")
	select {
	case <-workerCanceled:
		t.Fatal("workers stopped while HTTP request was active")
	default:
	}
	if conn, err := net.DialTimeout("tcp", l.Addr().String(), 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("server accepted a connection after shutdown started")
	}
	releaseRequest()
	select {
	case err := <-response:
		if err != nil {
			t.Fatalf("in-flight request failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	waitFor(t, workerCanceled, "worker cancellation")
	select {
	case err := <-finished:
		t.Fatalf("Serve returned before worker cleanup completed: %v", err)
	default:
	}
	releaseWorker()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not finish")
	}
}

func TestServeForcesTimedOutHTTPAndStillWaitsForWorkerCleanup(t *testing.T) {
	l := newListener(t)
	entered, requestCanceled := make(chan struct{}), make(chan struct{})
	workerCanceled, workerCleanup := make(chan struct{}), make(chan struct{})
	releaseWorker := closeOnce(workerCleanup)
	t.Cleanup(releaseWorker)
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(requestCanceled)
	})}
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- Serve(ctx, server, l, 30*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), func(ctx context.Context) { <-ctx.Done(); close(workerCanceled); <-workerCleanup })
	}()
	response := request(t, "http://"+l.Addr().String()+"/")
	waitFor(t, entered, "request entry")
	cancel()
	waitFor(t, requestCanceled, "forced request cancellation")
	waitFor(t, workerCanceled, "worker cancellation after timeout")
	select {
	case err := <-finished:
		t.Fatalf("Serve returned before canceled worker cleaned up: %v", err)
	default:
	}
	releaseWorker()
	select {
	case err := <-finished:
		if err == nil || !strings.Contains(err.Error(), "HTTP drain") || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected HTTP drain timeout, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forced shutdown did not finish")
	}
	select {
	case <-response:
	case <-time.After(3 * time.Second):
		t.Fatal("client request did not unblock after forced close")
	}
}
