package events

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunCancelsBlockedAMQPHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		// Accept TCP, but never respond to the AMQP protocol handshake.
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- New("amqp://user:password@"+listener.Addr().String()+"/", nil).Run(ctx, nil)
	}()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not connect")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt AMQP handshake")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("publisher left its transport open")
	}
}

func TestConnectionFailureDoesNotLogCredentials(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := New("amqp://user:sensitive-password@invalid-host:invalid-port/", logger).Run(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "sensitive-password") || strings.Contains(output.String(), "amqp://") {
		t.Fatal("connection credentials leaked to logs")
	}
	if !strings.Contains(output.String(), "outbox retained") {
		t.Fatal("delivery failure was not reported")
	}
}
