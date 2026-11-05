package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentRequestsShareOneBucket(t *testing.T) {
	l := New(5, time.Minute)
	l.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, retry := l.Allow("192.0.2.1")
			if ok {
				allowed.Add(1)
				if retry != 0 {
					t.Errorf("allowed request has retry delay %s", retry)
				}
			} else if retry != time.Minute {
				t.Errorf("denied request retry delay %s", retry)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 5 {
		t.Fatalf("allowed %d requests, want 5", got)
	}
	if ok, _ := l.Allow("192.0.2.2"); !ok {
		t.Fatal("independent IP was limited")
	}
}

func TestWindowResetRetryAndExpiredBucketPruning(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(1, time.Minute)
	l.now = func() time.Time { return now }
	if ok, _ := l.Allow("192.0.2.1"); !ok {
		t.Fatal("first request denied")
	}
	now = now.Add(20 * time.Second)
	if ok, retry := l.Allow("192.0.2.1"); ok || retry != 40*time.Second {
		t.Fatalf("second request: %v, %s", ok, retry)
	}
	if ok, _ := l.Allow("192.0.2.2"); !ok {
		t.Fatal("independent bucket denied")
	}
	now = now.Add(40 * time.Second)
	if ok, retry := l.Allow("192.0.2.1"); !ok || retry != 0 {
		t.Fatalf("boundary reset: %v, %s", ok, retry)
	}
	if _, exists := l.buckets["192.0.2.2"]; !exists {
		t.Fatal("active bucket pruned")
	}
	now = now.Add(time.Minute)
	if ok, _ := l.Allow("192.0.2.3"); !ok {
		t.Fatal("new bucket denied")
	}
	if len(l.buckets) != 1 {
		t.Fatalf("expired buckets retained: %d", len(l.buckets))
	}
}
