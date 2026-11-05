package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	count   int
	expires time.Time
}

type Limiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	buckets   map[string]bucket
	nextPrune time.Time
	now       func() time.Time
}

// New creates an in-memory fixed window limiter. Configuration must be positive.
func New(limit int, window time.Duration) *Limiter {
	if limit <= 0 || window <= 0 {
		panic("ratelimit: limit and window must be positive")
	}
	return &Limiter{limit: limit, window: window, buckets: make(map[string]bucket), now: time.Now}
}

func (l *Limiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !now.Before(l.nextPrune) {
		for key, entry := range l.buckets {
			if !now.Before(entry.expires) {
				delete(l.buckets, key)
			}
		}
		l.nextPrune = now.Add(l.window)
	}
	entry, exists := l.buckets[ip]
	if !exists || !now.Before(entry.expires) {
		entry = bucket{expires: now.Add(l.window)}
	}
	if entry.count >= l.limit {
		return false, entry.expires.Sub(now)
	}
	entry.count++
	l.buckets[ip] = entry
	return true, 0
}
