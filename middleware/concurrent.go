package middleware

import (
    "sync"
)

type ConcurrentLimiter struct {
    slots map[string]chan struct{}
    mu    sync.Mutex
    limit int
}

// NewConcurrentLimiter creates a new ConcurrentLimiter with the specified limit
func NewConcurrentLimiter(limit int) *ConcurrentLimiter {
    return &ConcurrentLimiter{
        slots: make(map[string]chan struct{}),
        limit: limit,
    }
}

// take a slot for the given IP, create if not exists
func (cl *ConcurrentLimiter) getSlot(ip string) chan struct{} {
    cl.mu.Lock()
    defer cl.mu.Unlock()
    ch, ok := cl.slots[ip]
    if !ok {
        ch = make(chan struct{}, cl.limit)
        cl.slots[ip] = ch
    }
    return ch
}

// try to acquire a slot for the given IP
func (cl *ConcurrentLimiter) Acquire(ip string) bool {
    ch := cl.getSlot(ip)
    select {
    case ch <- struct{}{}:
        return true
    default:
        return false
    }
}

// Releasing a slot for the given IP
func (cl *ConcurrentLimiter) Release(ip string) {
    ch := cl.getSlot(ip)
    select {
    case <-ch:
    default:
    }
}