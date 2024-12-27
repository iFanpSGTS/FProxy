package middleware

import (
	"sync"
	"time"
	"net/http"
)

type rateLimiter struct {
	mu        sync.Mutex
	clients   map[string]*clientData
	limit     int
	timeFrame time.Duration
}

type clientData struct {
	requests int
	lastSeen time.Time
}

func NewRateLimiter(limit int, timeFrame time.Duration) *rateLimiter {
	rl := &rateLimiter{
		clients:   make(map[string]*clientData),
		limit:     limit,
		timeFrame: timeFrame,
	}
	go rl.cleanupOldClients()
	return rl
}

func (rl *rateLimiter) AllowRequest(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	client, exists := rl.clients[ip]
	if !exists || now.Sub(client.lastSeen) > rl.timeFrame {
		rl.clients[ip] = &clientData{requests: 1, lastSeen: now}
		return true
	}

	client.lastSeen = now
	if client.requests < rl.limit {
		client.requests++
		return true
	}

	return false
}

func GetClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}
	return ip
}

func (rl *rateLimiter) cleanupOldClients() {
	var cleanupInterval   = 10 * time.Minute
	for {
		time.Sleep(cleanupInterval)

		rl.mu.Lock()
		now := time.Now()
		for ip, client := range rl.clients {
			if now.Sub(client.lastSeen) > rl.timeFrame {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}