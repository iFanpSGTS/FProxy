package middleware

import (
	"fmt"
	"fproxy/handler"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var forwardedIPs = make(map[string]struct{})
var badUa = []string{"python", "curl", "test", "mzilla/100.0"}
var badMethod = []string{"copy", "wasd", "proffff"}
var slots = make(map[string]chan struct{})

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

var (
	rmu 		sync.RWMutex
	mu            sync.Mutex
	uniqueIPs     = make(map[string]struct{})
	totalRequests int
	blockedCount  int
	reqTimestamps []time.Time
	statsUpdates  = make(chan struct{}, 1)
)

func init() {
    // Start the stats printer goroutine
    go func() {
        for range statsUpdates {
            printStats()
        }
    }()
}

func MarkForwarded(ip string) {
    rmu.Lock()
    forwardedIPs[ip] = struct{}{}
    rmu.Unlock()
}

func GetForwardedIPCount() int {
    rmu.Lock()
    defer rmu.Unlock()
    return len(forwardedIPs)
}
func GetNotForwardedIPCount() int {
    rmu.Lock()
    defer rmu.Unlock()
    count := 0
    for ip := range slots {
        if _, ok := forwardedIPs[ip]; !ok {
            count++
        }
    }
    return count
}

func IncrementBlockedCount() { // used for globals
    mu.Lock()
    blockedCount++
    mu.Unlock()
	select {
	case statsUpdates <- struct{}{}:
	default:
	}
}

func TrafficAnalyzerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		start := time.Now()

		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		mu.Lock()
		uniqueIPs[clientIP] = struct{}{}
		totalRequests++
		reqTimestamps = append(reqTimestamps, start)
		// Clean up old timestamps for RPS calculation (last 1 minute)
		cutoff := time.Now().Add(-1 * time.Minute)
		i := 0
		for ; i < len(reqTimestamps); i++ {
			if reqTimestamps[i].After(cutoff) {
				break
			}
		}
		reqTimestamps = reqTimestamps[i:]
		mu.Unlock()

		if isMaliciousRequest(r){
			handler.RespondBlocked(lrw, r)
			IncrementBlockedCount()
		} else {
			next.ServeHTTP(lrw, r)
		}

		printStats()
	})
}

func printStats() {
	mu.Lock()
	defer mu.Unlock()
	rps := float64(len(reqTimestamps)) / 60.0

	fmt.Fprint(os.Stdout, "\033[2J\033[H")

	fmt.Println("========= FProxy WAF Monitor =========")
	fmt.Printf("Time:           %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("Unique IPs:     %v\n", len(uniqueIPs))
	fmt.Printf("Forwarded IPs:  %d\n", GetForwardedIPCount())
	fmt.Printf("Not Forwarded:  %d\n", GetNotForwardedIPCount())
	fmt.Printf("Total Requests: %d\n", totalRequests)
	fmt.Printf("Blocked:        %d\n", blockedCount)
	fmt.Printf("RPS (1m avg):   %.2f\n", rps)
	fmt.Println("======================================")
}

func checkMaliciousContains(str string, mcs []string) bool {
	for _, mcs := range mcs {
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(mcs))
		re := regexp.MustCompile(pattern)
		if re.MatchString(strings.ToLower(str)) {
			return false
		}
	}
	return true
}

func isMaliciousRequest(r *http.Request) bool {
	// UA
	ua := r.UserAgent()
	if !checkMaliciousContains(ua, badUa) {
		return true
	}

	// QUERY PARAMS
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), "select ") || strings.Contains(strings.ToLower(value), "drop ") {
				return true
			}
		}
	}

	// METHODS
	method := r.Method
	if !checkMaliciousContains(method, badMethod) {
		return true
	}

	// Check request body for potential threats
	if r.Method == http.MethodPost {
		r.ParseForm()
		for _, values := range r.Form {
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), "<script>") || len(value) > 1024 {
					return true
				}
			}
		}
	}

	return false
}
