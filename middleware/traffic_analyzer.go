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

var badUa = []string{"python", "curl", "test", "mzilla/100.0"}
var badMethod = []string{"copy", "wasd", "proffff"}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

var (
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
		start := time.Now()
		clientIP := r.RemoteAddr

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
	fmt.Printf("Unique IPs:     %v\n", uniqueIPs)
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
