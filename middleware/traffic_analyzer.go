package middleware

import (
	"fproxy/handler"
	"log"
	"net/http"
	"strings"
	"time"
	"fmt"
	"regexp"
)

var badUa = []string{"python", "curl", "anon", "mozilla"}

func TrafficAnalyzerMiddleware(next http.Handler) (http.Handler) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		userAgent := r.UserAgent()
		method := r.Method
		url := r.URL.String()
		timestamp := time.Now().Format(time.RFC3339)

		// Log the request details
		log.Printf("Request received: IP=%s, Method=%s, URL=%s, UserAgent=%s, Timestamp=%s", clientIP, method, url, userAgent, timestamp)

		if isMaliciousRequest(r) {
			handler.RespondBlocked(w,r)
			return
		}

		next.ServeHTTP(w, r)
	})

}

func checkMaliciousUA(ua string, badUa []string) bool {
	for _, badUa := range badUa {
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(badUa))
		re := regexp.MustCompile(pattern)
		if re.MatchString(strings.ToLower(ua)) {
			return false
		}
	}
	return true
}

func isMaliciousRequest(r *http.Request) bool {
	// UA
	ua := r.UserAgent()
	if !checkMaliciousUA(ua, badUa) {
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
	if r.Method == "TRACE" || r.Method == "OPTIONS" {
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