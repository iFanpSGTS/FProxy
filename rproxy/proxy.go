package rproxy

import (
	"fproxy/captcha"
	"fproxy/handler"
	"fproxy/middleware"
	"io"
	"net/http"
	"net/url"
	"time"
)

var backendURL = "http://localhost:8000"
var (
	requestLimit      = 5              // Max requests allowed
	timeWindow        = 1 * time.Minute // Time window for rate limiting
	rl = middleware.NewRateLimiter(requestLimit, timeWindow)
)

func proxyToBackend(w http.ResponseWriter, r *http.Request) {
	backend, err := url.Parse(backendURL)
	if err != nil {
		http.Error(w, "Invalid backend URL", http.StatusInternalServerError)
		return
	}
	proxyReq, err := http.NewRequest(r.Method, backend.ResolveReference(r.URL).String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	proxyReq.Header = r.Header.Clone()

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Failed to connect to backend server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r)

	if !captcha.IsCaptchaSolved(r){
		http.Redirect(w, r, "/captcha", http.StatusFound)
		return
	}
	// Proxy logic
	if !rl.AllowRequest(ip){
		handler.RespondRatelimit(w, r)
		return
	}
	proxyToBackend(w, r)

	// Invalidate the CAPTCHA cookie after the proxy request
	http.SetCookie(w, &http.Cookie{
		Name:   "captcha_solved",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Deletes the cookie
	})
}