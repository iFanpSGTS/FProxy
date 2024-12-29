package rproxy

import (
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

func ProxyToBackend(w http.ResponseWriter, r *http.Request) {
	backend, err := url.Parse(backendURL)
	if err != nil {
		handler.GetResponseBody("HTTP Error", "BackendURL Error")
		return
	}
	proxyReq, err := http.NewRequest(r.Method, backend.ResolveReference(r.URL).String(), r.Body)
	if err != nil {
		handler.GetResponseBody("HTTP Error", "Front Request -> Backend Error")
		return
	}

	proxyReq.Header = r.Header.Clone()

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		handler.RespondUnavailable(w,r)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r)
	
	if !handler.VcaptchaCookies(r){
		http.Redirect(w, r, "/captcha", http.StatusFound)
		return
	}
	// Proxy logic
	if !rl.AllowRequest(ip){
		handler.RespondRatelimit(w, r)
		return
	}
	ProxyToBackend(w, r)
	
	// Invalidate the CAPTCHA cookie after the proxy request
	http.SetCookie(w, &http.Cookie{
		Name:   "captcha_solved",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Deletes the cookie
	})
}