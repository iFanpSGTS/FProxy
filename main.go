package main

import (
	"fproxy/captcha"
	"fproxy/rproxy"
	"fmt"
	"net/http"
	"fproxy/middleware"
)

func main() {
	trafficAnalyzer := middleware.TrafficAnalyzerMiddleware(http.DefaultServeMux)
	http.HandleFunc("/", rproxy.ProxyHandler)
	http.HandleFunc("/captcha", captcha.CaptchaHandler)
	http.HandleFunc("/validate-captcha", captcha.ValidateCaptchaHandler)

	fmt.Println("Server running on :8080")
	http.ListenAndServe("localhost:8080", trafficAnalyzer)
}