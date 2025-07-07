package main

import (
	"fproxy/captcha"
	"fproxy/rproxy"
	"fmt"
	"net/http"
	"fproxy/middleware"
)

func main() {
	addr := "localhost:8080"
	endpoints := map[string]string{
		"/":                 "Reverse Proxy",
		"/captcha":          "Captcha Challenge",
		"/validate-captcha": "Captcha Validation",
	}

	trafficAnalyzer := middleware.TrafficAnalyzerMiddleware(http.DefaultServeMux)
	http.HandleFunc("/", rproxy.ProxyHandler)
	http.HandleFunc("/captcha", captcha.CaptchaHandler)
	http.HandleFunc("/validate-captcha", captcha.ValidateCaptchaHandler)

	fmt.Println("======================================")
	fmt.Println(" FProxy Server is starting up...")
	fmt.Printf(" Listening on:   http://%s\n", addr)
	fmt.Println(" Endpoints:")
	for path, desc := range endpoints {
		fmt.Printf("   %-18s -> %s\n", path, desc)
	}
	fmt.Println("======================================")

	if err := http.ListenAndServe(addr, trafficAnalyzer); err != nil {
		fmt.Printf("Server failed to start: %v\n", err)
	}
}