package handler

import (
	"html/template"
	"net/http"
	"fmt"
	"bytes"
)

var (
	ratelimitTemplate = "assets/html/ratelimit.html"
	unavailableBackend	  = "assets/html/unavailable.html"
)

func getResponseBody(title string, msg string) string {
	return fmt.Sprintf("<html><head><title>%s</title></head><body>%s</body></html>", title, msg)
}

func loadErrorTemplate(templateName string, data map[string]interface{}) (string, error) {
	tmpl, err := template.ParseFiles(templateName)
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %v", templateName, err)
	}

	// Create a buffer to store the rendered template
	var buf bytes.Buffer

	// Execute the template with the provided data
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %v", templateName, err)
	}

	return buf.String(), nil
}

func RespondUnavailable(w http.ResponseWriter, r *http.Request) {
	response, err := loadErrorTemplate(
		unavailableBackend,
		map[string]interface{}{
		},
	)
	if err != nil {
		response = getResponseBody("502", "Bad Gateaway")
	}

	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, response)
}

func RespondRatelimit(w http.ResponseWriter, r *http.Request) {
	response, err := loadErrorTemplate(
		ratelimitTemplate,
		map[string]interface{}{
		},
	)
	if err != nil {
		response = getResponseBody("RateLimit", "You have been exceeded ratelimit!")
	}

	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprint(w, response)
}