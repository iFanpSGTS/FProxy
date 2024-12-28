package captcha

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"fproxy/middleware"
	"html/template"
	"fproxy/handler"
)

const (
	captchaWidth  = 200
	captchaHeight = 100
	chars         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
)

var (
	requestLimit	=	5
	timeWindow		=	1 * time.Minute
)

var (
	captchaMu  sync.Mutex
	captchas   = map[string]string{}
	rl = middleware.NewRateLimiter(requestLimit, timeWindow)
)

func LoadTemplate(data map[string]interface{}) (string,error) {
	tmpl, err := template.ParseFiles("assets/html/captcha.html")
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %v", "captcha.html", err)
	}

	// Create a buffer to store the rendered template
	var buf bytes.Buffer

	// Execute the template with the provided data
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %v", "captcha.html", err)
	}

	return buf.String(), nil
}

func CaptchaHandler(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r)
	if !rl.AllowRequest(ip){
		handler.RespondRatelimit(w, r)
		return
	}
	key, img, err := generateCaptcha()
	// fmt.Println("Base64 CAPTCHA Image:", img)
	if err != nil {
		http.Error(w, "Failed to generate CAPTCHA", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html")
	response, errs := LoadTemplate(map[string]interface{}{
		"CaptchaID": key,
		"CaptchaImg": img,
	},)
	if errs != nil {
		http.Error(w, "Error showing captcha", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, response)
}

func ValidateCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	captchaID := r.FormValue("captcha_id")
	userInput := r.FormValue("captcha")

	captchaMu.Lock()
	expectedValue, exists := captchas[captchaID]
	if exists {
		delete(captchas, captchaID) // Remove solved CAPTCHA
	}
	captchaMu.Unlock()

	if !exists || strings.TrimSpace(userInput) != expectedValue {
		http.Error(w, "Invalid CAPTCHA, please try again.", http.StatusForbidden)
		return
	}

	// Set a short-lived cookie for CAPTCHA solving
	http.SetCookie(w, &http.Cookie{
		Name:    "captcha_solved",
		Value:   "true",
		Path:    "/",
		Expires: time.Now().Add(1 * time.Minute), // Expires in 5 minutes
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func IsCaptchaSolved(r *http.Request) bool {
	cookie, err := r.Cookie("captcha_solved")
	return err == nil && cookie.Value == "true"
}