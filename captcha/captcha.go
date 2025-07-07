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
	mu sync.Mutex
	requestLimit	=	5
	timeWindow		=	1 * time.Minute
)

var (
	slots	  = make(map[string]chan struct{})
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
	fmt.Println("catch here")
	ip := middleware.GetClientIP(r)
	mu.Lock()
	ch, ok := slots[ip]
	if !ok {
		ch = make(chan struct{}, 1) // limit 1 per IP
		slots[ip] = ch
	}
	mu.Unlock()
	select {
	case ch <- struct{}{}:
		defer func() { <-ch }()

		if !rl.AllowRequest(ip){
			handler.RespondRatelimit(w, r)
			return
		}
		key, img, err := generateCaptcha()
		if err != nil {
			http.Error(w, "Failed to generate CAPTCHA", http.StatusInternalServerError)
			return
		}
		
		response, errs := LoadTemplate(map[string]interface{}{
			"CaptchaID": key,
			"CaptchaImg": img,
			},)
			if errs != nil {
				http.Error(w, "Error showing captcha", http.StatusInternalServerError)
				return
			}
		handler.SetCaptchaHeaders(w,r)
		fmt.Fprint(w, response)
	default:
		handler.RespondUnavailable(w, r)
		return
	}
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
		delete(captchas, captchaID)
	}
	captchaMu.Unlock()

	if !exists || strings.TrimSpace(userInput) != expectedValue {
		handler.RespondInvalidCaptcha(w, r)
		return
	}

	// Set a short-lived cookie for CAPTCHA solving
	handler.SetCaptchaSolvedCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}