package handler

import (
	"net/http"
	"time"
)

// validating every fproxy cookies
func VcaptchaCookies(r *http.Request) bool {
	cookie, err := r.Cookie("captcha_solved")
	return err == nil && cookie.Value == "true"
}

// SetCaptchaSolvedCookie sets the captcha_solved cookie for a short duration
func SetCaptchaSolvedCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    "captcha_solved",
		Value:   "true",
		Path:    "/",
		Expires: time.Now().Add(1 * time.Minute), // Expires in 1 minute
	})
}