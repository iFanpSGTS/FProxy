package handler

import (
	"net/http"
)

// validating every fproxy cookies
func VcaptchaCookies(r *http.Request) bool {
	cookie, err := r.Cookie("captcha_solved")
	return err == nil && cookie.Value == "true"
}