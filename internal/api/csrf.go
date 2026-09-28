package api

import (
	"crypto/subtle"
	"net/http"

	"waf/internal/security"
)

const csrfCookieName = "_waf_csrf"
const csrfHeaderName = "X-CSRF-Token"

// The session cookie is already SameSite=Strict, which alone stops the
// browser from attaching it to any cross-site request. The CSRF token is a
// second, independent layer: it does not rely on cookie-attachment
// behaviour at all, so it still holds even in a webview or older browser
// that handles SameSite differently than expected.
func issueCSRFCookie(w http.ResponseWriter, secure bool) (string, error) {
	token, err := security.RandomToken(24)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: false, // must be readable by frontend JS to echo back in a header
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
	return token, nil
}

func clearCSRFCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func csrfSafe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func validCSRF(r *http.Request) bool {
	if csrfSafe(r.Method) {
		return true
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get(csrfHeaderName)
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) == 1
}
