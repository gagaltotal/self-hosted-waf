package challenge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var turnstileHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// VerifyTurnstile checks a client-submitted Turnstile response token
// against Cloudflare's verification endpoint. This is only called for
// sites an operator has explicitly configured with bot_challenge_mode =
// "turnstile" and their own site/secret keys -- it is never on the default
// path, so a self-hosted deployment with no Cloudflare account never makes
// this call.
func VerifyTurnstile(ctx context.Context, secretKey, responseToken, remoteIP string) (bool, error) {
	if secretKey == "" || responseToken == "" {
		return false, fmt.Errorf("missing turnstile secret or response token")
	}

	form := url.Values{}
	form.Set("secret", secretKey)
	form.Set("response", responseToken)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := turnstileHTTPClient.Do(req)
	if err != nil {
		// Fail closed for this specific check: if Cloudflare is
		// unreachable we cannot confirm the visitor passed, so they are
		// asked to retry rather than being waved through.
		return false, fmt.Errorf("contacting turnstile verification endpoint: %w", err)
	}
	defer resp.Body.Close()

	var parsed turnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return false, fmt.Errorf("parsing turnstile response: %w", err)
	}
	return parsed.Success, nil
}
