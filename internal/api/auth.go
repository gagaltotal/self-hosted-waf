package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"waf/internal/security"
	"waf/internal/store"
)

// dummyHash is compared against on a login attempt for an email that does
// not exist, so a failed login takes roughly the same amount of time
// whether or not the account is real -- this stops an attacker from using
// response timing to enumerate valid admin email addresses. The password
// behind it is irrelevant and never used for anything else.
var dummyHash, _ = security.HashPassword("not-a-real-account-password")

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.trustedProxies.ClientIP(r)

	// A tight, dedicated limit on the login endpoint itself: this is the
	// single most attacked path in any admin panel.
	if d := s.limiter.Allow(r.Context(), "admin_login", clientIP, 1, 5); !d.Allowed {
		writeError(w, http.StatusTooManyRequests, "too many login attempts, please wait and try again")
		return
	}

	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		_, _ = security.VerifyPassword(req.Password, dummyHash) // burn comparable time
		s.limiter.Strike(r.Context(), clientIP)
		s.log.Warn("admin login failed", "email", email, "ip", clientIP, "reason", "no such user")
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	ok, err := security.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !ok {
		s.limiter.Strike(r.Context(), clientIP)
		s.log.Warn("admin login failed", "email", email, "ip", clientIP, "reason", "bad password")
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := s.sessions.Create(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	setSessionCookie(w, token, s.cookieSecure)
	if _, err := issueCSRFCookie(w, s.cookieSecure); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start session")
		return
	}

	s.log.Info("admin login succeeded", "user_id", user.ID, "ip", clientIP)
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "email": user.Email})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Destroy(r.Context(), sessionCookieValue(r))
	clearSessionCookie(w, s.cookieSecure)
	clearCSRFCookie(w, s.cookieSecure)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, err := s.db.GetUserByID(r.Context(), userIDFromContext(r))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "email": user.Email})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.NewPassword) < 12 {
		writeError(w, http.StatusBadRequest, "new password must be at least 12 characters")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), userIDFromContext(r))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	ok, err := security.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update password")
		return
	}
	if err := s.db.UpdateUserPassword(r.Context(), user.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update password")
		return
	}
	s.log.Info("admin password changed", "user_id", user.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Bootstrap ensures at least one admin account exists. It deliberately
// never ships a hardcoded default username/password: if the operator did
// not set ADMIN_EMAIL/ADMIN_PASSWORD, a cryptographically random password
// is generated and printed to the logs exactly once.
func Bootstrap(ctx context.Context, db *store.DB, log *slog.Logger, email, password string) error {
	n, err := db.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("counting users: %w", err)
	}
	if n > 0 {
		return nil
	}

	if email == "" {
		email = "admin@localhost"
	}
	generated := false
	if password == "" {
		password, err = security.RandomToken(18)
		if err != nil {
			return err
		}
		generated = true
	}
	if len(password) < 12 {
		return fmt.Errorf("ADMIN_PASSWORD must be at least 12 characters")
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := db.CreateUser(ctx, strings.ToLower(email), hash); err != nil {
		return fmt.Errorf("creating initial admin user: %w", err)
	}

	if generated {
		log.Warn("=== INITIAL ADMIN ACCOUNT CREATED ===",
			"email", email, "password", password,
			"note", "this password is shown only once in these logs -- log in now and change it")
	} else {
		log.Info("initial admin account created from ADMIN_EMAIL/ADMIN_PASSWORD", "email", email)
	}
	return nil
}
