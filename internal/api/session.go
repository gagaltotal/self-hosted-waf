package api

import (
	"context"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"waf/internal/security"
)

const (
	sessionTTL        = 12 * time.Hour
	sessionCookieName = "_waf_session"
)

type sessionStore struct {
	rdb *redis.Client
}

func newSessionStore(rdb *redis.Client) *sessionStore {
	return &sessionStore{rdb: rdb}
}

// Create issues a new session for userID and returns the raw token to be
// set as a cookie. Only SHA-256(token) is ever stored in Redis, so a
// snapshot/backup of the cache alone cannot be replayed as a live session.
func (s *sessionStore) Create(ctx context.Context, userID string) (token string, err error) {
	token, err = security.RandomToken(32)
	if err != nil {
		return "", err
	}
	key := "session:" + security.HashToken(token)
	if err := s.rdb.Set(ctx, key, userID, sessionTTL).Err(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *sessionStore) UserID(ctx context.Context, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	key := "session:" + security.HashToken(token)
	userID, err := s.rdb.Get(ctx, key).Result()
	if err != nil {
		return "", false
	}
	return userID, true
}

func (s *sessionStore) Destroy(ctx context.Context, token string) {
	if token == "" {
		return
	}
	key := "session:" + security.HashToken(token)
	_ = s.rdb.Del(ctx, key).Err()
}

func sessionCookieValue(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func setSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}
