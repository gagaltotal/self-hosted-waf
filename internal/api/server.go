// Package api implements the admin dashboard's REST API and serves the
// compiled dashboard frontend. It is deliberately served on a different
// listener/port than the public reverse proxy (see cmd/waf/main.go) so the
// two attack surfaces -- "arbitrary internet traffic to protected sites"
// and "authenticated site management" -- are never on the same port.
package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"

	"waf/internal/httpx"
	"waf/internal/proxy"
	"waf/internal/ratelimit"
	"waf/internal/store"
	"waf/internal/webui"
)

type Server struct {
	db             *store.DB
	sessions       *sessionStore
	limiter        *ratelimit.Limiter
	registry       *proxy.Registry
	trustedProxies *httpx.TrustedProxies
	cookieSecure   bool
	log            *slog.Logger
	handler        http.Handler
}

type Deps struct {
	DB             *store.DB
	Redis          *redis.Client
	Limiter        *ratelimit.Limiter
	Registry       *proxy.Registry
	TrustedProxies *httpx.TrustedProxies
	CookieSecure   bool
	Log            *slog.Logger
}

func NewServer(d Deps) (*Server, error) {
	s := &Server{
		db:             d.DB,
		sessions:       newSessionStore(d.Redis),
		limiter:        d.Limiter,
		registry:       d.Registry,
		trustedProxies: d.TrustedProxies,
		cookieSecure:   d.CookieSecure,
		log:            d.Log,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.Handle("POST /api/auth/logout", s.requireAuth(http.HandlerFunc(s.handleLogout)))
	mux.Handle("GET /api/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
	mux.Handle("POST /api/auth/change-password", s.requireAuth(http.HandlerFunc(s.handleChangePassword)))

	mux.Handle("GET /api/sites", s.requireAuth(http.HandlerFunc(s.handleListSites)))
	mux.Handle("POST /api/sites", s.requireAuth(http.HandlerFunc(s.handleCreateSite)))
	mux.Handle("GET /api/sites/{id}", s.requireAuth(http.HandlerFunc(s.handleGetSite)))
	mux.Handle("PUT /api/sites/{id}", s.requireAuth(http.HandlerFunc(s.handleUpdateSite)))
	mux.Handle("DELETE /api/sites/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteSite)))

	mux.Handle("GET /api/logs", s.requireAuth(http.HandlerFunc(s.handleListLogs)))
	mux.Handle("GET /api/stats/summary", s.requireAuth(http.HandlerFunc(s.handleStatsSummary)))

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	webHandler, err := webui.Handler()
	if err != nil {
		return nil, err
	}
	mux.Handle("/", webHandler)

	var h http.Handler = mux
	h = s.apiRateLimit(h)
	h = securityHeaders(h)
	h = recoverMiddleware(d.Log)(h)

	s.handler = h
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

// apiRateLimit applies a general-purpose limit to every /api/ call so the
// admin panel itself cannot be used as a DoS vector, on top of the much
// tighter, dedicated limit on the login endpoint specifically.
func (s *Server) apiRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ip := s.trustedProxies.ClientIP(r)
			if d := s.limiter.Allow(r.Context(), "admin_api", ip, 20, 40); !d.Allowed {
				writeError(w, http.StatusTooManyRequests, "too many requests")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
