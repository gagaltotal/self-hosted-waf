package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Server wraps the plain-HTTP and (optional) TLS listeners for the public
// reverse-proxy side of the WAF. Timeouts are set deliberately conservative
// -- a WAF that can itself be tied up by slow-headers / slow-body clients
// (Slowloris and friends) has failed at its one job.
type Server struct {
	http  *http.Server
	https *http.Server
	log   *slog.Logger
}

func NewServer(httpAddr, httpsAddr, certFile, keyFile string, handler http.Handler, log *slog.Logger) (*Server, error) {
	s := &Server{log: log}

	s.http = &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
		ErrorLog:          nil,
	}

	if httpsAddr != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS certificate: %w", err)
		}
		s.https = &http.Server{
			Addr:              httpsAddr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
				// TLS 1.3 cipher suites are not configurable in crypto/tls
				// (Go picks strong ones automatically); the list above only
				// constrains the TLS 1.2 fallback to forward-secret, AEAD suites.
			},
		}
	}

	return s, nil
}

// Start launches both listeners (if configured) in the background and sends
// any fatal listen error to errc.
func (s *Server) Start(errc chan<- error) {
	go func() {
		s.log.Info("proxy listening (http)", "addr", s.http.Addr)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errc <- fmt.Errorf("http listener: %w", err)
		}
	}()

	if s.https != nil {
		go func() {
			s.log.Info("proxy listening (https)", "addr", s.https.Addr)
			if err := s.https.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errc <- fmt.Errorf("https listener: %w", err)
			}
		}()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.http.Shutdown(ctx); err != nil {
		return err
	}
	if s.https != nil {
		return s.https.Shutdown(ctx)
	}
	return nil
}
