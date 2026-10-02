package ingress

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"time"
)

const maxBodyBytes int64 = 65536

// NewServer builds the closed foundation. It has no target or provider client.
// A verified client certificate is transport authentication, not earned authority.
func NewServer(addr string, certificate tls.Certificate, roots *x509.CertPool) (*http.Server, error) {
	if addr == "" || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil || roots == nil || len(roots.Subjects()) == 0 {
		return nil, errors.New("address, server certificate and client CA roots required")
	}
	return &http.Server{
		Addr:              addr,
		Handler:           closedHandler{},
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16384,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			ClientCAs:    roots.Clone(),
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   []string{"http/1.1"},
		},
	}, nil
}

type closedHandler struct{}

func (closedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "authenticated transport required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		http.Error(w, "request body rejected", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Method == http.MethodGet && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.URL.RawPath == "" && r.URL.Scheme == "" && r.URL.Host == "" {
		switch r.URL.Path {
		case "/health/live":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "live\n")
			return
		case "/health/ready":
			http.Error(w, "actions unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	// Action-shaped requests, health aliases and all other routes remain closed.
	http.Error(w, "actions unavailable", http.StatusServiceUnavailable)
}
