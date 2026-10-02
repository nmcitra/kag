package ingress

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// This is a handler invariant test, not evidence of real transport attribution.
func FuzzClosedRoutes(f *testing.F) {
	f.Add("POST", "/lab/marker", "", "", false, "", "")
	f.Add("GET", "/admin", "", "", false, "", "")
	f.Add("GET", "/health/live", "execute=marker", "", false, "", "")
	f.Add("GET", "/health/live", "", "", true, "", "")
	f.Add("GET", "/health/live", "", "", false, "http", "example.invalid")
	f.Fuzz(func(t *testing.T, method, path, query, rawPath string, forceQuery bool, scheme, host string) {
		if len(method)+len(path)+len(query)+len(rawPath)+len(scheme)+len(host) > 4096 {
			t.Skip()
		}
		request := &http.Request{
			Method: method,
			URL:    &url.URL{Path: path, RawQuery: query, RawPath: rawPath, ForceQuery: forceQuery, Scheme: scheme, Host: host},
			Body:   io.NopCloser(strings.NewReader("")),
			TLS:    &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{new(x509.Certificate)}}},
		}
		recorder := httptest.NewRecorder()
		closedHandler{}.ServeHTTP(recorder, request)
		permittedHealth := method == "GET" && path == "/health/live" && query == "" && rawPath == "" && !forceQuery && scheme == "" && host == ""
		if recorder.Code >= 200 && recorder.Code < 300 && !permittedHealth {
			t.Fatalf("unexpected success for %q %q", method, path)
		}
	})
}
