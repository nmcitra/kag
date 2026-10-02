package ingress

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	roots       *x509.CertPool
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return testCA{certificate, private, roots}
}

func (ca testCA) leaf(t *testing.T, server, expired bool) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	until := time.Now().Add(time.Hour)
	if expired {
		until = time.Now().Add(-time.Minute)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: until,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

func startClosedServer(t *testing.T, ca testCA) *httptest.Server {
	t.Helper()
	config, err := NewServer("127.0.0.1:0", ca.leaf(t, true, false), ca.roots)
	if err != nil {
		t.Fatal(err)
	}
	// Suppress expected handshake errors only in the test fixture.
	config.ErrorLog = log.New(io.Discard, "", 0)
	server := httptest.NewUnstartedServer(config.Handler)
	server.Config = config
	server.TLS = config.TLSConfig.Clone()
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func testClient(t *testing.T, ca testCA, certificates ...tls.Certificate) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: ca.roots, MinVersion: tls.VersionTLS13, Certificates: certificates,
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestMissingTrustConfiguration(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.leaf(t, true, false)
	for _, config := range []struct {
		addr  string
		cert  tls.Certificate
		roots *x509.CertPool
	}{
		{"", cert, ca.roots}, {"127.0.0.1:0", tls.Certificate{}, ca.roots},
		{"127.0.0.1:0", cert, nil}, {"127.0.0.1:0", cert, x509.NewCertPool()},
	} {
		if server, err := NewServer(config.addr, config.cert, config.roots); err == nil || server != nil {
			t.Fatal("incomplete trust configuration constructed a server")
		}
	}
}

func TestTransportRejectsSpoofedIdentity(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	server := startClosedServer(t, ca)
	for _, test := range []struct {
		name         string
		certificates []tls.Certificate
	}{
		{"missing", nil},
		{"untrusted", []tls.Certificate{other.leaf(t, false, false)}},
		{"expired", []tls.Certificate{ca.leaf(t, false, true)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, ca, test.certificates...)
			request, err := http.NewRequest(http.MethodGet, server.URL+"/health/live", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Agent-ID", "trusted-worker")
			response, err := client.Do(request)
			if response != nil {
				response.Body.Close()
			}
			if err == nil {
				t.Fatal("invalid transport identity reached a handler")
			}
		})
	}
}

func TestAuthenticatedWorkerCannotReleaseActions(t *testing.T) {
	ca := newTestCA(t)
	server := startClosedServer(t, ca)
	client := testClient(t, ca, ca.leaf(t, false, false))
	for _, test := range []struct {
		method, path string
		expected     int
	}{
		{"GET", "/health/live", 200}, {"GET", "/health/ready", 503},
		{"GET", "/lab/status", 503}, {"POST", "/lab/marker", 503},
		{"POST", "/mcp", 503}, {"POST", "/health/live", 503},
		{"GET", "/health/live?", 503},
		{"GET", "/health/live?execute=marker", 503}, {"GET", "/health/%6cive", 503},
		{"GET", "/admin", 503}, {"CONNECT", "/lab/marker", 503},
	} {
		request, err := http.NewRequest(test.method, server.URL+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Agent-ID", "operator")
		request.Header.Set("X-KAG-Allow", "true")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.expected {
			t.Fatalf("%s %s: got %d want %d", test.method, test.path, response.StatusCode, test.expected)
		}
	}
}

func TestOversizedBodyCannotReleaseActions(t *testing.T) {
	ca := newTestCA(t)
	server := startClosedServer(t, ca)
	client := testClient(t, ca, ca.leaf(t, false, false))
	for _, chunked := range []bool{false, true} {
		request, err := http.NewRequest("POST", server.URL+"/lab/marker", strings.NewReader(strings.Repeat("x", int(maxBodyBytes)+1)))
		if err != nil {
			t.Fatal(err)
		}
		if chunked {
			request.ContentLength = -1
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v got %d", chunked, response.StatusCode)
		}
	}
}

// Use the real TLS listener with raw HTTP request targets to exercise forms that
// http.Client ordinarily rewrites before sending to an origin server.
func TestLivenessRejectsNonOriginTargets(t *testing.T) {
	ca := newTestCA(t)
	server := startClosedServer(t, ca)
	for _, target := range []string{"/health/live?", "http://example.invalid/health/live"} {
		t.Run(target, func(t *testing.T) {
			conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{
				RootCAs: ca.roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{ca.leaf(t, false, false)},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "GET "+target+" HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("non-origin target %q got %d want 503", target, response.StatusCode)
			}
		})
	}
}
