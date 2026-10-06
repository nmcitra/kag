package labruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/authn"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type testListener struct {
	a       *authn.Acceptor
	addr    net.Addr
	ctx     context.Context
	cancel  context.CancelFunc
	handles chan authn.TransportHandle
}

func (l *testListener) Accept() (net.Conn, error) {
	a, e := l.a.Accept(l.ctx)
	if e != nil {
		return nil, e
	}
	l.handles <- a.Handle()
	return a.Conn(), nil
}
func (l *testListener) Close() error   { l.cancel(); return l.a.Close() }
func (l *testListener) Addr() net.Addr { return l.addr }
func testPKI(t *testing.T) (tls.Certificate, tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-lab-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(n int, usage x509.ExtKeyUsage) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(n)), Subject: pkix.Name{CommonName: "lab"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		b, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: key}
	}
	return issue(2, x509.ExtKeyUsageServerAuth), issue(3, x509.ExtKeyUsageClientAuth), issue(4, x509.ExtKeyUsageClientAuth), roots
}
func fingerprint(c tls.Certificate) string {
	d := sha256.Sum256(c.Certificate[0])
	return "cert-sha256:" + hex.EncodeToString(d[:])
}
func tlsClient(c tls.Certificate, roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{c}}, DisableKeepAlives: true}}
}
func TestActualGatewayLibrariesAndTargetBudget(t *testing.T) {
	serverCert, agentCert, dispatchCert, roots := testPKI(t)
	targetLedger, e := OpenLedger(filepath.Join(t.TempDir(), "target"), 20, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer targetLedger.Close()
	targetHandler := &Target{Ledger: targetLedger, DispatchPrincipal: fingerprint(dispatchCert), ObserverPrincipal: "unreachable", InspectorPrincipal: fingerprint(dispatchCert)}
	var loseReply atomic.Bool
	targetServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && loseReply.CompareAndSwap(true, false) {
			rec := httptest.NewRecorder()
			targetHandler.ServeHTTP(rec, r)
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		targetHandler.ServeHTTP(w, r)
	}))
	targetServer.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	targetServer.StartTLS()
	defer targetServer.Close()
	targetHandler.Authority = targetServer.Listener.Addr().String()
	var tampered atomic.Bool
	bridge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q BridgeRequest
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			w.WriteHeader(400)
			return
		}
		now := time.Now().UnixNano()
		out := BridgeReply{Allow: true, DecisionDigest: hexDigest(digest("observed-synthetic-kil-decision")), Issued: now, Expires: now + int64(4*time.Second), BindingDigest: q.BindingDigest, OperationDigest: q.OperationDigest, ReplayID: q.ReplayID}
		if tampered.Load() {
			out.BindingDigest = hexDigest(digest("wrong"))
		}
		respond(w, 200, out)
	}))
	bridge.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	bridge.StartTLS()
	defer bridge.Close()
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	acceptor, e := authn.NewAcceptor(raw, authn.Config{ServerCertificate: serverCert, ClientRoots: roots, TrustDomain: "lab-domain", CredentialProfile: "lab-mtls-v1", TrustRevision: 1, TrustValidFrom: now.Add(-time.Minute), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: time.Minute, HandshakeTimeout: time.Second, MaxHandshakes: 4, MaxSessions: 64})
	if e != nil {
		t.Fatal(e)
	}
	ledger, e := OpenLedger(filepath.Join(t.TempDir(), "gateway"), 4, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer ledger.Close()
	gateway, e := NewGateway(acceptor, ledger, tlsClient(dispatchCert, roots), map[string]string{fingerprint(agentCert): "agent-one"}, raw.Addr().String(), targetServer.URL, bridge.URL)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener := &testListener{acceptor, raw.Addr(), ctx, cancel, make(chan authn.TransportHandle, 1)}
	server := &http.Server{Handler: gateway, ConnContext: func(ctx context.Context, c net.Conn) context.Context { return WithTransport(ctx, <-listener.handles) }}
	go server.Serve(listener)
	defer server.Close()
	client := tlsClient(agentCert, roots)
	// A valid dispatch credential cannot substitute operation bytes under a
	// well-formed digest: the target independently rebuilds the operation.
	bad, _ := http.NewRequest("POST", targetServer.URL+"/lab/marker", bytes.NewReader([]byte(`{"marker":"set","expected_version":"0"}`)))
	bad.Header.Set("Content-Type", "application/json")
	for k, v := range map[string]string{"X-Lab-Replay-ID": ID(90), "X-KAG-Replay-ID": ID(90), "X-KAG-Binding-Digest": hexDigest(digest("well-formed-binding")), "X-KAG-Operation-Digest": hexDigest(digest("wrong-operation")), "X-KAG-Actor-ID": "agent-one", "X-KAG-Tenant-ID": "lab-tenant", "X-KAG-Operation-ID": "lab.set_marker"} {
		bad.Header.Set(k, v)
	}
	badRes, e := tlsClient(dispatchCert, roots).Do(bad)
	if e != nil {
		t.Fatal(e)
	}
	badRes.Body.Close()
	if badRes.StatusCode != 403 || targetLedger.Used() != 0 {
		t.Fatal("changed operation reached target")
	}
	validAction, _ := action.ParseMCPArguments("lab.set_marker", []byte(`{"marker":"set","expected_version":"0"}`))
	validOperation, _ := targetOperation(validAction, "0", ID(90))
	bad.Header.Set("X-KAG-Operation-Digest", hexDigest(validOperation))
	bad.Body, _ = bad.GetBody()
	bad.Header.Add("X-KAG-Replay-ID", ID(91))
	badRes, e = tlsClient(dispatchCert, roots).Do(bad)
	if e != nil {
		t.Fatal(e)
	}
	badRes.Body.Close()
	if badRes.StatusCode != 403 || targetLedger.Used() != 0 {
		t.Fatal("duplicate proof metadata reached target")
	}
	for i := 0; i < 5; i++ {
		if i == 2 {
			loseReply.Store(true)
		}
		body := []byte(`{"marker":"set","expected_version":"` + strconv.Itoa(i) + `"}`)
		req, _ := http.NewRequest("POST", "https://"+raw.Addr().String()+"/lab/marker", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if i == 2 && res.StatusCode != 503 {
			t.Fatal("lost response must be unknown", res.StatusCode, out)
		}
		if i < 4 && i != 2 && res.StatusCode != 200 {
			t.Fatal(i, res.StatusCode, out)
		}
		if i == 4 && res.StatusCode != 403 {
			t.Fatal("fifth escaped", res.StatusCode, out)
		}
	}
	if targetLedger.Used() != 4 || ledger.Used() != 4 {
		t.Fatal("effect accounting")
	}
	if len(targetLedger.Witness()) != 4 {
		t.Fatal("independent witness missing effects")
	}
	for _, event := range targetLedger.Witness() {
		if !validDigest(event["binding_digest"].(string)) || !validDigest(event["operation_digest"].(string)) {
			t.Fatal("witness not exact binding+operation")
		}
	}
	defer gateway.Audit.Close()
	// A new actor cannot reach target directly with its agent credential.
	req, _ := http.NewRequest("POST", targetServer.URL+"/lab/marker", bytes.NewReader([]byte(`{"marker":"set","expected_version":"4"}`)))
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("agent direct target")
	}
	// Tampered bridge echo is rejected before reservation even for read status.
	tampered.Store(true)
	res, e = client.Get("https://" + raw.Addr().String() + "/lab/status")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("tampered bridge accepted")
	}
	tampered.Store(false)
	gateway.Audit.sync = func() error { return ErrHeld }
	res, e = client.Get("https://" + raw.Addr().String() + "/lab/status")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatal("audit failure did not hold dispatch")
	}
	if targetLedger.Used() != 4 {
		t.Fatal("audit failure caused mutation")
	}
}
