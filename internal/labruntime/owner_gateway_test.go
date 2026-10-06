package labruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmcitra/kag/internal/authn"
)

type ownerTransport func(*http.Request) (*http.Response, error)

func (f ownerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOwnerGatewayReserveValidatesExactReceipt(t *testing.T) {
	q := ownerRequest(1, "0")
	policy := hexDigest(digest("owner-policy"))
	receipt := OwnerReceipt{ReservationID: ID(99), OwnerPolicyDigest: policy, RemainingAvailableStock: 95}
	client := &http.Client{Transport: ownerTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.String() != "https://owner.example/lab/reserve" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("wrong owner route")
		}
		var got OwnerReservation
		if json.NewDecoder(r.Body).Decode(&got) != nil || got != q {
			t.Fatal("reservation tuple changed")
		}
		b, _ := json.Marshal(receipt)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}}, nil
	})}
	g := &Gateway{Client: client, OwnerURL: "https://owner.example", OwnerPolicyDigest: policy}
	got, err := g.reserveOwner(context.Background(), q)
	if err != nil || got != receipt {
		t.Fatal(got, err)
	}
	receipt.OwnerPolicyDigest = "wrong"
	if _, err = g.reserveOwner(context.Background(), q); err == nil {
		t.Fatal("invalid receipt accepted")
	}
}

func TestOwnerGatewayCancelSendsExactTupleAndRequiresAck(t *testing.T) {
	q := ownerRequest(1, "0")
	policy := hexDigest(digest("owner-policy"))
	rc := OwnerReceipt{ReservationID: ID(99), OwnerPolicyDigest: policy, RemainingAvailableStock: 95}
	client := &http.Client{Transport: ownerTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.String() != "https://owner.example/lab/cancel" {
			t.Fatal("wrong cancellation route")
		}
		var got OwnerCancellation
		if json.NewDecoder(r.Body).Decode(&got) != nil || got.OwnerReservation != q || got.ReservationID != rc.ReservationID {
			t.Fatal("cancellation tuple changed", got)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte(`{"status":"cancelled","reservation_id":"` + rc.ReservationID + `","owner_policy_digest":"` + policy + `"}`))), Header: http.Header{}}, nil
	})}
	g := &Gateway{Client: client, OwnerURL: "https://owner.example", OwnerPolicyDigest: policy}
	if err := g.cancelOwner(context.Background(), q, rc); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerGatewayAuditFailureCancelsProvenNoDispatchHold(t *testing.T) {
	serverCert, agentCert, upstreamCert, roots := testPKI(t)
	owner, err := OpenOwnerLedger(filepath.Join(t.TempDir(), "owner"), ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	targetHandler := &Target{Owner: owner, DispatchPrincipal: fingerprint(upstreamCert), InspectorPrincipals: []string{fingerprint(upstreamCert)}}
	targetServer := httptest.NewUnstartedServer(targetHandler)
	targetServer.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	targetServer.StartTLS()
	defer targetServer.Close()
	targetHandler.Authority = targetServer.Listener.Addr().String()
	bridge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q BridgeRequest
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			w.WriteHeader(400)
			return
		}
		now := time.Now().UnixNano()
		respond(w, 200, BridgeReply{Allow: true, DecisionDigest: hexDigest(digest("allowed")), Issued: now, Expires: now + int64(4*time.Second), BindingDigest: q.BindingDigest, OperationDigest: q.OperationDigest, ReplayID: q.ReplayID})
	}))
	bridge.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	bridge.StartTLS()
	defer bridge.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	acceptor, err := authn.NewAcceptor(raw, authn.Config{ServerCertificate: serverCert, ClientRoots: roots, TrustDomain: "lab-domain", CredentialProfile: "lab-mtls-v1", TrustRevision: 1, TrustValidFrom: now.Add(-time.Minute), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: time.Minute, HandshakeTimeout: time.Second, MaxHandshakes: 4, MaxSessions: 64})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "gateway"), 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	gateway, err := NewGateway(acceptor, ledger, tlsClient(upstreamCert, roots), map[string]string{fingerprint(agentCert): "agent-one"}, raw.Addr().String(), targetServer.URL, bridge.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err = gateway.EnableOwner(targetServer.URL, ownerPolicy()); err != nil {
		t.Fatal(err)
	}
	defer gateway.Audit.Close()
	gateway.Audit.sync = func() error { return ErrHeld }
	ctx, cancel := context.WithCancel(context.Background())
	listener := &testListener{acceptor, raw.Addr(), ctx, cancel, make(chan authn.TransportHandle, 1)}
	server := &http.Server{Handler: gateway, ConnContext: func(ctx context.Context, c net.Conn) context.Context { return WithTransport(ctx, <-listener.handles) }}
	go server.Serve(listener)
	defer server.Close()
	req, _ := http.NewRequest("POST", "https://"+raw.Addr().String()+"/lab/marker", bytes.NewReader([]byte(`{"marker":"set","expected_version":"0"}`)))
	req.Header.Set("Content-Type", "application/json")
	res, err := tlsClient(agentCert, roots).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 || owner.State().Stock != 100 || len(owner.Reservations()) != 1 || owner.Reservations()[0].Status != "cancelled" {
		t.Fatal("audit failure stranded owner hold", res.StatusCode, owner.State(), owner.Reservations())
	}
}
