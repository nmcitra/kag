package labruntime

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nmcitra/kag/internal/action"
)

func ownerRequestWithPrincipal(method, path string, body []byte, cert tls.Certificate) *http.Request {
	r := httptest.NewRequest(method, "https://lab.example"+path, bytes.NewReader(body))
	r.RequestURI = path
	r.URL.Scheme = ""
	r.URL.Host = ""
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}, VerifiedChains: [][]*x509.Certificate{{parsed}}}
	return r
}

func TestOwnerTargetRequiresReservationBeforeExactCommit(t *testing.T) {
	_, gatewayCert, envoyCert, _ := testPKI(t)
	owner, err := OpenOwnerLedger(filepath.Join(t.TempDir(), "owner"), ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	target := &Target{Owner: owner, Authority: "lab.example", DispatchPrincipal: fingerprint(envoyCert), InspectorPrincipals: []string{fingerprint(gatewayCert)}, ObserverPrincipal: "observer"}
	args := []byte(`{"marker":"set","expected_version":"0"}`)
	a, _ := action.ParseMCPArguments("lab.set_marker", args)
	op, _ := targetOperation(a, "0", ID(1))
	q := ownerRequest(1, "0")
	q.OperationDigest = hexDigest(op)
	post := func(id, decision string) *httptest.ResponseRecorder {
		r := ownerRequestWithPrincipal("POST", "/lab/marker", args, envoyCert)
		r.Header.Set("Content-Type", "application/json")
		for k, v := range map[string]string{"X-Lab-Replay-ID": ID(1), "X-KAG-Replay-ID": ID(1), "X-KAG-Binding-Digest": q.BindingDigest, "X-KAG-Operation-Digest": q.OperationDigest, "X-KAG-Decision-Digest": decision, "X-KAG-Reservation-ID": id, "X-KAG-Owner-Policy-Digest": owner.PolicyDigest(), "X-KAG-Actor-ID": q.ActorID, "X-KAG-Tenant-ID": "lab-tenant", "X-KAG-Operation-ID": "lab.set_marker"} {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		target.ServeHTTP(w, r)
		return w
	}
	if w := post(ID(99), q.DecisionDigest); w.Code == 200 || owner.State().Effects != 0 {
		t.Fatal("unreserved target effect")
	}
	body, _ := json.Marshal(q)
	r := ownerRequestWithPrincipal("POST", "/lab/reserve", body, gatewayCert)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	target.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var receipt OwnerReceipt
	if json.Unmarshal(w.Body.Bytes(), &receipt) != nil || receipt.ReservationID == "" {
		t.Fatal(w.Body.String())
	}
	if owner.State().Stock != 100 {
		t.Fatal("reserve changed stock")
	}
	if w := post(receipt.ReservationID, hexDigest(digest("wrong"))); w.Code == 200 {
		t.Fatal("changed decision")
	}
	if w := post(receipt.ReservationID, q.DecisionDigest); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := post(receipt.ReservationID, q.DecisionDigest); w.Code == 200 {
		t.Fatal("replay committed twice")
	}
	if owner.State().Stock != 95 || len(owner.Witness()) != 1 {
		t.Fatal(owner.State())
	}
}

func TestOwnerTargetCancellationEndpointIsAuthenticatedAndExact(t *testing.T) {
	_, gatewayCert, envoyCert, _ := testPKI(t)
	owner, err := OpenOwnerLedger(filepath.Join(t.TempDir(), "owner"), ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	target := &Target{Owner: owner, Authority: "lab.example", DispatchPrincipal: fingerprint(envoyCert), InspectorPrincipals: []string{fingerprint(gatewayCert)}}
	q := ownerRequest(1, "0")
	rc, err := owner.Reserve(q)
	if err != nil {
		t.Fatal(err)
	}
	cancel := map[string]any{"replay_id": q.ReplayID, "binding_digest": q.BindingDigest, "operation_digest": q.OperationDigest, "decision_digest": q.DecisionDigest, "actor_id": q.ActorID, "target_id": q.TargetID, "target_version": q.TargetVersion, "reservation_id": rc.ReservationID}
	body, _ := json.Marshal(cancel)
	request := func(cert tls.Certificate, raw []byte) *httptest.ResponseRecorder {
		r := ownerRequestWithPrincipal("POST", "/lab/cancel", raw, cert)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		target.ServeHTTP(w, r)
		return w
	}
	if w := request(envoyCert, body); w.Code == 200 {
		t.Fatal("dispatch identity cancelled owner hold")
	}
	cancel["decision_digest"] = hexDigest(digest("altered"))
	bad, _ := json.Marshal(cancel)
	if w := request(gatewayCert, bad); w.Code == 200 {
		t.Fatal("altered cancellation")
	}
	if w := request(gatewayCert, body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if owner.State().Stock != 100 || owner.Reservations()[0].Status != "cancelled" {
		t.Fatal("no-dispatch cancellation failed")
	}
}

func TestOwnerTargetWitnessStartsWithEmptyEffectArray(t *testing.T) {
	_, observerCert, envoyCert, _ := testPKI(t)
	owner, err := OpenOwnerLedger(filepath.Join(t.TempDir(), "owner"), ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	target := &Target{Owner: owner, Authority: "lab.example", DispatchPrincipal: fingerprint(envoyCert), ObserverPrincipal: fingerprint(observerCert)}
	r := ownerRequestWithPrincipal("GET", "/witness", nil, observerCert)
	w := httptest.NewRecorder()
	target.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if string(result["witness"]) != "[]" || string(result["reservations"]) != "[]" {
		t.Fatal("zero-state arrays required", w.Body.String())
	}
}
