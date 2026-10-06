package labruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/nmcitra/kag/internal/action"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TargetState struct {
	Version string `json:"version"`
	Stock   uint64 `json:"stock"`
	Effects uint64 `json:"effects"`
}
type Target struct {
	mu                                                                  sync.Mutex
	Ledger                                                              *Ledger
	Owner                                                               *OwnerLedger
	Authority, DispatchPrincipal, ObserverPrincipal, InspectorPrincipal string
	InspectorPrincipals                                                 []string
}

func (l *Ledger) Used() uint64 { l.mu.Lock(); defer l.mu.Unlock(); return l.used }
func (t *Target) state() TargetState {
	if t.Owner != nil {
		s := t.Owner.State()
		return TargetState{s.Version, s.Stock, s.Effects}
	}
	n := t.Ledger.Used()
	return TargetState{strconv.FormatUint(n, 10), 100 - n*5, n}
}
func Principal(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	d := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return "cert-sha256:" + hex.EncodeToString(d[:])
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func (t *Target) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := Principal(r)
	inspector := p == t.InspectorPrincipal
	for _, allowed := range t.InspectorPrincipals {
		if p == allowed {
			inspector = true
		}
	}
	if p == t.ObserverPrincipal && r.Method == "GET" && r.RequestURI == "/witness" {
		if t.Owner != nil {
			respond(w, 200, map[string]any{"target": t.state(), "owner_policy": t.Owner.PolicyView(), "reservations": t.Owner.Reservations(), "witness": t.Owner.Witness()})
			return
		}
		respond(w, 200, map[string]any{"target": t.state(), "witness": t.Ledger.Witness()})
		return
	}
	if inspector && r.Method == "GET" && r.RequestURI == "/lab/status" {
		respond(w, 200, t.state())
		return
	}
	if t.Owner != nil && inspector && r.Method == "POST" && r.RequestURI == "/lab/reserve" {
		if r.Header.Get("Content-Type") != "application/json" || r.ContentLength < 1 || r.ContentLength > 2048 {
			respond(w, 403, map[string]string{"reason": "owner_request_invalid"})
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 2049))
		if e != nil || len(body) > 2048 || int64(len(body)) != r.ContentLength {
			respond(w, 403, map[string]string{"reason": "owner_request_invalid"})
			return
		}
		var q OwnerReservation
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF {
			respond(w, 403, map[string]string{"reason": "owner_request_invalid"})
			return
		}
		receipt, e := t.Owner.Reserve(q)
		if e != nil {
			respond(w, 403, map[string]string{"reason": e.Error()})
			return
		}
		respond(w, 200, receipt)
		return
	}
	if t.Owner != nil && inspector && r.Method == "POST" && r.RequestURI == "/lab/cancel" {
		if r.Header.Get("Content-Type") != "application/json" || r.ContentLength < 1 || r.ContentLength > 2048 {
			respond(w, 403, map[string]string{"reason": "owner_request_invalid"})
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 2049))
		if e != nil || len(body) > 2048 || int64(len(body)) != r.ContentLength {
			respond(w, 403, map[string]string{"reason": "owner_request_invalid"})
			return
		}
		var q OwnerCancellation
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF {
			respond(w, 403, map[string]string{"reason": "owner_request_invalid"})
			return
		}
		if e = t.Owner.Cancel(q.OwnerReservation, q.ReservationID); e != nil {
			respond(w, 403, map[string]string{"reason": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"status": "cancelled", "reservation_id": q.ReservationID, "owner_policy_digest": t.Owner.PolicyDigest()})
		return
	}
	if p != t.DispatchPrincipal {
		respond(w, 403, map[string]string{"reason": "target_identity_denied"})
		return
	}
	// The target receives only the gateway-owned idempotency key. Strip it from a
	// cloned request before independently applying the exact catalog parser.
	proofHeaders := []string{"X-Lab-Replay-ID", "X-KAG-Binding-Digest", "X-KAG-Operation-Digest", "X-KAG-Replay-ID", "X-KAG-Actor-ID", "X-KAG-Tenant-ID", "X-KAG-Operation-ID"}
	if t.Owner != nil {
		proofHeaders = append(proofHeaders, "X-KAG-Decision-Digest", "X-KAG-Reservation-ID", "X-KAG-Owner-Policy-Digest")
	}
	for _, name := range proofHeaders {
		if r.Method == "POST" && len(r.Header.Values(name)) != 1 {
			respond(w, 403, map[string]string{"reason": "target_binding_metadata_invalid"})
			return
		}
	}
	id := r.Header.Get("X-Lab-Replay-ID")
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Del("X-Lab-Replay-ID")
	for _, name := range proofHeaders[1:] {
		clone.Header.Del(name)
	}
	a, e := action.ParseHTTP(clone, t.Authority)
	if e != nil {
		respond(w, 400, map[string]string{"reason": "target_parser_denied"})
		return
	}
	if a.OperationID() == "lab.read_status" {
		respond(w, 200, t.state())
		return
	}
	marker, v := a.Arguments()
	if v != t.state().Version {
		respond(w, 409, map[string]string{"reason": "target_version_conflict"})
		return
	}
	if t.state().Effects >= 20 {
		respond(w, 403, map[string]string{"reason": "fixture_stock_exhausted"})
		return
	}
	_ = marker
	bindingHex, opHex := r.Header.Get("X-KAG-Binding-Digest"), r.Header.Get("X-KAG-Operation-Digest")
	if !validDigest(bindingHex) || !validDigest(opHex) || r.Header.Get("X-KAG-Replay-ID") != id || r.Header.Get("X-KAG-Operation-ID") != a.OperationID() || !validActor(r.Header.Get("X-KAG-Actor-ID")) || r.Header.Get("X-KAG-Tenant-ID") != "lab-tenant" {
		respond(w, 403, map[string]string{"reason": "target_binding_metadata_invalid"})
		return
	}
	recomputed, e := targetOperation(a, v, id)
	if e != nil || hexDigest(recomputed) != opHex {
		respond(w, 403, map[string]string{"reason": "target_operation_mismatch"})
		return
	}
	if t.Owner != nil {
		if r.Header.Get("X-KAG-Owner-Policy-Digest") != t.Owner.PolicyDigest() {
			respond(w, 403, map[string]string{"reason": "owner_policy_mismatch"})
			return
		}
		q := OwnerReservation{ReplayID: id, BindingDigest: bindingHex, OperationDigest: opHex, DecisionDigest: r.Header.Get("X-KAG-Decision-Digest"), ActorID: r.Header.Get("X-KAG-Actor-ID"), TargetID: action.TargetID, TargetVersion: v}
		if e = t.Owner.Commit(q, r.Header.Get("X-KAG-Reservation-ID")); e != nil {
			respond(w, 403, map[string]string{"reason": e.Error()})
			return
		}
	} else if e = t.Ledger.Reserve(id, bindingHex+opHex, time.Now()); e != nil {
		respond(w, 503, map[string]string{"reason": e.Error()})
		return
	}
	// A durable target attempt is its synthetic mutation; no external side effect
	// exists between reservation and response. Failure to reply is an unknown
	// gateway outcome, while independent witness still reveals committed state.
	respond(w, 200, t.state())
}

func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func validActor(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && strings.ContainsRune("._:-", rune(c)) {
			continue
		}
		return false
	}
	return true
}

// targetOperation independently rebuilds canonical fixed operation bytes. The
// full binding digest is authenticated forwarding; target cannot verify the
// gateway-owned identity projection/configuration from request metadata alone.
func targetOperation(a action.ParsedAction, version, replay string) ([32]byte, error) {
	gran, _ := action.NewIdentityGranularityProfile("instance-required")
	target, _ := action.NewTenantTargetProjection("lab-tenant", "lab-zone", action.TargetID, action.TargetID)
	d := digest("target-operation-reconstruction-v1")
	b, e := action.Bind(a, action.BindingContext{SchemaVersion: action.SchemaVersion, CatalogID: action.CatalogID, CatalogVersion: action.CatalogVersion, CatalogDigest: action.CatalogDigest(), PolicyDigest: d, GatewayBuildDigest: d, ProtectedConfigDigest: d, TargetBuildDigest: d, TargetContractDigest: d, DecisionProfileDigest: d, ActorID: "target-parser", TenantID: "lab-tenant", InstanceID: "target-parser-instance", IdentityProjectionDigest: d, IdentityGranularity: gran, ZoneID: "lab-zone", AudienceID: action.TargetID, TenantTarget: target, TargetVersion: version, ReplayID: replay, ValidFromUnixNS: "1", ExpiresUnixNS: "2"})
	if e != nil {
		return [32]byte{}, e
	}
	return b.Operation().Digest(), nil
}
