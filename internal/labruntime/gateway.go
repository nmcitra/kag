package labruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	urlpkg "net/url"
	"strconv"
	"time"

	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/authn"
	"github.com/nmcitra/kag/internal/decision"
	"github.com/nmcitra/kag/internal/execution"
	"github.com/nmcitra/kag/internal/identity"
)

type BridgeRequest struct {
	BindingDigest   string `json:"binding_digest"`
	OperationDigest string `json:"operation_digest"`
	ReplayID        string `json:"replay_id"`
	ActorID         string `json:"actor_id"`
	TenantID        string `json:"tenant_id"`
	OperationID     string `json:"operation_id"`
}
type BridgeReply struct {
	Allow           bool     `json:"allow"`
	DecisionDigest  string   `json:"decision_digest"`
	Reasons         []string `json:"reasons"`
	Issued          int64    `json:"issued_at_unix_ns"`
	Expires         int64    `json:"expires_unix_ns"`
	BindingDigest   string   `json:"binding_digest"`
	OperationDigest string   `json:"operation_digest"`
	ReplayID        string   `json:"replay_id"`
}
type Gateway struct {
	Audit                                         *Ledger
	Acceptor                                      *authn.Acceptor
	Resolver                                      *identity.Resolver
	Ledger                                        *Ledger
	Client                                        *http.Client
	Authority, TargetURL, DecisionURL, InspectURL string
	OwnerURL, OwnerPolicyDigest                   string
	Clock                                         RealClock
	private                                       ed25519.PrivateKey
	public                                        ed25519.PublicKey
	configDigest                                  [32]byte
}
type transportContext struct{}

func NewGateway(a *authn.Acceptor, l *Ledger, client *http.Client, actors map[string]string, authority, target, bridge string) (*Gateway, error) {
	for _, s := range []string{target, bridge} {
		u, e := urlpkg.Parse(s)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("protected_upstream_invalid")
		}
	}
	clock := RealClock{time.Now()}
	resolver, e := newResolver(a, actors, clock)
	if e != nil {
		return nil, e
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	audit, e := OpenAudit(l.file.Name() + ".audit")
	if e != nil {
		return nil, e
	}
	return &Gateway{Audit: audit, Acceptor: a, Resolver: resolver, Ledger: l, Client: client, Authority: authority, TargetURL: target, DecisionURL: bridge, InspectURL: target, Clock: clock, private: priv, public: pub, configDigest: digest("lab-gateway-v1:" + authority + ":" + target + ":" + bridge + ":" + strconv.FormatUint(l.budget, 10) + ":" + l.spacing.String())}, nil
}
func (g *Gateway) EnableOwner(url string, policy OwnerPolicy) error {
	u, e := urlpkg.Parse(url)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return ErrOwnerBinding
	}
	pd, e := policy.Digest()
	if e != nil {
		return e
	}
	g.OwnerURL = url
	g.OwnerPolicyDigest = pd
	g.configDigest = digest("lab-gateway-owner-v1:" + g.Authority + ":" + g.TargetURL + ":" + g.DecisionURL + ":" + url + ":" + pd)
	return nil
}
func hexDigest(d [32]byte) string { return hex.EncodeToString(d[:]) }
func bridgeRequest(b action.Binding) BridgeRequest {
	v, _ := b.View()
	return BridgeRequest{hexDigest(b.Digest()), hexDigest(v.OperationDigest), v.ReplayID, v.ActorID, v.TenantID, v.OperationID}
}
func (g *Gateway) kil(ctx context.Context, b action.Binding) (BridgeReply, error) {
	q := bridgeRequest(b)
	body, _ := json.Marshal(q)
	r, e := http.NewRequestWithContext(ctx, "POST", g.DecisionURL, bytes.NewReader(body))
	if e != nil {
		return BridgeReply{}, errors.New("bridge_invalid")
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := g.Client.Do(r)
	if e != nil {
		return BridgeReply{}, errors.New("kil_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return BridgeReply{}, errors.New("kil_withheld")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return BridgeReply{}, errors.New("kil_invalid")
	}
	var out BridgeReply
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
		return out, errors.New("kil_invalid")
	}
	now := time.Now().UnixNano()
	d, de := hex.DecodeString(out.DecisionDigest)
	if !out.Allow || de != nil || len(d) != 32 || out.Issued <= 0 || out.Issued > now || out.Expires <= now || out.Expires-out.Issued > int64(5*time.Second) || out.BindingDigest != q.BindingDigest || out.OperationDigest != q.OperationDigest || out.ReplayID != q.ReplayID {
		return out, errors.New("kil_withheld")
	}
	return out, nil
}
func (g *Gateway) status(ctx context.Context) (TargetState, error) {
	r, e := http.NewRequestWithContext(ctx, "GET", g.InspectURL+"/lab/status", nil)
	if e != nil {
		return TargetState{}, e
	}
	response, e := g.Client.Do(r)
	if e != nil {
		return TargetState{}, errors.New("target_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return TargetState{}, errors.New("target_unavailable")
	}
	var out TargetState
	d := json.NewDecoder(io.LimitReader(response.Body, 1024))
	if d.Decode(&out) != nil {
		return out, errors.New("target_invalid")
	}
	n, e := strconv.ParseUint(out.Version, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != out.Version || out.Effects != n || n > 20 || out.Stock != 100-n*5 {
		return out, errors.New("target_invalid")
	}
	return out, nil
}

// reserveOwner obtains the shared target-wide durable hold. No gateway-local
// budget can substitute for this receipt when owner mode is configured.
func (g *Gateway) reserveOwner(ctx context.Context, q OwnerReservation) (OwnerReceipt, error) {
	if g.OwnerURL == "" || !validDigest(g.OwnerPolicyDigest) {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	body, _ := json.Marshal(q)
	r, e := http.NewRequestWithContext(ctx, "POST", g.OwnerURL+"/lab/reserve", bytes.NewReader(body))
	if e != nil {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := g.Client.Do(r)
	if e != nil {
		return OwnerReceipt{}, ErrHeld
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return OwnerReceipt{}, ErrOwnerFloor
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1025))
	if e != nil || len(raw) > 1024 {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	var out OwnerReceipt
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || len(out.ReservationID) != 32 || out.OwnerPolicyDigest != g.OwnerPolicyDigest || out.RemainingAvailableStock > 100 {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	if parsed, e := hex.DecodeString(out.ReservationID); e != nil || len(parsed) != 16 || hex.EncodeToString(parsed) != out.ReservationID {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	return out, nil
}

func (g *Gateway) cancelOwner(ctx context.Context, q OwnerReservation, rc OwnerReceipt) error {
	if g.OwnerURL == "" || rc.OwnerPolicyDigest != g.OwnerPolicyDigest || len(rc.ReservationID) != 32 {
		return ErrOwnerBinding
	}
	body, _ := json.Marshal(OwnerCancellation{OwnerReservation: q, ReservationID: rc.ReservationID})
	r, e := http.NewRequestWithContext(ctx, "POST", g.OwnerURL+"/lab/cancel", bytes.NewReader(body))
	if e != nil {
		return ErrOwnerBinding
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := g.Client.Do(r)
	if e != nil {
		return ErrHeld
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return ErrHeld
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 513))
	if e != nil || len(raw) > 512 {
		return ErrOwnerBinding
	}
	var out struct {
		Status            string `json:"status"`
		ReservationID     string `json:"reservation_id"`
		OwnerPolicyDigest string `json:"owner_policy_digest"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Status != "cancelled" || out.ReservationID != rc.ReservationID || out.OwnerPolicyDigest != g.OwnerPolicyDigest {
		return ErrOwnerBinding
	}
	return nil
}

type sources struct{ gateway *Gateway }

func (s sources) Check(ctx context.Context, h identity.ActorHandle, b action.Binding) (decision.PermissionObservation, error) {
	v, e := b.View()
	if e != nil {
		return decision.PermissionObservation{}, e
	}
	p, e := s.gateway.kil(ctx, b)
	if e != nil {
		return decision.PermissionObservation{}, e
	}
	d, _ := hex.DecodeString(p.DecisionDigest)
	var ed [32]byte
	copy(ed[:], d)
	mask := uint8(0)
	if v.OperationID == "lab.set_marker" {
		mask = 3
	}
	return decision.PermissionObservation{SourceID: "lab-kil-bridge", ContractDigest: digest("lab-kil-bridge-v1"), EvidenceDigest: ed, ActorID: v.ActorID, TenantID: v.TenantID, IdentityProjectionDigest: v.IdentityProjectionDigest, BindingDigest: b.Digest(), OperationDigest: v.OperationDigest, ObservedAtUnixNS: p.Issued, ExpiresUnixNS: p.Expires, Outcome: "allowed", AllowedMarkers: mask}, nil
}
func (s sources) Inspect(ctx context.Context, b action.Binding) (decision.InspectionObservation, error) {
	v, e := b.View()
	if e != nil {
		return decision.InspectionObservation{}, e
	}
	status, e := s.gateway.status(ctx)
	if e != nil || status.Version != v.TargetVersion {
		return decision.InspectionObservation{}, errors.New("target_version_withheld")
	}
	now := time.Now().UnixNano()
	return decision.InspectionObservation{SourceID: "lab-target-inspector", ContractDigest: digest("lab-target-inspector-v1"), EvidenceDigest: digest(status.Version + ":" + hexDigest(b.Digest())), BindingDigest: b.Digest(), OperationDigest: v.OperationDigest, ObservedAtUnixNS: now, ExpiresUnixNS: now + int64(time.Second), Outcome: "allowed"}, nil
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var auditNonce [16]byte
	if _, e := rand.Read(auditNonce[:]); e != nil {
		respond(w, 503, map[string]string{"decision": "deny", "reason": "entropy_unavailable"})
		return
	}
	auditID := hex.EncodeToString(auditNonce[:])
	auditReplay, auditBinding := "", ""
	deny := func(reason string) {
		if g.Audit.Audit(auditID, auditReplay, auditBinding, "deny", reason) != nil {
			respond(w, 503, map[string]string{"decision": "deny", "reason": "recorder_held"})
			return
		}
		respond(w, 403, map[string]string{"decision": "deny", "reason": reason})
	}
	h, ok := r.Context().Value(transportContext{}).(authn.TransportHandle)
	if !ok {
		deny("transport_invalid")
		return
	}
	a, e := action.ParseHTTP(r, g.Authority)
	if e != nil {
		deny(e.Error())
		return
	}
	scope, e := identity.NewResolveScope(a, action.TargetID)
	if e != nil {
		deny(e.Error())
		return
	}
	actor, e := g.Resolver.Resolve(r.Context(), h, scope)
	if e != nil {
		deny(e.Error())
		return
	}
	projection, e := actor.Projection()
	if e != nil {
		deny(e.Error())
		return
	}
	status, e := g.status(r.Context())
	if e != nil {
		deny("target_unavailable")
		return
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		deny("entropy_unavailable")
		return
	}
	id := hex.EncodeToString(nonce[:])
	now := time.Now().UnixNano()
	end := now + int64(4*time.Second)
	if projection.ExpiresUnixNS < end {
		end = projection.ExpiresUnixNS
	}
	gran, _ := action.NewIdentityGranularityProfile("instance-required")
	target, _ := action.NewTenantTargetProjection("lab-tenant", "lab-zone", action.TargetID, action.TargetID)
	policyDigest := digest("lab-declared-marker-effects-v1")
	if g.OwnerURL != "" {
		policyDigest = digest("lab-owner-floor-v1:" + g.OwnerPolicyDigest)
	}
	b, e := action.Bind(a, action.BindingContext{SchemaVersion: action.SchemaVersion, CatalogID: action.CatalogID, CatalogVersion: action.CatalogVersion, CatalogDigest: action.CatalogDigest(), PolicyDigest: policyDigest, GatewayBuildDigest: digest("experimental-kag-lab-v1"), ProtectedConfigDigest: g.configDigest, TargetBuildDigest: digest("experimental-target-v1"), TargetContractDigest: digest("marker-five-units-v1"), DecisionProfileDigest: digest("experimental-model-decision-v1"), ActorID: projection.ActorID, TenantID: projection.TenantID, InstanceID: projection.InstanceID, IdentityProjectionDigest: projection.IdentityProjectionDigest, IdentityGranularity: gran, ZoneID: "lab-zone", AudienceID: action.TargetID, TenantTarget: target, TargetVersion: status.Version, ReplayID: id, ValidFromUnixNS: strconv.FormatInt(now, 10), ExpiresUnixNS: strconv.FormatInt(end, 10)})
	if e != nil {
		deny(e.Error())
		return
	}
	auditReplay, auditBinding = id, hexDigest(b.Digest())
	kil, e := g.kil(r.Context(), b)
	if e != nil {
		deny(e.Error())
		return
	}
	v, _ := b.View()
	demand := uint64(0)
	mask := uint8(0)
	if a.OperationID() == "lab.set_marker" {
		demand = 1
		mask = 3
	}
	claims := decision.Claims{ProducerID: "lab-kil-normalizer", ProfileID: decision.ProfileID, ResultKind: "final", ResultID: "kil:" + kil.DecisionDigest, BindingDigest: b.Digest(), OperationDigest: v.OperationDigest, IdentityProjectionDigest: v.IdentityProjectionDigest, ActorID: v.ActorID, TenantID: v.TenantID, InstanceID: v.InstanceID, ZoneID: v.ZoneID, AudienceID: v.AudienceID, ReplayID: id, CatalogDigest: v.CatalogDigest, PolicyDigest: v.PolicyDigest, GatewayBuildDigest: v.GatewayBuildDigest, ProtectedConfigDigest: v.ProtectedConfigDigest, TargetBuildDigest: v.TargetBuildDigest, TargetContractDigest: v.TargetContractDigest, DecisionProfileDigest: v.DecisionProfileDigest, IssuedAtUnixNS: time.Now().UnixNano(), ExpiresUnixNS: kil.Expires, Outcome: "allow", CapacityKnown: true, AutonomyDemand: demand, EffectiveCapacity: 1, Tier: "Operator", Supervision: "stable", Magnitude: "fixture-effects", Unit: "effects", ConstraintCeiling: 1, AllowedMarkers: mask}
	if claims.ExpiresUnixNS > end {
		claims.ExpiresUnixNS = end
	}
	payload, e := decision.EncodeClaims(claims)
	if e != nil {
		deny(e.Error())
		return
	}
	source := sources{g}
	validator, e := decision.NewValidator(decision.Config{Resolver: g.Resolver, Inspector: source, PermissionSource: source, Clock: g.Clock, EvidenceLane: identity.Modeled, ProducerID: claims.ProducerID, PublicKey: g.public, ProfileDigest: v.DecisionProfileDigest, InspectorID: "lab-target-inspector", InspectorContractDigest: digest("lab-target-inspector-v1"), PermissionID: "lab-kil-bridge", PermissionContractDigest: digest("lab-kil-bridge-v1"), MaxPermissionAge: 5 * time.Second, MaxInspectionAge: time.Second, MaxClockDriftNS: int64(time.Second), SourceTimeout: time.Second, MaxCalls: 16, MaxProofAge: 5 * time.Second})
	if e != nil {
		deny(e.Error())
		return
	}
	permit, e := validator.Evaluate(r.Context(), actor, scope, b, decision.SignedResult{Payload: payload, Signature: ed25519.Sign(g.private, payload)})
	if e != nil {
		deny(e.Error())
		return
	}
	reservation, e := execution.NewReservation(b, permit, "lab-episode")
	if e != nil {
		deny(e.Error())
		return
	}
	var ownerReceipt OwnerReceipt
	var ownerRequest OwnerReservation
	localReservation := false
	if demand > 0 {
		if g.OwnerURL != "" {
			ownerRequest = OwnerReservation{ReplayID: id, BindingDigest: hexDigest(b.Digest()), OperationDigest: hexDigest(b.Operation().Digest()), DecisionDigest: kil.DecisionDigest, ActorID: v.ActorID, TargetID: action.TargetID, TargetVersion: status.Version}
			ownerReceipt, e = g.reserveOwner(r.Context(), ownerRequest)
		} else {
			e = g.Ledger.Reserve(reservation.ReplayID(), hexDigest(b.Digest())+kil.DecisionDigest, time.Now())
			localReservation = e == nil
		}
		if e != nil {
			deny(e.Error())
			return
		}
	}
	// A cancelled client context cannot prevent a no-dispatch cancellation. A
	// failed cancellation remains an unknown held reservation and never releases.
	cancelBeforeDispatch := func() bool {
		if g.OwnerURL == "" || demand == 0 {
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := g.cancelOwner(ctx, ownerRequest, ownerReceipt); err != nil {
			respond(w, 503, map[string]string{"decision": "unknown", "reason": "owner_cancel_unknown", "replay_id": id, "reservation_id": ownerReceipt.ReservationID})
			return false
		}
		return true
	}
	// No outbound mutation occurs before durable attempt consumption and recheck.
	if _, e = validator.Recheck(r.Context(), permit, b); e != nil {
		if !cancelBeforeDispatch() {
			return
		}
		if localReservation {
			g.Ledger.Outcome(id, "unknown")
		}
		deny(e.Error())
		return
	}
	auditReason := "reserved_rechecked"
	if g.OwnerURL != "" && demand > 0 {
		auditReason += ":" + ownerReceipt.ReservationID + ":" + ownerReceipt.OwnerPolicyDigest
	}
	if e = g.Audit.Audit(auditID, id, hexDigest(b.Digest()), "pre_dispatch", auditReason); e != nil {
		if !cancelBeforeDispatch() {
			return
		}
		respond(w, 503, map[string]string{"decision": "deny", "reason": "recorder_held"})
		return
	}
	op := b.Operation()
	req, e := http.NewRequestWithContext(r.Context(), op.Method(), g.TargetURL+op.Path(), bytes.NewReader(op.Body()))
	if e != nil {
		if !cancelBeforeDispatch() {
			return
		}
		deny("dispatch_invalid")
		return
	}
	if op.ContentType() != "" {
		req.Header.Set("Content-Type", op.ContentType())
	}
	q := bridgeRequest(b)
	for k, val := range map[string]string{"X-Lab-Replay-ID": id, "X-KAG-Binding-Digest": q.BindingDigest, "X-KAG-Operation-Digest": q.OperationDigest, "X-KAG-Replay-ID": q.ReplayID, "X-KAG-Actor-ID": q.ActorID, "X-KAG-Tenant-ID": q.TenantID, "X-KAG-Operation-ID": q.OperationID} {
		req.Header.Set(k, val)
	}
	if g.OwnerURL != "" && demand > 0 {
		req.Header.Set("X-KAG-Decision-Digest", kil.DecisionDigest)
		req.Header.Set("X-KAG-Reservation-ID", ownerReceipt.ReservationID)
		req.Header.Set("X-KAG-Owner-Policy-Digest", ownerReceipt.OwnerPolicyDigest)
	}
	res, e := g.Client.Do(req)
	if e != nil {
		if localReservation {
			g.Ledger.Outcome(id, "unknown")
		}
		g.recordOutcome(id, hexDigest(b.Digest()), "unknown", "target_outcome_unknown")
		respond(w, 503, map[string]string{"decision": "unknown", "reason": "target_outcome_unknown", "replay_id": id, "binding_digest": hexDigest(b.Digest()), "operation_digest": hexDigest(b.Operation().Digest())})
		return
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 1025))
	var after TargetState
	known := res.StatusCode == 200 && e == nil && len(raw) <= 1024 && json.Unmarshal(raw, &after) == nil
	if localReservation {
		outcome := "unknown"
		if known {
			outcome = "known"
		}
		if e = g.Ledger.Outcome(id, outcome); e != nil {
			respond(w, 503, map[string]string{"decision": "unknown", "reason": "recorder_held", "replay_id": id, "binding_digest": hexDigest(b.Digest()), "operation_digest": hexDigest(b.Operation().Digest())})
			return
		}
	}
	if !known {
		g.recordOutcome(id, hexDigest(b.Digest()), "unknown", "target_outcome_unknown")
		respond(w, 503, map[string]string{"decision": "unknown", "reason": "target_outcome_unknown", "replay_id": id, "binding_digest": hexDigest(b.Digest()), "operation_digest": hexDigest(b.Operation().Digest())})
		return
	}
	if e = g.recordOutcome(id, hexDigest(b.Digest()), "permit", "target_known"); e != nil {
		respond(w, 503, map[string]string{"decision": "unknown", "reason": "recorder_held", "replay_id": id, "binding_digest": hexDigest(b.Digest()), "operation_digest": hexDigest(b.Operation().Digest())})
		return
	}
	response := map[string]any{"decision": "permit", "reason": "modeled_lab_permit", "replay_id": id, "binding_digest": hexDigest(b.Digest()), "operation_digest": hexDigest(b.Operation().Digest()), "kil_decision_digest": kil.DecisionDigest, "target": after}
	if g.OwnerURL != "" && demand > 0 {
		response["reservation_id"] = ownerReceipt.ReservationID
		response["owner_policy_digest"] = ownerReceipt.OwnerPolicyDigest
	}
	respond(w, 200, response)
}

// WithTransport attaches only the acceptor-owned possession handle captured by
// the executable's protected listener. Request metadata cannot construct one.
func WithTransport(ctx context.Context, h authn.TransportHandle) context.Context {
	return context.WithValue(ctx, transportContext{}, h)
}

func (g *Gateway) recordOutcome(replay, binding, decision, reason string) error {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return ErrHeld
	}
	return g.Audit.Audit(hex.EncodeToString(nonce[:]), replay, binding, decision, reason)
}
